//! Generic interpreter execution — feeds the script body via SSH stdin
//! so the source never gets re-parsed by an intermediate shell. Removes
//! the quoting-hell that plagues `ssh_exec "python3 -c '...'"`.
//!
//! Per-language wrapper tools (`python_exec`, `node_exec`, `bash_exec`)
//! call [`run`] with their interpreter and an optional argv. Each tool
//! gets its own MCP surface, baseline tokens, and filter integration —
//! this module is plumbing only.

use anyhow::{Result, bail};
use std::borrow::Cow;
use std::time::Duration;

use crate::inventory::HostConfig;
use crate::ssh::{ExecOutput, SshClient};

/// Allow-list of interpreter names. Restrictive by design — the value
/// flows into the remote shell command, and the goal is to fail closed
/// on typos rather than open a shell-injection vector.
pub const ALLOWED_INTERPRETERS: &[&str] = &[
    "python", "python3", "node", "deno", "bun", "ruby", "perl", "bash", "sh", "zsh",
];

pub fn validate_interpreter(name: &str) -> Result<()> {
    if !ALLOWED_INTERPRETERS.contains(&name) {
        bail!(
            "interpreter {name:?} not in allow-list (allowed: {:?})",
            ALLOWED_INTERPRETERS
        );
    }
    Ok(())
}

/// Validate one positional argument that will become argv[N] after the
/// script. Permissive enough for paths, flags, and `--key=value` shapes;
/// rejects shell metacharacters that would let the value break out.
pub fn validate_arg(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 1024 {
        bail!("script arg too long");
    }
    let bad_chars = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '*', '?', '(', ')', '{',
        '}', '\t', ' ',
    ];
    if value.chars().any(|c| bad_chars.contains(&c)) {
        bail!(
            "arg {value:?} contains shell metacharacter or whitespace — pass it via the script body instead"
        );
    }
    Ok(())
}

/// Pick the right "read script from stdin" flag for a given interpreter.
/// `python -`, `node -`, `ruby -`, `perl -`, `deno run -`, `bun run -` —
/// most read stdin when the script-path is `-`. Bash family uses `-s`.
fn stdin_marker(interpreter: &str) -> &'static str {
    match interpreter {
        "bash" | "sh" | "zsh" => "-s",
        "deno" => "run -",
        "bun" => "run -",
        _ => "-", // python, python3, node, ruby, perl
    }
}

/// Run a script through an interpreter on a remote host. Script body is
/// piped via SSH stdin so embedded quotes/heredocs/etc. survive
/// untouched. Args (if any) become positional argv after the script.
pub async fn run(
    ssh: &SshClient,
    host: &HostConfig,
    interpreter: &str,
    script: &str,
    args: &[String],
    cmd_timeout: Option<Duration>,
    sudo: bool,
) -> Result<ExecOutput> {
    validate_interpreter(interpreter)?;
    for a in args {
        validate_arg(a)?;
    }

    let mut cmd = format!("{interpreter} {}", stdin_marker(interpreter));
    for a in args {
        cmd.push(' ');
        cmd.push_str(a);
    }

    ssh.exec_stdin(host, &cmd, script.as_bytes(), cmd_timeout, sudo)
        .await
}

/// Compact a Node.js / V8 stack trace to "ExceptionType: message
/// (N frames; last: file:line)". Conservative: returns verbatim stderr
/// when no stack-frame lines (`    at func (file:line:col)`) are found.
pub fn compact_node_stack(stderr: &str) -> Cow<'_, str> {
    let lines: Vec<&str> = stderr.lines().collect();
    if lines.is_empty() {
        return Cow::Borrowed(stderr);
    }
    let mut frames: Vec<&str> = Vec::new();
    for line in &lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with("at ") {
            frames.push(trimmed);
        }
    }
    if frames.is_empty() {
        return Cow::Borrowed(stderr);
    }

    // Find the exception line: typically the first non-empty,
    // non-frame, non-source-context line that contains "Error:" or
    // "Exception:" or similar.
    let mut exc: Option<&str> = None;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if line.trim_start().starts_with("at ") {
            continue;
        }
        if trimmed.contains("Error:")
            || trimmed.contains("Error ")
            || trimmed.ends_with("Error")
            || trimmed.contains("Exception:")
        {
            exc = Some(trimmed);
            break;
        }
    }

    let last_frame = frames.last().copied().unwrap_or("");
    let frame_count = frames.len();

    match exc {
        Some(e) => Cow::Owned(format!(
            "{} ({} frames; last: {})\n",
            e, frame_count, last_frame,
        )),
        None => Cow::Borrowed(stderr),
    }
}

/// Compact a Python traceback to "ExceptionType: message (at file:line in
/// func, N frames)". Conservative: if stderr doesn't contain a
/// recognisable traceback header, returns the original verbatim.
///
/// This is wired through `python_exec` directly (not the FilterChain),
/// because the chain keys on the user's command and `python_exec`'s
/// internal cmd is `python3 -` regardless of what script ran.
pub fn compact_python_traceback(stderr: &str) -> Cow<'_, str> {
    let Some(start) = stderr.find("Traceback (most recent call last):") else {
        return Cow::Borrowed(stderr);
    };
    let preamble = &stderr[..start];
    let traceback = &stderr[start..];

    let lines: Vec<&str> = traceback.lines().collect();
    if lines.len() < 3 {
        return Cow::Borrowed(stderr);
    }

    // Frames look like:  '  File "<stdin>", line 5, in <module>'
    let mut last_frame: Option<&str> = None;
    let mut frame_count = 0u32;
    for line in &lines {
        if line.trim_start().starts_with("File ") {
            frame_count += 1;
            last_frame = Some(line.trim());
        }
    }

    // The exception line is the last non-empty line that doesn't start
    // with whitespace (frame headers / source lines are indented).
    let mut exc: Option<&str> = None;
    for line in lines.iter().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Frame headers and source-context lines are indented; the
        // exception summary is at column 0.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            exc = Some(trimmed);
            break;
        }
    }

    match (exc, last_frame) {
        (Some(e), Some(f)) => Cow::Owned(format!(
            "{}{} ({} frames; last: {})\n",
            preamble, e, frame_count, f,
        )),
        (Some(e), None) => Cow::Owned(format!("{}{}\n", preamble, e)),
        _ => Cow::Borrowed(stderr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_interpreter_accepts_allow_list() {
        for name in ALLOWED_INTERPRETERS {
            validate_interpreter(name).unwrap();
        }
    }

    #[test]
    fn validate_interpreter_rejects_unknown() {
        assert!(validate_interpreter("notalang").is_err());
        assert!(validate_interpreter("python; rm -rf /").is_err());
    }

    #[test]
    fn validate_arg_accepts_normal_inputs() {
        validate_arg("--flag").unwrap();
        validate_arg("--key=value").unwrap();
        validate_arg("/path/to/file.txt").unwrap();
        validate_arg("42").unwrap();
        validate_arg("").unwrap();
    }

    #[test]
    fn validate_arg_rejects_shell_metas() {
        assert!(validate_arg("foo;bar").is_err());
        assert!(validate_arg("foo|bar").is_err());
        assert!(validate_arg("$(whoami)").is_err());
        assert!(validate_arg("`id`").is_err());
        assert!(validate_arg("foo bar").is_err(), "spaces blocked too");
        assert!(validate_arg("foo\nbar").is_err());
        assert!(validate_arg(&"x".repeat(2000)).is_err());
    }

    #[test]
    fn stdin_marker_per_interpreter() {
        assert_eq!(stdin_marker("python3"), "-");
        assert_eq!(stdin_marker("python"), "-");
        assert_eq!(stdin_marker("node"), "-");
        assert_eq!(stdin_marker("ruby"), "-");
        assert_eq!(stdin_marker("bash"), "-s");
        assert_eq!(stdin_marker("sh"), "-s");
        assert_eq!(stdin_marker("zsh"), "-s");
        assert_eq!(stdin_marker("deno"), "run -");
        assert_eq!(stdin_marker("bun"), "run -");
    }

    #[test]
    fn compact_traceback_collapses_to_exception_and_last_frame() {
        let stderr = "Traceback (most recent call last):\n\
                      \x20 File \"/usr/lib/python3.11/foo.py\", line 12, in bar\n\
                      \x20\x20\x20 do_thing()\n\
                      \x20 File \"<stdin>\", line 5, in <module>\n\
                      \x20\x20\x20 bar()\n\
                      ValueError: bad input 'xyz'\n";
        let out = compact_python_traceback(stderr);
        let s = out.as_ref();
        assert!(s.contains("ValueError: bad input 'xyz'"));
        assert!(s.contains("2 frames"));
        assert!(s.contains("<stdin>"));
        assert!(!s.contains("/usr/lib/python3.11/foo.py")); // first frame stripped
    }

    #[test]
    fn compact_traceback_passes_through_when_no_traceback() {
        let stderr = "warning: deprecated thing\n";
        let out = compact_python_traceback(stderr);
        assert_eq!(out, "warning: deprecated thing\n");
    }

    #[test]
    fn compact_node_stack_collapses_v8_trace() {
        let stderr = "/home/cali/x.js:3\n\
                      throw new TypeError('foo');\n\
                      ^\n\
                      \n\
                      TypeError: foo\n\
                      \x20\x20\x20\x20at fn (/home/cali/x.js:3:11)\n\
                      \x20\x20\x20\x20at /home/cali/x.js:5:1\n\
                      \x20\x20\x20\x20at Script.runInThisContext (node:vm:144:12)\n";
        let out = compact_node_stack(stderr);
        let s = out.as_ref();
        assert!(s.contains("TypeError: foo"));
        assert!(s.contains("3 frames"));
        assert!(s.contains("Script.runInThisContext"));
    }

    #[test]
    fn compact_node_stack_passes_through_when_no_frames() {
        let stderr = "/usr/local/bin/node: bad option\n";
        let out = compact_node_stack(stderr);
        assert_eq!(out, "/usr/local/bin/node: bad option\n");
    }

    #[test]
    fn compact_traceback_preserves_preamble_warnings() {
        let stderr = "DeprecationWarning: thing\n\
                      Traceback (most recent call last):\n\
                      \x20 File \"<stdin>\", line 1, in <module>\n\
                      RuntimeError: oh no\n";
        let out = compact_python_traceback(stderr);
        let s = out.as_ref();
        assert!(s.starts_with("DeprecationWarning: thing"));
        assert!(s.contains("RuntimeError: oh no"));
    }
}
