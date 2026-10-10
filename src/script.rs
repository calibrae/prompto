//! Script execution — feeds the script body via SSH stdin so the source
//! never gets re-parsed by an intermediate shell. Removes the quoting
//! hell of `ssh_exec "bash -c '...'"`.
//!
//! `bash_exec` calls [`run`] with `bash` and an optional argv. This
//! module is plumbing only. (The other interpreter tools were removed in
//! v0.12.2; `ssh_exec` with a heredoc replaces them.)

use anyhow::Result;
use std::time::Duration;

use crate::ctx::CallCtx;
use crate::inventory::HostConfig;
use crate::ssh::{ExecOutput, SshClient};

/// Allow-list of interpreter names. Restrictive by design — the value
/// flows into the remote shell command, and the goal is to fail closed
/// on typos rather than open a shell-injection vector.
pub const ALLOWED_INTERPRETERS: &[&str] = &["bash"];

pub fn validate_interpreter(name: &str) -> Result<()> {
    if !ALLOWED_INTERPRETERS.contains(&name) {
        crate::fail!(
            InvalidArgs,
            "interpreter {name:?} not in allow-list (allowed: {:?})",
            ALLOWED_INTERPRETERS
        );
    }
    Ok(())
}

/// The interpreter each interpreter tool runs.
pub const INTERPRETER_TOOLS: &[(&str, &str)] = &[("bash_exec", "bash")];

/// The interpreter `tool` runs, if it is an interpreter tool.
pub fn interpreter_for_tool(tool: &str) -> Option<&'static str> {
    INTERPRETER_TOOLS
        .iter()
        .find(|(t, _)| *t == tool)
        .map(|(_, i)| *i)
}

/// The remote shell could not find `interpreter`, so nothing of the
/// script ran — `bash_exec` on a host without bash (FreeBSD, OPNsense).
/// Each shell words it its own way:
///
/// - dash, FreeBSD sh: `sh: 1: bash: not found`, exit 127
/// - zsh: `zsh:1: command not found: bash`, exit 127
/// - csh/tcsh (FreeBSD, OPNsense): `bash: Command not found.`, exit 1
/// - `env` (the root side of the vault sudo path):
///   `env: 'bash': No such file or directory`, exit 127
/// - another shell in the bash family: `ksh: bash: command not found`
///
/// A script that fails on its own with one of these lines still needs
/// the matching exit status, and the name must be the interpreter's.
pub fn interpreter_missing(interpreter: &str, exit_code: Option<i32>, stderr: &str) -> bool {
    let named = |l: &str, suffix: &str| {
        [
            format!("{interpreter}{suffix}"),
            format!("'{interpreter}'{suffix}"),
        ]
        .iter()
        .any(|pat| {
            l.match_indices(pat.as_str()).any(|(i, _)| {
                !l[..i]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || "_-.".contains(c))
            })
        })
    };
    stderr.lines().any(|l| match exit_code {
        Some(127) => {
            named(l, ": command not found")
                || named(l, ": not found")
                || l.trim_end()
                    .ends_with(&format!("command not found: {interpreter}"))
                || (l.starts_with("env: ") && named(l, ": No such file or directory"))
        }
        Some(1) => named(l, ": Command not found."),
        _ => false,
    })
}

/// Validate one positional argument that will become argv[N] after the
/// script. Permissive enough for paths, flags, and `--key=value` shapes;
/// rejects shell metacharacters that would let the value break out.
pub fn validate_arg(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 1024 {
        crate::fail!(InvalidArgs, "script arg too long");
    }
    let bad_chars = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '*', '?', '(', ')', '{',
        '}', '\t', ' ',
    ];
    if value.chars().any(|c| bad_chars.contains(&c)) {
        crate::fail!(
            InvalidArgs,
            "arg {value:?} contains shell metacharacter or whitespace — pass it via the script body instead"
        );
    }
    Ok(())
}

/// Run a script through an interpreter on a remote host. Script body is
/// piped via SSH stdin so embedded quotes/heredocs/etc. survive
/// untouched. Args (if any) become positional argv after the script.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ssh: &SshClient,
    ctx: &CallCtx,
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

    let mut cmd = format!("{interpreter} -s");
    for a in args {
        cmd.push(' ');
        cmd.push_str(a);
    }

    ssh.exec_stdin(ctx, host, &cmd, script.as_bytes(), cmd_timeout, sudo)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreter_missing_in_every_shells_wording() {
        for (exit, stderr) in [
            (127, "ksh: line 1: bash: command not found\n"),
            (127, "sh: 1: bash: not found\n"),
            (127, "bash: not found\n"),
            (127, "zsh:1: command not found: bash\n"),
            (1, "bash: Command not found.\n"),
            (127, "env: 'bash': No such file or directory\n"),
            (127, "env: bash: No such file or directory\n"),
        ] {
            assert!(
                interpreter_missing("bash", Some(exit), stderr),
                "{exit} {stderr:?}"
            );
        }
    }

    #[test]
    fn interpreter_missing_needs_the_interpreter_and_the_exit() {
        for (exit, stderr) in [
            // Another program missing, as the script's own failure.
            (127, "bash: line 3: foo: command not found\n"),
            (127, "sh: 1: xbash: not found\n"),
            (127, "bash: line 1: bash5: command not found\n"),
            // Right words, wrong exit: the script printed them itself.
            (1, "bash: command not found\n"),
            (2, "bash: Command not found.\n"),
            (127, "bash: No such file or directory\n"),
        ] {
            assert!(
                !interpreter_missing("bash", Some(exit), stderr),
                "{exit} {stderr:?}"
            );
        }
        assert!(!interpreter_missing("bash", None, "bash: not found"));
    }

    #[test]
    fn every_interpreter_tool_maps_to_an_allowed_interpreter() {
        for (tool, i) in INTERPRETER_TOOLS {
            assert!(ALLOWED_INTERPRETERS.contains(i), "{tool}");
            assert_eq!(interpreter_for_tool(tool), Some(*i));
        }
        assert_eq!(interpreter_for_tool("ssh_exec"), None);
        assert_eq!(interpreter_for_tool("python_exec"), None);
    }

    #[test]
    fn validate_interpreter_accepts_allow_list() {
        for name in ALLOWED_INTERPRETERS {
            validate_interpreter(name).unwrap();
        }
    }

    #[test]
    fn validate_interpreter_rejects_unknown() {
        assert!(validate_interpreter("notalang").is_err());
        assert!(validate_interpreter("python3").is_err());
        assert!(validate_interpreter("bash; rm -rf /").is_err());
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
}
