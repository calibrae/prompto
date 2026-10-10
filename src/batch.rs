//! Batch SSH execution — run N independent commands in one SSH session.
//!
//! Replaces the "call ssh_exec N times" anti-pattern that blows up the
//! conversation accumulation cost on the agent side. One round-trip,
//! one structured response with per-command status.
//!
//! Wire protocol: prompto generates a bash script that holds each
//! command base64-encoded, runs them in order, and emits exactly one
//! line per command of the form `BATCH:<idx>:<rc>:<exec_ms>:<base64>`.
//! FreeBSD has no bash (OPNsense's login shell is csh), so there the
//! same protocol is driven by a POSIX `/bin/sh` script ([`Driver`]).
//!
//! Base64 dodges every quoting / marker-collision issue (newlines,
//! shell metas, control bytes in command output). The `BATCH:` prefix
//! lets the parser ignore stray banner lines from `.bashrc` / MOTD /
//! whatever else the remote shell sprinkles before the script runs.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;

use crate::inventory::Platform;

/// Which shell drives the batch on a host.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Driver {
    /// [`build_script`] under `bash`, each command under `bash -c`
    /// (Linux, macOS).
    Bash,
    /// [`build_script_sh`] under `/bin/sh`, each command under `sh -c`
    /// (FreeBSD, where the login shell may be csh and bash is absent).
    PosixSh,
}

impl Driver {
    /// `None`: no POSIX shell to drive a batch (Windows).
    pub fn for_platform(p: Platform) -> Option<Self> {
        match p {
            Platform::Linux | Platform::Macos => Some(Driver::Bash),
            Platform::Freebsd => Some(Driver::PosixSh),
            Platform::Windows => None,
        }
    }

    /// The remote command that reads the script from stdin. A plain
    /// word, so any login shell (csh included) runs it unchanged.
    pub fn remote_cmd(self) -> &'static str {
        match self {
            Driver::Bash => "bash",
            Driver::PosixSh => "/bin/sh",
        }
    }

    pub fn script(self, commands: &[String], fail_fast: bool) -> String {
        match self {
            Driver::Bash => build_script(commands, fail_fast),
            Driver::PosixSh => build_script_sh(commands, fail_fast),
        }
    }
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct BatchItem {
    /// Original command string (echoed back so the agent doesn't have
    /// to correlate by index).
    pub cmd: String,
    /// `Some(rc)` if the command ran, `None` if it was skipped because
    /// an earlier command failed under `fail_fast`.
    pub exit_code: Option<i32>,
    /// Per-command wall time in milliseconds. `0` for skipped entries.
    pub exec_ms: u64,
    /// Combined stdout+stderr. Skipped entries get an empty string.
    pub output: String,
    /// True iff this entry was skipped (fail_fast tripped).
    pub skipped: bool,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct BatchOutput {
    pub items: Vec<BatchItem>,
    /// Sum of every item's `exec_ms` (skipped items contribute 0).
    pub total_exec_ms: u64,
    /// True iff every non-skipped item exited 0 and nothing was skipped.
    pub all_ok: bool,
}

/// Generate the bash script body. Send it to the remote shell via
/// stdin (e.g. through `SshClient::exec_stdin` with `cmd = "bash"`).
pub fn build_script(commands: &[String], fail_fast: bool) -> String {
    let mut s = String::new();
    s.push_str("set +e\n");
    s.push_str("__cmds=(\n");
    for c in commands {
        s.push_str("  '");
        s.push_str(&B64.encode(c.as_bytes()));
        s.push_str("'\n");
    }
    s.push_str(")\n");
    s.push_str(&format!("__ff={}\n", if fail_fast { 1 } else { 0 }));
    s.push_str("__failed=0\n");
    s.push_str("for __i in \"${!__cmds[@]}\"; do\n");
    s.push_str("  __cmd=$(printf '%s' \"${__cmds[$__i]}\" | base64 -d)\n");
    s.push_str("  if [ \"$__ff\" = \"1\" ] && [ \"$__failed\" = \"1\" ]; then\n");
    s.push_str("    printf 'BATCH:%d:SKIP:0:\\n' \"$__i\"\n");
    s.push_str("    continue\n");
    s.push_str("  fi\n");
    s.push_str("  __t0=$(date +%s%N)\n");
    s.push_str("  __out=$(bash -c \"$__cmd\" 2>&1)\n");
    s.push_str("  __rc=$?\n");
    s.push_str("  __t1=$(date +%s%N)\n");
    s.push_str("  __ms=$(( (__t1 - __t0) / 1000000 ))\n");
    s.push_str("  if [ \"$__rc\" != \"0\" ]; then __failed=1; fi\n");
    s.push_str("  __ob64=$(printf '%s' \"$__out\" | base64 -w0)\n");
    s.push_str("  printf 'BATCH:%d:%d:%d:%s\\n' \"$__i\" \"$__rc\" \"$__ms\" \"$__ob64\"\n");
    s.push_str("done\n");
    s
}

/// [`build_script`] in POSIX sh: no arrays, each command under `sh -c`.
/// Same output lines, so [`parse_output`] reads both.
///
/// Portability: `base64 | tr -d '\n'` instead of GNU's `-w0`; a `date`
/// without `%N` (it prints a literal `N`) gives `exec_ms` 0 rather than
/// an arithmetic error.
pub fn build_script_sh(commands: &[String], fail_fast: bool) -> String {
    let mut s = String::new();
    s.push_str("set +e\n");
    s.push_str(&format!("__ff={}\n", if fail_fast { 1 } else { 0 }));
    s.push_str("__failed=0\n");
    s.push_str("__i=0\n");
    s.push_str("for __c in");
    for c in commands {
        // Base64 has no quote characters.
        s.push_str(" '");
        s.push_str(&B64.encode(c.as_bytes()));
        s.push('\'');
    }
    s.push_str("; do\n");
    s.push_str("  if [ \"$__ff\" = \"1\" ] && [ \"$__failed\" = \"1\" ]; then\n");
    s.push_str("    printf 'BATCH:%d:SKIP:0:\\n' \"$__i\"\n");
    s.push_str("    __i=$((__i + 1))\n");
    s.push_str("    continue\n");
    s.push_str("  fi\n");
    s.push_str("  __cmd=$(printf '%s' \"$__c\" | base64 -d)\n");
    s.push_str("  __t0=$(date +%s%N)\n");
    s.push_str("  __out=$(sh -c \"$__cmd\" 2>&1)\n");
    s.push_str("  __rc=$?\n");
    s.push_str("  __t1=$(date +%s%N)\n");
    s.push_str("  case \"$__t0$__t1\" in\n");
    s.push_str("    *[!0-9]*) __ms=0 ;;\n");
    s.push_str("    *) __ms=$(( (__t1 - __t0) / 1000000 )) ;;\n");
    s.push_str("  esac\n");
    s.push_str("  if [ \"$__rc\" != \"0\" ]; then __failed=1; fi\n");
    s.push_str("  __ob64=$(printf '%s' \"$__out\" | base64 | tr -d '\\n')\n");
    s.push_str("  printf 'BATCH:%d:%d:%d:%s\\n' \"$__i\" \"$__rc\" \"$__ms\" \"$__ob64\"\n");
    s.push_str("  __i=$((__i + 1))\n");
    s.push_str("done\n");
    s
}

/// Parse the script's stdout into a `BatchOutput`. `commands` is the
/// original input list; we use it to fill in the `cmd` field of each
/// item (and to detect missing records).
pub fn parse_output(stdout: &str, commands: &[String]) -> Result<BatchOutput> {
    let mut items: Vec<Option<BatchItem>> = (0..commands.len()).map(|_| None).collect();
    let mut total_ms: u64 = 0;
    let mut all_ok = true;

    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("BATCH:") else {
            continue;
        };
        // BATCH:<idx>:<rc_or_SKIP>:<ms>:<b64>
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 {
            continue;
        }
        let Ok(idx): std::result::Result<usize, _> = parts[0].parse() else {
            continue;
        };
        if idx >= commands.len() {
            continue;
        }
        let rc_field = parts[1];
        let Ok(ms): std::result::Result<u64, _> = parts[2].parse() else {
            continue;
        };
        let b64 = parts[3];

        let (exit_code, skipped, output) = if rc_field == "SKIP" {
            all_ok = false;
            (None, true, String::new())
        } else {
            let Ok(rc): std::result::Result<i32, _> = rc_field.parse() else {
                continue;
            };
            if rc != 0 {
                all_ok = false;
            }
            let bytes = B64.decode(b64).unwrap_or_default();
            let out = String::from_utf8_lossy(&bytes).into_owned();
            (Some(rc), false, out)
        };

        total_ms += ms;
        items[idx] = Some(BatchItem {
            cmd: commands[idx].clone(),
            exit_code,
            exec_ms: ms,
            output,
            skipped,
        });
    }

    let mut out = Vec::with_capacity(commands.len());
    for (i, slot) in items.into_iter().enumerate() {
        let Some(item) = slot else {
            crate::fail!(
                RemoteNonzero,
                "batch protocol: missing record for command {} (\"{}\"); remote bash may have crashed mid-batch",
                i,
                commands[i]
            );
        };
        out.push(item);
    }

    Ok(BatchOutput {
        items: out,
        total_exec_ms: total_ms,
        all_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_embeds_base64_commands() {
        let s = build_script(&["echo hi".into(), "ls /".into()], true);
        // base64 of "echo hi" = "ZWNobyBoaQ=="
        assert!(s.contains("ZWNobyBoaQ=="));
        assert!(s.contains("__ff=1"));
        assert!(s.contains("BATCH:%d"));
    }

    #[test]
    fn parse_simple_success_run() {
        let cmds = vec!["echo a".into(), "echo b".into()];
        // base64("a\n") = "YQo=", base64("b\n") = "Ygo="
        let stdout = "BATCH:0:0:5:YQo=\nBATCH:1:0:7:Ygo=\n";
        let out = parse_output(stdout, &cmds).unwrap();
        assert_eq!(out.items.len(), 2);
        assert_eq!(out.items[0].exit_code, Some(0));
        assert_eq!(out.items[0].output, "a\n");
        assert_eq!(out.items[1].output, "b\n");
        assert_eq!(out.total_exec_ms, 12);
        assert!(out.all_ok);
    }

    #[test]
    fn parse_skip_marker() {
        let cmds = vec!["true".into(), "false".into(), "echo never".into()];
        // base64("") = "" (empty); base64("") = ""
        let stdout = "BATCH:0:0:1:\nBATCH:1:1:2:\nBATCH:2:SKIP:0:\n";
        let out = parse_output(stdout, &cmds).unwrap();
        assert_eq!(out.items[0].exit_code, Some(0));
        assert_eq!(out.items[1].exit_code, Some(1));
        assert!(out.items[2].skipped);
        assert_eq!(out.items[2].exit_code, None);
        assert!(!out.all_ok);
    }

    #[test]
    fn parse_ignores_banner_noise() {
        let cmds = vec!["echo x".into()];
        let stdout = "Last login: ...\n*** banner ***\nBATCH:0:0:3:eAo=\n";
        let out = parse_output(stdout, &cmds).unwrap();
        assert_eq!(out.items[0].output, "x\n");
        assert!(out.all_ok);
    }

    #[test]
    fn driver_per_platform() {
        assert_eq!(Driver::for_platform(Platform::Linux), Some(Driver::Bash));
        assert_eq!(Driver::for_platform(Platform::Macos), Some(Driver::Bash));
        assert_eq!(
            Driver::for_platform(Platform::Freebsd),
            Some(Driver::PosixSh)
        );
        assert_eq!(Driver::for_platform(Platform::Windows), None);
        assert_eq!(Driver::PosixSh.remote_cmd(), "/bin/sh");
        // Linux and macOS keep the bash script byte for byte.
        let c = vec!["uname".to_string(), "echo two".to_string()];
        assert_eq!(Driver::Bash.script(&c, true), build_script(&c, true));
    }

    /// The bash script needs arrays; under a POSIX sh it is a syntax
    /// error, which is why FreeBSD got a refusal before task 017.
    #[test]
    fn sh_script_has_no_bashisms() {
        let s = build_script_sh(&["echo a".into()], true);
        for b in ["${!", "__cmds=(", "[[", "-w0", "bash"] {
            assert!(!s.contains(b), "{b} in {s}");
        }
    }

    /// Run the POSIX script with the local `/bin/sh` (dash on Debian,
    /// bash-as-sh on macOS): outputs, exit codes, fail_fast, metas and
    /// an empty output all come back through the real protocol.
    #[cfg(unix)]
    #[test]
    fn sh_script_runs_under_local_sh() {
        use std::io::Write;
        let run = |cmds: &[String], ff: bool| {
            let mut child = std::process::Command::new("/bin/sh")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(build_script_sh(cmds, ff).as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            parse_output(&String::from_utf8(out.stdout).unwrap(), cmds).unwrap()
        };
        let cmds: Vec<String> = vec![
            "echo 'a b'; echo \"$((1+2))\" | cat".into(),
            "true".into(),
            "echo err >&2; exit 3".into(),
            "echo never".into(),
        ];
        let out = run(&cmds, true);
        assert_eq!(out.items[0].output, "a b\n3");
        assert_eq!(out.items[0].exit_code, Some(0));
        assert_eq!(out.items[1].output, "");
        assert_eq!(out.items[2].exit_code, Some(3));
        assert_eq!(out.items[2].output, "err");
        assert!(out.items[3].skipped);
        assert!(!out.all_ok);
        let out = run(&cmds, false);
        assert_eq!(out.items[3].output, "never");
        assert!(!out.items[3].skipped);
    }

    #[test]
    fn parse_fails_on_missing_record() {
        let cmds = vec!["a".into(), "b".into()];
        let stdout = "BATCH:0:0:1:\n"; // record 1 missing
        let err = parse_output(stdout, &cmds).unwrap_err();
        assert!(err.to_string().contains("missing record"));
    }
}
