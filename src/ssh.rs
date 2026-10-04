//! SSH transport — shells out to the system `ssh` binary.
//!
//! Inherits known_hosts and key permissions from the host. v0.1 keeps
//! key-management code at zero by relying on the operator-managed key path.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::inventory::HostConfig;
use crate::vault::VaultClient;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// Remote command used when sudo needs a password.
///
/// Both the password and the real command travel over stdin: sudo reads
/// the first line as the password (`-S`, no prompt via `-p ''`), then a
/// root `sh -s` reads the command from the remainder. Two properties
/// matter:
///
/// - **Nothing secret on a command line.** This string is all `ps` can
///   see, on prompto's host or on the target.
/// - **sudo reads stdin before anything else runs.** Splicing the
///   caller's command in as shell text (`sudo -S -- {cmd}`) would let
///   `x & cat` background sudo with its stdin detached while `cat` reads
///   the password, and `true; cat` would leak it whenever sudo had cached
///   credentials and skipped reading stdin. `-k` forces sudo to ignore
///   any cached credentials and consume the line every time, and
///   wrapping the command in `sh -s` means none of it executes until
///   sudo has authenticated.
///
/// `-k` does nothing against a NOPASSWD rule: sudo then never reads the
/// password line, and the root shell gets it as its first command
/// (`sh: 1: <password>: not found` on stderr, or the first line of a
/// `file_write`). So sudo runs a guard first: it reads one line and
/// demands [`SUDO_MARKER`], which is only the next line if sudo took the
/// password. Otherwise it exits [`SUDO_GUARD_EXIT`] without echoing what
/// it read or running anything. The guard is single-quoted on the remote
/// command line, so it must never contain `'` or `!` (csh history-expands
/// `!` even inside single quotes).
///
/// Also avoids remote quoting entirely, which matters because the login
/// shell on some BSD hosts is csh.
pub const SUDO_STDIN_SHELL: &str = "sudo -k -S -p '' -- sh -c '\
IFS= read -r l; [ \"$l\" = prompto-sudo-ok ] || { echo \"prompto: sudo did not read the password - \
this host has a passwordless sudo rule, drop its sudo_password_vault_path\" >&2; exit 97; }; \
exec \"$@\"' prompto-sudo sh -s";

/// Line sent right after the password; see [`SUDO_STDIN_SHELL`].
pub const SUDO_MARKER: &str = "prompto-sudo-ok";

/// Exit status of the guard when sudo did not read the password.
pub const SUDO_GUARD_EXIT: i32 = 97;

/// [`SUDO_STDIN_SHELL`] with a prompto-built `cmd` in place of `sh -s`.
pub fn sudo_guarded(cmd: &str) -> String {
    let prefix = SUDO_STDIN_SHELL
        .strip_suffix("sh -s")
        .expect("ends with sh -s");
    format!("{prefix}{cmd}")
}

#[derive(Clone, Debug)]
pub struct SshClient {
    pub ssh_bin: PathBuf,
    pub default_timeout: Duration,
    pub connect_timeout: Duration,
    vault: Option<Arc<VaultClient>>,
}

impl SshClient {
    pub fn new(ssh_bin: PathBuf, default_timeout: Duration) -> Self {
        Self {
            ssh_bin,
            default_timeout,
            connect_timeout: Duration::from_secs(5),
            vault: None,
        }
    }

    /// Enable vault-backed sudo for hosts that declare
    /// `sudo_password_vault_path`.
    pub fn with_vault(mut self, vault: Arc<VaultClient>) -> Self {
        self.vault = Some(vault);
        self
    }

    /// Run an arbitrary remote command.
    ///
    /// With `sudo`, a host carrying `sudo_password_vault_path` gets the
    /// stdin-fed password path (see [`SUDO_STDIN_SHELL`]); every other
    /// host gets `sudo -n`, which fails fast instead of hanging on a TTY
    /// prompt when there's no passwordless rule.
    pub async fn exec(
        &self,
        host: &HostConfig,
        cmd: &str,
        cmd_timeout: Option<Duration>,
        sudo: bool,
    ) -> Result<ExecOutput> {
        if cmd.trim().is_empty() {
            bail!("empty command");
        }
        if sudo {
            if let Some(pw) = self.sudo_password(host).await? {
                let input = sudo_stdin_payload(&pw, cmd.as_bytes());
                return self
                    .run(host, SUDO_STDIN_SHELL, Some(&input), cmd_timeout)
                    .await;
            }
            return self
                .run(host, &format!("sudo -n -- {cmd}"), None, cmd_timeout)
                .await;
        }
        self.run(host, cmd, None, cmd_timeout).await
    }

    /// Run a remote command and feed `stdin_bytes` into its stdin. Used by
    /// `script::run` and `file_write` to pipe content through SSH without
    /// going through shell-argument quoting hell.
    ///
    /// With `sudo` on a vault-backed host, the password and marker lines
    /// are prepended for `sudo -S` and the guard (see [`SUDO_STDIN_SHELL`]),
    /// and the content follows for the command. `cmd` lands after the
    /// guard's `exec "$@"`, so it must be a simple command that prompto
    /// built itself (`tee -- <validated path>`, `<interpreter> -`), never
    /// caller-supplied shell text.
    pub async fn exec_stdin(
        &self,
        host: &HostConfig,
        cmd: &str,
        stdin_bytes: &[u8],
        cmd_timeout: Option<Duration>,
        sudo: bool,
    ) -> Result<ExecOutput> {
        if cmd.trim().is_empty() {
            bail!("empty command");
        }
        if sudo {
            if let Some(pw) = self.sudo_password(host).await? {
                let mut input = sudo_preamble(&pw);
                input.extend_from_slice(stdin_bytes);
                return self
                    .run(host, &sudo_guarded(cmd), Some(&input), cmd_timeout)
                    .await;
            }
            let remote = format!("sudo -n -- {cmd}");
            return self
                .run(host, &remote, Some(stdin_bytes), cmd_timeout)
                .await;
        }
        self.run(host, cmd, Some(stdin_bytes), cmd_timeout).await
    }

    /// The host's sudo password from vault, if it declares one.
    async fn sudo_password(&self, host: &HostConfig) -> Result<Option<String>> {
        let Some(path) = host.sudo_password_vault_path.as_deref() else {
            return Ok(None);
        };
        let vault = self.vault.as_ref().context(
            "host declares sudo_password_vault_path but prompto has no vault configured \
             (set PROMPTO_VAULT_TOKEN)",
        )?;
        let field = host
            .sudo_password_vault_field
            .as_deref()
            .unwrap_or("password");
        let pw = vault.kv2_field(path, field).await?;
        // sudo -S takes the first line as the password. A newline inside
        // it would hand the remainder to the root shell as a command.
        if pw.is_empty() || pw.contains(['\n', '\r']) {
            bail!(
                "vault {path:?}/{field:?} is empty or multi-line; refusing to use it as a sudo password"
            );
        }
        // The guard can't tell the password from the marker.
        if pw == SUDO_MARKER {
            bail!("vault {path:?}/{field:?} equals the sudo marker; refusing it");
        }
        Ok(Some(pw))
    }

    /// The one place that spawns ssh.
    async fn run(
        &self,
        host: &HostConfig,
        remote: &str,
        stdin_bytes: Option<&[u8]>,
        cmd_timeout: Option<Duration>,
    ) -> Result<ExecOutput> {
        use tokio::io::AsyncWriteExt;

        let mut command = Command::new(&self.ssh_bin);
        command
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!(
                "ConnectTimeout={}",
                self.connect_timeout.as_secs().max(1)
            ))
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-i")
            .arg(&host.ssh_key)
            .arg("-p")
            .arg(host.ssh_port.to_string())
            .arg(format!("{}@{}", host.ssh_user, host.ip))
            .arg("--")
            .arg(remote)
            .stdin(if stdin_bytes.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let dur = cmd_timeout.unwrap_or(self.default_timeout);
        let mut child = command.spawn().context("spawn ssh")?;

        if let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) {
            if let Err(e) = stdin.write_all(bytes).await {
                return Ok(ExecOutput {
                    stdout: String::new(),
                    // The io::Error, never the bytes — they may hold a password.
                    stderr: format!("ssh stdin write failed: {e}"),
                    exit_code: None,
                    timed_out: false,
                });
            }
            // Drop closes the pipe so the remote side sees EOF.
            drop(stdin);
        }

        match timeout(dur, child.wait_with_output()).await {
            Ok(Ok(out)) => Ok(ExecOutput {
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
                exit_code: out.status.code(),
                timed_out: false,
            }),
            Ok(Err(e)) => Err(e).context("ssh wait_with_output"),
            Err(_) => Ok(ExecOutput {
                stdout: String::new(),
                stderr: format!("ssh command timed out after {}s", dur.as_secs()),
                exit_code: None,
                timed_out: true,
            }),
        }
    }
}

/// Password line, then the marker line the guard in [`SUDO_STDIN_SHELL`] checks for.
fn sudo_preamble(password: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(password.len() + SUDO_MARKER.len() + 2);
    v.extend_from_slice(password.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(SUDO_MARKER.as_bytes());
    v.push(b'\n');
    v
}

/// stdin for [`SUDO_STDIN_SHELL`]: the password line, the marker line,
/// then the command for the root shell.
pub fn sudo_stdin_payload(password: &str, cmd: &[u8]) -> Vec<u8> {
    let mut v = sudo_preamble(password);
    v.extend_from_slice(cmd);
    v.push(b'\n');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remote command in password mode is a fixed string: no part of
    /// the caller's command and no part of the password may reach ssh's
    /// argv, where `ps` on either machine could read it. Reverting to
    /// `sudo -S -- {cmd}` reintroduces the `x & cat` / cached-credential
    /// leaks described on SUDO_STDIN_SHELL.
    #[test]
    fn sudo_stdin_shell_is_fixed_and_forces_a_fresh_read() {
        assert!(SUDO_STDIN_SHELL.starts_with("sudo -k -S -p '' -- sh -c '"));
        assert!(
            SUDO_STDIN_SHELL.ends_with("' prompto-sudo sh -s"),
            "command must come from stdin"
        );
        assert!(SUDO_STDIN_SHELL.contains(SUDO_MARKER));
        assert!(SUDO_STDIN_SHELL.contains(&format!("exit {SUDO_GUARD_EXIT};")));
    }

    #[test]
    fn guard_survives_single_quoting_and_csh() {
        let body = guard_body();
        assert!(!body.contains('\''), "would close the remote single quotes");
        assert!(
            !body.contains('!'),
            "csh history-expands ! inside single quotes"
        );
        assert!(!body.contains('\n'), "csh rejects newlines in quoted words");
    }

    #[test]
    fn sudo_payload_is_password_marker_then_command() {
        let p = sudo_stdin_payload("pw", b"id -un");
        assert_eq!(p, b"pw\nprompto-sudo-ok\nid -un\n");
    }

    #[test]
    fn sudo_guarded_swaps_only_the_command() {
        let r = sudo_guarded("tee -- /etc/x >/dev/null");
        assert_eq!(
            r,
            SUDO_STDIN_SHELL.replace(
                "prompto-sudo sh -s",
                "prompto-sudo tee -- /etc/x >/dev/null"
            )
        );
    }

    /// The `sh -c` body, unquoted as the remote shell would.
    fn guard_body() -> &'static str {
        let start = SUDO_STDIN_SHELL.find("sh -c '").unwrap() + "sh -c '".len();
        let end = SUDO_STDIN_SHELL.rfind("' prompto-sudo").unwrap();
        &SUDO_STDIN_SHELL[start..end]
    }

    /// Run the guard locally under /bin/sh with `stdin`, as root's shell
    /// would after sudo, and with `sh -s` as the guarded command.
    fn run_guard(stdin: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", guard_body(), "prompto-sudo", "sh", "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// sudo took the password line: the guard sees the marker and the
    /// command runs.
    #[test]
    fn guard_runs_the_command_after_sudo_consumed_the_password() {
        let payload = sudo_stdin_payload("hunter2-canary", b"echo ran");
        // sudo -S eats the password line; the root shell sees the rest.
        let after_sudo = &payload["hunter2-canary\n".len()..];
        let out = run_guard(after_sudo);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n");
    }

    /// NOPASSWD: sudo never read stdin, so the guard reads the password
    /// itself. It must refuse, run nothing, and never print the password.
    #[test]
    fn guard_refuses_and_hides_password_under_nopasswd() {
        let out = run_guard(&sudo_stdin_payload("hunter2-canary", b"echo ran"));
        assert_eq!(out.status.code(), Some(SUDO_GUARD_EXIT), "{out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stdout.contains("ran"), "command must not run");
        assert!(
            !stdout.contains("hunter2") && !stderr.contains("hunter2"),
            "leaked: {out:?}"
        );
        assert!(stderr.contains("passwordless sudo rule"), "{stderr}");
    }

    #[test]
    fn ok_requires_zero_exit_and_no_timeout() {
        let mut o = ExecOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
        };
        assert!(o.ok());
        o.exit_code = Some(1);
        assert!(!o.ok());
        o.exit_code = Some(0);
        o.timed_out = true;
        assert!(!o.ok());
        o.timed_out = false;
        o.exit_code = None;
        assert!(!o.ok());
    }
}
