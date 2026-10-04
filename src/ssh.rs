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
///   see, on mista or on the target.
/// - **sudo reads stdin before anything else runs.** Splicing the
///   caller's command in as shell text (`sudo -S -- {cmd}`) would let
///   `x & cat` background sudo with its stdin detached while `cat` reads
///   the password, and `true; cat` would leak it whenever sudo had cached
///   credentials and skipped reading stdin. `-k` forces sudo to ignore
///   any cached credentials and consume the line every time, and
///   wrapping the command in `sh -s` means none of it executes until
///   sudo has authenticated.
///
/// Also avoids remote quoting entirely, which matters because the login
/// shell on the OPNsense boxes is csh.
pub const SUDO_STDIN_SHELL: &str = "sudo -k -S -p '' -- sh -s";

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
    /// With `sudo` on a vault-backed host, the password is prepended as the
    /// first stdin line for `sudo -S` to consume, and the content follows
    /// for the command. Only safe because every caller passing `sudo=true`
    /// here builds `cmd` itself (`tee -- <validated path>`); it is never
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
                let mut input = Vec::with_capacity(pw.len() + 1 + stdin_bytes.len());
                input.extend_from_slice(pw.as_bytes());
                input.push(b'\n');
                input.extend_from_slice(stdin_bytes);
                let remote = format!("sudo -k -S -p '' -- {cmd}");
                return self.run(host, &remote, Some(&input), cmd_timeout).await;
            }
            let remote = format!("sudo -n -- {cmd}");
            return self.run(host, &remote, Some(stdin_bytes), cmd_timeout).await;
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
            bail!("vault {path:?}/{field:?} is empty or multi-line; refusing to use it as a sudo password");
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

/// stdin for [`SUDO_STDIN_SHELL`]: the password line, then the command
/// for the root shell.
pub fn sudo_stdin_payload(password: &str, cmd: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(password.len() + cmd.len() + 2);
    v.extend_from_slice(password.as_bytes());
    v.push(b'\n');
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
        assert_eq!(SUDO_STDIN_SHELL, "sudo -k -S -p '' -- sh -s");
        assert!(SUDO_STDIN_SHELL.contains(" -k "), "must ignore cached credentials");
        assert!(SUDO_STDIN_SHELL.ends_with("sh -s"), "command must come from stdin");
    }

    #[test]
    fn sudo_payload_is_password_line_then_command() {
        let p = sudo_stdin_payload("pw", b"id -un");
        assert_eq!(p, b"pw\nid -un\n");
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
