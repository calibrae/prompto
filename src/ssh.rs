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

#[derive(Clone, Debug)]
pub struct SshClient {
    pub ssh_bin: PathBuf,
    pub default_timeout: Duration,
    pub connect_timeout: Duration,
}

impl SshClient {
    pub fn new(ssh_bin: PathBuf, default_timeout: Duration) -> Self {
        Self {
            ssh_bin,
            default_timeout,
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// Run an arbitrary remote command. `sudo` prepends `sudo -n ` so a
    /// missing sudoers rule fails fast instead of hanging on a TTY prompt.
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
        let remote = if sudo {
            format!("sudo -n -- {cmd}")
        } else {
            cmd.to_string()
        };

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
            .arg(&remote)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let dur = cmd_timeout.unwrap_or(self.default_timeout);
        let started = command.spawn().context("spawn ssh")?;
        let waited = timeout(dur, started.wait_with_output()).await;

        match waited {
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

#[cfg(test)]
mod tests {
    use super::*;

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
