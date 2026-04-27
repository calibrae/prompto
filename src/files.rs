//! Typed file read/write over SSH. Replaces the ad-hoc
//! `ssh host cat /path` and `ssh host "cat > /path" < content` dance
//! with a tight, validated, capability-gated pair.

use anyhow::{Result, bail};
use std::time::Duration;

use crate::inventory::HostConfig;
use crate::ssh::{ExecOutput, SshClient};

/// Default + max read size. Operators can ask for less via `max_bytes`;
/// can't go above 1 MB to keep MCP responses bounded.
pub const DEFAULT_READ_BYTES: u64 = 65_536;
pub const MAX_READ_BYTES: u64 = 1_048_576;

/// Validate a remote path. Permissive enough for normal absolute/relative
/// paths and `~/foo`-style home shortcuts; rejects anything that would
/// let the path escape the argument position.
pub fn validate_path(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("path is empty");
    }
    if p.len() > 4096 {
        bail!("path too long");
    }
    let bad = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '*', '?', '(', ')', '{',
        '}', '\t', ' ',
    ];
    if p.chars().any(|c| bad.contains(&c)) {
        bail!("path {p:?} contains shell metacharacter or whitespace");
    }
    Ok(())
}

/// Validate an octal mode string ("0644", "755", etc.). Only digits, max
/// 5 chars (so e.g. "01777" still fits).
pub fn validate_mode(m: &str) -> Result<()> {
    if m.is_empty() {
        bail!("mode is empty");
    }
    if m.len() > 5 {
        bail!("mode too long");
    }
    if !m.chars().all(|c| c.is_ascii_digit()) {
        bail!("mode {m:?} must be octal digits only");
    }
    Ok(())
}

/// Read up to `max_bytes` from a remote path via `head -c`. Caller gets
/// the bytes plus a `truncated` flag (true when the read hit the cap and
/// the file may be larger).
pub async fn read(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    max_bytes: u64,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("head -c {max_bytes} -- {path}");
    let res = ssh
        .exec(host, &cmd, Some(Duration::from_secs(15)), false)
        .await?;
    if !res.ok() {
        bail!(
            "head failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res)
}

/// Write bytes to a remote path. Pipes the content through SSH stdin to
/// `tee -- <path> >/dev/null`. With `sudo=true` the tee runs as root via
/// `sudo -n tee` (caller must have `sudo_exec` capability checked).
pub async fn write(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    content: &[u8],
    sudo: bool,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("tee -- {path} >/dev/null");
    let res = ssh
        .exec_stdin(host, &cmd, content, Some(Duration::from_secs(30)), sudo)
        .await?;
    if !res.ok() {
        bail!(
            "tee {path} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res)
}

/// Optional chmod after a write. No-op if `mode` is `None`.
pub async fn chmod(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    mode: &str,
    sudo: bool,
) -> Result<()> {
    validate_path(path)?;
    validate_mode(mode)?;
    let cmd = format!("chmod {mode} -- {path}");
    let res = ssh
        .exec(host, &cmd, Some(Duration::from_secs(10)), sudo)
        .await?;
    if !res.ok() {
        bail!(
            "chmod {mode} {path} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_path_accepts_normal_inputs() {
        validate_path("/etc/prompto.toml").unwrap();
        validate_path("./relative/file").unwrap();
        validate_path("~/Developer/project").unwrap();
        validate_path("/var/log/syslog.1").unwrap();
        validate_path("file-with_dashes.txt").unwrap();
    }

    #[test]
    fn validate_path_rejects_shell_metas() {
        assert!(validate_path("/etc; rm -rf /").is_err());
        assert!(validate_path("/etc/$(whoami)").is_err());
        assert!(validate_path("/etc/`id`").is_err());
        assert!(validate_path("/etc/foo bar").is_err());
        assert!(validate_path("/etc/foo|bar").is_err());
        assert!(validate_path("/etc/foo>bar").is_err());
        assert!(validate_path("").is_err());
        assert!(validate_path(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn validate_mode_accepts_octal() {
        validate_mode("644").unwrap();
        validate_mode("0644").unwrap();
        validate_mode("0755").unwrap();
        validate_mode("01777").unwrap();
    }

    #[test]
    fn validate_mode_rejects_garbage() {
        assert!(validate_mode("rw-r--r--").is_err());
        assert!(validate_mode("644a").is_err());
        assert!(validate_mode("").is_err());
        assert!(validate_mode("999999").is_err());
    }
}
