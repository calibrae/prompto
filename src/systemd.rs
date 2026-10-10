//! systemd helpers for `service_control` and `service_logs` (and the
//! plain-HTTP `/log` tail, which runs the same journal read).

use anyhow::Result;
use std::time::Duration;

use crate::ctx::CallCtx;
use crate::inventory::HostConfig;
use crate::ssh::SshClient;

/// Tail a systemd unit's journal on a host. Wraps
/// `journalctl -u <unit> -n <lines> --no-pager` as root. Requires
/// `sudo_exec` capability on the target.
pub async fn journalctl_tail(
    ssh: &SshClient,
    ctx: &CallCtx,
    host: &HostConfig,
    unit: &str,
    lines: u32,
) -> Result<String> {
    validate_unit_name(unit)?;
    let lines = lines.clamp(1, 1000);
    let cmd = format!("journalctl -u {unit} -n {lines} --no-pager");
    let res = ssh
        .exec(ctx, host, &cmd, Some(Duration::from_secs(15)), true)
        .await?;
    if !res.ok() {
        return Err(crate::error_class::ClassifiedError::exec_failure(
            &res,
            true,
            format!(
                "journalctl -u {unit} failed (exit={:?}): {}",
                res.exit_code,
                res.stderr.trim()
            ),
        )
        .into());
    }
    Ok(res.stdout)
}

/// systemd unit names are conservatively `[A-Za-z0-9._-]{1,64}`. Same
/// shape as VM-name validation — the value flows into the remote shell.
pub fn validate_unit_name(unit: &str) -> Result<()> {
    if unit.is_empty() {
        crate::fail!(InvalidArgs, "unit name is empty");
    }
    if unit.len() > 64 {
        crate::fail!(InvalidArgs, "unit name too long");
    }
    let ok = unit
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'));
    if !ok {
        crate::fail!(
            InvalidArgs,
            "unit name {unit:?} contains illegal characters"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_unit_name_accepts_normal_inputs() {
        validate_unit_name("memqdrant").unwrap();
        validate_unit_name("prompto.service").unwrap();
        validate_unit_name("getty@tty1.service").unwrap();
    }

    #[test]
    fn validate_unit_name_rejects_shell_injection() {
        assert!(validate_unit_name("memqdrant; rm -rf /").is_err());
        assert!(validate_unit_name("memqdrant`whoami`").is_err());
        assert!(validate_unit_name("memqdrant$VAR").is_err());
        assert!(validate_unit_name("memqdrant\nfoo").is_err());
        assert!(validate_unit_name("").is_err());
        assert!(validate_unit_name(&"x".repeat(80)).is_err());
    }
}
