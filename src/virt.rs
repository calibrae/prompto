//! libvirt operations — composed on top of `SshClient`.
//!
//! The `stop_vm` fallback chain is the v0.1 reason this module exists:
//!   1. `virsh dompmsuspend <vm> disk`  (S4 hibernate, preserves state)
//!   2. `virsh shutdown <vm>`           (ACPI clean shutdown)
//!   3. `virsh destroy <vm>`            (force-kill)
//!
//! Each step waits up to `step_timeout` for the domain to reach the expected
//! state before falling through. Mirrors the canonical shape used by many
//! homelab MQTT-driven VM lifecycle scripts.

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use std::time::Duration;

use crate::inventory::HostConfig;
use crate::ssh::SshClient;

const VIRSH: &str = "virsh -c qemu:///system";

/// VM names must look like libvirt domain names — alphanumerics plus `-`,
/// `_` and `.`. Anything else gets rejected before it reaches the remote
/// shell, since the command is interpolated into a shell string.
pub fn validate_vm_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("vm name is empty");
    }
    if name.len() > 64 {
        bail!("vm name too long");
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("vm name {name:?} contains illegal characters (allowed: A-Z a-z 0-9 - _ .)");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct VmRow {
    pub name: String,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct StopVmResult {
    /// One of `hibernated`, `shutdown`, `destroyed`, `already-off`, or `failed`.
    pub outcome: String,
    /// Names of fallback steps that actually ran.
    pub steps: Vec<String>,
    /// Final libvirt state (`shut off`, `running`, `pmsuspended`, …).
    pub final_state: String,
}

/// Parse `virsh list --all` output to typed rows.
///
/// Format (header + dashes + rows):
/// ```text
///  Id   Name      State
/// -----------------------
///  -    web       shut off
///  3    db        running
/// ```
pub fn parse_virsh_list(stdout: &str) -> Vec<VmRow> {
    let mut out = Vec::new();
    let mut after_dashes = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.chars().all(|c| c == '-') {
            after_dashes = true;
            continue;
        }
        if !after_dashes {
            continue;
        }
        // Id is column 0, name column 1, then state may be multi-word.
        let mut parts = trimmed.split_whitespace();
        let _id = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        let name = match parts.next() {
            Some(v) => v.to_string(),
            None => continue,
        };
        let state = parts.collect::<Vec<_>>().join(" ");
        if state.is_empty() {
            continue;
        }
        out.push(VmRow { name, state });
    }
    out
}

pub async fn list(ssh: &SshClient, host: &HostConfig) -> Result<Vec<VmRow>> {
    let cmd = format!("{VIRSH} list --all");
    let res = ssh.exec(host, &cmd, None, false).await?;
    if !res.ok() {
        bail!(
            "virsh list failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(parse_virsh_list(&res.stdout))
}

pub async fn domstate(ssh: &SshClient, host: &HostConfig, vm: &str) -> Result<String> {
    validate_vm_name(vm)?;
    let cmd = format!("{VIRSH} domstate {vm}");
    let res = ssh.exec(host, &cmd, None, false).await?;
    if !res.ok() {
        bail!(
            "virsh domstate {vm} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res.stdout.trim().to_string())
}

pub async fn start(ssh: &SshClient, host: &HostConfig, vm: &str) -> Result<String> {
    validate_vm_name(vm)?;
    let cmd = format!("{VIRSH} start {vm}");
    let res = ssh.exec(host, &cmd, None, false).await?;
    if !res.ok() {
        bail!(
            "virsh start {vm} failed (exit={:?}): {} / {}",
            res.exit_code,
            res.stdout.trim(),
            res.stderr.trim()
        );
    }
    Ok(res.stdout.trim().to_string())
}

/// Run the `stop_vm` fallback chain. `step_timeout` bounds each individual
/// virsh sub-step (poll cycle included).
pub async fn stop(
    ssh: &SshClient,
    host: &HostConfig,
    vm: &str,
    step_timeout: Duration,
) -> Result<StopVmResult> {
    validate_vm_name(vm)?;

    let mut steps = Vec::new();
    let initial = domstate(ssh, host, vm).await?;
    if initial == "shut off" || initial == "pmsuspended" {
        return Ok(StopVmResult {
            outcome: "already-off".into(),
            steps,
            final_state: initial,
        });
    }

    // Step 1: dompmsuspend disk — S4 hibernate.
    steps.push("dompmsuspend".into());
    let cmd = format!("{VIRSH} dompmsuspend {vm} disk");
    let _ = ssh.exec(host, &cmd, Some(step_timeout), false).await?;
    if let Some(state) =
        wait_for_state(ssh, host, vm, &["pmsuspended", "shut off"], step_timeout).await?
    {
        return Ok(StopVmResult {
            outcome: "hibernated".into(),
            steps,
            final_state: state,
        });
    }

    // Step 2: shutdown — ACPI.
    steps.push("shutdown".into());
    let cmd = format!("{VIRSH} shutdown {vm}");
    let _ = ssh.exec(host, &cmd, Some(step_timeout), false).await?;
    if let Some(state) = wait_for_state(ssh, host, vm, &["shut off"], step_timeout).await? {
        return Ok(StopVmResult {
            outcome: "shutdown".into(),
            steps,
            final_state: state,
        });
    }

    // Step 3: destroy — force kill.
    steps.push("destroy".into());
    let cmd = format!("{VIRSH} destroy {vm}");
    let res = ssh.exec(host, &cmd, Some(step_timeout), false).await?;
    if let Some(state) = wait_for_state(ssh, host, vm, &["shut off"], step_timeout).await? {
        return Ok(StopVmResult {
            outcome: "destroyed".into(),
            steps,
            final_state: state,
        });
    }

    Err(anyhow!(
        "stop_vm exhausted all fallbacks; last destroy stderr: {}",
        res.stderr.trim()
    ))
}

async fn wait_for_state(
    ssh: &SshClient,
    host: &HostConfig,
    vm: &str,
    accept: &[&str],
    total_timeout: Duration,
) -> Result<Option<String>> {
    let deadline = std::time::Instant::now() + total_timeout;
    loop {
        let state = match domstate(ssh, host, vm).await {
            Ok(s) => s,
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if accept.iter().any(|a| *a == state) {
            return Ok(Some(state));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_list_output() {
        let s = " Id   Name        State\n------------------------------\n -    web         shut off\n 3    db          running\n";
        let rows = parse_virsh_list(s);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "web");
        assert_eq!(rows[0].state, "shut off");
        assert_eq!(rows[1].name, "db");
        assert_eq!(rows[1].state, "running");
    }

    #[test]
    fn parse_handles_paused_state_with_extra_words() {
        let s = " Id   Name   State\n--------------------\n -    foo    in shutdown\n";
        let rows = parse_virsh_list(s);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "in shutdown");
    }

    #[test]
    fn parse_empty_when_no_rows() {
        let rows = parse_virsh_list(" Id   Name   State\n---------------\n");
        assert!(rows.is_empty());
    }

    #[test]
    fn vm_name_validation_accepts_normal_names() {
        validate_vm_name("web").unwrap();
        validate_vm_name("debian-13_test.v2").unwrap();
    }

    #[test]
    fn vm_name_validation_rejects_shell_injection() {
        assert!(validate_vm_name("web; rm -rf /").is_err());
        assert!(validate_vm_name("web&&halt").is_err());
        assert!(validate_vm_name("web`whoami`").is_err());
        assert!(validate_vm_name("web$VAR").is_err());
        assert!(validate_vm_name("web\nfoo").is_err());
        assert!(validate_vm_name(" ").is_err());
        assert!(validate_vm_name("").is_err());
    }
}
