//! Host-level operations — wake, sleep, status. Compositions on top of
//! `wol`, `ssh`, and (optionally) `virt`.

use anyhow::{Context, Result};
use serde::Serialize;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::inventory::HostConfig;
use crate::ssh::SshClient;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct HostStatus {
    /// `up` — TCP connect to the SSH port succeeded.
    /// `unreachable` — TCP refused (host responded but ssh closed).
    /// `off` — TCP connect timed out (host appears down).
    pub state: &'static str,
    pub probed: String,
    pub probe_ms: u64,
}

/// Send a WOL magic packet to the host. Caller must have checked `wake`
/// capability.
pub async fn wake(host: &HostConfig) -> Result<()> {
    let mac_str = host.mac.as_deref().context("host has no MAC configured")?;
    let mac = crate::wol::parse_mac(mac_str)?;
    crate::wol::send(mac).await
}

/// Probe SSH reachability with a TCP connect. 2 s default — fast feedback,
/// short enough that callers can poll cheaply during `vm_ensure_up`.
pub async fn status(host: &HostConfig, probe_timeout: Duration) -> Result<HostStatus> {
    let target = format!("{}:{}", host.ip, host.ssh_port);
    let started = std::time::Instant::now();
    let res = timeout(probe_timeout, TcpStream::connect(&target)).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let state = match res {
        Ok(Ok(_)) => "up",
        Ok(Err(_)) => "unreachable", // refused / no route — host responded with a denial
        Err(_) => "off",             // timed out — host did not respond at all
    };
    Ok(HostStatus {
        state,
        probed: target,
        probe_ms: elapsed_ms,
    })
}

/// `sudo -n shutdown -h now`. Caller must have checked `sudo_exec`.
pub async fn sleep(ssh: &SshClient, host: &HostConfig) -> Result<()> {
    // Fire-and-forget — the connection drops as soon as init begins shutting
    // down, so any non-zero exit / broken pipe is fine.
    let _ = ssh
        .exec(host, "shutdown -h now", Some(Duration::from_secs(10)), true)
        .await?;
    Ok(())
}

/// Wait until `host_status` reports `up`, or fail after `total_timeout`.
pub async fn wait_until_up(host: &HostConfig, total_timeout: Duration) -> Result<HostStatus> {
    let probe = Duration::from_secs(2);
    let deadline = std::time::Instant::now() + total_timeout;
    loop {
        let s = status(host, probe).await?;
        if s.state == "up" {
            return Ok(s);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "host {} not reachable after {}s",
                host.ip,
                total_timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
