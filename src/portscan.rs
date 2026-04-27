//! Lightweight TCP port probe. For each (host, port) does a TCP connect
//! within a per-probe budget and reports reachable + latency. No raw-
//! socket nmap stuff — keeps prompto's RestrictAddressFamilies posture
//! intact.

use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct PortResult {
    pub port: u16,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn probe_one(host: &str, port: u16, probe_timeout: Duration) -> PortResult {
    let started = Instant::now();
    let res = timeout(probe_timeout, TcpStream::connect((host, port))).await;
    let latency = started.elapsed().as_millis() as u64;
    match res {
        Ok(Ok(_)) => PortResult {
            port,
            reachable: true,
            latency_ms: Some(latency),
            error: None,
        },
        Ok(Err(e)) => PortResult {
            port,
            reachable: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
        Err(_) => PortResult {
            port,
            reachable: false,
            latency_ms: None,
            error: Some(format!("timeout after {}ms", probe_timeout.as_millis())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_unreachable_target_marked_unreachable() {
        // TEST-NET-1 is guaranteed non-routable.
        let r = probe_one("192.0.2.1", 9999, Duration::from_millis(100)).await;
        assert!(!r.reachable);
        assert!(r.error.is_some());
    }
}
