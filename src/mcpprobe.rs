//! Health probes for MCP servers.
//!
//! Splits two states that v0.3 conflated:
//!   * "configured but unreachable" — the daemon is dead or networked-out;
//!     a fresh `claude -p` would also see it dropped. Real outage.
//!   * "configured and reachable" — the agent's session connection has
//!     simply been recycled. `/mcp` (or a new claudecli message) fixes
//!     it without touching the daemon.
//!
//! `mcp_status` calls `claude mcp list` on a client to discover what's
//! configured, then probes each URL directly from prompto's host. Tells
//! the two states apart before anyone reaches for `mcp_restart_claudecli`.

use anyhow::Result;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct McpEntry {
    pub name: String,
    /// Transport tag from `claude mcp list` — typically "HTTP", "SSE", or
    /// "STDIO". `None` for entries the parser couldn't classify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// URL for HTTP/SSE; full command line for STDIO. Empty if absent.
    pub target: String,
    /// Status string `claude mcp list` reported (e.g. "✓ Connected",
    /// "Needs authentication"). Free-text; don't pattern-match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct ProbeResult {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub target: String,
    /// `true` if a TCP connect to the URL's host:port succeeded inside
    /// the probe budget.
    pub tcp_reachable: bool,
    /// Round-trip time of the TCP connect (or `None` if it didn't
    /// succeed). Includes DNS resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// `true` for STDIO entries — we mark them `skipped` because there's
    /// no socket to probe. They show up in the report so the caller sees
    /// the full list.
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_status_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parse `claude mcp list` (text form). One entry per non-blank line that
/// matches `<name>: <target> [(<transport>)]? [- <status>]?`. Tolerates a
/// "Checking MCP server health…" preamble and blank separator lines.
pub fn parse_mcp_list(stdout: &str) -> Vec<McpEntry> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Skip claude's preamble line.
        if line.starts_with("Checking ") || line.starts_with("No MCP servers") {
            continue;
        }
        // Pattern: "<name>: <rest>"
        let Some((name, rest)) = line.split_once(": ") else {
            continue;
        };
        let mut rest = rest.trim().to_string();

        // Strip a trailing " - <status>" if present.
        let status_hint = if let Some(idx) = rest.rfind(" - ") {
            let s = rest[idx + 3..].trim().to_string();
            rest.truncate(idx);
            Some(s)
        } else {
            None
        };

        // Strip a trailing " (TRANSPORT)".
        let mut transport = None;
        let trimmed = rest.trim_end();
        if trimmed.ends_with(')')
            && let Some(open_idx) = trimmed.rfind(" (")
        {
            let candidate = &trimmed[open_idx + 2..trimmed.len() - 1];
            // Heuristic: transport tags are short uppercase tokens.
            if candidate.len() <= 16
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                transport = Some(candidate.to_string());
                rest = trimmed[..open_idx].to_string();
            }
        }

        out.push(McpEntry {
            name: name.trim().to_string(),
            transport,
            target: rest.trim().to_string(),
            status_hint,
        });
    }
    out
}

/// Probe one MCP entry. For HTTP/SSE: parse the URL, TCP-connect to
/// host:port within `probe_timeout`. For STDIO: skip — the entry is in
/// the report but flagged `skipped`.
pub async fn probe(entry: &McpEntry, probe_timeout: Duration) -> ProbeResult {
    let stdio = matches!(
        entry.transport.as_deref(),
        Some("STDIO") | Some("stdio") | Some("Stdio")
    );
    if stdio || !entry.target.contains("://") {
        return ProbeResult {
            name: entry.name.clone(),
            transport: entry.transport.clone(),
            target: entry.target.clone(),
            tcp_reachable: false,
            latency_ms: None,
            skipped: true,
            claude_status_hint: entry.status_hint.clone(),
            error: None,
        };
    }

    let (host, port) = match parse_host_port(&entry.target) {
        Ok(hp) => hp,
        Err(e) => {
            return ProbeResult {
                name: entry.name.clone(),
                transport: entry.transport.clone(),
                target: entry.target.clone(),
                tcp_reachable: false,
                latency_ms: None,
                skipped: false,
                claude_status_hint: entry.status_hint.clone(),
                error: Some(format!("parse url: {e}")),
            };
        }
    };

    let started = Instant::now();
    let connect = timeout(probe_timeout, TcpStream::connect((host.as_str(), port))).await;
    let latency = started.elapsed().as_millis() as u64;

    match connect {
        Ok(Ok(_)) => ProbeResult {
            name: entry.name.clone(),
            transport: entry.transport.clone(),
            target: entry.target.clone(),
            tcp_reachable: true,
            latency_ms: Some(latency),
            skipped: false,
            claude_status_hint: entry.status_hint.clone(),
            error: None,
        },
        Ok(Err(e)) => ProbeResult {
            name: entry.name.clone(),
            transport: entry.transport.clone(),
            target: entry.target.clone(),
            tcp_reachable: false,
            latency_ms: None,
            skipped: false,
            claude_status_hint: entry.status_hint.clone(),
            error: Some(e.to_string()),
        },
        Err(_) => ProbeResult {
            name: entry.name.clone(),
            transport: entry.transport.clone(),
            target: entry.target.clone(),
            tcp_reachable: false,
            latency_ms: None,
            skipped: false,
            claude_status_hint: entry.status_hint.clone(),
            error: Some(format!(
                "connect timed out after {}ms",
                probe_timeout.as_millis()
            )),
        },
    }
}

/// Parse out (host, port) from a URL. Lightweight — handles the shapes
/// `claude mcp` emits without pulling a URL parsing crate.
pub fn parse_host_port(url: &str) -> Result<(String, u16)> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Drop credentials prefix, fragment, query, path
    let after_creds = after_scheme
        .rsplit_once('@')
        .map(|(_, r)| r)
        .unwrap_or(after_scheme);
    let host_port = after_creds
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_creds);
    let scheme_default_port = if url.starts_with("https") { 443u16 } else { 80 };

    // Handle IPv6 literal `[::1]:1234`
    if let Some(rest) = host_port.strip_prefix('[') {
        if let Some((h, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .map(|p| p.parse::<u16>())
                .transpose()
                .map_err(|e| anyhow::anyhow!("port: {e}"))?
                .unwrap_or(scheme_default_port);
            return Ok((h.to_string(), port));
        }
        anyhow::bail!("malformed IPv6 host: {host_port}");
    }

    if let Some((h, p)) = host_port.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|e| anyhow::anyhow!("port {p:?}: {e}"))?;
        Ok((h.to_string(), port))
    } else {
        Ok((host_port.to_string(), scheme_default_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_claude_mcp_list_output() {
        let s = "Checking MCP server health…\n\
                 \n\
                 claude.ai Google Drive: https://drivemcp.googleapis.com/mcp/v1 - ! Needs authentication\n\
                 hass: http://192.0.2.2:8123/api/mcp (HTTP) - ✓ Connected\n\
                 memqdrant: http://192.0.2.3:6335/mcp (HTTP) - ✓ Connected\n";
        let entries = parse_mcp_list(s);
        assert_eq!(entries.len(), 3);
        let gd = &entries[0];
        assert_eq!(gd.name, "claude.ai Google Drive");
        assert_eq!(gd.target, "https://drivemcp.googleapis.com/mcp/v1");
        assert_eq!(gd.transport, None);
        assert_eq!(gd.status_hint.as_deref(), Some("! Needs authentication"));
        let h = &entries[1];
        assert_eq!(h.name, "hass");
        assert_eq!(h.target, "http://192.0.2.2:8123/api/mcp");
        assert_eq!(h.transport.as_deref(), Some("HTTP"));
        assert_eq!(h.status_hint.as_deref(), Some("✓ Connected"));
    }

    #[test]
    fn parse_empty_output_returns_empty() {
        assert!(parse_mcp_list("").is_empty());
        assert!(parse_mcp_list("No MCP servers configured. Use `claude mcp add`…").is_empty());
    }

    #[test]
    fn parse_handles_stdio_entries() {
        let s = "myserver: /usr/local/bin/myserver --flag (STDIO) - ✓ Connected\n";
        let entries = parse_mcp_list(s);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].transport.as_deref(), Some("STDIO"));
        assert_eq!(entries[0].target, "/usr/local/bin/myserver --flag");
    }

    #[test]
    fn parse_host_port_basic() {
        assert_eq!(
            parse_host_port("http://192.0.2.3:6335/mcp").unwrap(),
            ("192.0.2.3".to_string(), 6335)
        );
        assert_eq!(
            parse_host_port("https://example.com/mcp").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("http://example.com/mcp").unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn parse_host_port_strips_credentials_query_fragment() {
        assert_eq!(
            parse_host_port("http://user:pw@host.example:1234/x?a=b#frag").unwrap(),
            ("host.example".to_string(), 1234)
        );
    }

    #[test]
    fn parse_host_port_handles_ipv6() {
        assert_eq!(
            parse_host_port("http://[::1]:6335/mcp").unwrap(),
            ("::1".to_string(), 6335)
        );
    }

    #[test]
    fn parse_host_port_rejects_bad_port() {
        assert!(parse_host_port("http://h:notaport/x").is_err());
    }

    #[tokio::test]
    async fn probe_skips_stdio_entries() {
        let e = McpEntry {
            name: "x".into(),
            transport: Some("STDIO".into()),
            target: "/bin/cat".into(),
            status_hint: None,
        };
        let r = probe(&e, Duration::from_millis(50)).await;
        assert!(r.skipped);
        assert!(!r.tcp_reachable);
    }

    #[tokio::test]
    async fn probe_marks_unreachable_with_error() {
        // TEST-NET-1 is guaranteed non-routable.
        let e = McpEntry {
            name: "blackhole".into(),
            transport: Some("HTTP".into()),
            target: "http://192.0.2.99:6335/mcp".into(),
            status_hint: None,
        };
        let r = probe(&e, Duration::from_millis(150)).await;
        assert!(!r.skipped);
        assert!(!r.tcp_reachable);
        assert!(r.error.is_some());
    }
}
