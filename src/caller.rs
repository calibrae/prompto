//! Per-request caller IP tracking.
//!
//! Captured by an axum middleware on the HTTP transport and propagated
//! through the tool handlers via a tokio task-local. Tools that want to
//! refuse self-targeting (`caller == target`) read [`current`] and
//! compare against the inventory's host IP.
//!
//! Falls back to `None` on transports that don't set it (stdio, unit
//! tests) — call sites must treat absence as "no check available" and
//! NOT as "the caller is unknown therefore deny." We don't want to
//! break legitimate code paths that don't carry caller info.
//!
//! # Reverse proxies
//!
//! prompto binds loopback and is fronted by nginx, so the TCP peer of
//! every real request is the proxy, not the client. Taking the peer
//! address at face value made the self-targeting guard compare
//! `127.0.0.1` against inventory IPs — it could never match, so the
//! guard was inert in production while looking healthy.
//!
//! [`resolve_client_ip`] fixes that, but only under a strict rule:
//! forwarding headers are honoured **only when the direct peer is a
//! configured trusted proxy**. A header from anyone else is ignored
//! entirely. Trusting `X-Forwarded-For` unconditionally would be worse
//! than having no guard at all — any client could then claim any source
//! address and walk straight through the check it is meant to fail.

use std::net::IpAddr;

tokio::task_local! {
    static CALLER_IP: IpAddr;
}

/// Run `f` with `ip` installed as the current caller for the duration
/// of the future.
pub async fn scoped<F: std::future::Future>(ip: IpAddr, f: F) -> F::Output {
    CALLER_IP.scope(ip, f).await
}

/// Return the current caller's IP, or `None` if no scope is active
/// (stdio transport, tests, etc.).
pub fn current() -> Option<IpAddr> {
    CALLER_IP.try_with(|ip| *ip).ok()
}

/// Loopback addresses — the default trusted-proxy set, since the
/// production deployment has nginx on the same host proxying to
/// `127.0.0.1:6337`.
pub const DEFAULT_TRUSTED_PROXIES: &[IpAddr] = &[
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
];

/// Determine the real client IP for a request.
///
/// `peer` is the TCP peer (axum `ConnectInfo`). Forwarding headers are
/// consulted **only** when `peer` is in `trusted_proxies`; otherwise
/// `peer` is returned unchanged and the headers are ignored. This is
/// the whole security property — see the module docs.
///
/// When the peer is trusted, `X-Real-IP` wins over `X-Forwarded-For`:
/// nginx sets it to `$remote_addr`, a single value it observed itself,
/// so a client cannot inject into it. For `X-Forwarded-For` we take the
/// **last** element, because `$proxy_add_x_forwarded_for` appends the
/// address nginx saw to whatever the client sent — so the last entry is
/// proxy-authored and the earlier ones are client-controlled.
///
/// Unparseable header values fall back to `peer` rather than failing
/// the request; the guard treats a wrong-but-real address the same as
/// any other non-matching one.
pub fn resolve_client_ip(
    peer: IpAddr,
    trusted_proxies: &[IpAddr],
    x_real_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        // Untrusted peer: whatever it claims about its own origin is
        // unverifiable, so it does not get to claim anything.
        return peer;
    }
    if let Some(raw) = x_real_ip
        && let Ok(ip) = raw.trim().parse::<IpAddr>()
    {
        return ip;
    }
    if let Some(raw) = x_forwarded_for
        && let Some(ip) = raw
            .split(',')
            .rev()
            .filter_map(|part| part.trim().parse::<IpAddr>().ok())
            .next()
    {
        return ip;
    }
    peer
}

/// Parse a comma-separated trusted-proxy list (e.g. from
/// `PROMPTO_TRUSTED_PROXIES`). Invalid entries are dropped. An empty or
/// all-invalid list yields `None` so callers can fall back to
/// [`DEFAULT_TRUSTED_PROXIES`].
pub fn parse_trusted_proxies(raw: &str) -> Option<Vec<IpAddr>> {
    let v: Vec<IpAddr> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// THE security property: a client that is not a trusted proxy
    /// cannot talk its way into a different source address, no matter
    /// what headers it sends.
    #[test]
    fn untrusted_peer_cannot_spoof_via_headers() {
        let peer = ip("10.10.0.99");
        let got = resolve_client_ip(
            peer,
            DEFAULT_TRUSTED_PROXIES,
            Some("10.10.0.2"),
            Some("10.10.0.2"),
        );
        assert_eq!(got, peer, "headers from an untrusted peer must be ignored");
    }

    #[test]
    fn trusted_proxy_x_real_ip_is_honoured() {
        let got = resolve_client_ip(
            ip("127.0.0.1"),
            DEFAULT_TRUSTED_PROXIES,
            Some("10.10.0.2"),
            None,
        );
        assert_eq!(got, ip("10.10.0.2"));
    }

    #[test]
    fn x_real_ip_wins_over_forwarded_for() {
        let got = resolve_client_ip(
            ip("127.0.0.1"),
            DEFAULT_TRUSTED_PROXIES,
            Some("10.10.0.2"),
            Some("203.0.113.9"),
        );
        assert_eq!(got, ip("10.10.0.2"));
    }

    /// `$proxy_add_x_forwarded_for` appends what nginx saw, so the last
    /// entry is the trustworthy one — a client pre-seeding the header
    /// only controls the earlier entries.
    #[test]
    fn forwarded_for_takes_last_entry_not_first() {
        let got = resolve_client_ip(
            ip("127.0.0.1"),
            DEFAULT_TRUSTED_PROXIES,
            None,
            Some("203.0.113.9, 198.51.100.7, 10.10.0.2"),
        );
        assert_eq!(
            got,
            ip("10.10.0.2"),
            "client-supplied leading entries must not win"
        );
    }

    #[test]
    fn trusted_proxy_without_headers_falls_back_to_peer() {
        let peer = ip("127.0.0.1");
        assert_eq!(resolve_client_ip(peer, DEFAULT_TRUSTED_PROXIES, None, None), peer);
    }

    #[test]
    fn garbage_headers_fall_back_to_peer() {
        let peer = ip("127.0.0.1");
        let got = resolve_client_ip(
            peer,
            DEFAULT_TRUSTED_PROXIES,
            Some("not-an-ip"),
            Some("also, not, ips"),
        );
        assert_eq!(got, peer);
    }

    #[test]
    fn ipv6_loopback_is_trusted_by_default() {
        let got = resolve_client_ip(ip("::1"), DEFAULT_TRUSTED_PROXIES, Some("10.10.0.2"), None);
        assert_eq!(got, ip("10.10.0.2"));
    }

    #[test]
    fn parse_trusted_proxies_filters_garbage() {
        assert_eq!(
            parse_trusted_proxies("127.0.0.1, nonsense, 10.10.0.3"),
            Some(vec![ip("127.0.0.1"), ip("10.10.0.3")])
        );
        assert_eq!(parse_trusted_proxies(""), None);
        assert_eq!(parse_trusted_proxies("garbage"), None);
    }
}
