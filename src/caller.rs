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
