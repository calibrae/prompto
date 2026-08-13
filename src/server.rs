//! HTTP transport assembly.
//!
//! Lives in the library rather than in `main.rs` so integration tests can
//! drive the *shipping* wiring — middleware, service factory, capability
//! guard — instead of a hand-rolled approximation. The self-targeting
//! guard has failed open twice; a test that doesn't exercise the real
//! chain is not evidence that it works.

use crate::advisor::Advisor;
use crate::caller;
use crate::filters::FilterChain;
use crate::inventory::InventoryStore;
use crate::mcp::Prompto;
use crate::ssh::SshClient;
use axum::extract::ConnectInfo;
use axum::middleware::{self, Next};
use axum::response::Response;
use mcp_gain::Tracker;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// How the Host-header allowlist should be configured.
#[derive(Clone, Debug, Default)]
pub enum AllowedHosts {
    /// Keep rmcp's default (localhost only).
    #[default]
    Default,
    /// Explicit allowlist.
    List(Vec<String>),
    /// Disabled — only safe behind a trusted proxy or firewall.
    Disabled,
}

/// Everything the HTTP transport needs. Assembled by `main` from env/config.
pub struct HttpParams {
    pub store: InventoryStore,
    pub ssh: Arc<SshClient>,
    pub tracker: Arc<Tracker>,
    pub stop_vm_step: Duration,
    /// Peers permitted to speak for someone else via forwarding headers.
    pub trusted_proxies: Arc<Vec<IpAddr>>,
    pub allowed_hosts: AllowedHosts,
    /// Serve pre-2026-07-28 clients through the legacy *session* machinery
    /// (`true`) or statelessly (`false`).
    ///
    /// prompto ships `false`. Sessions are the source of the redeploy-404
    /// class: a client holds an `Mcp-Session-Id`, prompto restarts, the ID
    /// is unknown, every subsequent call 404s and clients that can't
    /// re-handshake are simply stuck until a human intervenes. That is the
    /// exact failure the retired `accept_unknown_sessions` fork existed to
    /// paper over, and with the fork gone the only real fix is to stop
    /// having sessions. A control plane that needs a human to reconnect it
    /// after its own redeploy is the wrong shape.
    ///
    /// Legacy clients are NOT rejected when this is `false` — rmcp routes
    /// them down the stateless path (see the `legacy_session_mode` docs in
    /// rmcp 3.1.2). What they lose is the standalone GET/SSE stream and
    /// DELETE-based termination, neither of which prompto's tools use.
    ///
    /// Kept configurable via `PROMPTO_LEGACY_SESSION_MODE` so a client that
    /// unexpectedly depends on sessions can be unblocked with an env var
    /// and a restart instead of a rebuild — cheap insurance for the box
    /// that controls every other box.
    pub legacy_session_mode: bool,
    pub cancel: CancellationToken,
}

/// axum middleware: resolve the real client IP and stash it in the
/// caller task-local for the duration of the downstream handler.
///
/// The TCP peer is the reverse proxy in production, so forwarding
/// headers are consulted — but ONLY when the peer is a trusted proxy.
/// See [`caller::resolve_client_ip`] for why that condition is the
/// whole point.
async fn capture_caller_ip(
    trusted: Arc<Vec<IpAddr>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // Resolve inside a block so nothing borrowing `req` survives into
    // the await below (the future must stay `Send`).
    let client = {
        let headers = req.headers();
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        caller::resolve_client_ip(
            addr.ip(),
            &trusted,
            get("x-real-ip"),
            get("x-forwarded-for"),
        )
    };
    caller::scoped(client, next.run(req)).await
}

/// State for the plain-HTTP `/log` endpoint.
#[derive(Clone)]
struct LogState {
    store: InventoryStore,
    ssh: Arc<SshClient>,
}

#[derive(serde::Deserialize)]
struct LogQuery {
    host: String,
    unit: String,
    #[serde(default)]
    lines: Option<u32>,
}

/// `GET /log?host=<name>&unit=<unit>&lines=<n>` — tail a systemd unit's
/// journal as plain text, outside the MCP protocol, for curl and browsers.
///
/// # No authentication
///
/// This endpoint is deliberately unauthenticated (operator's call). It is
/// reachable wherever prompto's listener is: in the homelab deployment
/// that is `prompto.portal.calii.net`, i.e. anyone on the LAN or WireGuard.
/// Anyone who can reach it can read journals on any inventory host that
/// grants `sudo_exec`.
///
/// It is held to *exactly* the same limits as the `service_logs` MCP tool
/// and given no capability the tool lacks: same `sudo_exec` gate, same
/// `validate_unit_name` on the unit (so it cannot be turned into a shell),
/// same 1..=1000 line clamp, same 15 s timeout. So it widens *reach*, not
/// *power* — the MCP surface was already unauthenticated on the same port.
/// Adding auth here without also adding it to `/mcp` would be theatre.
async fn log_handler(
    axum::extract::State(state): axum::extract::State<LogState>,
    axum::extract::Query(q): axum::extract::Query<LogQuery>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;

    // Validate up front so a malformed unit is a 400 (caller's fault),
    // not a 502 from the exec layer. `journalctl_tail` re-checks — this
    // is for the status code, never the safety.
    if let Err(e) = crate::claudemgr::validate_unit_name(&q.unit) {
        return (StatusCode::BAD_REQUEST, format!("{e}\n"));
    }
    let inv = state.store.snapshot();
    let host = match inv.require(&q.host, crate::inventory::Capability::SudoExec) {
        Ok(h) => h.clone(),
        // Unknown host or missing capability are both caller errors.
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}\n")),
    };
    match crate::claudemgr::journalctl_tail(&state.ssh, &host, &q.unit, q.lines.unwrap_or(50)).await
    {
        Ok(out) => (StatusCode::OK, out),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}\n")),
    }
}

/// Build the axum router serving MCP at `/mcp` and the plain-HTTP log
/// tail at `/log`.
pub fn build_router(p: HttpParams) -> axum::Router {
    // `stateless_protocol_metadata_required` is left at its default of
    // false: enabling it rejects ordinary requests from any client
    // negotiated below 2026-07-28, because those don't attach per-request
    // protocol metadata. Legacy clients must keep working.
    //
    // The fork's `accept_unknown_sessions` is gone and NOT replaced — see
    // `HttpParams::legacy_session_mode` for why the answer is to drop
    // sessions rather than to keep patching around them.
    let mut http_config = StreamableHttpServerConfig::default()
        .with_cancellation_token(p.cancel.child_token())
        .with_legacy_session_mode(p.legacy_session_mode);
    match p.allowed_hosts {
        AllowedHosts::Disabled => http_config = http_config.disable_allowed_hosts(),
        AllowedHosts::List(hosts) => http_config = http_config.with_allowed_hosts(hosts),
        AllowedHosts::Default => {}
    }

    // Process-wide state, built once and shared by every per-request
    // handler. Must NOT move inside the factory — see
    // `Prompto::new_with_caller` for why the advisor in particular would
    // be silently neutered.
    let filters = Arc::new(FilterChain::default());
    let advisor = Arc::new(Advisor::new());

    let HttpParams {
        store,
        ssh,
        tracker,
        stop_vm_step,
        trusted_proxies,
        ..
    } = p;

    // Clones for the /log endpoint; the originals move into the factory.
    let store_for_log = store.clone();
    let ssh_for_log = ssh.clone();

    let service = StreamableHttpService::new(
        move || {
            // rmcp 3.x calls this factory inline in the request future,
            // before any `tokio::spawn` — verified against 3.1.2 on both
            // the stateless dispatch path and the legacy session-create
            // path — so the middleware's task-local is still set here.
            // Snapshot it onto the instance; handlers cannot read the
            // task-local once rmcp hands work to a spawned task.
            Ok(Prompto::new_with_caller(
                store.clone(),
                ssh.clone(),
                tracker.clone(),
                filters.clone(),
                advisor.clone(),
                stop_vm_step,
                caller::current(),
            ))
        },
        LocalSessionManager::default().into(),
        http_config,
    );

    let log_state = LogState {
        store: store_for_log,
        ssh: ssh_for_log,
    };

    axum::Router::new()
        .nest_service("/mcp", service)
        .route(
            "/log",
            axum::routing::get(log_handler).with_state(log_state),
        )
        .layer(middleware::from_fn(
            move |conn: ConnectInfo<SocketAddr>, req, next| {
                let trusted = trusted_proxies.clone();
                async move { capture_caller_ip(trusted, conn, req, next).await }
            },
        ))
}
