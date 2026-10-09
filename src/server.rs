//! HTTP transport assembly.
//!
//! Lives in the library rather than in `main.rs` so integration tests can
//! drive the *shipping* wiring — middleware, service factory, capability
//! guard — instead of a hand-rolled approximation. The self-targeting
//! guard has failed open twice; a test that doesn't exercise the real
//! chain is not evidence that it works.

use crate::advisor::Advisor;
use crate::agent::{self, AuthConfig, Decision};
use crate::audit::{self, Audit};
use crate::authz::Need;
use crate::caller;
use crate::error_class::ErrorClass;
use crate::filters::FilterChain;
use crate::inventory::InventoryStore;
use crate::mcp::Prompto;
use crate::sessions::{self, BoundSessionManager, SessionOwners};
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
    /// `PROMPTO_AUTH` and the agent token store. `Default` is auth off,
    /// which is today's behaviour.
    pub auth: AuthConfig,
    /// The audit log (`crate::audit`): every tool call, `GET /log` and
    /// every 401.
    pub audit: Audit,
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
    let (client, ua) = {
        let headers = req.headers();
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        let client = caller::resolve_client_ip(
            addr.ip(),
            &trusted,
            get("x-real-ip"),
            get("x-forwarded-for"),
        );
        (client, get("user-agent").map(str::to_string))
    };
    caller::scoped(
        client,
        caller::scoped_user_agent(ua.as_deref(), next.run(req)),
    )
    .await
}

/// axum middleware: authenticate the caller (`PROMPTO_AUTH`) and install
/// the resulting [`agent::Identity`] in the agent task-local, which the
/// rmcp factory and `/log` snapshot like the caller IP.
///
/// Runs inside [`capture_caller_ip`], so warnings carry the real client
/// address. It also holds legacy MCP sessions to their creator: a request
/// whose agent differs from the one that created its `Mcp-Session-Id` is
/// refused (see [`crate::sessions`]). A refusal is a 401: a JSON-RPC error object on `/mcp` (so an
/// MCP client can show the reason), plain text on `/log`.
async fn authenticate(
    auth: AuthConfig,
    owners: SessionOwners,
    audit: Audit,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // Every 401 is an audit record (`type = auth`, rate-limited).
    let refuse = |path: &str, reason: &str, session: Option<String>, mcp: Option<String>| {
        audit.write_auth(
            caller::current(),
            caller::user_agent(),
            session,
            mcp,
            path,
            reason,
        );
        unauthorized(path, reason)
    };
    let decision = {
        let headers = req.headers();
        // A header that isn't visible ASCII is "present but invalid",
        // not "absent": in required mode it must not fall through to
        // the missing-token branch, and either way it is a warning.
        let authz = headers
            .get(axum::http::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap_or(""));
        let session = headers
            .get(agent::SESSION_HEADER)
            .map(|v| v.to_str().unwrap_or("\u{fffd}"));
        agent::authenticate_request(&auth, authz, session, caller::current())
    };
    match decision {
        Decision::Proceed(id) => {
            // A legacy MCP session runs as whoever created it (the
            // factory snapshots the identity once), so reusing someone
            // else's `Mcp-Session-Id` would act as them. Refused in
            // optional mode too. With auth off nobody is identified and
            // there is nothing to compare.
            if auth.mode != agent::AuthMode::Off
                && let Some(mcp_session) = req
                    .headers()
                    .get(MCP_SESSION_HEADER)
                    .and_then(|v| v.to_str().ok())
                && !owners.check(mcp_session, &id)
            {
                tracing::warn!(
                    caller_ip = ?caller::current(),
                    agent = id.agent.as_ref().map(|a| a.name.as_str()),
                    mcp_session = %sessions::redact(mcp_session),
                    mode = auth.mode.as_str(),
                    "refused: Mcp-Session-Id belongs to another agent"
                );
                // Both IDs shortened as in the journal line above: the
                // record must not hand out a replayable session handle.
                return refuse(
                    req.uri().path(),
                    "session belongs to another agent",
                    id.session_id.as_deref().map(sessions::redact),
                    Some(sessions::redact(mcp_session)),
                );
            }
            agent::scoped(id, next.run(req)).await
        }
        Decision::Reject(reason) => {
            let session = req
                .headers()
                .get(agent::SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .and_then(agent::parse_session);
            refuse(req.uri().path(), reason, session, None)
        }
    }
}

/// rmcp's legacy session header.
const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// The 401: a JSON-RPC error object on `/mcp` (so an MCP client can show
/// the reason), plain text on `/log`.
fn unauthorized(path: &str, reason: &str) -> Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let www = (header::WWW_AUTHENTICATE, r#"Bearer realm="prompto""#);
    if path == "/log" {
        (
            StatusCode::UNAUTHORIZED,
            [www],
            format!("unauthorized: {reason}\n"),
        )
            .into_response()
    } else {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32001,
                "message": format!(
                    "unauthorized: {reason} — prompto requires `Authorization: Bearer <agent token>`"
                ),
            }
        });
        (
            StatusCode::UNAUTHORIZED,
            [www, (header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response()
    }
}

/// State for the plain-HTTP `/log` endpoint.
#[derive(Clone)]
struct LogState {
    store: InventoryStore,
    ssh: Arc<SshClient>,
    policy: Option<crate::policy::Enforcer>,
    audit: Audit,
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
/// Every response carries the call's request ID in
/// [`REQUEST_ID_HEADER`].
///
/// # Authentication
///
/// Gated exactly like `/mcp` by [`authenticate`]: with `PROMPTO_AUTH=off`
/// (the default) it is unauthenticated, and anyone who can reach the
/// listener can read journals on any inventory host that grants
/// `sudo_exec`; `required` makes it a 401 without a valid agent token.
///
/// It is held to *exactly* the same limits as the `service_logs` MCP tool
/// and given no capability the tool lacks: same `sudo_exec` gate, self-target guard and policy (via `authz`), same
/// `validate_unit_name` on the unit (so it cannot be turned into a shell),
/// same 1..=1000 line clamp, same 15 s timeout. So it widens *reach*, not
/// *power* — it shares `/mcp`'s listener and its authentication.
async fn log_handler(
    axum::extract::State(state): axum::extract::State<LogState>,
    axum::extract::Query(q): axum::extract::Query<LogQuery>,
) -> impl axum::response::IntoResponse {
    let mut ctx = crate::ctx::CallCtx::new(caller::current()).with_identity(agent::current());
    ctx.user_agent = caller::user_agent();
    let (status, body, err) = match log_tail(&state, &ctx, &q).await {
        Ok(out) => (axum::http::StatusCode::OK, out, None),
        Err((status, e)) => (status, format!("{e:#}\n"), Some(e)),
    };
    audit_log_call(&state, &ctx, &q, err.as_ref(), body.len() as u64);
    ([(REQUEST_ID_HEADER, ctx.request_id())], (status, body))
}

/// `/log`'s audit record: the call it is, `service_logs`.
fn audit_log_call(
    state: &LogState,
    ctx: &crate::ctx::CallCtx,
    q: &LogQuery,
    err: Option<&anyhow::Error>,
    bytes: u64,
) {
    let args = serde_json::json!({ "host": q.host, "unit": q.unit, "lines": q.lines });
    let payload = serde_json::Value::Null;
    let outcome = match err {
        Some(e) => audit::Outcome::Failure(e),
        None => audit::Outcome::Success(&payload),
    };
    let verdict = audit::judge("service_logs", &outcome, &ctx.notes(), true);
    let mut rec = audit::tool_record(ctx, "service_logs", args).with_verdict(verdict);
    (rec.host, rec.queried_as) = audit::resolve_host(&state.store.snapshot(), Some(&q.host));
    rec.path = Some("/log".into());
    rec.bytes = bytes;
    state.audit.write(rec);
}

async fn log_tail(
    state: &LogState,
    ctx: &crate::ctx::CallCtx,
    q: &LogQuery,
) -> Result<String, (axum::http::StatusCode, anyhow::Error)> {
    use axum::http::StatusCode;

    // Validate up front so a malformed unit is a 400 (caller's fault),
    // not a 502 from the exec layer. `journalctl_tail` re-checks — this
    // is for the status code, never the safety.
    if let Err(e) = crate::claudemgr::validate_unit_name(&q.unit) {
        return Err((StatusCode::BAD_REQUEST, e));
    }
    // Same gate as the tool, under the tool's name, so `/log` keeps
    // exactly the tool's limits — the self-target guard included.
    let target = match crate::authz::authorize(
        &state.store.snapshot(),
        state.policy.as_ref(),
        ctx,
        "service_logs",
        &q.host,
        Need::Cap(crate::inventory::Capability::SudoExec),
    ) {
        Ok(t) => t,
        // Unknown host, missing capability or self-target are caller
        // errors; a policy refusal is a 403.
        Err(e) => {
            let status = match e.class {
                ErrorClass::RefusedPolicy | ErrorClass::ApprovalRequired => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            return Err((status, e.into()));
        }
    };
    // Same audit gate as the tools: nothing runs that can't be recorded.
    if let Err(e) = state.audit.preflight(ctx, "service_logs") {
        return Err((StatusCode::SERVICE_UNAVAILABLE, e.into()));
    }
    ctx.note(|n| {
        n.authorized = true;
        n.rule = target.rule.clone();
    });
    let lines = q.lines.unwrap_or(50);
    crate::claudemgr::journalctl_tail(&state.ssh, ctx, &target.host, &q.unit, lines)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))
}

/// Response header carrying the request ID on `GET /log`.
pub const REQUEST_ID_HEADER: &str = "x-prompto-request-id";

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
        auth,
        audit,
        ..
    } = p;

    // Clones for the /log endpoint; the originals move into the factory.
    let store_for_log = store.clone();
    let owners = SessionOwners::default();
    let owners_for_auth = owners.clone();
    let ssh_for_log = ssh.clone();
    // Policy is enforced on /mcp and /log alike, `None` with auth off.
    let policy = auth.enforcer();
    let policy_for_log = policy.clone();
    let audit_for_log = audit.clone();
    let audit_for_auth = audit.clone();

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
            )
            .with_identity(agent::current())
            .with_policy(policy.clone())
            .with_audit(audit.clone())
            .with_user_agent(caller::user_agent()))
        },
        BoundSessionManager::new(LocalSessionManager::default(), owners).into(),
        http_config,
    );

    let log_state = LogState {
        store: store_for_log,
        ssh: ssh_for_log,
        policy: policy_for_log,
        audit: audit_for_log,
    };

    axum::Router::new()
        .nest_service("/mcp", service)
        .route(
            "/log",
            axum::routing::get(log_handler).with_state(log_state),
        )
        // Layers wrap outward: the caller-IP layer (added last) runs
        // first, so authentication sees the resolved client address.
        .layer(middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            let owners = owners_for_auth.clone();
            let audit = audit_for_auth.clone();
            async move { authenticate(auth, owners, audit, req, next).await }
        }))
        .layer(middleware::from_fn(
            move |conn: ConnectInfo<SocketAddr>, req, next| {
                let trusted = trusted_proxies.clone();
                async move { capture_caller_ip(trusted, conn, req, next).await }
            },
        ))
}
