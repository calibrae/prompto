//! What an agent may ask prompto about itself (roadmap E7, for the Claude
//! Code plugin): `GET /v1/whoami`, `GET /v1/audit` and `POST /v1/kill`.
//!
//! They sit behind the same middleware as `/mcp`, so the agent is the
//! bearer token's and the session is `X-Prompto-Session`.
//!
//! - **whoami**: the agent, its groups and the session the request
//!   carries. Nothing else; it is what the caller already sent.
//! - **audit**: the caller's **own** records (`agent` equal to the token's
//!   agent), newest last, optionally for one host and/or one session.
//!   With a host, policy must grant the agent some host-targeting tool
//!   there (the `inventory_list` visibility rule): an agent can't read
//!   its history on a host it has been taken off. `anonymous` gets
//!   nothing (every unauthenticated caller shares that name), nor does
//!   anyone with `PROMPTO_AUTH=off` (no identity to filter on). Only the
//!   live log's last [`SCAN_BYTES`] are searched.
//! - **kill**: `scope: "session"` stops the caller's own calls in its own
//!   session (the switch names agent *and* session, so it never stops
//!   another agent that claims the same session ID). `scope: "global"`
//!   stops every call, and needs an approver's TOTP code: the role token
//!   alone can't stop other agents. Neither can be lifted over HTTP:
//!   `prompto unkill session <id>` / `prompto kill off`. Both are audited
//!   (`"type": "kill"`), refused attempts included.

use crate::agent::AuthMode;
use crate::approval::ApproveError;
use crate::audit::{self, Filter};
use crate::ctx::CallCtx;
use crate::precheck::ApiState;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;

/// How much of the live audit log `GET /v1/audit` reads, from its end.
pub const SCAN_BYTES: u64 = 8 * 1024 * 1024;
/// Default and largest `limit`.
pub const DEFAULT_LIMIT: usize = 20;
pub const MAX_LIMIT: usize = 200;

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// The caller as a context the gates understand (no call).
fn ctx() -> CallCtx {
    let mut ctx = CallCtx::new(crate::caller::current()).with_identity(crate::agent::current());
    ctx.user_agent = crate::caller::user_agent();
    ctx
}

/// The named agent behind the request, or why there is none (a 403).
fn own_agent(st: &ApiState, ctx: &CallCtx) -> Result<String, &'static str> {
    if st.mode == AuthMode::Off {
        return Err("this prompto runs with PROMPTO_AUTH=off: calls carry no agent identity");
    }
    match ctx.agent.as_ref().map(|a| a.name.as_str()) {
        Some(name) if name != crate::agent::ANONYMOUS && name != crate::agent::LOCAL => {
            Ok(name.to_string())
        }
        _ => Err("anonymous callers share one identity: send a role token"),
    }
}

/// `GET /v1/whoami`.
pub async fn whoami(State(st): State<ApiState>) -> Response {
    let ctx = ctx();
    let (agent, groups) = match &ctx.agent {
        Some(a) => (Some(a.name.clone()), a.groups.clone()),
        None => (None, vec![]),
    };
    Json(json!({
        "agent": agent,
        "groups": groups,
        "session": ctx.session_id,
        "auth": st.mode.as_str(),
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// The last `max` bytes of `path`, from the first full line. A missing
/// file is empty. `.1` says whether the start was cut.
fn tail(path: &std::path::Path, max: u64) -> std::io::Result<(String, bool)> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((String::new(), false)),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let cut = len > max;
    if cut {
        f.seek(SeekFrom::Start(len - max))?;
    }
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if cut {
        // The first line is probably partial.
        text = text.split_once('\n').map(|x| x.1).unwrap_or("").to_string();
    }
    Ok((text, cut))
}

/// Is `rec` one of `agent`'s own records? Its calls, prechecks and
/// approvals, and the kills it set over HTTP.
fn is_own(rec: &Value, agent: &str) -> bool {
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    match s(rec, "type").as_deref() {
        Some("tool" | "precheck" | "approve") => s(rec, "agent").as_deref() == Some(agent),
        Some("kill") => rec
            .get("by")
            .and_then(|b| s(b, "agent"))
            .is_some_and(|a| a == agent),
        _ => false,
    }
}

/// `GET /v1/audit?host=&session=&limit=`.
pub async fn audit(
    State(st): State<ApiState>,
    query: Result<Query<AuditQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let ctx = ctx();
    let agent = match own_agent(&st, &ctx) {
        Ok(a) => a,
        Err(why) => return error(StatusCode::FORBIDDEN, why),
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    if let Some(s) = &q.session
        && crate::agent::parse_session(s).is_none()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "`session` must be 1-128 chars of A-Za-z0-9._:-",
        );
    }
    // A host: only one policy lets the agent see (unknown hosts look the
    // same, so this doesn't tell which names exist).
    let host = match &q.host {
        None => None,
        Some(typed) => {
            let inv = st.store.snapshot();
            let seen = inv.canonical(typed).and_then(|name| {
                let h = inv.get(name).ok()?;
                let listed = match &st.policy {
                    None => true,
                    Some(p) => {
                        static TOOLS: OnceLock<Vec<String>> = OnceLock::new();
                        let tools = TOOLS.get_or_init(crate::mcp::Prompto::tool_names);
                        let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
                        p.visibility(&ctx, (name, h), &tools).listed
                    }
                };
                listed.then(|| name.to_string())
            });
            match seen {
                Some(name) => Some(name),
                None => {
                    return error(
                        StatusCode::FORBIDDEN,
                        format!(
                            "refused_policy: agent {agent} has no grant on host {:?}, so its \
                             audit records there are not shown",
                            audit::clamp(typed, 64)
                        ),
                    );
                }
            }
        }
    };
    let Some(path) = st.audit.log().map(|l| l.path().to_path_buf()) else {
        return Json(json!({ "records": [], "count": 0, "truncated": false })).into_response();
    };
    let (text, cut) = match tail(&path, SCAN_BYTES) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "GET /v1/audit: cannot read the audit log");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prompto cannot read its audit log",
            );
        }
    };
    let filter = Filter {
        host,
        ..Default::default()
    };
    let mut records: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| is_own(r, &agent))
        .filter(|r| filter.matches(r))
        .filter(|r| {
            q.session.as_deref().is_none_or(|want| {
                r.get("session_id").and_then(Value::as_str) == Some(want)
                    || r.pointer("/by/session_id").and_then(Value::as_str) == Some(want)
            })
        })
        .collect();
    let start = records.len().saturating_sub(limit);
    let records = records.split_off(start);
    Json(json!({
        "count": records.len(),
        "records": records,
        "truncated": cut,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillRequest {
    /// `session` or `global`.
    pub scope: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// `global` only.
    #[serde(default)]
    pub approver: Option<String>,
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// The `"type": "kill"` record of an HTTP kill, set or refused. `by` is
/// the caller (agent, session, address), not an OS user.
#[allow(clippy::too_many_arguments)]
fn kill_record(
    ctx: &CallCtx,
    agent: &str,
    scope: crate::kill::Scope,
    target: Option<&str>,
    reason: &str,
    file: Option<&std::path::Path>,
    approver: Option<&str>,
    refused: Option<&str>,
) -> Value {
    let mut rec = json!({
        "ts": audit::now_ts(),
        "type": "kill",
        "request_id": ctx.request_id(),
        "action": if refused.is_some() { "refused" } else { "on" },
        "scope": scope,
        "target": target.map(|t| audit::clamp(t, audit::MAX_FIELD)),
        "reason": crate::kill::sanitize_reason(reason).map(|r| audit::clamp(&r, audit::MAX_FIELD)),
        "file": file.map(|f| f.display().to_string()),
        "by": {
            "agent": agent,
            "session_id": ctx.session_id,
            "client_ip": ctx.caller_ip.map(|ip| ip.to_canonical().to_string()),
        },
    });
    if scope == crate::kill::Scope::AgentSession {
        rec["agent"] = agent.into();
    }
    if let Some(a) = approver {
        rec["approved_by"] = audit::clamp(a, 64).into();
    }
    if let Some(why) = refused {
        rec["refused"] = audit::clamp(why, audit::MAX_FIELD).into();
    }
    rec
}

fn write_kill_record(st: &ApiState, rec: &Value) {
    tracing::warn!(target: audit::TARGET, record = %rec, "kill switch change over HTTP");
    if let Some(log) = st.audit.log() {
        let mut line = rec.to_string().into_bytes();
        line.push(b'\n');
        // The switch applies whether or not this is recorded: the
        // journal line above has it either way.
        let _ = log.append(&line);
    }
}

/// `POST /v1/kill`.
pub async fn kill(
    State(st): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<KillRequest>, JsonRejection>,
) -> Response {
    use crate::kill::Scope;
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let mut ctx = ctx();
    let agent = match own_agent(&st, &ctx) {
        Ok(a) => a,
        Err(why) => return error(StatusCode::FORBIDDEN, why),
    };
    if let Some(s) = &req.session {
        let Some(s) = crate::agent::parse_session(s) else {
            return error(
                StatusCode::BAD_REQUEST,
                "`session` must be 1-128 chars of A-Za-z0-9._:-",
            );
        };
        let header = headers
            .get(crate::agent::SESSION_HEADER)
            .and_then(|v| v.to_str().ok());
        if header.is_some_and(|h| h != s) {
            return error(
                StatusCode::BAD_REQUEST,
                "`session` differs from the X-Prompto-Session header",
            );
        }
        ctx.session_id = Some(s);
    }
    let reason = req.reason.as_deref().unwrap_or("").trim().to_string();
    match req.scope.as_str() {
        "session" => {
            let Some(session) = ctx.session_id.clone() else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "a session kill needs the session: X-Prompto-Session or `session`",
                );
            };
            let why = format!("stopped by agent {agent} itself: {reason}");
            match st.kill.set_agent_session(&agent, &session, &why) {
                Ok(path) => {
                    let rec = kill_record(
                        &ctx,
                        &agent,
                        Scope::AgentSession,
                        Some(&session),
                        &why,
                        Some(&path),
                        None,
                        None,
                    );
                    write_kill_record(&st, &rec);
                    Json(json!({
                        "request_id": ctx.request_id(),
                        "killed": { "scope": "agent_session", "agent": agent, "session": session },
                        "reason": format!(
                            "every call by agent {agent} in session {session} is refused from \
                             now on; an operator lifts it with `prompto unkill session {session}`"
                        ),
                    }))
                    .into_response()
                }
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "POST /v1/kill: cannot set the session kill");
                    error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "prompto cannot write its kill switch directory (PROMPTO_KILL_API_DIR); \
                         ask the operator to run `prompto kill session <id>`",
                    )
                }
            }
        }
        "global" => {
            let (Some(approver), Some(code)) = (req.approver.as_deref(), req.totp_code.as_deref())
            else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "a global kill needs an approver and their current TOTP code \
                     (`approver`, `totp_code`)",
                );
            };
            if let Some(why) = st.approvals.unavailable() {
                return error(StatusCode::SERVICE_UNAVAILABLE, why);
            }
            if let Err(e) = st.approvals.verify_approver(approver, code).await {
                let (status, msg) = match e {
                    ApproveError::Locked(name, _) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("approver {name} is locked out after too many wrong codes"),
                    ),
                    ApproveError::Refused(why) => (StatusCode::FORBIDDEN, why),
                    ApproveError::Unavailable(why) => (StatusCode::SERVICE_UNAVAILABLE, why),
                };
                let rec = kill_record(
                    &ctx,
                    &agent,
                    Scope::Global,
                    None,
                    &reason,
                    None,
                    Some(approver),
                    Some(&msg),
                );
                write_kill_record(&st, &rec);
                return error(status, msg);
            }
            let approver = audit::clamp(approver, 64);
            let why = format!("set over HTTP by approver {approver} (agent {agent}): {reason}");
            match st.kill.set_api_global(&why) {
                Ok(path) => {
                    let rec = kill_record(
                        &ctx,
                        &agent,
                        Scope::Global,
                        None,
                        &why,
                        Some(&path),
                        Some(&approver),
                        None,
                    );
                    write_kill_record(&st, &rec);
                    tracing::warn!(agent = %agent, approver = %approver, "GLOBAL KILL ON (set over HTTP)");
                    Json(json!({
                        "request_id": ctx.request_id(),
                        "killed": { "scope": "global", "approved_by": approver },
                        "reason": "every prompto tool call is refused from now on; an operator \
                                   lifts it with `prompto kill off`",
                    }))
                    .into_response()
                }
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "POST /v1/kill: cannot set the global kill");
                    error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "prompto cannot write its kill switch directory (PROMPTO_KILL_API_DIR); \
                         ask the operator to run `prompto kill on`",
                    )
                }
            }
        }
        other => error(
            StatusCode::BAD_REQUEST,
            format!(
                "scope {:?}: use \"session\" (your own) or \"global\" (needs an approver's code)",
                audit::clamp(other, 32)
            ),
        ),
    }
}
