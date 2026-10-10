//! `POST /v1/precheck` and `POST /v1/approve` (roadmap S6.2, S6.3).
//!
//! Both sit behind the same middleware as `/mcp` (caller IP, bearer
//! authentication), so the agent is the token's and the session is
//! `X-Prompto-Session` — or the body's `session`, which must then agree
//! with the header if both are sent.
//!
//! **Precheck** runs the whole authorization of the call it is given —
//! kill switches, host existence, capability, self-target guard, policy,
//! and the ticket in `arguments.ticket` if there is one — exactly as the
//! tool would (`authz::requirements` lists what each tool authorizes; a
//! test holds it to the handlers), and runs nothing: no SSH, no nonce
//! spent. It answers:
//!
//! - `deny`: some step refused; `error_class`, `rule` and `reason` say
//!   which and why;
//! - `allow`: policy grants it. When the rule has `approval = "ticket"`
//!   the answer carries a fresh `ticket` for exactly this call;
//! - `ask`: the rule has `approval = "human"` — get a ticket from
//!   `/v1/approve`.
//!
//! **Approve** re-runs the same evaluation (so an approval can't be
//! minted for a call policy denies), checks the approver's TOTP code
//! (`crate::approval::Approvals::verify_approver`), and mints an
//! `approval = "human"` ticket naming the approver: single-use for
//! exactly this call, or with `scope_minutes` (1–60) a multi-use ticket
//! for every call of the same agent, session, tool and host(s), whatever
//! the other arguments.
//!
//! Both are audited (`type: precheck` / `type: approve`), refusals and
//! wrong codes included. A minted ticket is recorded by its SHA-256,
//! never in clear.

use crate::approval::{Approvals, ApproveError};
use crate::audit::{self, Audit, Record};
use crate::authz::{self, Requirements};
use crate::caller;
use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::InventoryStore;
use crate::policy::{Approval, Enforcer};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// What the endpoints need.
#[derive(Clone)]
pub struct ApiState {
    pub store: InventoryStore,
    /// `None` with `PROMPTO_AUTH=off`: no policy, so nothing needs an
    /// approval.
    pub policy: Option<Enforcer>,
    pub approvals: Approvals,
    pub audit: Audit,
    pub kill: crate::kill::KillSwitch,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecheckRequest {
    pub tool: String,
    #[serde(default)]
    pub arguments: Option<Map<String, Value>>,
    #[serde(default)]
    pub session: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub tool: String,
    #[serde(default)]
    pub arguments: Option<Map<String, Value>>,
    #[serde(default)]
    pub session: Option<String>,
    pub approver: String,
    pub totp_code: String,
    #[serde(default)]
    pub scope_minutes: Option<u32>,
}

/// The outcome of authorizing a call without running it.
#[derive(Debug)]
enum Verdict {
    Deny(ClassifiedError),
    Allow {
        rule: Option<String>,
        /// The strictest approval the granting rules demand.
        required: Approval,
        /// A ticket in the arguments satisfied it.
        covered: bool,
    },
}

fn level(a: Approval) -> u8 {
    match a {
        Approval::None => 0,
        Approval::Ticket => 1,
        Approval::Human => 2,
    }
}

fn parse_approval(s: Option<&str>) -> Approval {
    match s {
        Some("human") => Approval::Human,
        Some("ticket") => Approval::Ticket,
        _ => Approval::None,
    }
}

/// Authorize `ctx.call` as its tool would, without running it.
fn evaluate(st: &ApiState, ctx: &CallCtx) -> Verdict {
    let call = ctx.call.as_ref().expect("evaluate needs the call");
    let (tool, args) = (call.tool.as_str(), &*call.args);
    let inv = st.store.snapshot();
    // Kill switches first, as on /mcp.
    let subject = crate::kill::Subject {
        agent: ctx.agent.as_ref().map(|a| a.name.as_str()),
        session: ctx.session_id.as_deref(),
        hosts: crate::kill::hosts_in(args, &inv),
    };
    if let Some(kill) = st.kill.check(&subject) {
        ctx.note(|n| n.kill = Some(kill.clone()));
        return Verdict::Deny(kill.refusal());
    }
    let Some(reqs) = authz::requirements(tool, args) else {
        return Verdict::Deny(ClassifiedError::refused(
            ErrorClass::InvalidArgs,
            format!("unknown tool {:?}", audit::clamp(tool, 64)),
        ));
    };
    let policy = st.policy.as_ref();
    let arg = |field: &str| {
        args.get(field)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                ClassifiedError::refused(
                    ErrorClass::InvalidArgs,
                    format!("missing string argument `{field}`"),
                )
            })
    };
    // Each authorization with what its granting rule demanded (policy
    // notes it on every decision).
    let mut results = Vec::new();
    let mut push = |r: Result<Option<String>, ClassifiedError>| {
        results.push((r, parse_approval(ctx.notes().approval)));
    };
    match reqs {
        Requirements::Hostless => push(authz::authorize_tool(policy, ctx, tool)),
        Requirements::Lookup(field) => match arg(field) {
            Ok(name) => push(authz::lookup(&inv, policy, ctx, tool, &name).map(|t| t.rule)),
            Err(e) => return Verdict::Deny(e),
        },
        Requirements::Hosts(list) => {
            for (field, need) in list {
                match arg(field) {
                    Ok(name) => {
                        push(authz::authorize(&inv, policy, ctx, tool, &name, need).map(|t| t.rule))
                    }
                    Err(e) => return Verdict::Deny(e),
                }
            }
        }
    }
    let (mut rule, mut required, mut uncovered) = (None, Approval::None, false);
    for (r, demanded) in results {
        let r = match r {
            Err(e) if e.class == ErrorClass::ApprovalRequired => {
                uncovered = true;
                e.rule
            }
            Err(e) => return Verdict::Deny(e),
            Ok(r) => r,
        };
        rule = rule.or(r);
        if level(demanded) > level(required) {
            required = demanded;
        }
    }
    Verdict::Allow {
        rule,
        required,
        covered: required != Approval::None && !uncovered,
    }
}

/// The call described by a request, as a context the gates understand.
fn call_ctx(
    headers: &HeaderMap,
    tool: &str,
    arguments: Option<Map<String, Value>>,
    session: Option<String>,
) -> Result<CallCtx, String> {
    let mut ctx = CallCtx::new(caller::current()).with_identity(crate::agent::current());
    ctx.user_agent = caller::user_agent();
    ctx.dry_run = true;
    if let Some(s) = session {
        let Some(s) = crate::agent::parse_session(&s) else {
            return Err("`session` must be 1-128 chars of A-Za-z0-9._:-".into());
        };
        let header = headers
            .get(crate::agent::SESSION_HEADER)
            .and_then(|v| v.to_str().ok());
        if header.is_some_and(|h| h != s) {
            return Err("`session` differs from the X-Prompto-Session header".into());
        }
        ctx.session_id = Some(s);
    }
    ctx.call = Some(audit::CallScope::new(tool, arguments));
    Ok(ctx)
}

fn bad_request(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}

/// The record for a precheck or an approval.
fn record(
    st: &ApiState,
    ctx: &CallCtx,
    kind: &'static str,
    decision: &'static str,
    error: Option<&ClassifiedError>,
) -> Record {
    let call = ctx.call.as_ref().expect("call");
    let mut rec = audit::tool_record(ctx, &call.tool, (*call.args).clone());
    rec.kind = kind;
    rec.decision = Some(decision);
    let inv = st.store.snapshot();
    let (host, _) = authz::bound_hosts(&call.tool, &call.args, None);
    (rec.host, rec.queried_as) = audit::resolve_host(&inv, host.as_deref());
    if call.tool == "rsync_sync" {
        let dest = call.args.get("dest_host").and_then(Value::as_str);
        (rec.dest_host, rec.dest_queried_as) = audit::resolve_host(&inv, dest);
    }
    rec.ok = error.is_none();
    rec.error_class = error.map(|e| e.class);
    rec.rule = error.and_then(|e| e.rule.clone()).or(rec.rule);
    rec
}

/// `POST /v1/precheck`.
pub async fn precheck(
    State(st): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<PrecheckRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return bad_request(e.body_text()),
    };
    let ctx = match call_ctx(&headers, &req.tool, req.arguments, req.session) {
        Ok(c) => c,
        Err(e) => return bad_request(e),
    };
    let request_id = ctx.request_id();
    let verdict = evaluate(&st, &ctx);
    let mut out = json!({ "request_id": request_id });
    let (decision, err, minted, rule) = match verdict {
        Verdict::Deny(e) => {
            out["error_class"] = e.class.as_str().into();
            out["reason"] = e.message.clone().into();
            ("deny", Some(e), None, None)
        }
        Verdict::Allow {
            rule,
            required,
            covered,
        } => {
            out["approval"] = required.as_str().into();
            if covered {
                out["reason"] = "the ticket in `arguments` is valid for this call".into();
                ("allow", None, None, rule)
            } else {
                match required {
                    Approval::None => {
                        out["reason"] = "policy grants this call; no approval needed".into();
                        ("allow", None, None, rule)
                    }
                    Approval::Ticket => match mint(&st, &ctx, Approval::Ticket, None, None) {
                        Ok((t, exp)) => {
                            out["reason"] = format!(
                                "rule {} grants this call with a ticket: pass it as the call's \
                                 `ticket` argument (single-use, expires in {} s)",
                                rule.as_deref().unwrap_or("-"),
                                crate::ticket::TTL_SECS
                            )
                            .into();
                            out["ticket"] = t.clone().into();
                            out["expires_at"] = exp.into();
                            ("allow", None, Some(t), rule)
                        }
                        Err(e) => {
                            out["error_class"] = e.class.as_str().into();
                            out["reason"] = e.message.clone().into();
                            (
                                "deny",
                                Some(e.with_rule(rule.clone().unwrap_or_default())),
                                None,
                                None,
                            )
                        }
                    },
                    Approval::Human => {
                        out["reason"] = format!(
                            "rule {} requires a human approval: POST /v1/approve with this call, \
                             the approver's name and their current TOTP code",
                            rule.as_deref().unwrap_or("-")
                        )
                        .into();
                        ("ask", None, None, rule)
                    }
                }
            }
        }
    };
    out["decision"] = decision.into();
    out["rule"] = rule
        .clone()
        .or_else(|| err.as_ref().and_then(|e| e.rule.clone()))
        .into();
    let mut rec = record(&st, &ctx, "precheck", decision, err.as_ref());
    if rule.is_some() {
        rec.rule = rule;
    }
    rec.ticket_sha256 = minted.as_deref().map(sha256_hex);
    rec.reason = out["reason"].as_str().map(str::to_string);
    st.audit.write(rec);
    (StatusCode::OK, Json(out)).into_response()
}

/// Mint for the call in `ctx`, after the audit gate. Returns the ticket
/// and its expiry.
fn mint(
    st: &ApiState,
    ctx: &CallCtx,
    approval: Approval,
    approved_by: Option<String>,
    scope: Option<u32>,
) -> Result<(String, u64), ClassifiedError> {
    let tool = ctx.call.as_ref().map_or("", |c| c.tool.as_str());
    st.audit.preflight(ctx, tool)?;
    let inv = st.store.snapshot();
    st.approvals
        .mint(Some(&inv), ctx, approval, approved_by, scope)
        .map(|(t, c)| (t, c.exp))
        .map_err(|e| {
            ClassifiedError::refused(ErrorClass::RefusedTicket, format!("refused_ticket: {e}"))
        })
}

fn sha256_hex(s: &str) -> String {
    crate::agent::hex(&crate::agent::sha256(s.as_bytes()))
}

/// `POST /v1/approve`.
pub async fn approve(
    State(st): State<ApiState>,
    headers: HeaderMap,
    body: Result<Json<ApproveRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return bad_request(e.body_text()),
    };
    let ctx = match call_ctx(&headers, &req.tool, req.arguments, req.session) {
        Ok(c) => c,
        Err(e) => return bad_request(e),
    };
    let approver = audit::clamp(&req.approver, 64);
    let request_id = ctx.request_id();
    let finish = |status: StatusCode,
                  decision: &'static str,
                  err: Option<ClassifiedError>,
                  rule: Option<String>,
                  minted: Option<(String, u64)>,
                  reason: String| {
        let mut rec = record(&st, &ctx, "approve", decision, err.as_ref());
        if rule.is_some() {
            rec.rule = rule.clone();
        }
        rec.approval = Some(Approval::Human.as_str());
        rec.approved_by = Some(approver.clone());
        rec.scope_minutes = req.scope_minutes;
        rec.ticket_sha256 = minted.as_ref().map(|(t, _)| sha256_hex(t));
        rec.reason = Some(reason.clone());
        st.audit.write(rec);
        let mut out = json!({
            "request_id": request_id,
            "decision": decision,
            "rule": rule,
            "reason": reason,
        });
        if let Some(e) = &err {
            out["error_class"] = e.class.as_str().into();
        }
        if let Some((t, exp)) = minted {
            out["ticket"] = t.into();
            out["expires_at"] = exp.into();
            out["approval"] = "human".into();
            out["approved_by"] = approver.clone().into();
            out["scoped"] = req.scope_minutes.is_some().into();
        }
        (status, Json(out)).into_response()
    };
    let refused = |class, msg: String| ClassifiedError::refused(class, msg);

    let (rule, required) = match evaluate(&st, &ctx) {
        Verdict::Deny(e) => {
            let (rule, msg) = (e.rule.clone(), e.message.clone());
            return finish(StatusCode::FORBIDDEN, "deny", Some(e), rule, None, msg);
        }
        Verdict::Allow { rule, required, .. } => (rule, required),
    };
    if required == Approval::None {
        let msg = format!(
            "no approval needed: rule {} grants this call without one",
            rule.as_deref().unwrap_or("-")
        );
        let e = refused(ErrorClass::InvalidArgs, msg.clone());
        return finish(StatusCode::CONFLICT, "allow", Some(e), rule, None, msg);
    }
    if let Some(m) = req.scope_minutes
        && (m == 0 || m > crate::ticket::MAX_SCOPE_MINUTES)
    {
        let msg = format!(
            "scope_minutes must be 1..={}",
            crate::ticket::MAX_SCOPE_MINUTES
        );
        let e = refused(ErrorClass::InvalidArgs, msg.clone());
        return finish(StatusCode::BAD_REQUEST, "deny", Some(e), rule, None, msg);
    }
    if req.scope_minutes.is_some() && ctx.session_id.is_none() {
        let msg = "a scoped approval needs a session (X-Prompto-Session or `session`): without \
                   one it would cover every session of the agent"
            .to_string();
        let e = refused(ErrorClass::InvalidArgs, msg.clone());
        return finish(StatusCode::BAD_REQUEST, "deny", Some(e), rule, None, msg);
    }
    if let Some(why) = st.approvals.unavailable() {
        let e = refused(ErrorClass::RefusedTicket, why.clone());
        return finish(
            StatusCode::SERVICE_UNAVAILABLE,
            "deny",
            Some(e),
            rule,
            None,
            why,
        );
    }
    if let Err(e) = st
        .approvals
        .verify_approver(&req.approver, &req.totp_code)
        .await
    {
        let (status, msg) = match e {
            ApproveError::Locked(name, until) => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "approver {name} is locked out after too many wrong codes, until {}",
                    chrono::DateTime::from_timestamp(until as i64, 0)
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default()
                ),
            ),
            ApproveError::Refused(why) => (StatusCode::FORBIDDEN, why),
            ApproveError::Unavailable(why) => (StatusCode::SERVICE_UNAVAILABLE, why),
        };
        let e = refused(ErrorClass::RefusedTicket, format!("refused_ticket: {msg}"));
        return finish(status, "deny", Some(e), rule, None, msg);
    }
    match mint(
        &st,
        &ctx,
        Approval::Human,
        Some(approver.clone()),
        req.scope_minutes,
    ) {
        Ok((t, exp)) => {
            let msg = match req.scope_minutes {
                Some(m) => format!(
                    "approved by {approver}: the ticket covers every {} call to the same \
                     host(s) in this session for {m} min, whatever the other arguments",
                    req.tool
                ),
                None => format!(
                    "approved by {approver}: pass the ticket as the call's `ticket` argument \
                     (single-use, expires in {} s)",
                    crate::ticket::TTL_SECS
                ),
            };
            tracing::info!(
                request_id = %ctx.request_id,
                agent = ctx.agent_name(),
                tool = %req.tool,
                approver = %approver,
                scope_minutes = req.scope_minutes,
                required = required.as_str(),
                "human approval granted"
            );
            finish(StatusCode::OK, "allow", None, rule, Some((t, exp)), msg)
        }
        Err(e) => {
            let msg = e.message.clone();
            finish(
                StatusCode::SERVICE_UNAVAILABLE,
                "deny",
                Some(e),
                rule,
                None,
                msg,
            )
        }
    }
}
