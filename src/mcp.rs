//! rmcp tool router for prompto. Every tool builds a [`CallCtx`], passes
//! [`Prompto::authorize`] (or `authorize_tool` when it targets no host,
//! `lookup` when it only reads the inventory) before touching anything,
//! returns `anyhow::Result<impl Serialize>`, and routes through
//! `finish_tool`, which records the gain event and the audit record
//! (`crate::audit`) and stamps the request ID on the result. Each gate
//! also asks the audit log whether it can record the call
//! ([`crate::audit::Audit::preflight`]), so in strict mode nothing runs
//! unaudited.

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mcp_gain::Tracker;

use crate::advisor::Advisor;
use crate::audit::{self, Audit};
use crate::authz::{self, Authorized, Need};
use crate::batch;
use crate::ctx::CallCtx;
use crate::diagnose;
use crate::error_class::{self, ClassifiedError, Classify, ErrorClass};
use crate::files;
use crate::filters::FilterChain;
use crate::host;
use crate::inventory::{Capability, HostConfig, InventoryStore};
use crate::policy::Visibility;
use crate::portscan;
use crate::rsync;
use crate::script;
use crate::ssh::SshClient;
use crate::systemd;
use crate::virt;

/// Refuse a systemd-only tool on a host that hasn't got systemd.
///
/// These tools are NOT adapted the way `file_stat`/`file_list` are:
/// launchd and rc.d are different service models, not different flags,
/// so a translation would be a guess dressed as support. Better to say
/// what's missing and point at the tool that does work.
fn require_systemd(
    host: &crate::inventory::HostConfig,
    name: &str,
    tool: &str,
) -> anyhow::Result<()> {
    if host.platform.has_systemd() {
        return Ok(());
    }
    let alt = match host.platform {
        crate::inventory::Platform::Macos => "launchctl",
        _ => "service(8) / rc.d",
    };
    crate::fail!(
        RefusedCapability,
        "{tool} drives systemd, and {name:?} is {} — no systemctl/journalctl there. \
         Use ssh_exec with {alt} instead.",
        host.platform.as_str()
    )
}

#[derive(Clone)]
pub struct Prompto {
    inv: InventoryStore,
    ssh: Arc<SshClient>,
    tracker: Arc<Tracker>,
    filters: Arc<FilterChain>,
    advisor: Arc<Advisor>,
    /// Source IP of the MCP client that opened this session, captured
    /// at session-init time from the axum middleware's task-local. Once
    /// rmcp spawns the per-session service (see rmcp 1.5
    /// `streamable_http_server::tower:657`), the task-local is gone —
    /// hence the eager snapshot. None on stdio / tests.
    caller_ip: Option<std::net::IpAddr>,
    /// Agent and session, snapshotted the same way from the auth
    /// middleware's task-local (`agent::current`). `local` on stdio.
    identity: crate::agent::Identity,
    /// Policy (`crate::policy`); `None` with `PROMPTO_AUTH=off`.
    policy: Option<crate::policy::Enforcer>,
    /// The audit log (`crate::audit`). [`Audit::null`] unless set.
    audit: Audit,
    /// The client's `User-Agent`, snapshotted like `caller_ip`.
    user_agent: Option<String>,
    /// Kill switches (`crate::kill`), checked before anything else on
    /// every call. The default paths unless set, so an instance built
    /// without [`Prompto::with_kill`] still honours `/etc/prompto/kill`.
    kill: crate::kill::KillSwitch,
    stop_vm_step: Duration,
    #[allow(dead_code)]
    tool_router: ToolRouter<Prompto>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostArgs {
    /// Host name as defined in the inventory (e.g. "gpu-rig").
    pub host: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VmArgs {
    /// Hypervisor host name in the inventory.
    pub host: String,
    /// libvirt domain name (alphanumerics + `-`, `_`, `.` only).
    pub vm: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VmStopArgs {
    pub host: String,
    pub vm: String,
    /// Per-step timeout in seconds for the dompmsuspend → shutdown → destroy
    /// chain. Defaults to the server's `PROMPTO_STOP_VM_STEP_SECS`.
    #[serde(default)]
    pub step_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VmEnsureUpArgs {
    pub host: String,
    pub vm: String,
    /// Total timeout (seconds) for the host-wake + vm-start sequence to
    /// succeed end-to-end. Defaults to 180.
    #[serde(default)]
    pub total_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    pub host: String,
    /// Command, interpreted by the remote shell.
    pub cmd: String,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BatchArgs {
    pub host: String,
    /// Shell commands to run in order. Each runs under `bash -c`
    /// (`sh -c` on FreeBSD hosts).
    pub commands: Vec<String>,
    /// Stop on first non-zero exit. Default true; skipped entries get exit_code=null.
    #[serde(default)]
    pub fail_fast: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GainArgs {
    /// Lookback window in seconds. Omit for all-time.
    #[serde(default)]
    pub since_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScriptExecArgs {
    pub host: String,
    /// Source code, piped via SSH stdin.
    pub script: String,
    /// Positional args (no whitespace, no shell metas).
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PathArgs {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RsyncSyncArgs {
    pub source_host: String,
    /// Trailing `/` matters: `/foo/` → contents, `/foo` → the dir.
    pub source_path: String,
    pub dest_host: String,
    pub dest_path: String,
    /// `-a` (archive). Default true.
    #[serde(default)]
    pub archive: Option<bool>,
    /// `--delete`. Default false.
    #[serde(default)]
    pub delete: Option<bool>,
    /// `--dry-run`. Default false.
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// `--exclude=PATTERN` values.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// Optional identity file for the source→dest hop, as a path ON THE
    /// SOURCE HOST. Omit to let the source host pick (its ~/.ssh/config,
    /// default keys, agent) — correct for hosts that already trust each
    /// other. This is NOT prompto's key path; prompto's keys do not exist
    /// on the source box.
    #[serde(default)]
    pub dest_key: Option<String>,
    /// Default 300s.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PortScanArgs {
    pub host: String,
    pub ports: Vec<u16>,
    /// Per-port budget (ms). Default 500, clamped 50..5000.
    #[serde(default)]
    pub probe_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InventoryHostNameArgs {
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceControlArgs {
    pub host: String,
    pub unit: String,
    /// start | stop | restart | reload | enable | disable | status | is-active | is-enabled.
    pub action: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileReadArgs {
    pub host: String,
    /// No shell metas, no whitespace.
    pub path: String,
    /// Default 64 KB, clamped to 1 MB.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileWriteArgs {
    pub host: String,
    pub path: String,
    /// Piped via SSH stdin (no shell quoting).
    pub content: String,
    /// Octal mode applied via chmod after write.
    #[serde(default)]
    pub mode: Option<String>,
    /// Write as root (needs `sudo_exec`). Default false.
    #[serde(default)]
    pub sudo: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceLogsArgs {
    pub host: String,
    pub unit: String,
    /// Default 50, clamped 1..1000.
    #[serde(default)]
    pub lines: Option<u32>,
}

#[derive(Serialize)]
struct WakeResult {
    host: String,
    sent_to_mac: String,
}

#[derive(Serialize)]
struct ScriptExecResult {
    stdout: String,
    stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    timed_out: bool,
    /// `true` if stderr was compacted from a longer trace.
    stderr_compacted: bool,
    original_stderr_bytes: usize,
    final_stderr_bytes: usize,
}

#[derive(Serialize)]
struct FilteredExecOutput {
    stdout: String,
    stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    timed_out: bool,
    /// Name of the filter that compacted stdout, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<&'static str>,
    /// Original stdout byte count before filtering. Equal to the filtered
    /// count when no filter applied.
    original_bytes: usize,
    filtered_bytes: usize,
}

#[derive(Serialize)]
struct VmEnsureUpResult {
    host_wake: bool,
    vm_started: bool,
    final_vm_state: String,
}

#[tool_router]
impl Prompto {
    pub fn new(
        inv: InventoryStore,
        ssh: Arc<SshClient>,
        tracker: Arc<Tracker>,
        stop_vm_step: Duration,
    ) -> Self {
        Self::new_with_caller(
            inv,
            ssh,
            tracker,
            Arc::new(FilterChain::default()),
            Arc::new(Advisor::new()),
            stop_vm_step,
            None,
        )
    }

    /// Variant of [`new`] that captures the MCP caller's source IP and
    /// takes process-wide shared state.
    ///
    /// Used by the streamable-http transport factory closure. rmcp 3.x
    /// calls the factory **once per request** (inline in the request
    /// future, before any `tokio::spawn`), which is why the caller IP
    /// can still be read from the axum task-local here and snapshotted
    /// onto the instance.
    ///
    /// It is also why `filters` and `advisor` are passed in rather than
    /// constructed here. The advisor's whole job is to notice patterns
    /// **across** recent calls; a fresh one per request would hold an
    /// empty ring buffer and never fire a single hint. Building the
    /// 30-filter chain per request would also be pure waste. This is
    /// the "persistent state must live outside the handler" rule from
    /// the rmcp 3.0 notes, applied.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_caller(
        inv: InventoryStore,
        ssh: Arc<SshClient>,
        tracker: Arc<Tracker>,
        filters: Arc<FilterChain>,
        advisor: Arc<Advisor>,
        stop_vm_step: Duration,
        caller_ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            inv,
            ssh,
            tracker,
            filters,
            advisor,
            caller_ip,
            identity: Default::default(),
            policy: None,
            audit: Audit::null(),
            user_agent: None,
            kill: Default::default(),
            stop_vm_step,
            tool_router: Self::tool_router(),
        }
    }

    /// Set the caller's identity (agent + session) for every call made
    /// through this instance.
    pub fn with_identity(mut self, identity: crate::agent::Identity) -> Self {
        self.identity = identity;
        self
    }

    /// Enforce `policy` on every call made through this instance (`None`:
    /// policy off).
    pub fn with_policy(mut self, policy: Option<crate::policy::Enforcer>) -> Self {
        self.policy = policy;
        self
    }

    /// Record every call made through this instance in `audit`.
    pub fn with_audit(mut self, audit: Audit) -> Self {
        self.audit = audit;
        self
    }

    /// Check these kill switches (`crate::kill`) on every call.
    pub fn with_kill(mut self, kill: crate::kill::KillSwitch) -> Self {
        self.kill = kill;
        self
    }

    /// The client's `User-Agent`, for the audit record.
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Names of every tool this server exposes.
    pub fn tool_names() -> Vec<String> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    /// Every tool's name and input schema (`tools/list`'s `inputSchema`),
    /// in the router's order.
    pub fn tool_schemas() -> Vec<(String, serde_json::Value)> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|t| {
                let schema = serde_json::Value::Object((*t.input_schema).clone());
                (t.name.to_string(), schema)
            })
            .collect()
    }

    /// Run the filter chain on an `ExecOutput.stdout` and bundle the
    /// result into a serializable shape the MCP tool returns.
    fn apply_filters(&self, cmd: &str, raw: crate::ssh::ExecOutput) -> FilteredExecOutput {
        let (stdout, report) = self.filters.apply(cmd, &raw.stdout);
        FilteredExecOutput {
            stdout: stdout.into_owned(),
            stderr: raw.stderr,
            exit_code: raw.exit_code,
            timed_out: raw.timed_out,
            filter: report.applied,
            original_bytes: report.original_bytes,
            filtered_bytes: report.filtered_bytes,
        }
    }

    /// A fresh [`CallCtx`] for one tool call: new request ID, this
    /// instance's caller IP and identity, clock started.
    fn new_ctx(&self) -> CallCtx {
        let mut ctx = CallCtx::new(self.caller_ip).with_identity(self.identity.clone());
        ctx.user_agent = self.user_agent.clone();
        ctx.call = audit::current_call();
        if let Some(c) = &ctx.call {
            c.set_ctx(&ctx);
        }
        ctx
    }

    /// After a gate let a call through: note it for the record, and in
    /// strict mode refuse it unless the audit log can record it.
    fn passed(&self, ctx: &CallCtx, tool: &str, rule: Option<&str>) -> Result<(), ClassifiedError> {
        self.audit.preflight(ctx, tool)?;
        ctx.note(|n| {
            n.authorized = true;
            if n.rule.is_none() {
                n.rule = rule.map(str::to_string);
            }
        });
        Ok(())
    }

    /// The single authorization gate for a tool call that targets a host:
    /// existence, capability, self-target guard, policy, and (later)
    /// ticket. See [`authz::authorize`].
    pub fn authorize(
        &self,
        ctx: &CallCtx,
        tool: &str,
        host: &str,
        need: Need,
    ) -> Result<Authorized, ClassifiedError> {
        let target = authz::authorize(
            &self.inv.snapshot(),
            self.policy.as_ref(),
            ctx,
            tool,
            host,
            need,
        )?;
        self.passed(ctx, tool, target.rule.as_deref())?;
        Ok(target)
    }

    /// The gate for a tool that reads a host's inventory entry and never
    /// contacts it. See [`authz::lookup`].
    fn lookup(&self, ctx: &CallCtx, tool: &str, host: &str) -> Result<Authorized, ClassifiedError> {
        let target = authz::lookup(&self.inv.snapshot(), self.policy.as_ref(), ctx, tool, host)?;
        self.passed(ctx, tool, target.rule.as_deref())?;
        Ok(target)
    }

    /// What the inventory tools may show this caller of `host`: all of it
    /// with policy off.
    fn visibility(&self, ctx: &CallCtx, name: &str, host: &HostConfig) -> Visibility {
        match &self.policy {
            None => Visibility {
                listed: true,
                sudo: true,
            },
            Some(p) => {
                static TOOLS: OnceLock<Vec<String>> = OnceLock::new();
                let tools = TOOLS.get_or_init(Self::tool_names);
                let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
                p.visibility(ctx, (name, host), &tools)
            }
        }
    }

    /// The gate for a tool that targets no host. See
    /// [`authz::authorize_tool`].
    fn authorize_tool(&self, ctx: &CallCtx, tool: &str) -> Result<(), ClassifiedError> {
        let rule = authz::authorize_tool(self.policy.as_ref(), ctx, tool)?;
        self.passed(ctx, tool, rule.as_deref())
    }

    /// Finalise a tool call. The single emission point for every call's
    /// outcome: records the gain-tracker event and the audit record,
    /// stamps the request ID on the result — success and error alike —
    /// and converts `anyhow::Result<T>` to what rmcp expects.
    fn finish_tool<T: serde::Serialize>(
        &self,
        ctx: &CallCtx,
        tool: &'static str,
        host: Option<&str>,
        res: anyhow::Result<T>,
    ) -> Result<CallToolResult, McpError> {
        let exec_ms = ctx.started.elapsed().as_millis() as u64;
        let hint = self.advisor.record(tool, host);
        let request_id = ctx.request_id();
        match res {
            Ok(v) => {
                let payload = serde_json::to_value(&v).unwrap_or_default();
                let verdict = self.judge(ctx, tool, &audit::Outcome::Success(&payload));
                let payload = with_error_class(payload, verdict.error_class);
                let mut blocks = success_blocks(payload, &request_id);
                let bytes = blocks.iter().map(|b| b.len()).sum::<usize>();
                self.tracker.record(tool, host, true, exec_ms, bytes as u64);
                self.audit_record(ctx, tool, host, verdict, bytes as u64);
                if let Some(h) = hint {
                    blocks.push(format!("[advisor] {h}"));
                }
                Ok(CallToolResult::success(
                    blocks.into_iter().map(ContentBlock::text).collect(),
                ))
            }
            Err(e) => {
                let classified = e.downcast_ref::<ClassifiedError>();
                let (msg, data) = error_parts(&e, classified, &request_id);
                self.tracker
                    .record(tool, host, false, exec_ms, msg.len() as u64);
                let verdict = self.judge(ctx, tool, &audit::Outcome::Failure(&e));
                self.audit_record(ctx, tool, host, verdict, msg.len() as u64);
                // mcp-gain's Event has no room for a class, so a
                // classified failure is also logged here, for journald.
                if let Some(c) = classified {
                    tracing::warn!(
                        request_id,
                        agent = ctx.agent_name(),
                        session_id = ctx.session_id.as_deref(),
                        tool,
                        host,
                        error_class = c.class.as_str(),
                        exit_code = c.exit_code,
                        rule = c.rule.as_deref(),
                        "tool call failed"
                    );
                }
                Err(McpError::internal_error(msg, Some(data)))
            }
        }
    }

    /// The audit verdict on a call's outcome.
    fn judge(&self, ctx: &CallCtx, tool: &str, outcome: &audit::Outcome) -> audit::Verdict {
        let args = ctx.call.as_ref().map(|c| c.args.clone());
        // Did it run through prompto's sudo path (for `sudo_guard`)?
        let sudo = authz::ROOT_TOOLS.contains(&tool)
            || args.as_ref().and_then(|a| a.get("sudo")) == Some(&serde_json::Value::Bool(true));
        audit::judge(tool, outcome, &ctx.notes(), sudo)
    }

    /// Write the call's audit record. `host` is what the caller typed;
    /// the record resolves it against the live inventory.
    fn audit_record(
        &self,
        ctx: &CallCtx,
        tool: &str,
        host: Option<&str>,
        verdict: audit::Verdict,
        bytes: u64,
    ) {
        let args = ctx
            .call
            .as_ref()
            .map(|c| (*c.args).clone())
            .unwrap_or(serde_json::Value::Null);
        let inv = self.inv.snapshot();
        let mut rec = audit::tool_record(ctx, tool, args.clone()).with_verdict(verdict);
        (rec.host, rec.queried_as) = audit::resolve_host(&inv, host);
        if tool == "rsync_sync" {
            let dest = args.get("dest_host").and_then(|v| v.as_str());
            (rec.dest_host, rec.dest_queried_as) = audit::resolve_host(&inv, dest);
        }
        rec.bytes = bytes;
        self.audit.write(rec);
        if let Some(c) = &ctx.call {
            c.mark_recorded();
        }
    }

    /// The kill switch that stops this call, if any (`crate::kill`).
    fn killed(&self, call: &audit::CallScope) -> Option<crate::kill::Kill> {
        let hosts = crate::kill::hosts_in(&call.args, &self.inv.snapshot());
        self.kill.check(&crate::kill::Subject {
            agent: self.identity.agent.as_ref().map(|a| a.name.as_str()),
            session: self.identity.session_id.as_deref(),
            hosts,
        })
    }

    /// Refuse a call stopped by a kill switch: before anything else ran
    /// (no audit preflight — a broken log must not stop a kill), recorded
    /// like any refusal, class `killed`, with the switch in the record.
    fn refuse_killed(
        &self,
        call: &audit::CallScope,
        kill: crate::kill::Kill,
    ) -> Result<CallToolResponse, McpError> {
        let mut ctx = self.new_ctx();
        ctx.call = Some(call.clone());
        ctx.note(|n| n.kill = Some(kill.clone()));
        let err = anyhow::Error::new(kill.refusal());
        let request_id = ctx.request_id();
        let (msg, data) = error_parts(&err, err.downcast_ref(), &request_id);
        let host = record_host(&call.args);
        tracing::warn!(
            request_id,
            agent = ctx.agent_name(),
            session_id = ctx.session_id.as_deref(),
            tool = %call.tool,
            host = host.as_deref(),
            kill_scope = kill.scope.as_str(),
            kill_target = kill.target.as_deref(),
            error_class = ErrorClass::Killed.as_str(),
            "tool call refused by a kill switch"
        );
        self.tracker.record(
            &call.tool,
            host.as_deref(),
            false,
            ctx.started.elapsed().as_millis() as u64,
            msg.len() as u64,
        );
        let verdict = audit::judge(
            &call.tool,
            &audit::Outcome::Failure(&err),
            &ctx.notes(),
            false,
        );
        self.audit_record(&ctx, &call.tool, host.as_deref(), verdict, msg.len() as u64);
        Err(McpError::internal_error(msg, Some(data)))
    }

    /// Record a call no handler recorded: its arguments did not parse, it
    /// named no tool, or (`res` is `None`) it never finished — dropped
    /// mid-way by a client that went away, a panic or a shutdown
    /// (`aborted`). One record per call, always.
    fn audit_unrouted(
        &self,
        call: &audit::CallScope,
        res: Option<&Result<CallToolResponse, McpError>>,
    ) {
        let mut ctx = call.handler_ctx().unwrap_or_else(|| self.new_ctx());
        ctx.call = Some(call.clone());
        // rmcp answers bad arguments with an error *result*, and an
        // unknown tool with an error.
        let rejected = match res {
            None => None,
            Some(Err(e)) => Some(e.message.to_string()),
            Some(Ok(CallToolResponse::Complete(r))) if r.is_error == Some(true) => Some(
                r.content
                    .first()
                    .and_then(|c| c.as_text())
                    .map(|t| t.text.clone())
                    .unwrap_or_default(),
            ),
            Some(Ok(_)) => None,
        };
        let (class, msg) = match (res, rejected) {
            (None, _) => {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    agent = ctx.agent_name(),
                    tool = %call.tool,
                    "tool call aborted before it finished (client gone, cancelled, panic or \
                     shutdown); recorded as aborted"
                );
                (
                    ErrorClass::Aborted,
                    String::from("the call was aborted before it finished"),
                )
            }
            (_, Some(m)) => (ErrorClass::InvalidArgs, m),
            // A handler that returned without `finish_tool` is a bug.
            (_, None) => {
                error_class::note_unclassified();
                tracing::error!(tool = %call.tool, "BUG: tool returned without an audit record");
                (
                    ErrorClass::Internal,
                    String::from("tool returned without an audit record"),
                )
            }
        };
        let err = anyhow::Error::new(ClassifiedError::refused(class, msg.clone()));
        let verdict = audit::judge(
            &call.tool,
            &audit::Outcome::Failure(&err),
            &ctx.notes(),
            false,
        );
        let host = record_host(&call.args);
        let bytes = if res.is_some() { msg.len() as u64 } else { 0 };
        // The record clamps the name (`Record::clamp_strings`).
        self.audit_record(&ctx, &call.tool, host.as_deref(), verdict, bytes);
    }

    #[tool(description = "Wake a host via WOL magic packet.")]
    async fn host_wake(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "host_wake", &args.host, Need::Cap(Capability::Wake))?;
            let host = &target.host;
            host::wake(host).await?;
            Ok(WakeResult {
                host: args.host.clone(),
                sent_to_mac: host.mac.clone().unwrap_or_default(),
            })
        }
        .await;
        self.finish_tool(&ctx, "host_wake", Some(&host_name), res)
    }

    #[tool(description = "TCP-probe a host's SSH port. Returns up | unreachable | off.")]
    async fn host_status(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(&ctx, "host_status", &args.host, Need::Exists)?;
            let host = &target.host;
            host::status(host, Duration::from_secs(2)).await
        }
        .await;
        self.finish_tool(&ctx, "host_status", Some(&host_name), res)
    }

    #[tool(description = "Shutdown a host (`shutdown -h now` as root).")]
    async fn host_sleep(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "host_sleep",
                &args.host,
                Need::Cap(Capability::SudoExec),
            )?;
            let host = &target.host;
            host::sleep(&self.ssh, &ctx, host).await?;
            Ok(serde_json::json!({ "host": host_name, "sent": "shutdown -h now" }))
        }
        .await;
        self.finish_tool(&ctx, "host_sleep", Some(&args.host), res)
    }

    #[tool(description = "List libvirt domains on a host (`virsh list --all`).")]
    async fn vm_list(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "vm_list", &args.host, Need::Cap(Capability::Virt))?;
            let host = &target.host;
            virt::list(&self.ssh, &ctx, host).await
        }
        .await;
        self.finish_tool(&ctx, "vm_list", Some(&host_name), res)
    }

    #[tool(
        description = "Get libvirt domain state (`virsh domstate`): running | shut off | pmsuspended | …"
    )]
    async fn vm_state(
        &self,
        Parameters(args): Parameters<VmArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "vm_state", &args.host, Need::Cap(Capability::Virt))?;
            let host = &target.host;
            let s = virt::domstate(&self.ssh, &ctx, host, &args.vm).await?;
            Ok(serde_json::json!({ "host": args.host, "vm": args.vm, "state": s }))
        }
        .await;
        self.finish_tool(&ctx, "vm_state", Some(&host_name), res)
    }

    #[tool(description = "Start a libvirt domain (`virsh start`).")]
    async fn vm_start(
        &self,
        Parameters(args): Parameters<VmArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "vm_start", &args.host, Need::Cap(Capability::Virt))?;
            let host = &target.host;
            let out = virt::start(&self.ssh, &ctx, host, &args.vm).await?;
            Ok(serde_json::json!({ "host": args.host, "vm": args.vm, "stdout": out }))
        }
        .await;
        self.finish_tool(&ctx, "vm_start", Some(&host_name), res)
    }

    #[tool(
        description = "Stop a libvirt domain via dompmsuspend → shutdown → destroy fallback chain."
    )]
    async fn vm_stop(
        &self,
        Parameters(args): Parameters<VmStopArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let step = args
            .step_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.stop_vm_step);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "vm_stop", &args.host, Need::Cap(Capability::Virt))?;
            let host = &target.host;
            virt::stop(&self.ssh, &ctx, host, &args.vm, step).await
        }
        .await;
        self.finish_tool(&ctx, "vm_stop", Some(&host_name), res)
    }

    #[tool(
        description = "Wake host (if down) + start VM (if not running) + wait for SSH-ready. One call before issuing VM work."
    )]
    async fn vm_ensure_up(
        &self,
        Parameters(args): Parameters<VmEnsureUpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let total = Duration::from_secs(args.total_timeout_secs.unwrap_or(180));
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "vm_ensure_up",
                &args.host,
                Need::Cap(Capability::Virt),
            )?;
            let host = &target.host;
            // Every authorization runs before the first probe. Wake is only
            // needed if the host turns out to be down, so its verdict is
            // held and enforced then: a host without `wake` that is already
            // up keeps working, but nothing touches the network until all
            // the checks have run.
            let wake_auth = self.authorize(
                &ctx,
                "vm_ensure_up",
                &args.host,
                Need::Cap(Capability::Wake),
            );

            let initial = host::status(host, Duration::from_secs(2)).await?;
            let mut woke = false;
            if initial.state != "up" {
                wake_auth?;
                host::wake(host).await?;
                woke = true;
                host::wait_until_up(host, total).await?;
            }

            let state_before = virt::domstate(&self.ssh, &ctx, host, &args.vm).await?;
            let mut started_vm = false;
            if state_before != "running" {
                let _ = virt::start(&self.ssh, &ctx, host, &args.vm).await?;
                started_vm = true;
            }
            let state_after = virt::domstate(&self.ssh, &ctx, host, &args.vm).await?;

            Ok(VmEnsureUpResult {
                host_wake: woke,
                vm_started: started_vm,
                final_vm_state: state_after,
            })
        }
        .await;
        self.finish_tool(&ctx, "vm_ensure_up", Some(&host_name), res)
    }

    #[tool(
        description = "Run a command on a host over SSH. Returns stdout/stderr/exit. stdout passes through a 26-filter chain (cargo, git, journalctl, find, pkg, k8s, …) that names the applied filter in the response. For N commands on the same host, prefer ssh_batch."
    )]
    async fn ssh_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "ssh_exec", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = self.ssh.exec(&ctx, host, &args.cmd, to, false).await?;
            Ok(self.apply_filters(&args.cmd, raw))
        }
        .await;
        self.finish_tool(&ctx, "ssh_exec", Some(&host_name), res)
    }

    #[tool(
        description = "Run N commands on one host in a single SSH session. PREFER OVER repeated ssh_exec for same-host sequences (snapshot destroys, service restarts, fan-out checks) — saves N-1 round trips and the conversation accumulation cost. Returns per-command exit/output/timing. fail_fast (default true) skips remaining on first failure. Keep commands tight; batch stdout is not filter-chained."
    )]
    async fn ssh_batch(
        &self,
        Parameters(args): Parameters<BatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            if args.commands.is_empty() {
                crate::fail!(InvalidArgs, "commands list is empty");
            }
            let target =
                self.authorize(&ctx, "ssh_batch", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            // The batch wire protocol needs a POSIX shell: bash on Linux
            // and macOS, /bin/sh on FreeBSD. Without one the remote shell
            // mangles the script and the failure surfaces as "missing
            // record for command 0", which blames the protocol rather
            // than the absent shell. Say the real thing instead.
            let Some(driver) = batch::Driver::for_platform(host.platform) else {
                crate::fail!(
                    RefusedCapability,
                    "ssh_batch needs a POSIX shell, and {:?} is {}. \
                     Use ssh_exec instead, one call per command.",
                    args.host,
                    host.platform.as_str()
                );
            };
            let fail_fast = args.fail_fast.unwrap_or(true);
            let n = args.commands.len() as u64;
            let to = args
                .timeout_secs
                .map(Duration::from_secs)
                .or_else(|| Some(self.ssh.default_timeout * n.max(1) as u32));
            let script = driver.script(&args.commands, fail_fast);
            let raw = self
                .ssh
                .exec_stdin(
                    &ctx,
                    host,
                    driver.remote_cmd(),
                    script.as_bytes(),
                    to,
                    false,
                )
                .await?;
            if raw.timed_out {
                crate::fail!(Timeout, "batch timed out (>{:?})", to.unwrap_or_default());
            }
            // ssh itself failed: no batch ran, so say that rather than
            // "missing record for command 0".
            if let Some(class @ (ErrorClass::SshConnect | ErrorClass::SshAuth)) =
                crate::error_class::classify_exec(&raw, false)
            {
                return Err(ClassifiedError {
                    class,
                    exit_code: raw.exit_code,
                    stderr_tail: Some(crate::error_class::stderr_tail(&raw.stderr)),
                    message: "ssh_batch: ssh failed before the batch ran".into(),
                    rule: None,
                }
                .into());
            }
            let parsed = batch::parse_output(&raw.stdout, &args.commands)?;
            Ok(parsed)
        }
        .await;
        self.finish_tool(&ctx, "ssh_batch", Some(&host_name), res)
    }

    #[tool(
        description = "List a directory on a remote host (a symlink to a directory lists the directory). Returns parsed { name, mode, size, owner, group, mtime, is_dir, is_link } plus, when set, link_target, device, xattrs, acl, security_context; lines that could not be parsed come back in `unparsed`."
    )]
    async fn file_list(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "file_list", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            files::validate_path(&args.path)?;
            let cmd = files::ls_command(host.platform, &args.path);
            let raw = self
                .ssh
                .exec(&ctx, host, &cmd, Some(Duration::from_secs(10)), false)
                .await?;
            if !raw.ok() {
                return Err(crate::error_class::ClassifiedError::exec_failure(
                    &raw,
                    false,
                    format!(
                        "ls failed (exit={:?}): {}",
                        raw.exit_code,
                        raw.stderr.trim()
                    ),
                )
                .into());
            }
            let listing = files::parse_ls(host.platform, &raw.stdout);
            let mut out = serde_json::json!({
                "host": args.host,
                "path": args.path,
                "count": listing.entries.len(),
                "entries": listing.entries,
            });
            // Lines that weren't entries are returned, never dropped.
            if listing.unparsed_count > 0 {
                out["unparsed"] = serde_json::json!(listing.unparsed);
                out["unparsed_count"] = serde_json::json!(listing.unparsed_count);
            }
            Ok(out)
        }
        .await;
        self.finish_tool(&ctx, "file_list", Some(&host_name), res)
    }

    #[tool(
        description = "Stat a remote file. Returns typed { path, mode (octal), size, owner, group, mtime, kind }."
    )]
    async fn file_stat(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "file_stat", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            files::validate_path(&args.path)?;
            let cmd = files::stat_command(host.platform, &args.path);
            let raw = self
                .ssh
                .exec(&ctx, host, &cmd, Some(Duration::from_secs(10)), false)
                .await?;
            if !raw.ok() {
                return Err(crate::error_class::ClassifiedError::exec_failure(
                    &raw,
                    false,
                    format!(
                        "stat failed (exit={:?}): {}",
                        raw.exit_code,
                        raw.stderr.trim()
                    ),
                )
                .into());
            }
            let parsed = files::parse_stat(&raw.stdout);
            Ok(serde_json::json!({
                "host": args.host,
                "stat": parsed,
                "raw": raw.stdout,
            }))
        }
        .await;
        self.finish_tool(&ctx, "file_stat", Some(&host_name), res)
    }

    #[tool(description = "List inventory hosts with their capabilities. Read-only.")]
    async fn inventory_list(&self) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let res: anyhow::Result<_> = async {
            self.authorize_tool(&ctx, "inventory_list")?;
            let inv = self.inv.snapshot();
            let hosts: Vec<serde_json::Value> = inv
                .hosts
                .iter()
                .filter_map(|(name, h)| {
                    // With policy on: only hosts the agent has a grant on.
                    let seen = self.visibility(&ctx, name, h);
                    if !seen.listed {
                        return None;
                    }
                    let mut v = serde_json::json!({
                        "name": name,
                        "ip": h.ip,
                        "mac": h.mac,
                        "ssh_user": h.ssh_user,
                        "ssh_port": h.ssh_port,
                        "platform": h.platform.as_str(),
                        "chassis": h.chassis.as_str(),
                        "aliases": h.aliases,
                        "sudo_password_vault_path": h.sudo_password_vault_path,
                        "hypervisor": h.hypervisor,
                        "request_id_env": h.request_id_env().as_str(),
                        "extra_ips": h.extra_ips,
                        "capabilities": h.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    });
                    with_groups(&mut v, &h.groups);
                    hide_vault_path(&mut v, seen);
                    Some(v)
                })
                .collect();
            Ok(serde_json::json!({
                "count": hosts.len(),
                "hosts": hosts,
            }))
        }
        .await;
        self.finish_tool(&ctx, "inventory_list", None, res)
    }

    #[tool(description = "Get one host's inventory config (ssh_key path elided).")]
    async fn inventory_get_host(
        &self,
        Parameters(args): Parameters<InventoryHostNameArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            let target = self.lookup(&ctx, "inventory_get_host", &args.name)?;
            let h = &target.host;
            // Report the canonical name, not whatever the caller typed —
            // asking for an alias and being told it IS that host hides
            // the indirection. `queried_as` shows up only when they differ.
            let canon = target.canonical.clone();
            let queried_as = (canon != args.name).then(|| args.name.clone());
            let mut v = serde_json::json!({
                "name": canon,
                "queried_as": queried_as,
                "ip": h.ip,
                "mac": h.mac,
                "ssh_user": h.ssh_user,
                "ssh_port": h.ssh_port,
                "platform": h.platform.as_str(),
                "chassis": h.chassis.as_str(),
                "aliases": h.aliases,
                "sudo_password_vault_path": h.sudo_password_vault_path,
                "hypervisor": h.hypervisor,
                "request_id_env": h.request_id_env().as_str(),
                "extra_ips": h.extra_ips,
                "capabilities": h.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            });
            with_groups(&mut v, &h.groups);
            hide_vault_path(&mut v, self.visibility(&ctx, &canon, h));
            Ok(v)
        }
        .await;
        self.finish_tool(&ctx, "inventory_get_host", Some(&host_name), res)
    }

    #[tool(
        description = "rsync files between two inventory hosts in one call. PREFER OVER N×file_write loops (~17K tokens vs ~150). PRECONDITION: the rsync runs ON source_host, so source_host must already be able to SSH to dest_host as its inventory ssh_user — prompto's own keys are not available there. Optional dest_key names an identity file on source_host. Trailing `/` on paths matters. Output is the --stats block. A failure names its cause as `[error_class=…]` (e.g. dest_ssh_auth = source_host can't log into dest_host) with rsync's exit code and stderr tail."
    )]
    async fn rsync_sync(
        &self,
        Parameters(args): Parameters<RsyncSyncArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.source_host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            // Both ends are guarded against self-targeting: prompto logs
            // into the source, and the dest receives files written as its
            // ssh_user — on the caller's own box that is the same sandbox
            // escape as file_write.
            let need = Need::Cap(Capability::Exec);
            let source = self.authorize(&ctx, "rsync_sync", &args.source_host, need)?;
            let dest = self.authorize(&ctx, "rsync_sync", &args.dest_host, need)?;
            let (source_host, dest_host) = (&source.host, &dest.host);
            let opts = rsync::RsyncOptions {
                archive: args.archive.unwrap_or(true),
                delete: args.delete.unwrap_or(false),
                dry_run: args.dry_run.unwrap_or(false),
                excludes: &args.excludes,
            };
            let raw = rsync::run(
                &self.ssh,
                &ctx,
                source_host,
                &args.source_path,
                dest_host,
                &args.dest_path,
                args.dest_key.as_deref(),
                &opts,
                to,
            )
            .await?;
            // Compact via the chain so the stats block is what comes back.
            let (stdout, report) = self.filters.apply("rsync", &raw.stdout);
            Ok(serde_json::json!({
                "source_host": args.source_host,
                "source_path": args.source_path,
                "dest_host": args.dest_host,
                "dest_path": args.dest_path,
                "stdout": stdout,
                "stderr": raw.stderr,
                "exit_code": raw.exit_code,
                "error_class": None::<ErrorClass>,
                "filter": report.applied,
                "original_bytes": report.original_bytes,
                "filtered_bytes": report.filtered_bytes,
            }))
        }
        .await;
        self.finish_tool(&ctx, "rsync_sync", Some(&host_name), res)
    }

    #[tool(
        description = "TCP-probe a list of ports on a host (no SSH). Returns per-port reachable + latency_ms."
    )]
    async fn port_scan(
        &self,
        Parameters(args): Parameters<PortScanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(&ctx, "port_scan", &args.host, Need::Exists)?;
            let host = &target.host;
            let probe = Duration::from_millis(args.probe_ms.unwrap_or(500).clamp(50, 5000));
            let mut results = Vec::with_capacity(args.ports.len());
            let ip = host.ip.to_string();
            for port in &args.ports {
                results.push(portscan::probe_one(&ip, *port, probe).await);
            }
            let reachable = results.iter().filter(|r| r.reachable).count();
            Ok(serde_json::json!({
                "host": args.host,
                "ip": host.ip,
                "total": args.ports.len(),
                "reachable": reachable,
                "results": results,
            }))
        }
        .await;
        self.finish_tool(&ctx, "port_scan", Some(&host_name), res)
    }

    #[tool(
        description = "Composite host health: uptime, load, mem (MB), disk, last-boot, kernel, listening ports (top 30), failed units. One round-trip; replaces ~5 ssh_exec calls."
    )]
    async fn host_diagnose(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "host_diagnose",
                &args.host,
                Need::Cap(Capability::Exec),
            )?;
            let host = &target.host;
            let raw = script::run(
                &self.ssh,
                &ctx,
                host,
                "bash",
                diagnose::DIAGNOSE_SCRIPT,
                &[],
                Some(Duration::from_secs(15)),
                false,
            )
            .await?;
            let report = diagnose::parse(&raw.stdout);
            Ok(serde_json::json!({
                "host": args.host,
                "report": report,
                "stderr": raw.stderr,
                "exit_code": raw.exit_code,
            }))
        }
        .await;
        self.finish_tool(&ctx, "host_diagnose", Some(&host_name), res)
    }

    #[tool(
        description = "Drive a systemd unit (start/stop/restart/reload/enable/disable/status/is-active/is-enabled). status output is auto-compacted (journal tail dropped — use service_logs for logs)."
    )]
    async fn service_control(
        &self,
        Parameters(args): Parameters<ServiceControlArgs>,
    ) -> Result<CallToolResult, McpError> {
        const ACTIONS: &[&str] = &[
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
            "status",
            "is-active",
            "is-enabled",
        ];
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            if !ACTIONS.contains(&args.action.as_str()) {
                crate::fail!(
                    InvalidArgs,
                    "action {:?} not in allow-list (allowed: {:?})",
                    args.action,
                    ACTIONS
                );
            }
            systemd::validate_unit_name(&args.unit)?;
            let target = self.authorize(
                &ctx,
                "service_control",
                &args.host,
                Need::Cap(Capability::SudoExec),
            )?;
            let host = &target.host;
            require_systemd(host, &args.host, "service_control")?;
            let cmd = format!("systemctl {} -- {}", args.action, args.unit);
            let raw = self
                .ssh
                .exec(&ctx, host, &cmd, Some(Duration::from_secs(15)), true)
                .await?;
            let stdout = if args.action == "status" {
                let (compacted, _report) = self.filters.apply("systemctl status", &raw.stdout);
                compacted.into_owned()
            } else {
                raw.stdout
            };
            Ok(serde_json::json!({
                "host": args.host,
                "unit": args.unit,
                "action": args.action,
                "exit_code": raw.exit_code,
                "stdout": stdout,
                "stderr": raw.stderr,
            }))
        }
        .await;
        self.finish_tool(&ctx, "service_control", Some(&host_name), res)
    }

    #[tool(
        description = "Read a remote file. max_bytes default 64 KB, clamped to 1 MB. Returns content + `truncated` flag."
    )]
    async fn file_read(
        &self,
        Parameters(args): Parameters<FileReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let max_bytes = args
            .max_bytes
            .unwrap_or(files::DEFAULT_READ_BYTES)
            .clamp(1, files::MAX_READ_BYTES);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "file_read", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = files::read(&self.ssh, &ctx, host, &args.path, max_bytes).await?;
            let bytes = raw.stdout.len();
            let truncated = bytes as u64 >= max_bytes;
            Ok(serde_json::json!({
                "host": args.host,
                "path": args.path,
                "content": raw.stdout,
                "bytes": bytes,
                "truncated": truncated,
                "max_bytes": max_bytes,
            }))
        }
        .await;
        self.finish_tool(&ctx, "file_read", Some(&host_name), res)
    }

    #[tool(
        description = "Write a remote file (content via SSH stdin, no shell quoting). Optional mode runs chmod after. sudo=true writes as root."
    )]
    async fn file_write(
        &self,
        Parameters(args): Parameters<FileWriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let sudo = args.sudo.unwrap_or(false);
        let res: anyhow::Result<_> = async {
            let cap = if sudo {
                Capability::SudoExec
            } else {
                Capability::Exec
            };
            let target = self.authorize(&ctx, "file_write", &args.host, Need::Cap(cap))?;
            let host = &target.host;
            files::write(
                &self.ssh,
                &ctx,
                host,
                &args.path,
                args.content.as_bytes(),
                sudo,
            )
            .await?;
            if let Some(mode) = &args.mode {
                files::chmod(&self.ssh, &ctx, host, &args.path, mode, sudo).await?;
            }
            Ok(serde_json::json!({
                "host": args.host,
                "path": args.path,
                "bytes_written": args.content.len(),
                "sudo": sudo,
                "mode": args.mode,
            }))
        }
        .await;
        self.finish_tool(&ctx, "file_write", Some(&host_name), res)
    }

    #[tool(description = "Run Bash on a remote host. Script body via SSH stdin.")]
    async fn bash_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "bash_exec", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = script::run(
                &self.ssh,
                &ctx,
                host,
                "bash",
                &args.script,
                &args.args,
                to,
                false,
            )
            .await?;
            let len = raw.stderr.len();
            Ok(ScriptExecResult {
                stdout: raw.stdout,
                stderr: raw.stderr,
                exit_code: raw.exit_code,
                timed_out: raw.timed_out,
                stderr_compacted: false,
                original_stderr_bytes: len,
                final_stderr_bytes: len,
            })
        }
        .await;
        self.finish_tool(&ctx, "bash_exec", Some(&host_name), res)
    }

    #[tool(
        description = "Run a command as root over SSH. The whole command runs as root, including every part of a compound command (`a; b`, pipes, redirects). Uses passwordless sudo (`sudo -n -- <cmd>` for a command of plain words, so narrow sudoers rules match; otherwise `sudo -n -- sh -s` with the command on stdin), or a vault-held sudo password when the host declares one (the password never reaches the caller; the command runs under a root sh). Same filter chain as ssh_exec."
    )]
    async fn ssh_sudo_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "ssh_sudo_exec",
                &args.host,
                Need::Cap(Capability::SudoExec),
            )?;
            let host = &target.host;
            let raw = self.ssh.exec(&ctx, host, &args.cmd, to, true).await?;
            Ok(self.apply_filters(&args.cmd, raw))
        }
        .await;
        self.finish_tool(&ctx, "ssh_sudo_exec", Some(&host_name), res)
    }

    #[tool(
        description = "Read logs for ANY systemd unit on a host — this is how you find out why something failed to start or crashed. Tails the journal (`journalctl -u <unit>`). lines default 50, clamped 1..1000. Pairs with service_control, which drives the unit. Requires sudo_exec."
    )]
    async fn service_logs(
        &self,
        Parameters(args): Parameters<ServiceLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let lines = args.lines.unwrap_or(50);
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "service_logs",
                &args.host,
                Need::Cap(Capability::SudoExec),
            )?;
            let host = &target.host;
            require_systemd(host, &args.host, "service_logs")?;
            let stdout = systemd::journalctl_tail(&self.ssh, &ctx, host, &args.unit, lines).await?;
            Ok(serde_json::json!({
                "host": args.host,
                "unit": args.unit,
                "lines": lines,
                "stdout": stdout,
            }))
        }
        .await;
        self.finish_tool(&ctx, "service_logs", Some(&host_name), res)
    }

    #[tool(
        description = "Token-savings analytics vs an SSH+bash baseline. Optional since_secs lookback. Returns total + per-tool breakdown."
    )]
    async fn prompto_gain(
        &self,
        Parameters(args): Parameters<GainArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let cutoff = args
            .since_secs
            .map(|s| chrono::Utc::now() - chrono::Duration::seconds(s as i64));
        let res = self
            .authorize_tool(&ctx, "prompto_gain")
            .map_err(anyhow::Error::from)
            .and_then(|()| self.tracker.summary(cutoff).class(ErrorClass::Internal));
        self.finish_tool(&ctx, "prompto_gain", None, res)
    }
}

/// Text blocks for a successful result, carrying `request_id`.
///
/// An object payload (every tool but `vm_list`) gains a `request_id`
/// field, appended so existing keys keep their order. Anything else — an
/// array, whose shape clients may depend on — is left untouched and the
/// ID follows in its own `[request_id=…]` block, like the advisor's.
/// Add a host's policy `groups` to its inventory view — only when it has
/// some, so an inventory without groups reads exactly as before E3.
/// Drop `sudo_password_vault_path` for a caller without a `sudo = true`
/// grant on the host. The key goes, rather than becoming `null`, which
/// would claim the host has no vault-held password.
fn hide_vault_path(v: &mut serde_json::Value, seen: Visibility) {
    if !seen.sudo
        && let Some(m) = v.as_object_mut()
    {
        m.remove("sudo_password_vault_path");
    }
}

fn with_groups(v: &mut serde_json::Value, groups: &[String]) {
    if !groups.is_empty() {
        v["groups"] = groups.into();
    }
}

/// An exec-style result — one carrying `exit_code`, `timed_out` or
/// (`ssh_batch`) `all_ok` — gets `error_class`: the audit record's class
/// for the call (`remote_nonzero`, `ssh_connect`, `timeout`, …), `null`
/// when the command succeeded. Same field and values as `rsync_sync`,
/// which sets its own. Additive: nothing else in the result changes.
fn with_error_class(
    mut payload: serde_json::Value,
    class: Option<ErrorClass>,
) -> serde_json::Value {
    if let serde_json::Value::Object(map) = &mut payload
        && ["exit_code", "timed_out", "all_ok"]
            .iter()
            .any(|k| map.contains_key(*k))
        && !map.contains_key("error_class")
    {
        map.insert("error_class".into(), serde_json::json!(class));
    }
    payload
}

fn success_blocks(payload: serde_json::Value, request_id: &str) -> Vec<String> {
    match payload {
        serde_json::Value::Object(mut map) => {
            map.insert("request_id".into(), request_id.into());
            vec![serde_json::Value::Object(map).to_string()]
        }
        other => vec![other.to_string(), format!("[request_id={request_id}]")],
    }
}

/// Message and `data` for a failed call.
///
/// The message leads with a bracketed prefix carrying the request ID —
/// merged with the class prefix when the error is classified
/// (`[request_id=… error_class=… exit=…] …`) — because not every client
/// shows `data` to the model. `data` always has `request_id`, plus the
/// classified fields when there are any.
fn error_parts(
    e: &anyhow::Error,
    classified: Option<&ClassifiedError>,
    request_id: &str,
) -> (String, serde_json::Value) {
    let msg = e.to_string();
    let Some(c) = classified else {
        return (
            format!("[request_id={request_id}] {msg}"),
            serde_json::json!({ "request_id": request_id }),
        );
    };
    let mut data = c.data();
    data["request_id"] = request_id.into();
    // Only splice into the class prefix when the classified error is what
    // the message shows; under added context it isn't, so prefix instead.
    let msg = if msg == c.to_string() {
        c.render(Some(request_id))
    } else {
        format!("[request_id={request_id}] {msg}")
    };
    (msg, data)
}

/// The host a record made from raw arguments names (`rsync_sync`'s
/// `dest_host` is added by `audit_record`).
fn record_host(args: &serde_json::Value) -> Option<String> {
    ["host", "source_host"]
        .iter()
        .find_map(|k| args.get(*k)?.as_str())
        .map(str::to_string)
}

/// Writes the `aborted` record of a call whose future is dropped before
/// it recorded anything (see `Prompto::audit_unrouted`).
struct AbortGuard<'a> {
    prompto: &'a Prompto,
    call: audit::CallScope,
}

impl Drop for AbortGuard<'_> {
    fn drop(&mut self) {
        if !self.call.recorded() {
            self.prompto.audit_unrouted(&self.call, None);
        }
    }
}

#[tool_handler]
impl ServerHandler for Prompto {
    /// rmcp's generated dispatch, inside an audit scope holding the raw
    /// call: `finish_tool` takes the record's arguments from it, and a
    /// call no handler recorded (arguments that don't parse, an unknown
    /// tool) is recorded here.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let call = audit::CallScope::new(&request.name, request.arguments.clone());
        // Kill switches come first, before rmcp even parses the arguments.
        if let Some(kill) = self.killed(&call) {
            return self.refuse_killed(&call, kill);
        }
        // Dropped before the end (cancelled, panicked, shut down): the
        // guard writes an `aborted` record.
        let _guard = AbortGuard {
            prompto: self,
            call: call.clone(),
        };
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let res = audit::scoped(call.clone(), self.tool_router.call(tcc)).await;
        if !call.recorded() {
            self.audit_unrouted(&call, Some(&res));
        }
        res
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            // Pinned deliberately — never ride `ProtocolVersion::LATEST`.
            // LATEST is not "the newest version rmcp knows": in 3.1.2 it
            // resolves to 2025-11-25 even though V_2026_07_28 exists, and
            // it moves silently between releases. This value is what
            // LATEST resolved to at the time of the rmcp 3 migration, so
            // pinning it is a no-op today and a guarantee tomorrow.
            // Clients newer or older than this still negotiate normally:
            // `supported_protocol_versions()` is left at its default of
            // ProtocolVersion::KNOWN_VERSIONS.
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_instructions(instructions().to_string())
    }
}

/// The advertised tool surface and usage notes handed to clients.
///
/// Split out of [`ServerHandler::get_info`] so `baselines.rs` can parse
/// the `Tools: …` list and assert every advertised tool has a gain
/// baseline — a tool with no entry silently records as pure cost.
pub const fn instructions() -> &'static str {
    "prompto — homelab power, libvirt and SSH exec over MCP. \
                 Tools: host_wake, host_sleep, host_status, host_diagnose, vm_list, vm_state, vm_start, vm_stop, vm_ensure_up, ssh_exec, ssh_batch, ssh_sudo_exec, bash_exec, file_read, file_write, file_list, file_stat, rsync_sync, port_scan, service_control, service_logs, inventory_list, inventory_get_host, prompto_gain. \
                 Prefer a typed tool (file_*, service_*, host_*, vm_*) over ssh_exec when one fits. \
                 Hosts are looked up by name in the server's inventory; every call is gated on the host's capabilities (`wake`, `exec`, `sudo_exec`, `virt`). Inventory is operator-managed — edit /etc/prompto.toml and SIGHUP to reload. \
                 vm_stop runs the dompmsuspend → shutdown → destroy fallback chain. \
                 prompto_gain returns the token-savings summary for this instance."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_payload_gains_a_trailing_request_id_field() {
        let b = success_blocks(serde_json::json!({ "a": 1, "z": 2 }), "RID");
        assert_eq!(b, vec![r#"{"a":1,"z":2,"request_id":"RID"}"#.to_string()]);
    }

    /// vm_list returns an array; wrapping it would change its shape for
    /// every client, so the ID rides in its own block instead.
    #[test]
    fn array_payload_keeps_its_shape() {
        let b = success_blocks(serde_json::json!([{ "name": "vm1" }]), "RID");
        assert_eq!(b[0], r#"[{"name":"vm1"}]"#);
        assert_eq!(b[1], "[request_id=RID]");
    }

    #[test]
    fn classified_error_under_context_is_prefixed_not_spliced() {
        let e = anyhow::Error::new(ClassifiedError::refused(ErrorClass::Timeout, "slow"))
            .context("outer");
        let c = e.downcast_ref::<ClassifiedError>();
        let (msg, data) = error_parts(&e, c, "RID");
        assert_eq!(msg, "[request_id=RID] outer");
        assert_eq!(data["error_class"], "timeout");
        assert_eq!(data["request_id"], "RID");
    }
}
