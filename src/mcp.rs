//! rmcp tool router for prompto. Every tool builds a [`CallCtx`], passes
//! [`Prompto::authorize`] (or `authz::authorize_tool` when it targets no
//! host, `authz::lookup` when it only reads the inventory) before
//! touching anything, returns `anyhow::Result<impl
//! Serialize>`, and routes through `finish_tool`, which records one event
//! per call and stamps the request ID on the result.

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use mcp_gain::Tracker;

use crate::advisor::Advisor;
use crate::apytti_client::{ApyttiClient, AskRequest as ApyttiAsk};
use crate::authz::{self, Authorized, Need};
use crate::batch;
use crate::claudemgr::{self, Scope};
use crate::ctx::CallCtx;
use crate::diagnose;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::files;
use crate::filters::FilterChain;
use crate::host;
use crate::inventory::{Capability, InventoryStore};
use crate::mcpprobe;
use crate::portscan;
use crate::router::{self, Tier};
use crate::rsync;
use crate::script;
use crate::ssh::SshClient;
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
    anyhow::bail!(
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
    /// Shell commands to run in order. Each runs under `bash -c`.
    pub commands: Vec<String>,
    /// Stop on first non-zero exit. Default true; skipped entries get exit_code=null.
    #[serde(default)]
    pub fail_fast: Option<bool>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ClaudeExecArgs {
    /// Inventory host with `claude_exec` (apytti gateway must be reachable).
    pub host: String,
    /// What you want the remote agent to do, in plain language.
    /// The agent runs ON the target host and can use its tools (Bash,
    /// Read, etc.) to investigate before answering.
    pub task: String,
    /// Semantic resource hint: fast (Haiku, triage) | balanced (Sonnet,
    /// diagnostic) | deep (Opus, real fuckeries). Default: balanced.
    #[serde(default)]
    pub tier: Option<Tier>,
    /// Override apytti backend (claude / gemini / copilot / ollama).
    #[serde(default)]
    pub backend: Option<String>,
    /// Override model within the chosen backend.
    #[serde(default)]
    pub model: Option<String>,
    /// Override effort (low / medium / high).
    #[serde(default)]
    pub effort: Option<String>,
    /// Resume an earlier remote-agent conversation.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Hard wall-time cap for the whole call (seconds). Default 120.
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
pub struct McpClientArgs {
    /// Inventory host with `claude_admin`.
    pub client: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpGetArgs {
    pub client: String,
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpAddArgs {
    pub client: String,
    pub name: String,
    /// "http" for streamable-HTTP, "stdio" for child-process.
    pub transport: String,
    /// URL for http, executable path for stdio.
    pub url_or_cmd: String,
    /// user (default) | project | local.
    #[serde(default)]
    pub scope: Option<Scope>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpRemoveArgs {
    pub client: String,
    pub name: String,
    #[serde(default)]
    pub scope: Option<Scope>,
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
pub struct PythonExecArgs {
    pub host: String,
    /// Python source, piped via SSH stdin.
    pub script: String,
    /// argv tail (no whitespace, no shell metas).
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
pub struct McpLogsArgs {
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
struct PythonExecResult {
    stdout: String,
    /// Compacted via `script::compact_python_traceback` when a traceback
    /// is detected — falls back to verbatim stderr otherwise.
    stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    timed_out: bool,
    /// `true` if the stderr was compacted from a longer traceback.
    traceback_compacted: bool,
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

    /// Names of every tool this server exposes.
    pub fn tool_names() -> Vec<String> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    /// Shared body for the trivial interpreter wrappers (ruby/perl/deno
    /// at present). No language-specific compactor — pass-through with
    /// the standard ScriptExecResult shape.
    async fn script_exec_simple(
        &self,
        tool: &'static str,
        interpreter: &'static str,
        args: ScriptExecArgs,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target = self.authorize(&ctx, tool, &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = script::run(
                &self.ssh,
                &ctx,
                host,
                interpreter,
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
        self.finish_tool(&ctx, tool, Some(&host_name), res)
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
        CallCtx::new(self.caller_ip).with_identity(self.identity.clone())
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
        authz::authorize(
            &self.inv.snapshot(),
            self.policy.as_ref(),
            ctx,
            tool,
            host,
            need,
        )
    }

    /// The gate for a tool that targets no host. See
    /// [`authz::authorize_tool`].
    fn authorize_tool(&self, ctx: &CallCtx, tool: &str) -> Result<(), ClassifiedError> {
        authz::authorize_tool(self.policy.as_ref(), ctx, tool).map(|_| ())
    }

    /// Finalise a tool call. The single emission point for every call's
    /// outcome: records the gain-tracker event (and, with E4, the audit
    /// record), stamps the request ID on the result — success and error
    /// alike — and converts `anyhow::Result<T>` to what rmcp expects.
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
                let mut blocks = success_blocks(payload, &request_id);
                let bytes = blocks.iter().map(|b| b.len()).sum::<usize>();
                self.tracker.record(tool, host, true, exec_ms, bytes as u64);
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
                anyhow::bail!("commands list is empty");
            }
            let target =
                self.authorize(&ctx, "ssh_batch", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            // The batch wire protocol runs each entry under `bash -c`.
            // Without bash the remote shell mangles the script and the
            // failure surfaces as "missing record for command 0 — remote
            // bash may have crashed", which blames the protocol rather
            // than the absent shell. Say the real thing instead.
            if !host.platform.has_bash() {
                anyhow::bail!(
                    "ssh_batch needs bash, and {:?} is {} (no bash — OPNsense ships csh/tcsh). \
                     Use ssh_exec instead, one call per command.",
                    args.host,
                    host.platform.as_str()
                );
            }
            let fail_fast = args.fail_fast.unwrap_or(true);
            let n = args.commands.len() as u64;
            let to = args
                .timeout_secs
                .map(Duration::from_secs)
                .or_else(|| Some(self.ssh.default_timeout * n.max(1) as u32));
            let script = batch::build_script(&args.commands, fail_fast);
            let raw = self
                .ssh
                .exec_stdin(&ctx, host, "bash", script.as_bytes(), to, false)
                .await?;
            if raw.timed_out {
                anyhow::bail!("batch timed out (>{:?})", to.unwrap_or_default());
            }
            let parsed = batch::parse_output(&raw.stdout, &args.commands)?;
            Ok(parsed)
        }
        .await;
        self.finish_tool(&ctx, "ssh_batch", Some(&host_name), res)
    }

    #[tool(
        description = "Delegate a task to a Claude agent running on the target host (intelligent compaction). The remote agent reads verbose output, runs whatever commands it needs, and returns one tight summary — vs ssh_exec where YOU pull raw output and parse it. Best for triage, log analysis, multi-step diagnostics. Routes through apytti gateway on the host. Tier hint (fast/balanced/deep) maps to model+effort; explicit backend/model/effort fields override. Slower than ssh_exec (3-30s) and non-deterministic — don't use for structured tasks where filters already do the job."
    )]
    async fn claude_exec(
        &self,
        Parameters(args): Parameters<ClaudeExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let total_timeout = Duration::from_secs(args.timeout_secs.unwrap_or(120));
        let res: anyhow::Result<_> = async {
            if args.task.trim().is_empty() {
                anyhow::bail!("task is empty");
            }
            let target = self.authorize(
                &ctx,
                "claude_exec",
                &args.host,
                Need::Cap(Capability::ClaudeExec),
            )?;
            let host = &target.host;
            let url = host
                .apytti_url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("host {} has no apytti_url", args.host))?;

            let route = router::route(
                args.tier,
                args.backend.as_deref(),
                args.model.as_deref(),
                args.effort.as_deref(),
            );

            let client = ApyttiClient::new(url.to_string());
            let req = ApyttiAsk {
                prompt: &args.task,
                backend: Some(route.backend.as_str()),
                model: Some(route.model.as_str()),
                effort: Some(route.effort.as_str()),
                session_id: args.session_id.as_deref(),
            };
            let resp = client.ask(req, total_timeout).await?;
            Ok(serde_json::json!({
                "host": args.host,
                "response": resp.response,
                "session_id": resp.session_id,
                "cost_usd": resp.cost_usd,
                "backend": resp.backend.unwrap_or_else(|| route.backend.clone()),
                "model": route.model,
                "effort": route.effort,
                "tier": route.tier,
            }))
        }
        .await;
        self.finish_tool(&ctx, "claude_exec", Some(&host_name), res)
    }

    #[tool(
        description = "Run Python on a remote host. Script body piped via SSH stdin — no shell quoting hell. args → sys.argv[1:]. Tracebacks auto-compacted."
    )]
    async fn python_exec(
        &self,
        Parameters(args): Parameters<PythonExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "python_exec", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = script::run(
                &self.ssh,
                &ctx,
                host,
                "python3",
                &args.script,
                &args.args,
                to,
                false,
            )
            .await?;
            let original_stderr = raw.stderr.len();
            let compacted = script::compact_python_traceback(&raw.stderr);
            let traceback_compacted = compacted.len() != original_stderr;
            let stderr = compacted.into_owned();
            let final_stderr = stderr.len();
            Ok(PythonExecResult {
                stdout: raw.stdout,
                stderr,
                exit_code: raw.exit_code,
                timed_out: raw.timed_out,
                traceback_compacted,
                original_stderr_bytes: original_stderr,
                final_stderr_bytes: final_stderr,
            })
        }
        .await;
        self.finish_tool(&ctx, "python_exec", Some(&host_name), res)
    }

    #[tool(
        description = "Run Node.js on a remote host. Script body via SSH stdin. Stack traces auto-compacted."
    )]
    async fn node_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let target =
                self.authorize(&ctx, "node_exec", &args.host, Need::Cap(Capability::Exec))?;
            let host = &target.host;
            let raw = script::run(
                &self.ssh,
                &ctx,
                host,
                "node",
                &args.script,
                &args.args,
                to,
                false,
            )
            .await?;
            let original = raw.stderr.len();
            let compacted = script::compact_node_stack(&raw.stderr);
            let was_compacted = compacted.len() != original;
            let stderr = compacted.into_owned();
            let final_len = stderr.len();
            Ok(ScriptExecResult {
                stdout: raw.stdout,
                stderr,
                exit_code: raw.exit_code,
                timed_out: raw.timed_out,
                stderr_compacted: was_compacted,
                original_stderr_bytes: original,
                final_stderr_bytes: final_len,
            })
        }
        .await;
        self.finish_tool(&ctx, "node_exec", Some(&host_name), res)
    }

    #[tool(description = "Run Ruby on a remote host. Script body via SSH stdin.")]
    async fn ruby_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("ruby_exec", "ruby", args).await
    }

    #[tool(description = "Run Perl on a remote host. Script body via SSH stdin.")]
    async fn perl_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("perl_exec", "perl", args).await
    }

    #[tool(
        description = "Run Deno (TS/JS) on a remote host via `deno run -`. Script body via SSH stdin."
    )]
    async fn deno_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("deno_exec", "deno", args).await
    }

    #[tool(
        description = "List a directory on a remote host. Returns parsed { name, mode, size, owner, group, mtime, is_dir, is_link }."
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
                anyhow::bail!(
                    "ls failed (exit={:?}): {}",
                    raw.exit_code,
                    raw.stderr.trim()
                );
            }
            let entries = files::parse_ls(host.platform, &raw.stdout);
            Ok(serde_json::json!({
                "host": args.host,
                "path": args.path,
                "entries": entries,
                "count": entries.len(),
            }))
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
                anyhow::bail!(
                    "stat failed (exit={:?}): {}",
                    raw.exit_code,
                    raw.stderr.trim()
                );
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
                .map(|(name, h)| {
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
                    v
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
            let target = authz::lookup(
                &self.inv.snapshot(),
                self.policy.as_ref(),
                &ctx,
                "inventory_get_host",
                &args.name,
            )?;
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
        description = "Drive a systemd unit (start/stop/restart/reload/enable/disable/status/is-active/is-enabled). status output is auto-compacted (journal tail dropped — use mcp_logs for logs)."
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
                anyhow::bail!(
                    "action {:?} not in allow-list (allowed: {:?})",
                    args.action,
                    ACTIONS
                );
            }
            crate::claudemgr::validate_unit_name(&args.unit)?;
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
        description = "Run a command as root over SSH. Uses passwordless sudo, or a vault-held sudo password when the host declares one (the password never reaches the caller; the whole command then runs as root under sh). Same filter chain as ssh_exec."
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

    #[tool(description = "List MCP servers registered on a client (`claude mcp list`).")]
    async fn mcp_list(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_list",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let raw = claudemgr::list(&self.ssh, &ctx, host).await?;
            Ok(serde_json::json!({ "client": args.client, "stdout": raw }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_list", Some(&client), res)
    }

    #[tool(description = "Show one MCP server's config on a client (`claude mcp get <name>`).")]
    async fn mcp_get(
        &self,
        Parameters(args): Parameters<McpGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_get",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let raw = claudemgr::get(&self.ssh, &ctx, host, &args.name).await?;
            Ok(serde_json::json!({ "client": args.client, "name": args.name, "stdout": raw }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_get", Some(&client), res)
    }

    #[tool(
        description = "Register an MCP server on a client. Edits on-disk config; interactive sessions need /mcp to refresh."
    )]
    async fn mcp_add(
        &self,
        Parameters(args): Parameters<McpAddArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_add",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let scope = args.scope.unwrap_or(Scope::User);
            let out = claudemgr::add(
                &self.ssh,
                &ctx,
                host,
                &args.name,
                &args.transport,
                &args.url_or_cmd,
                scope,
            )
            .await?;
            Ok(serde_json::json!({
                "client": args.client,
                "name": args.name,
                "stdout": out,
            }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_add", Some(&client), res)
    }

    #[tool(description = "Unregister an MCP server on a client.")]
    async fn mcp_remove(
        &self,
        Parameters(args): Parameters<McpRemoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_remove",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let scope = args.scope.unwrap_or(Scope::User);
            let out = claudemgr::remove(&self.ssh, &ctx, host, &args.name, scope).await?;
            Ok(serde_json::json!({
                "client": args.client,
                "name": args.name,
                "stdout": out,
            }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_remove", Some(&client), res)
    }

    #[tool(
        description = "Restart claudecli (Telegram bridge) on a client. systemctl-then-tmux fallback. Best-effort."
    )]
    async fn mcp_restart_claudecli(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_restart_claudecli",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let detail = claudemgr::restart_claudecli(&self.ssh, &ctx, host).await?;
            Ok(serde_json::json!({ "client": args.client, "result": detail }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_restart_claudecli", Some(&client), res)
    }

    #[tool(
        description = "Health-check every MCP server on a client. Distinguishes 'unreachable' (real outage) from 'reachable but session stale' (/mcp will fix)."
    )]
    async fn mcp_status(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let target = self.authorize(
                &ctx,
                "mcp_status",
                &args.client,
                Need::Cap(Capability::ClaudeAdmin),
            )?;
            let host = &target.host;
            let raw = claudemgr::list(&self.ssh, &ctx, host).await?;
            let entries = mcpprobe::parse_mcp_list(&raw);

            let mut probes = Vec::with_capacity(entries.len());
            for e in &entries {
                probes.push(mcpprobe::probe(e, Duration::from_millis(500)).await);
            }

            let total = probes.len();
            let reachable = probes.iter().filter(|p| p.tcp_reachable).count();
            let unreachable = probes
                .iter()
                .filter(|p| !p.tcp_reachable && !p.skipped)
                .count();
            let skipped = probes.iter().filter(|p| p.skipped).count();
            Ok(serde_json::json!({
                "client": args.client,
                "total": total,
                "reachable": reachable,
                "unreachable": unreachable,
                "skipped": skipped,
                "servers": probes,
            }))
        }
        .await;
        self.finish_tool(&ctx, "mcp_status", Some(&client), res)
    }

    #[tool(
        description = "Read logs for ANY systemd unit on a host — this is how you find out why something failed to start or crashed. Tails the journal (`journalctl -u <unit>`). lines default 50, clamped 1..1000. Pairs with service_control, which drives the unit. Requires sudo_exec."
    )]
    async fn service_logs(
        &self,
        Parameters(args): Parameters<McpLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.journal_tail("service_logs", args).await
    }

    /// Deprecated alias for [`service_logs`], kept so existing callers
    /// and pinned configs don't break.
    ///
    /// The `mcp_` prefix was always wrong: this tool tails ANY systemd
    /// unit and gates on `sudo_exec`, not `claude_admin` — it never
    /// belonged to the MCP fleet-management family. The prefix grouped it
    /// by implementation lineage rather than by what a caller wants, so
    /// "why did prometheus fail to start" never found it. Discovered when
    /// an embedding-based tool router refused to route to it, which was
    /// the router being right.
    #[tool(
        name = "mcp_logs",
        description = "DEPRECATED alias for service_logs. Use service_logs."
    )]
    async fn mcp_logs(
        &self,
        Parameters(args): Parameters<McpLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Recorded under its own name so the gain log shows how much the
        // old name is still used, i.e. when the alias can be retired.
        self.journal_tail("mcp_logs", args).await
    }

    /// Shared body for `service_logs` and its `mcp_logs` alias.
    async fn journal_tail(
        &self,
        tool: &'static str,
        args: McpLogsArgs,
    ) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let host_name = args.host.clone();
        let lines = args.lines.unwrap_or(50);
        let res: anyhow::Result<_> = async {
            let target = self.authorize(&ctx, tool, &args.host, Need::Cap(Capability::SudoExec))?;
            let host = &target.host;
            require_systemd(host, &args.host, tool)?;
            let stdout =
                claudemgr::journalctl_tail(&self.ssh, &ctx, host, &args.unit, lines).await?;
            Ok(serde_json::json!({
                "host": args.host,
                "unit": args.unit,
                "lines": lines,
                "stdout": stdout,
            }))
        }
        .await;
        self.finish_tool(&ctx, tool, Some(&host_name), res)
    }

    #[tool(
        description = "Advice for recovering from MCP-server disconnects (interactive sessions need /mcp; claude -p refreshes per-message)."
    )]
    async fn mcp_reconnect_hint(&self) -> Result<CallToolResult, McpError> {
        let ctx = self.new_ctx();
        let hint = "If an MCP server appears disconnected:\n\
            1. Run `mcp_status <client>` first — distinguishes 'daemon down' from 'session stale'.\n\
            2. Daemon down: check `mcp_logs <host> <unit>`; if needed, restart via `ssh_sudo_exec`.\n\
            3. Session stale (probe says reachable, but your tool calls still fail):\n\
               • Interactive Claude Code session: type `/mcp` and reconnect the server.\n\
               • Telegram via claudecli: `mcp_restart_claudecli <client>` — claudecli runs\n\
                 `claude -p` per message, so the next message handshakes fresh.\n\
            prompto refuses every one of these against the caller's own machine: on the client\n\
            itself, run the equivalent (`claude mcp list`, `systemctl restart …`) in your local shell.\n\
               • There is no in-session re-handshake hook today; this hint is the honest answer.";
        let res = self
            .authorize_tool(&ctx, "mcp_reconnect_hint")
            .map(|()| serde_json::json!({ "hint": hint }))
            .map_err(anyhow::Error::from);
        self.finish_tool(&ctx, "mcp_reconnect_hint", None, res)
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
            .and_then(|()| self.tracker.summary(cutoff));
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
fn with_groups(v: &mut serde_json::Value, groups: &[String]) {
    if !groups.is_empty() {
        v["groups"] = groups.into();
    }
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

#[tool_handler]
impl ServerHandler for Prompto {
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
    "prompto — homelab power, libvirt, SSH exec, and remote `claude mcp` management over MCP. \
                 Tools: host_wake, host_sleep, host_status, host_diagnose, vm_list, vm_state, vm_start, vm_stop, vm_ensure_up, ssh_exec, ssh_batch, ssh_sudo_exec, claude_exec, python_exec, node_exec, bash_exec, ruby_exec, perl_exec, deno_exec, file_read, file_write, file_list, file_stat, rsync_sync, port_scan, service_control, inventory_list, inventory_get_host, service_logs, mcp_list, mcp_get, mcp_add, mcp_remove, mcp_restart_claudecli, mcp_status, mcp_logs, mcp_reconnect_hint, prompto_gain. \
                 Hosts are looked up by name in the server's inventory; every call is gated on the host's capabilities (`wake`, `exec`, `sudo_exec`, `virt`, `claude_admin`, `claude_exec`). Inventory is operator-managed — edit /etc/prompto.toml and SIGHUP to reload. \
                 vm_stop runs the dompmsuspend → shutdown → destroy fallback chain. \
                 The mcp_* tools shell out to `claude mcp …` on a `claude_admin`-capable client. They edit on-disk config; running interactive sessions still need `/mcp` to refresh, but stateless callers (claudecli's `claude -p`) pick up changes on their next invocation. \
                 prompto_gain returns the token-savings summary for this instance. \
                 Reload the inventory live by sending SIGHUP to the server process."
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
