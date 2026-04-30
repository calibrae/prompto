//! rmcp tool router for prompto. Every tool body returns
//! `anyhow::Result<impl Serialize>` and routes through `finish_tool`,
//! which records one event per call into the gain tracker.

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_gain::Tracker;

use crate::advisor::Advisor;
use crate::batch;
use crate::claudemgr::{self, Scope};
use crate::diagnose;
use crate::files;
use crate::filters::FilterChain;
use crate::host;
use crate::inventory::HostConfig;
use crate::inventory::{Capability, InventoryStore};
use crate::mcpprobe;
use crate::portscan;
use crate::rsync;
use crate::script;
use crate::ssh::SshClient;
use crate::virt;

#[derive(Clone)]
pub struct Prompto {
    inv: InventoryStore,
    ssh: Arc<SshClient>,
    tracker: Arc<Tracker>,
    filters: Arc<FilterChain>,
    advisor: Arc<Advisor>,
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
pub struct InventoryAddHostArgs {
    /// Inventory key (alnum + -_).
    pub name: String,
    pub ip: String,
    pub ssh_user: String,
    pub ssh_key: String,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InventoryHostNameArgs {
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InventoryCapabilityArgs {
    pub name: String,
    pub capability: Capability,
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
    /// Use `sudo -n tee`. Default false.
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
        Self {
            inv,
            ssh,
            tracker,
            filters: Arc::new(FilterChain::default()),
            advisor: Arc::new(Advisor::new()),
            stop_vm_step,
            tool_router: Self::tool_router(),
        }
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
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw = script::run(
                &self.ssh,
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
        self.finish_tool(tool, Some(&host_name), started, res)
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

    /// Finalise a tool call: record the event and convert
    /// `anyhow::Result<T>` to the `CallToolResult`/`McpError` rmcp expects.
    fn finish_tool<T: serde::Serialize>(
        &self,
        tool: &'static str,
        host: Option<&str>,
        started: Instant,
        res: anyhow::Result<T>,
    ) -> Result<CallToolResult, McpError> {
        let exec_ms = started.elapsed().as_millis() as u64;
        let hint = self.advisor.record(tool, host);
        match res {
            Ok(v) => {
                let payload = serde_json::to_value(&v).unwrap_or_default();
                let body = payload.to_string();
                self.tracker
                    .record(tool, host, true, exec_ms, body.len() as u64);
                let mut blocks = vec![Content::text(body)];
                if let Some(h) = hint {
                    blocks.push(Content::text(format!("[advisor] {h}")));
                }
                Ok(CallToolResult::success(blocks))
            }
            Err(e) => {
                let msg = e.to_string();
                self.tracker
                    .record(tool, host, false, exec_ms, msg.len() as u64);
                Err(McpError::internal_error(msg, None))
            }
        }
    }

    #[tool(
        description = "Wake a host via WOL magic packet."
    )]
    async fn host_wake(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Wake)?;
            host::wake(host).await?;
            Ok(WakeResult {
                host: args.host.clone(),
                sent_to_mac: host.mac.clone().unwrap_or_default(),
            })
        }
        .await;
        self.finish_tool("host_wake", Some(&host_name), started, res)
    }

    #[tool(
        description = "TCP-probe a host's SSH port. Returns up | unreachable | off."
    )]
    async fn host_status(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.get(&args.host)?;
            host::status(host, Duration::from_secs(2)).await
        }
        .await;
        self.finish_tool("host_status", Some(&host_name), started, res)
    }

    #[tool(
        description = "Shutdown a host (`sudo -n shutdown -h now`)."
    )]
    async fn host_sleep(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::SudoExec)?;
            host::sleep(&self.ssh, host).await?;
            Ok(serde_json::json!({ "host": host_name, "sent": "shutdown -h now" }))
        }
        .await;
        self.finish_tool("host_sleep", Some(&args.host), started, res)
    }

    #[tool(
        description = "List libvirt domains on a host (`virsh list --all`)."
    )]
    async fn vm_list(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Virt)?;
            virt::list(&self.ssh, host).await
        }
        .await;
        self.finish_tool("vm_list", Some(&host_name), started, res)
    }

    #[tool(
        description = "Get libvirt domain state (`virsh domstate`): running | shut off | pmsuspended | …"
    )]
    async fn vm_state(
        &self,
        Parameters(args): Parameters<VmArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Virt)?;
            let s = virt::domstate(&self.ssh, host, &args.vm).await?;
            Ok(serde_json::json!({ "host": args.host, "vm": args.vm, "state": s }))
        }
        .await;
        self.finish_tool("vm_state", Some(&host_name), started, res)
    }

    #[tool(description = "Start a libvirt domain (`virsh start`).")]
    async fn vm_start(
        &self,
        Parameters(args): Parameters<VmArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Virt)?;
            let out = virt::start(&self.ssh, host, &args.vm).await?;
            Ok(serde_json::json!({ "host": args.host, "vm": args.vm, "stdout": out }))
        }
        .await;
        self.finish_tool("vm_start", Some(&host_name), started, res)
    }

    #[tool(
        description = "Stop a libvirt domain via dompmsuspend → shutdown → destroy fallback chain."
    )]
    async fn vm_stop(
        &self,
        Parameters(args): Parameters<VmStopArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let step = args
            .step_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.stop_vm_step);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Virt)?;
            virt::stop(&self.ssh, host, &args.vm, step).await
        }
        .await;
        self.finish_tool("vm_stop", Some(&host_name), started, res)
    }

    #[tool(
        description = "Wake host (if down) + start VM (if not running) + wait for SSH-ready. One call before issuing VM work."
    )]
    async fn vm_ensure_up(
        &self,
        Parameters(args): Parameters<VmEnsureUpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let total = Duration::from_secs(args.total_timeout_secs.unwrap_or(180));
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Virt)?;

            let initial = host::status(host, Duration::from_secs(2)).await?;
            let mut woke = false;
            if initial.state != "up" {
                inv.require(&args.host, Capability::Wake)?;
                host::wake(host).await?;
                woke = true;
                host::wait_until_up(host, total).await?;
            }

            let state_before = virt::domstate(&self.ssh, host, &args.vm).await?;
            let mut started_vm = false;
            if state_before != "running" {
                let _ = virt::start(&self.ssh, host, &args.vm).await?;
                started_vm = true;
            }
            let state_after = virt::domstate(&self.ssh, host, &args.vm).await?;

            Ok(VmEnsureUpResult {
                host_wake: woke,
                vm_started: started_vm,
                final_vm_state: state_after,
            })
        }
        .await;
        self.finish_tool("vm_ensure_up", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run a command on a host over SSH. Returns stdout/stderr/exit. stdout passes through a 26-filter chain (cargo, git, journalctl, find, pkg, k8s, …) that names the applied filter in the response. For N commands on the same host, prefer ssh_batch."
    )]
    async fn ssh_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw = self.ssh.exec(host, &args.cmd, to, false).await?;
            Ok(self.apply_filters(&args.cmd, raw))
        }
        .await;
        self.finish_tool("ssh_exec", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run N commands on one host in a single SSH session. PREFER OVER repeated ssh_exec for same-host sequences (snapshot destroys, service restarts, fan-out checks) — saves N-1 round trips and the conversation accumulation cost. Returns per-command exit/output/timing. fail_fast (default true) skips remaining on first failure. Keep commands tight; batch stdout is not filter-chained."
    )]
    async fn ssh_batch(
        &self,
        Parameters(args): Parameters<BatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            if args.commands.is_empty() {
                anyhow::bail!("commands list is empty");
            }
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let fail_fast = args.fail_fast.unwrap_or(true);
            let n = args.commands.len() as u64;
            let to = args
                .timeout_secs
                .map(Duration::from_secs)
                .or_else(|| Some(self.ssh.default_timeout * n.max(1) as u32));
            let script = batch::build_script(&args.commands, fail_fast);
            let raw = self
                .ssh
                .exec_stdin(host, "bash", script.as_bytes(), to, false)
                .await?;
            if raw.timed_out {
                anyhow::bail!("batch timed out (>{:?})", to.unwrap_or_default());
            }
            let parsed = batch::parse_output(&raw.stdout, &args.commands)?;
            Ok(parsed)
        }
        .await;
        self.finish_tool("ssh_batch", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run Python on a remote host. Script body piped via SSH stdin — no shell quoting hell. args → sys.argv[1:]. Tracebacks auto-compacted."
    )]
    async fn python_exec(
        &self,
        Parameters(args): Parameters<PythonExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw = script::run(
                &self.ssh,
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
        self.finish_tool("python_exec", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run Node.js on a remote host. Script body via SSH stdin. Stack traces auto-compacted."
    )]
    async fn node_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw =
                script::run(&self.ssh, host, "node", &args.script, &args.args, to, false).await?;
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
        self.finish_tool("node_exec", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run Ruby on a remote host. Script body via SSH stdin."
    )]
    async fn ruby_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("ruby_exec", "ruby", args).await
    }

    #[tool(
        description = "Run Perl on a remote host. Script body via SSH stdin."
    )]
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
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            files::validate_path(&args.path)?;
            let cmd = format!("ls -la --time-style=long-iso -- {}", args.path);
            let raw = self
                .ssh
                .exec(host, &cmd, Some(Duration::from_secs(10)), false)
                .await?;
            if !raw.ok() {
                anyhow::bail!(
                    "ls failed (exit={:?}): {}",
                    raw.exit_code,
                    raw.stderr.trim()
                );
            }
            let entries = files::parse_ls_long(&raw.stdout);
            Ok(serde_json::json!({
                "host": args.host,
                "path": args.path,
                "entries": entries,
                "count": entries.len(),
            }))
        }
        .await;
        self.finish_tool("file_list", Some(&host_name), started, res)
    }

    #[tool(
        description = "Stat a remote file. Returns typed { path, mode (octal), size, owner, group, mtime, kind }."
    )]
    async fn file_stat(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            files::validate_path(&args.path)?;
            let cmd = format!("stat -c '%a|%s|%U|%G|%y|%F|%n' -- {}", args.path);
            let raw = self
                .ssh
                .exec(host, &cmd, Some(Duration::from_secs(10)), false)
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
        self.finish_tool("file_stat", Some(&host_name), started, res)
    }

    #[tool(
        description = "List inventory hosts with their capabilities. Read-only."
    )]
    async fn inventory_list(&self) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let hosts: Vec<serde_json::Value> = inv
                .hosts
                .iter()
                .map(|(name, h)| {
                    serde_json::json!({
                        "name": name,
                        "ip": h.ip,
                        "mac": h.mac,
                        "ssh_user": h.ssh_user,
                        "ssh_port": h.ssh_port,
                        "capabilities": h.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "count": hosts.len(),
                "hosts": hosts,
            }))
        }
        .await;
        self.finish_tool("inventory_list", None, started, res)
    }

    #[tool(
        description = "Get one host's inventory config (ssh_key path elided)."
    )]
    async fn inventory_get_host(
        &self,
        Parameters(args): Parameters<InventoryHostNameArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let h = inv.get(&args.name)?;
            Ok(serde_json::json!({
                "name": args.name,
                "ip": h.ip,
                "mac": h.mac,
                "ssh_user": h.ssh_user,
                "ssh_port": h.ssh_port,
                "capabilities": h.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            }))
        }
        .await;
        self.finish_tool("inventory_get_host", Some(&host_name), started, res)
    }

    #[tool(
        description = "Add a host to the inventory and persist (atomic). Validates before write. NOTE: TOML comments/ordering are NOT preserved across edits."
    )]
    async fn inventory_add_host(
        &self,
        Parameters(args): Parameters<InventoryAddHostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            validate_inventory_name(&args.name)?;
            let host = HostConfig {
                ip: args.ip,
                mac: args.mac,
                ssh_user: args.ssh_user,
                ssh_key: args.ssh_key.into(),
                ssh_port: args.ssh_port.unwrap_or(22),
                capabilities: args.capabilities,
            };
            self.inv.edit(|inv| {
                if inv.hosts.contains_key(&args.name) {
                    anyhow::bail!(
                        "host {:?} already exists — use inventory_remove_host first",
                        args.name
                    );
                }
                inv.hosts.insert(args.name.clone(), host);
                Ok(())
            })?;
            Ok(serde_json::json!({
                "name": args.name,
                "added": true,
                "host_count": self.inv.snapshot().hosts.len(),
            }))
        }
        .await;
        self.finish_tool("inventory_add_host", Some(&host_name), started, res)
    }

    #[tool(description = "Remove a host from the inventory and persist to disk.")]
    async fn inventory_remove_host(
        &self,
        Parameters(args): Parameters<InventoryHostNameArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            validate_inventory_name(&args.name)?;
            let mut removed = false;
            self.inv.edit(|inv| {
                removed = inv.hosts.remove(&args.name).is_some();
                if !removed {
                    anyhow::bail!("host {:?} not found", args.name);
                }
                Ok(())
            })?;
            Ok(serde_json::json!({
                "name": args.name,
                "removed": removed,
                "host_count": self.inv.snapshot().hosts.len(),
            }))
        }
        .await;
        self.finish_tool("inventory_remove_host", Some(&host_name), started, res)
    }

    #[tool(
        description = "Grant a capability to a host. Idempotent."
    )]
    async fn inventory_grant_capability(
        &self,
        Parameters(args): Parameters<InventoryCapabilityArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            validate_inventory_name(&args.name)?;
            let mut already_present = false;
            self.inv.edit(|inv| {
                let h = inv
                    .hosts
                    .get_mut(&args.name)
                    .ok_or_else(|| anyhow::anyhow!("host {:?} not found", args.name))?;
                if h.capabilities.contains(&args.capability) {
                    already_present = true;
                } else {
                    h.capabilities.push(args.capability);
                }
                Ok(())
            })?;
            Ok(serde_json::json!({
                "name": args.name,
                "capability": args.capability.as_str(),
                "already_present": already_present,
            }))
        }
        .await;
        self.finish_tool("inventory_grant_capability", Some(&host_name), started, res)
    }

    #[tool(
        description = "Revoke a capability from a host. Idempotent."
    )]
    async fn inventory_revoke_capability(
        &self,
        Parameters(args): Parameters<InventoryCapabilityArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.name.clone();
        let res: anyhow::Result<_> = async {
            validate_inventory_name(&args.name)?;
            let mut was_present = false;
            self.inv.edit(|inv| {
                let h = inv
                    .hosts
                    .get_mut(&args.name)
                    .ok_or_else(|| anyhow::anyhow!("host {:?} not found", args.name))?;
                let before = h.capabilities.len();
                h.capabilities.retain(|c| *c != args.capability);
                was_present = h.capabilities.len() != before;
                Ok(())
            })?;
            Ok(serde_json::json!({
                "name": args.name,
                "capability": args.capability.as_str(),
                "was_present": was_present,
            }))
        }
        .await;
        self.finish_tool(
            "inventory_revoke_capability",
            Some(&host_name),
            started,
            res,
        )
    }

    #[tool(
        description = "rsync files between two inventory hosts in one call. PREFER OVER N×file_write loops (~17K tokens vs ~150). source_host SSHs to dest_host (needs key already trusted). Trailing `/` on paths matters. Output is the --stats block."
    )]
    async fn rsync_sync(
        &self,
        Parameters(args): Parameters<RsyncSyncArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.source_host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let source_host = inv.require(&args.source_host, Capability::Exec)?;
            let dest_host = inv.require(&args.dest_host, Capability::Exec)?;
            let opts = rsync::RsyncOptions {
                archive: args.archive.unwrap_or(true),
                delete: args.delete.unwrap_or(false),
                dry_run: args.dry_run.unwrap_or(false),
                excludes: &args.excludes,
            };
            let raw = rsync::run(
                &self.ssh,
                source_host,
                &args.source_path,
                dest_host,
                &args.dest_path,
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
                "filter": report.applied,
                "original_bytes": report.original_bytes,
                "filtered_bytes": report.filtered_bytes,
            }))
        }
        .await;
        self.finish_tool("rsync_sync", Some(&host_name), started, res)
    }

    #[tool(
        description = "TCP-probe a list of ports on a host (no SSH). Returns per-port reachable + latency_ms."
    )]
    async fn port_scan(
        &self,
        Parameters(args): Parameters<PortScanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.get(&args.host)?;
            let probe = Duration::from_millis(args.probe_ms.unwrap_or(500).clamp(50, 5000));
            let mut results = Vec::with_capacity(args.ports.len());
            for port in &args.ports {
                results.push(portscan::probe_one(&host.ip, *port, probe).await);
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
        self.finish_tool("port_scan", Some(&host_name), started, res)
    }

    #[tool(
        description = "Composite host health: uptime, load, mem (MB), disk, last-boot, kernel, listening ports (top 30), failed units. One round-trip; replaces ~5 ssh_exec calls."
    )]
    async fn host_diagnose(
        &self,
        Parameters(args): Parameters<HostArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw = script::run(
                &self.ssh,
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
        self.finish_tool("host_diagnose", Some(&host_name), started, res)
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
        let started = Instant::now();
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
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::SudoExec)?;
            let cmd = format!("systemctl {} -- {}", args.action, args.unit);
            let raw = self
                .ssh
                .exec(host, &cmd, Some(Duration::from_secs(15)), true)
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
        self.finish_tool("service_control", Some(&host_name), started, res)
    }

    #[tool(
        description = "Read a remote file. max_bytes default 64 KB, clamped to 1 MB. Returns content + `truncated` flag."
    )]
    async fn file_read(
        &self,
        Parameters(args): Parameters<FileReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let max_bytes = args
            .max_bytes
            .unwrap_or(files::DEFAULT_READ_BYTES)
            .clamp(1, files::MAX_READ_BYTES);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw = files::read(&self.ssh, host, &args.path, max_bytes).await?;
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
        self.finish_tool("file_read", Some(&host_name), started, res)
    }

    #[tool(
        description = "Write a remote file (content via SSH stdin, no shell quoting). Optional mode runs chmod after. sudo=true uses sudo -n tee."
    )]
    async fn file_write(
        &self,
        Parameters(args): Parameters<FileWriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let sudo = args.sudo.unwrap_or(false);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let cap = if sudo {
                Capability::SudoExec
            } else {
                Capability::Exec
            };
            let host = inv.require(&args.host, cap)?;
            files::write(&self.ssh, host, &args.path, args.content.as_bytes(), sudo).await?;
            if let Some(mode) = &args.mode {
                files::chmod(&self.ssh, host, &args.path, mode, sudo).await?;
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
        self.finish_tool("file_write", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run Bash on a remote host. Script body via SSH stdin."
    )]
    async fn bash_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::Exec)?;
            let raw =
                script::run(&self.ssh, host, "bash", &args.script, &args.args, to, false).await?;
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
        self.finish_tool("bash_exec", Some(&host_name), started, res)
    }

    #[tool(
        description = "Run a command via `sudo -n` over SSH. Passwordless sudo only. Same filter chain as ssh_exec."
    )]
    async fn ssh_sudo_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let to = args.timeout_secs.map(Duration::from_secs);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::SudoExec)?;
            let raw = self.ssh.exec(host, &args.cmd, to, true).await?;
            Ok(self.apply_filters(&args.cmd, raw))
        }
        .await;
        self.finish_tool("ssh_sudo_exec", Some(&host_name), started, res)
    }

    #[tool(
        description = "List MCP servers registered on a client (`claude mcp list`)."
    )]
    async fn mcp_list(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let raw = claudemgr::list(&self.ssh, host).await?;
            Ok(serde_json::json!({ "client": args.client, "stdout": raw }))
        }
        .await;
        self.finish_tool("mcp_list", Some(&client), started, res)
    }

    #[tool(
        description = "Show one MCP server's config on a client (`claude mcp get <name>`)."
    )]
    async fn mcp_get(
        &self,
        Parameters(args): Parameters<McpGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let raw = claudemgr::get(&self.ssh, host, &args.name).await?;
            Ok(serde_json::json!({ "client": args.client, "name": args.name, "stdout": raw }))
        }
        .await;
        self.finish_tool("mcp_get", Some(&client), started, res)
    }

    #[tool(
        description = "Register an MCP server on a client. Edits on-disk config; interactive sessions need /mcp to refresh."
    )]
    async fn mcp_add(
        &self,
        Parameters(args): Parameters<McpAddArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let scope = args.scope.unwrap_or(Scope::User);
            let out = claudemgr::add(
                &self.ssh,
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
        self.finish_tool("mcp_add", Some(&client), started, res)
    }

    #[tool(
        description = "Unregister an MCP server on a client."
    )]
    async fn mcp_remove(
        &self,
        Parameters(args): Parameters<McpRemoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let scope = args.scope.unwrap_or(Scope::User);
            let out = claudemgr::remove(&self.ssh, host, &args.name, scope).await?;
            Ok(serde_json::json!({
                "client": args.client,
                "name": args.name,
                "stdout": out,
            }))
        }
        .await;
        self.finish_tool("mcp_remove", Some(&client), started, res)
    }

    #[tool(
        description = "Restart claudecli (Telegram bridge) on a client. systemctl-then-tmux fallback. Best-effort."
    )]
    async fn mcp_restart_claudecli(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let detail = claudemgr::restart_claudecli(&self.ssh, host).await?;
            Ok(serde_json::json!({ "client": args.client, "result": detail }))
        }
        .await;
        self.finish_tool("mcp_restart_claudecli", Some(&client), started, res)
    }

    #[tool(
        description = "Health-check every MCP server on a client. Distinguishes 'unreachable' (real outage) from 'reachable but session stale' (/mcp will fix)."
    )]
    async fn mcp_status(
        &self,
        Parameters(args): Parameters<McpClientArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let client = args.client.clone();
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.client, Capability::ClaudeAdmin)?;
            let raw = claudemgr::list(&self.ssh, host).await?;
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
        self.finish_tool("mcp_status", Some(&client), started, res)
    }

    #[tool(
        description = "Tail systemd journal for a unit. lines default 50, clamped 1..1000."
    )]
    async fn mcp_logs(
        &self,
        Parameters(args): Parameters<McpLogsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let host_name = args.host.clone();
        let lines = args.lines.unwrap_or(50);
        let res: anyhow::Result<_> = async {
            let inv = self.inv.snapshot();
            let host = inv.require(&args.host, Capability::SudoExec)?;
            let stdout = claudemgr::journalctl_tail(&self.ssh, host, &args.unit, lines).await?;
            Ok(serde_json::json!({
                "host": args.host,
                "unit": args.unit,
                "lines": lines,
                "stdout": stdout,
            }))
        }
        .await;
        self.finish_tool("mcp_logs", Some(&host_name), started, res)
    }

    #[tool(
        description = "Advice for recovering from MCP-server disconnects (interactive sessions need /mcp; claude -p refreshes per-message)."
    )]
    async fn mcp_reconnect_hint(&self) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let hint = "If an MCP server appears disconnected:\n\
            1. Run `mcp_status <client>` first — distinguishes 'daemon down' from 'session stale'.\n\
            2. Daemon down: check `mcp_logs <host> <unit>`; if needed, restart via `ssh_sudo_exec`.\n\
            3. Session stale (probe says reachable, but your tool calls still fail):\n\
               • Interactive Claude Code session: type `/mcp` and reconnect the server.\n\
               • Telegram via claudecli: ask me to call `mcp_restart_claudecli <client>` — claudecli\n\
                 runs `claude -p` per message, so the next message handshakes fresh.\n\
               • There is no in-session re-handshake hook today; this hint is the honest answer.";
        let res: anyhow::Result<serde_json::Value> = Ok(serde_json::json!({ "hint": hint }));
        self.finish_tool("mcp_reconnect_hint", None, started, res)
    }

    #[tool(
        description = "Token-savings analytics vs an SSH+bash baseline. Optional since_secs lookback. Returns total + per-tool breakdown."
    )]
    async fn prompto_gain(
        &self,
        Parameters(args): Parameters<GainArgs>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        let cutoff = args
            .since_secs
            .map(|s| chrono::Utc::now() - chrono::Duration::seconds(s as i64));
        let res = self.tracker.summary(cutoff);
        self.finish_tool("prompto_gain", None, started, res)
    }
}

#[tool_handler]
impl ServerHandler for Prompto {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_instructions(
                "prompto — homelab power, libvirt, SSH exec, and remote `claude mcp` management over MCP. \
                 Tools: host_wake, host_sleep, host_status, host_diagnose, vm_list, vm_state, vm_start, vm_stop, vm_ensure_up, ssh_exec, ssh_sudo_exec, python_exec, node_exec, bash_exec, ruby_exec, perl_exec, deno_exec, file_read, file_write, file_list, file_stat, rsync_sync, port_scan, service_control, inventory_list, inventory_get_host, inventory_add_host, inventory_remove_host, inventory_grant_capability, inventory_revoke_capability, mcp_list, mcp_get, mcp_add, mcp_remove, mcp_restart_claudecli, mcp_status, mcp_logs, mcp_reconnect_hint, prompto_gain. \
                 Hosts are looked up by name in the server's inventory; every call is gated on the host's capabilities (`wake`, `exec`, `sudo_exec`, `virt`, `claude_admin`). \
                 vm_stop runs the dompmsuspend → shutdown → destroy fallback chain. \
                 The mcp_* tools shell out to `claude mcp …` on a `claude_admin`-capable client. They edit on-disk config; running interactive sessions still need `/mcp` to refresh, but stateless callers (claudecli's `claude -p`) pick up changes on their next invocation. \
                 prompto_gain returns the token-savings summary for this instance. \
                 Reload the inventory live by sending SIGHUP to the server process."
                    .to_string(),
            )
    }
}

/// Inventory keys are alphanumerics + `-`/`_`/`.`, max 64. Validated
/// before the value reaches TOML serialization or the persisted file.
fn validate_inventory_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("inventory name is empty");
    }
    if name.len() > 64 {
        anyhow::bail!("inventory name too long");
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        anyhow::bail!("inventory name {name:?} must be alphanumerics + - _ .");
    }
    Ok(())
}
