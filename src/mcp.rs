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

use crate::claudemgr::{self, Scope};
use crate::diagnose;
use crate::files;
use crate::filters::FilterChain;
use crate::host;
use crate::inventory::HostConfig;
use crate::inventory::{Capability, InventoryStore};
use crate::mcpprobe;
use crate::portscan;
use crate::script;
use crate::ssh::SshClient;
use crate::virt;

#[derive(Clone)]
pub struct Prompto {
    inv: InventoryStore,
    ssh: Arc<SshClient>,
    tracker: Arc<Tracker>,
    filters: Arc<FilterChain>,
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
    /// Command to run on the remote host (interpreted by the remote shell).
    pub cmd: String,
    /// Per-command timeout (seconds). Defaults to the server's
    /// `PROMPTO_DEFAULT_TIMEOUT_SECS`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GainArgs {
    /// Optional lookback window in seconds. Omit to include every event
    /// in the log.
    #[serde(default)]
    pub since_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpClientArgs {
    /// Inventory host name with the `claude_admin` capability — the
    /// machine prompto will SSH to in order to run `claude mcp …`.
    pub client: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpGetArgs {
    pub client: String,
    /// MCP server name as registered in the client's `~/.claude.json`.
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpAddArgs {
    pub client: String,
    /// Name to register the MCP under (e.g. "memqdrant").
    pub name: String,
    /// Transport — typically "http" for streamable-HTTP servers, or
    /// "stdio" for child-process MCPs.
    pub transport: String,
    /// URL for HTTP transports, or full executable path for stdio.
    pub url_or_cmd: String,
    /// Scope: `user` (default), `project`, or `local`.
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
    /// Source code, sent through SSH stdin verbatim.
    pub script: String,
    /// Optional positional arguments — become argv after the script.
    /// No whitespace or shell metacharacters.
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PythonExecArgs {
    /// Inventory host with the `exec` capability.
    pub host: String,
    /// Python source code. Sent through SSH stdin, not interpolated into
    /// a shell — quotes, heredocs, embedded JSON all survive untouched.
    pub script: String,
    /// Optional positional arguments. Become `sys.argv[1:]` inside the
    /// script. Each arg is validated against shell metacharacters and
    /// must not contain whitespace — pass complex inputs via the script
    /// body or stdin instead.
    #[serde(default)]
    pub args: Vec<String>,
    /// Per-command timeout (seconds). Defaults to the server's
    /// `PROMPTO_DEFAULT_TIMEOUT_SECS`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PathArgs {
    pub host: String,
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PortScanArgs {
    pub host: String,
    /// List of TCP ports to probe (e.g. [22, 80, 443, 6337]).
    pub ports: Vec<u16>,
    /// Per-port probe budget in milliseconds. Default 500, clamped 50..=5000.
    #[serde(default)]
    pub probe_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct InventoryAddHostArgs {
    /// Inventory key (e.g. "doppio", "alpha"). Validated against
    /// alphanumerics + `-`/`_`.
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
    /// systemd unit name (e.g. "memqdrant", "nginx", "doppio-mqtt").
    pub unit: String,
    /// One of: start, stop, restart, reload, enable, disable, status,
    /// is-active, is-enabled.
    pub action: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileReadArgs {
    pub host: String,
    /// Absolute or relative path on the remote host. Must contain no
    /// shell metacharacters or whitespace.
    pub path: String,
    /// Max bytes to read. Defaults to 65_536 (64 KB). Clamped to 1 MB.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileWriteArgs {
    pub host: String,
    pub path: String,
    /// Bytes to write. Stored verbatim — pipes through SSH stdin to
    /// avoid shell quoting on the content.
    pub content: String,
    /// Optional octal mode (`"0644"`, `"755"`, …). Applied via `chmod`
    /// after the write.
    #[serde(default)]
    pub mode: Option<String>,
    /// Set to `true` to write via `sudo -n tee` (requires the host to
    /// have the `sudo_exec` capability). Default `false`.
    #[serde(default)]
    pub sudo: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct McpLogsArgs {
    /// Inventory host where the MCP daemon's systemd unit lives. Must
    /// have the `sudo_exec` capability so journalctl can read the unit
    /// scope.
    pub host: String,
    /// systemd unit name (e.g. "memqdrant", "bucciarati", "prompto").
    pub unit: String,
    /// Lines to tail. Clamped server-side to 1..=1000. Default 50.
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
        match res {
            Ok(v) => {
                let payload = serde_json::to_value(&v).unwrap_or_default();
                let body = payload.to_string();
                self.tracker
                    .record(tool, host, true, exec_ms, body.len() as u64);
                Ok(CallToolResult::success(vec![Content::text(body)]))
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
        description = "Wake a host with a UDP magic packet (broadcast :9). The host's MAC must be in the inventory and the host must have the `wake` capability."
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
        description = "Probe the host's SSH port with a TCP connect. Returns `up` (connected), `unreachable` (refused), or `off` (timed out)."
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
        description = "Shutdown a host via `sudo -n shutdown -h now` over SSH. Requires the `sudo_exec` capability."
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
        description = "List all libvirt domains on a host (`virsh list --all`). Requires the `virt` capability."
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
        description = "Get the libvirt state of a single domain (`virsh domstate`). Returns the raw state string (e.g. \"running\", \"shut off\", \"pmsuspended\")."
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

    #[tool(description = "Start a libvirt domain (`virsh start`). Requires `virt`.")]
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
        description = "Stop a libvirt domain via the fallback chain: `dompmsuspend disk` (S4 hibernate) → `shutdown` (ACPI) → `destroy` (force kill). Each step has its own timeout. Returns the outcome and the final state. Requires `virt`."
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
        description = "Wake a host (if needed), start a VM (if needed), and wait until the host is SSH-reachable. Useful as a single call before issuing other work to a VM. Requires `wake` + `virt`."
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
        description = "Run a command on a host over SSH and return stdout, stderr, exit code, and timeout flag. Output is run through the built-in filter chain (cargo test/build, git log/diff/show, journalctl, find, ls -l) — the response includes a `filter` field naming whichever filter compacted stdout, plus original/filtered byte counts. Requires `exec`."
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
        description = "Run a Python script on a remote host. The script body is piped through SSH stdin, NOT interpolated into a shell — embedded quotes, heredocs, JSON literals, etc. survive untouched, eliminating the quoting hell of `ssh_exec \"python3 -c '...'\"`. Optional `args` become `sys.argv[1:]` inside the script. stderr is auto-compacted to `ExceptionType: message (N frames; last: file:line)` when a Python traceback is detected. Requires `exec`."
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
        description = "Run a Node.js script on a remote host. Same stdin-piping shape as `python_exec` — embedded quotes, JSON literals, multi-line code all survive. stderr is auto-compacted to `Error: message (N frames; last: file:line)` when a V8 stack trace is detected. Requires `exec`."
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
        description = "Run a Ruby script on a remote host. Body piped through SSH stdin (no quoting hell). Output passes through unchanged. Requires `exec`."
    )]
    async fn ruby_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("ruby_exec", "ruby", args).await
    }

    #[tool(
        description = "Run a Perl script on a remote host. Body piped through SSH stdin. Output passes through unchanged. Requires `exec`."
    )]
    async fn perl_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("perl_exec", "perl", args).await
    }

    #[tool(
        description = "Run a Deno (TypeScript/JavaScript) script on a remote host via `deno run -`. Body piped through SSH stdin. Output passes through unchanged. Requires `exec`."
    )]
    async fn deno_exec(
        &self,
        Parameters(args): Parameters<ScriptExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.script_exec_simple("deno_exec", "deno", args).await
    }

    #[tool(
        description = "List a directory on a remote host (`ls -la --time-style=long-iso <path>`) and return parsed entries: { name, mode, size, owner, group, mtime, is_dir, is_link }. Requires `exec`."
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
        description = "Stat a file on a remote host (`stat -c '%a|%s|%U|%G|%y|%F|%n' <path>`) and return typed { path, mode (octal), size, owner, group, mtime, kind }. Requires `exec`."
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
        description = "List every host in the inventory with its capabilities. ssh_key paths are NOT exposed (they're server-side filesystem details). Read-only — no inventory mutation."
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
        description = "Get one host's full configuration from the inventory. ssh_key path is NOT exposed."
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
        description = "Add a new host to the inventory and persist to disk (atomic tmp+rename). The prompto user must have write permission on the inventory file. Validates the host config before persisting and refuses to write an inventory that wouldn't parse back. NOTE: comments and key ordering in the source TOML are NOT preserved across edits."
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
        description = "Add a capability to a host's allowlist (e.g. grant `wake` to a newly-discovered MAC-known host). Idempotent — granting an already-present capability is a no-op."
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
        description = "Remove a capability from a host's allowlist. Idempotent — revoking an absent capability is a no-op."
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
        description = "TCP-probe a list of ports against a host from prompto's vantage point (no SSH). Returns per-port reachability + latency_ms. Useful for verifying which services are actually listening before touching them. Per-probe timeout default 500ms. Capability: none beyond inventory presence."
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
        description = "Composite health probe for a host. Runs a single bash pipeline that gathers uptime, load average, memory (MB), root-disk usage, last-boot time, kernel version, listening sockets (top 30), and failed systemd units. Parses everything into a tight typed report. Replaces ~5 sequential ssh_exec calls with one round-trip. Requires `exec`."
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
        description = "Drive a systemd unit on a remote host (`sudo -n systemctl <action> <unit>`). Action must be one of: start, stop, restart, reload, enable, disable, status, is-active, is-enabled. unit name is validated against shell metacharacters before interpolation. For `status`, stdout is auto-compacted to header + Loaded/Active/Memory/etc lines (the journal tail is dropped — use `mcp_logs` for logs). Requires `sudo_exec`."
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
        description = "Read a file from a remote host (`head -c <max_bytes> -- <path>`). Default max_bytes 65_536; clamped to 1 MB. Path is validated against shell metacharacters. Returns the bytes plus a `truncated` flag set when the read hit the cap (file may be larger). Requires `exec`."
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
        description = "Write bytes to a file on a remote host (`tee -- <path>`, content piped via SSH stdin so no shell quoting applies to the body). Optional `mode` runs `chmod <mode>` after. Set `sudo=true` to use `sudo -n tee` (requires `sudo_exec` capability — otherwise `exec` is enough). Path is validated against shell metacharacters."
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
        description = "Run a Bash script on a remote host. Body piped through SSH stdin (no quoting hell). Output is NOT auto-compacted — bash errors are usually short enough that any compaction would risk dropping context. Requires `exec`."
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
        description = "Run a command via `sudo -n` over SSH (passwordless sudo only — fails fast if a password would be required). Output is run through the same filter chain as `ssh_exec`. Requires `sudo_exec`."
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
        description = "List MCP servers registered in the target client's `~/.claude.json` (`claude mcp list`). Requires the `claude_admin` capability."
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
        description = "Show full config for one registered MCP server on a client (`claude mcp get <name>`). Requires `claude_admin`."
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
        description = "Register an MCP server on a client (`claude mcp add --transport <transport> --scope <scope> <name> <url|cmd>`). Affects the on-disk config; running interactive sessions still need `/mcp` to refresh, but stateless callers like `claude -p` (claudecli's per-message path) pick up the change on their next invocation. Requires `claude_admin`."
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
        description = "Unregister an MCP server on a client (`claude mcp remove --scope <scope> <name>`). Requires `claude_admin`."
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
        description = "Restart claudecli (the Telegram bridge) on a client. Tries `systemctl --user restart claudecli` first, then falls back to re-spawning the tmux session. Best-effort. Requires `claude_admin`."
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
        description = "Health-check every MCP server registered on a client. Reads `claude mcp list` from the client, then probes each entry's URL directly from prompto's host (TCP connect within ~500ms). Distinguishes 'configured but unreachable' (real outage — daemon down or network broken) from 'configured and reachable' (just a stale session — `/mcp` or a fresh `claude -p` will fix it). Requires `claude_admin` on the target client."
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
        description = "Tail the systemd journal of a service on a host (`sudo -n journalctl -u <unit> -n <lines> --no-pager`). Use this to inspect why an MCP daemon (memqdrant, bucciarati, prompto, etc.) is misbehaving. Requires the `sudo_exec` capability on the target. `lines` defaults to 50 and is clamped to 1..=1000."
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
        description = "Returns advice on how to recover from an MCP-server disconnect. There is no in-session re-handshake API in Claude Code today — interactive sessions need `/mcp`, while stateless callers (claudecli's `claude -p`) refresh on every message. Surface this hint to the user when `mcp_status` reports a server as reachable but their tool calls still fail."
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
        description = "Token-savings analytics — how much agent context this prompto instance has saved versus an estimated SSH+bash baseline. Pass `since_secs` to bound the lookback window (e.g. 86400 for the last 24h). Returns total + per-tool breakdown."
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
                 Tools: host_wake, host_sleep, host_status, host_diagnose, vm_list, vm_state, vm_start, vm_stop, vm_ensure_up, ssh_exec, ssh_sudo_exec, python_exec, node_exec, bash_exec, ruby_exec, perl_exec, deno_exec, file_read, file_write, file_list, file_stat, port_scan, service_control, inventory_list, inventory_get_host, inventory_add_host, inventory_remove_host, inventory_grant_capability, inventory_revoke_capability, mcp_list, mcp_get, mcp_add, mcp_remove, mcp_restart_claudecli, mcp_status, mcp_logs, mcp_reconnect_hint, prompto_gain. \
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
