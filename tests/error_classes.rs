//! Every failure of every tool has an `error_class` (S4.4).
//!
//! Sweeps `tools/list` and drives each tool into every failure this
//! harness can force: an unreachable host (ssh exit 255), a command that
//! fails (exit 1), an unknown host, a host without the capability, a
//! platform without systemd/bash, invalid arguments, arguments that don't
//! parse, and a policy that grants nothing. Then:
//!
//! - every error the caller got carries `error_class`;
//! - every audit record that is not `ok` has an `error_class`;
//! - no error reached `finish_tool` unclassified
//!   (`error_class::unclassified_count`, process-wide — which is why this
//!   sweep lives alone in its own test binary);
//! - every tool failed at least once, so none was skipped.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::audit::{Audit, AuditLog};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const FAKE_SSH: &str = r#"#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-i|-p|-l) shift 2 ;;
    -*) shift ;;
    *) target=${1#*@}; shift; break ;;
  esac
done
case "$target" in
  127.0.0.40) echo "ssh: connect to host 127.0.0.40 port 22: Connection refused" >&2; exit 255 ;;
  127.0.0.41) echo "boom" >&2; exit 1 ;;
esac
exit 0
"#;

// No `wake` anywhere (it would need a MAC): `host_wake` and
// `vm_ensure_up` fail on the capability and never send a real packet.
const INVENTORY: &str = r#"
[host.down]
ip = "127.0.0.40"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec", "virt"]

[host.failing]
ip = "127.0.0.41"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec", "virt"]

[host.bare]
ip = "127.0.0.42"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = []

[host.fw]
ip = "127.0.0.43"
ssh_user = "admin"
ssh_key = "/dev/null"
platform = "freebsd"
capabilities = ["exec", "sudo_exec"]
"#;

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    audit_path: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn spawn(mode: AuthMode, policy: &str) -> Server {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    std::fs::write(&ssh, FAKE_SSH).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let h = prompto::agent::hex(&prompto::agent::sha256(b"pto_dev"));
    let agents = format!("[agent.dev]\ntoken_sha256 = \"{h}\"\n");
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(SshClient::new(ssh, Duration::from_secs(10))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(1),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth: AuthConfig {
            mode,
            store: AgentStore::new(Agents::from_toml_str(&agents).unwrap(), None),
            policy: PolicyStore::new(Policy::from_toml_str(policy, "policy.toml").unwrap(), None),
            approvals: Default::default(),
        },
        audit: Audit::new(AuditLog::open(audit_path.clone(), None, mode != AuthMode::Off).unwrap()),
        kill: prompto::kill::KillSwitch::in_dir(dir.path()),
        cancel: cancel.clone(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Server {
        addr,
        cancel,
        audit_path,
        _dir: dir,
    }
}

async fn rpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("authorization", "Bearer pto_dev");
    if let Some(n) = params["name"].as_str() {
        req = req.header("mcp-name", n.to_string());
    }
    let text = req
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(&text);
    serde_json::from_str(raw).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// Arguments that pass every tool's validation, aimed at `host`.
fn args_for(tool: &str, host: &str) -> Value {
    match tool {
        "rsync_sync" => json!({
            "source_host": host, "source_path": "/tmp/a/", "dest_host": host, "dest_path": "/tmp/b/"
        }),
        "inventory_get_host" => json!({ "name": host }),
        _ => json!({
            "host": host, "cmd": "true", "commands": ["true"], "script": "true",
            "path": "/tmp/x", "content": "x", "vm": "v", "unit": "u", "action": "restart",
            "ports": [9], "probe_ms": 50, "step_timeout_secs": 1,
            "total_timeout_secs": 1, "timeout_secs": 5
        }),
    }
}

/// The same with every validated field made invalid.
fn invalid_args(tool: &str) -> Value {
    let mut a = args_for(tool, "failing");
    let bad = [
        ("path", json!("a b")),
        ("source_path", json!("a;b")),
        ("unit", json!("u;rm")),
        ("vm", json!("v m")),
        ("commands", json!([])),
        ("name", json!("x y")),
        ("cmd", json!(" ")),
        ("action", json!("explode")),
        ("mode", json!("rwx")),
        ("args", json!(["a b"])),
    ];
    for (k, v) in bad {
        if a.get(k).is_some() || ["mode", "args"].contains(&k) {
            a[k] = v;
        }
    }
    a
}

/// Remove a required field so the arguments don't parse.
fn unparseable(tool: &str) -> Value {
    let mut a = args_for(tool, "failing");
    if let Some(m) = a.as_object_mut() {
        for k in ["host", "name", "source_host"] {
            m.remove(k);
        }
    }
    a
}

#[tokio::test]
async fn every_tool_failure_is_classified() {
    let before = prompto::error_class::unclassified_count();
    let off = spawn(AuthMode::Off, "").await;
    let list = rpc(off.addr, "tools/list", json!({})).await;
    let tools: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(tools.len() >= 21, "{tools:?}");

    let mut missing = Vec::new();
    let mut check = |tool: &str, what: &str, resp: &Value| {
        let failed = resp.get("error").is_some() || resp["result"]["isError"] == true;
        if resp.get("error").is_some() && !resp["error"]["data"]["error_class"].is_string() {
            missing.push(format!(
                "{tool} [{what}]: error without error_class: {resp}"
            ));
        }
        failed
    };
    for tool in &tools {
        let mut scenarios: Vec<(&str, Value)> = vec![
            ("unreachable", args_for(tool, "down")),
            ("failing", args_for(tool, "failing")),
            ("unknown host", args_for(tool, "ghost")),
            ("no capability", args_for(tool, "bare")),
            ("no systemd or bash", args_for(tool, "fw")),
            ("invalid args", invalid_args(tool)),
            ("unparseable", unparseable(tool)),
        ];
        // sudo variant of file_write (the vault-less sudo path).
        if tool == "file_write" {
            let mut a = args_for(tool, "failing");
            a["sudo"] = true.into();
            scenarios.push(("sudo", a));
        }
        for (what, args) in scenarios {
            let resp = rpc(
                off.addr,
                "tools/call",
                json!({ "name": tool, "arguments": args }),
            )
            .await;
            check(tool, what, &resp);
        }
    }

    // A policy that grants nothing: every tool, hostless ones included,
    // is refused — and classified.
    let none = spawn(AuthMode::Required, "").await;
    for tool in &tools {
        let resp = rpc(
            none.addr,
            "tools/call",
            json!({ "name": tool, "arguments": args_for(tool, "failing") }),
        )
        .await;
        // (Capability is checked before policy, so host_wake says so.)
        let class = resp["error"]["data"]["error_class"].as_str();
        assert!(
            matches!(class, Some("refused_policy" | "refused_capability")),
            "{tool}: {resp}"
        );
    }

    assert!(missing.is_empty(), "{}", missing.join("\n"));
    assert_eq!(
        prompto::error_class::unclassified_count(),
        before,
        "some tool error reached finish_tool without an error_class (see the BUG log line)"
    );

    // The audit: every failed call has a class, and every tool failed.
    let mut failed_tools = BTreeSet::new();
    for s in [&off, &none] {
        let text = std::fs::read_to_string(&s.audit_path).unwrap();
        for line in text.lines() {
            let r: Value = serde_json::from_str(line).unwrap();
            if r["ok"] == false {
                assert!(r["error_class"].is_string(), "failed without a class: {r}");
                failed_tools.insert(r["tool"].as_str().unwrap().to_string());
            }
        }
    }
    let never: Vec<&String> = tools
        .iter()
        .filter(|t| !failed_tools.contains(*t))
        .collect();
    assert!(never.is_empty(), "never driven into a failure: {never:?}");
}
