//! Call context end-to-end, through the shipping HTTP router:
//!
//! - every result carries a `request_id`, on success and on error (in
//!   `error.data` and the message prefix);
//! - the self-targeting guard covers every tool that reaches a host, with
//!   no exemptions — enumerated from `tools/list`, so a new tool is
//!   covered the day it appears;
//! - `PROMPTO_REQUEST_ID` reaches the remote command, including the root
//!   side of the vault sudo path, without the password reaching argv.
//!
//! A fake `ssh` logs its argv and, for the two "runner" IPs, runs the
//! remote command locally under /bin/sh with a fake `sudo` first on PATH.
//! The fake sudo eats the password line like `sudo -S` and then wipes
//! the environment like `env_reset`, so the request ID can only reach the
//! root shell through prompto's own plumbing. Every other target IP is a
//! no-op that exits 0: nothing a tool asks for runs on this machine.

use axum::{Json, Router, routing::get};
use mcp_gain::Tracker;
use prompto::inventory::{Inventory, InventoryStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use prompto::vault::VaultClient;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "canary-pw-must-not-leak";

const FAKE_SSH: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
printf '%s\n' "$@" >> "$dir/argv.log"
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-i|-p|-l) shift 2 ;;
    -*) shift ;;
    *) target=${1#*@}; shift; break ;;
  esac
done
[ "$1" = "--" ] && shift
case "$target" in
  127.0.0.20|127.0.0.21) PATH="$dir:$PATH" exec /bin/sh -c "$*" ;;
esac
exit 0
"#;

/// `sudo [-k] [-n] [-S] [-p prompt] -- cmd…`: with -S, consume the
/// password line from stdin; then run cmd in an emptied environment.
const FAKE_SUDO: &str = r#"#!/bin/sh
s=0
while [ $# -gt 0 ]; do
  case "$1" in
    -S) s=1; shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ $s = 1 ] && IFS= read -r _pw
exec env -i PATH=/usr/bin:/bin "$@"
"#;

const INVENTORY: &str = r#"
# The test client connects from 127.0.0.1: targeting `loopback` is
# self-targeting. It carries every capability, so each tool gets past the
# capability check and reaches the guard. (`wake` uses a locally
# administered MAC; the guard refuses before any packet would be sent.)
[host.loopback]
ip = "127.0.0.1"
mac = "02:00:00:00:00:01"
ssh_user = "admin"
ssh_key = "/dev/null"
apytti_url = "http://127.0.0.1:9"
capabilities = ["wake", "exec", "sudo_exec", "virt", "claude_admin", "claude_exec"]

[host.runner]
ip = "127.0.0.20"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]

# Its key is restricted (`command=`, rrsync…): nothing may be added to
# the command line.
[host.restricted]
ip = "127.0.0.22"
ssh_user = "admin"
ssh_key = "/dev/null"
request_id_env = "off"
capabilities = ["exec"]

[host.vaulted]
ip = "127.0.0.21"
ssh_user = "admin"
ssh_key = "/dev/null"
sudo_password_vault_path = "infra/default"
capabilities = ["exec", "sudo_exec"]
"#;

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Server {
    fn argv_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("argv.log")).unwrap_or_default()
    }
}

fn write_exe(path: &PathBuf, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn spawn_fake_vault() -> String {
    let app = Router::new().route(
        "/v1/secret/data/infra/default",
        get(|| async { Json(json!({ "data": { "data": { "password": PASSWORD } } })) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    format!("http://{addr}")
}

async fn spawn_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    write_exe(&ssh, FAKE_SSH);
    write_exe(&dir.path().join("sudo"), FAKE_SUDO);

    let vault = VaultClient::new(spawn_fake_vault().await, "secret", "tok");
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(SshClient::new(ssh, Duration::from_secs(10)).with_vault(Arc::new(vault))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(1),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth: Default::default(),
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
    tokio::time::sleep(Duration::from_millis(80)).await;
    Server { addr, cancel, dir }
}

/// One JSON-RPC request over the 2026-07-28 stateless path; returns the
/// response object.
async fn rpc(server: &Server, method: &str, name: Option<&str>, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/mcp", server.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(n) = name {
        req = req.header("mcp-name", n);
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

async fn call(server: &Server, tool: &str, args: Value) -> Value {
    rpc(
        server,
        "tools/call",
        Some(tool),
        json!({ "name": tool, "arguments": args }),
    )
    .await
}

/// The first content block of a successful result, parsed as JSON.
fn ok_payload(resp: &Value) -> Value {
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a result, got {resp}"));
    serde_json::from_str(text).unwrap()
}

fn assert_ulid(id: &str) {
    assert_eq!(id.len(), 26, "{id}");
    assert!(id.parse::<ulid::Ulid>().is_ok(), "not a ULID: {id}");
}

#[tokio::test]
async fn success_results_carry_a_fresh_request_id() {
    let s = spawn_server().await;
    let a = ok_payload(&call(&s, "inventory_list", json!({})).await);
    let b = ok_payload(&call(&s, "inventory_list", json!({})).await);
    let (a, b) = (
        a["request_id"].as_str().unwrap(),
        b["request_id"].as_str().unwrap(),
    );
    assert_ulid(a);
    assert_ne!(a, b, "every call needs its own ID");
}

#[tokio::test]
async fn unclassified_error_carries_request_id_in_data_and_message() {
    let s = spawn_server().await;
    let resp = call(&s, "ssh_batch", json!({ "host": "runner", "commands": [] })).await;
    let err = &resp["error"];
    let rid = err["data"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{resp}"));
    assert_ulid(rid);
    assert_eq!(
        err["message"],
        format!("[request_id={rid}] commands list is empty")
    );
}

#[tokio::test]
async fn classified_error_merges_request_id_with_the_class() {
    let s = spawn_server().await;
    let resp = call(&s, "ssh_exec", json!({ "host": "ghost", "cmd": "true" })).await;
    let err = &resp["error"];
    assert_eq!(err["data"]["error_class"], "unknown_host", "{resp}");
    let rid = err["data"]["request_id"].as_str().unwrap();
    assert_ulid(rid);
    let msg = err["message"].as_str().unwrap();
    assert!(
        msg.starts_with(&format!("[request_id={rid} error_class=unknown_host] ")),
        "{msg}"
    );
}

/// Tools that never contact a host: the hostless ones, and
/// `inventory_get_host`, which only reads the inventory. Everything else
/// must refuse the caller's own machine.
const NEVER_CONTACTS_A_HOST: &[&str] = &[
    "inventory_list",
    "mcp_reconnect_hint",
    "prompto_gain",
    "inventory_get_host",
];

/// The refusal an agent sees for its own host (`loopback`, 127.0.0.1).
const SELF_TARGET_MSG: &str = "refused_self_target: you are calling from loopback (127.0.0.1) \
     — prompto never acts on the caller's own machine; run this in your local shell instead.";

/// Arguments that pass every tool's own validation, aimed at `loopback`.
fn self_targeting_args(tool: &str) -> Value {
    match tool {
        "rsync_sync" => json!({
            "source_host": "loopback", "source_path": "/tmp/a/",
            "dest_host": "runner", "dest_path": "/tmp/b/"
        }),
        "inventory_get_host" => json!({ "name": "loopback" }),
        "mcp_list" | "mcp_status" | "mcp_restart_claudecli" => json!({ "client": "loopback" }),
        "mcp_get" | "mcp_remove" => json!({ "client": "loopback", "name": "x" }),
        "mcp_add" => json!({
            "client": "loopback", "name": "x", "transport": "http", "url_or_cmd": "http://x"
        }),
        _ => json!({
            "host": "loopback", "cmd": "true", "commands": ["true"], "script": "true",
            "path": "/tmp/x", "content": "x", "vm": "v", "unit": "u", "action": "status",
            "ports": [9], "task": "t", "probe_ms": 50, "step_timeout_secs": 1,
            "total_timeout_secs": 1
        }),
    }
}

/// THE test for the universal guard. Every tool `tools/list` advertises
/// is called against the caller's own host and must be refused as
/// `refused_self_target`, unless it never contacts a host. There is no
/// exemption list to consult: a new tool is expected to refuse.
/// Removing the guard, or a handler skipping `authorize`, fails here.
#[tokio::test]
async fn every_host_contacting_tool_refuses_self_targeting() {
    let s = spawn_server().await;
    let list = rpc(&s, "tools/list", None, json!({})).await;
    let tools: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{list}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(tools.len() >= 38, "tools/list looks short: {tools:?}");

    let mut wrong = Vec::new();
    for tool in &tools {
        let resp = call(&s, tool, self_targeting_args(tool)).await;
        let class = resp["error"]["data"]["error_class"].as_str();
        let exempt = NEVER_CONTACTS_A_HOST.contains(&tool.as_str());
        let refused = class == Some("refused_self_target");
        if refused == exempt {
            wrong.push(format!("{tool} (never contacts a host={exempt}): {resp}"));
        }
        if refused {
            let msg = resp["error"]["message"].as_str().unwrap();
            assert!(msg.ends_with(SELF_TARGET_MSG), "{tool}: {msg}");
        }
    }
    assert!(wrong.is_empty(), "guard wrong for:\n{}", wrong.join("\n"));
}

/// The one host-addressed tool that may name the caller's own machine:
/// it reads the inventory and never contacts the host.
#[tokio::test]
async fn inventory_get_host_may_name_the_callers_own_host() {
    let s = spawn_server().await;
    let out = ok_payload(&call(&s, "inventory_get_host", json!({ "name": "loopback" })).await);
    assert_eq!(out["name"], "loopback");
    assert_eq!(out["request_id_env"], "export");
}

/// rsync_sync guards its dest too: files written onto the caller's own
/// box as the dest's ssh_user are the same escape as file_write.
#[tokio::test]
async fn rsync_dest_on_the_callers_host_is_refused() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "rsync_sync",
        json!({ "source_host": "runner", "source_path": "/tmp/a/",
                "dest_host": "loopback", "dest_path": "/tmp/b/" }),
    )
    .await;
    assert_eq!(
        resp["error"]["data"]["error_class"], "refused_self_target",
        "{resp}"
    );
}

/// A child process sees the variable, so it is exported, not just set.
#[tokio::test]
async fn request_id_reaches_the_remote_command() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_exec",
        json!({ "host": "runner", "cmd": "sh -c 'echo rid=$PROMPTO_REQUEST_ID'" }),
    )
    .await;
    let out = ok_payload(&resp);
    let rid = out["request_id"].as_str().unwrap();
    assert_eq!(out["stdout"], format!("rid={rid}\n"), "{out}");
    assert!(
        s.argv_log()
            .contains(&format!("SetEnv=PROMPTO_REQUEST_ID={rid}")),
        "SetEnv missing from ssh argv: {}",
        s.argv_log()
    );
}

/// `request_id_env = "off"`: ssh gets the caller's command verbatim and
/// no SetEnv, so a forced-command key sees nothing prompto added.
#[tokio::test]
async fn request_id_env_off_leaves_the_command_line_alone() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_exec",
        json!({ "host": "restricted", "cmd": "uptime" }),
    )
    .await;
    ok_payload(&resp);
    let argv = s.argv_log();
    assert!(argv.lines().any(|l| l == "uptime"), "{argv}");
    assert!(!argv.contains("PROMPTO_REQUEST_ID"), "{argv}");
}

/// The vault sudo path: sudo wipes the environment, so the ID reaches the
/// root shell only through prompto's `env` in the guarded command. The
/// guard/marker protocol must still work, and the password must appear
/// in neither ssh's argv nor the result.
#[tokio::test]
async fn request_id_reaches_root_on_the_vault_sudo_path() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_sudo_exec",
        json!({ "host": "vaulted", "cmd": "echo rid=$PROMPTO_REQUEST_ID" }),
    )
    .await;
    let out = ok_payload(&resp);
    let rid = out["request_id"].as_str().unwrap();
    assert_eq!(out["exit_code"], 0, "{out}");
    assert_eq!(out["stdout"], format!("rid={rid}\n"), "{out}");
    assert!(!resp.to_string().contains(PASSWORD), "password in result");
    let argv = s.argv_log();
    assert!(
        argv.contains("prompto-sudo-ok"),
        "not the guarded path: {argv}"
    );
    assert!(!argv.contains(PASSWORD), "password in ssh argv: {argv}");
    assert!(
        !argv.contains("echo rid="),
        "caller's command reached argv on the vault path: {argv}"
    );
}

/// `/log` goes through the same gate as service_logs, so it refuses the
/// caller's own host and says which request it was.
#[tokio::test]
async fn log_endpoint_refuses_self_target_and_returns_request_id() {
    let s = spawn_server().await;
    let resp = reqwest::get(format!("http://{}/log?host=loopback&unit=x", s.addr))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let rid = resp
        .headers()
        .get(prompto::server::REQUEST_ID_HEADER)
        .expect("request id header")
        .to_str()
        .unwrap()
        .to_string();
    assert_ulid(&rid);
    let body = resp.text().await.unwrap();
    assert!(body.contains(SELF_TARGET_MSG), "{body}");
}
