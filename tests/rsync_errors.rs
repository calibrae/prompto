//! `rsync_sync` failure classification, end-to-end: real HTTP router,
//! real rsync between temp dirs, and a fake `ssh` that runs remote
//! commands locally.
//!
//! The fake ssh is used for BOTH hops — prompto → source, and the
//! source's rsync → dest (it is first on the rsync's PATH). It fails on
//! purpose for certain target IPs, reproducing the stderr shapes of the
//! real failures, so each class is produced by real rsync behaviour
//! rather than by hand-written stderr.
//!
//! Skipped (with a message) when rsync is not installed.

use mcp_gain::Tracker;
use prompto::inventory::{Inventory, InventoryStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Drops ssh options, takes the target (`user@ip`, or `-l user ip` as
/// rsync passes it), and runs the rest under /bin/sh with its own dir
/// first on PATH.
const FAKE_SSH: &str = r#"#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-i|-p|-l) shift 2 ;;
    -*) shift ;;
    *) target=${1#*@}; shift; break ;;
  esac
done
[ "$1" = "--" ] && shift
export PATH="$(dirname "$0"):$PATH"
case "$target" in
  127.0.0.11) echo "$target: Permission denied (publickey)." >&2; exit 255 ;;
  127.0.0.12) echo "ssh: connect to host $target port 22: Connection refused" >&2; exit 255 ;;
  127.0.0.13) PATH=/nonexistent exec /bin/sh -c "$*" ;;
esac
exec /bin/sh -c "$*"
"#;

const INVENTORY: &str = r#"
[host.ok]
ip = "127.0.0.10"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.denied]
ip = "127.0.0.11"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.refused]
ip = "127.0.0.12"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.norsync]
ip = "127.0.0.13"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.noexec]
ip = "127.0.0.14"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = []
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
    fn src(&self) -> PathBuf {
        self.dir.path().join("src")
    }
    fn dst(&self) -> PathBuf {
        self.dir.path().join("dst")
    }
}

fn rsync_installed() -> bool {
    std::process::Command::new("rsync")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn spawn_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("bin").join("ssh");
    std::fs::create_dir_all(ssh.parent().unwrap()).unwrap();
    std::fs::write(&ssh, FAKE_SSH).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::create_dir_all(dir.path().join("dst")).unwrap();
    std::fs::write(dir.path().join("src").join("hello.txt"), "hi\n").unwrap();

    let inv = Inventory::from_toml_str(INVENTORY).unwrap();
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(inv, None),
        ssh: Arc::new(SshClient::new(ssh, Duration::from_secs(30))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(5),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth: Default::default(),
        audit: Default::default(),
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
    tokio::time::sleep(Duration::from_millis(80)).await;
    Server { addr, cancel, dir }
}

fn p(path: &Path) -> String {
    format!("{}/", path.display())
}

/// Call `rsync_sync` over the stateless HTTP path; return the JSON-RPC
/// response object.
async fn rsync_sync(server: &Server, args: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "rsync_sync",
            "arguments": args,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let text = reqwest::Client::new()
        .post(format!("http://{}/mcp", server.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "rsync_sync")
        .json(&body)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // SSE (`data: {...}`) or plain JSON.
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(&text);
    serde_json::from_str(raw).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// The JSON-RPC error of a failed call, asserting its class in both
/// `data` and the message, behind the same request ID in both.
fn expect_class(resp: &Value, class: &str) -> Value {
    let err = resp
        .get("error")
        .unwrap_or_else(|| panic!("expected an error, got {resp}"));
    assert_eq!(err["data"]["error_class"], class, "{resp}");
    let rid = err["data"]["request_id"].as_str().expect("data.request_id");
    let msg = err["message"].as_str().unwrap();
    assert!(
        msg.starts_with(&format!("[request_id={rid} error_class={class}")),
        "message must lead with the request ID and the class: {msg}"
    );
    err.clone()
}

macro_rules! require_rsync {
    () => {
        if !rsync_installed() {
            eprintln!("rsync not installed; skipping");
            return;
        }
    };
}

#[tokio::test]
async fn success_reports_null_error_class_and_copies() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "ok", "source_path": p(&s.src()),
                "dest_host": "ok", "dest_path": p(&s.dst()) }),
    )
    .await;
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{resp}"));
    let out: Value = serde_json::from_str(text).unwrap();
    assert_eq!(out["exit_code"], 0, "{out}");
    assert!(out.get("error_class").is_some_and(Value::is_null), "{out}");
    assert_eq!(
        std::fs::read_to_string(s.dst().join("hello.txt")).unwrap(),
        "hi\n"
    );
}

/// The documented precondition failure, which used to come back as
/// "unexplained error (code 255)".
#[tokio::test]
async fn dest_refusing_the_source_is_dest_ssh_auth() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "ok", "source_path": p(&s.src()),
                "dest_host": "denied", "dest_path": p(&s.dst()) }),
    )
    .await;
    let err = expect_class(&resp, "dest_ssh_auth");
    assert_eq!(err["data"]["exit_code"], 255);
    let tail = err["data"]["stderr_tail"].as_str().unwrap();
    assert!(tail.contains("Permission denied (publickey)"), "{tail}");
    assert!(tail.contains("rsync error"), "{tail}");
}

#[tokio::test]
async fn unreachable_dest_is_dest_ssh_connect() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "ok", "source_path": p(&s.src()),
                "dest_host": "refused", "dest_path": p(&s.dst()) }),
    )
    .await;
    expect_class(&resp, "dest_ssh_connect");
}

/// Same 255, other hop: prompto itself can't reach the source.
#[tokio::test]
async fn unreachable_source_is_ssh_connect() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "refused", "source_path": p(&s.src()),
                "dest_host": "ok", "dest_path": p(&s.dst()) }),
    )
    .await;
    expect_class(&resp, "ssh_connect");
}

#[tokio::test]
async fn missing_source_path_is_rsync_partial() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "ok", "source_path": p(&s.dir.path().join("nope")),
                "dest_host": "ok", "dest_path": p(&s.dst()) }),
    )
    .await;
    let err = expect_class(&resp, "rsync_partial");
    assert_eq!(err["data"]["exit_code"], 23);
}

#[tokio::test]
async fn rsync_missing_on_dest() {
    require_rsync!();
    let s = spawn_server().await;
    let resp = rsync_sync(
        &s,
        json!({ "source_host": "ok", "source_path": p(&s.src()),
                "dest_host": "norsync", "dest_path": p(&s.dst()) }),
    )
    .await;
    expect_class(&resp, "rsync_missing");
}

/// Refusals before anything runs: no exit code, no stderr.
#[tokio::test]
async fn preconditions_are_classified() {
    let s = spawn_server().await;
    let src = p(&s.src());
    let dst = p(&s.dst());
    for (args, class) in [
        (
            json!({ "source_host": "ghost", "source_path": src,
                    "dest_host": "ok", "dest_path": dst }),
            "unknown_host",
        ),
        (
            json!({ "source_host": "ok", "source_path": src,
                    "dest_host": "noexec", "dest_path": dst }),
            "refused_capability",
        ),
        (
            json!({ "source_host": "ok", "source_path": "/tmp/a;id",
                    "dest_host": "ok", "dest_path": dst }),
            "invalid_args",
        ),
    ] {
        let err = expect_class(&rsync_sync(&s, args).await, class);
        assert!(err["data"]["exit_code"].is_null(), "{err}");
    }
}
