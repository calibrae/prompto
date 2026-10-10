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
  127.0.0.20|127.0.0.21|127.0.0.23|127.0.0.26) umask 022; PATH="$dir:$PATH" exec /bin/sh -c "$*" ;;
  127.0.0.25) PATH="$dir" exec /bin/sh -c "$*" ;;
esac
exit 0
"#;

/// `sudo [-k] [-n] [-S] [-p prompt] -- cmd…`: with -S, consume the
/// password line from stdin; then run cmd in an emptied environment.
/// "Root" is `rootbin/` first on PATH (`id -u` → 0, `whoami` → root)
/// and umask 077, so a file a redirect creates as root is mode 600
/// (the ssh user's umask is 022).
const FAKE_SUDO: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
umask 077
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
exec env -i PATH="$dir/rootbin:/usr/bin:/bin" "$@"
"#;

const FAKE_ROOT_ID: &str = r#"#!/bin/sh
case "$1" in
  -u) echo 0 ;;
  -un|-nu) echo root ;;
  *) echo 'uid=0(root) gid=0(root) groups=0(root)' ;;
esac
"#;

const FAKE_ROOT_WHOAMI: &str = "#!/bin/sh\necho root\n";

/// `virsh -c URI list --all` / `virsh -c URI domstate <vm>`: domains
/// `web` (running) and `db` (shut off).
const FAKE_VIRSH: &str = r#"#!/bin/sh
shift 2
case "$1" in
  list) printf ' Id   Name   State\n---------------------\n 1    web    running\n -    db     shut off\n' ;;
  domstate) case "$2" in
    web) echo running ;;
    db) echo 'shut off' ;;
    *) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
  esac ;;
esac
"#;

/// GNU `stat -c FORMAT -- path`, on any test machine.
const FAKE_STAT: &str =
    "#!/bin/sh\necho '640|12|admin|wheel|2026-10-10 12:00:00.5 +0200|regular file|/etc/x'\n";

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
capabilities = ["wake", "exec", "sudo_exec", "virt"]

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

# FreeBSD: no bash, so ssh_batch is driven by /bin/sh (task 017).
[host.bsd]
ip = "127.0.0.23"
ssh_user = "admin"
ssh_key = "/dev/null"
platform = "freebsd"
capabilities = ["exec"]

[host.win]
ip = "127.0.0.24"
ssh_user = "admin"
ssh_key = "/dev/null"
platform = "windows"
capabilities = ["exec"]

# Runs commands with nothing on PATH (no bash).
[host.bare]
ip = "127.0.0.25"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

# A hypervisor; `virsh` and `stat` are the fakes below.
[host.hyper]
ip = "127.0.0.26"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "virt"]

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
    let rootbin = dir.path().join("rootbin");
    std::fs::create_dir(&rootbin).unwrap();
    write_exe(&rootbin.join("id"), FAKE_ROOT_ID);
    write_exe(&rootbin.join("whoami"), FAKE_ROOT_WHOAMI);
    write_exe(&dir.path().join("virsh"), FAKE_VIRSH);
    write_exe(&dir.path().join("stat"), FAKE_STAT);

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
async fn invalid_args_error_carries_request_id_in_data_and_message() {
    let s = spawn_server().await;
    let resp = call(&s, "ssh_batch", json!({ "host": "runner", "commands": [] })).await;
    let err = &resp["error"];
    let rid = err["data"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{resp}"));
    assert_ulid(rid);
    assert_eq!(err["data"]["error_class"], "invalid_args", "{resp}");
    assert_eq!(
        err["message"],
        format!("[request_id={rid} error_class=invalid_args] commands list is empty")
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
const NEVER_CONTACTS_A_HOST: &[&str] = &["inventory_list", "prompto_gain", "inventory_get_host"];

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
        _ => json!({
            "host": "loopback", "cmd": "true", "commands": ["true"], "script": "true",
            "path": "/tmp/x", "content": "x", "vm": "v", "unit": "u", "action": "status",
            "ports": [9], "probe_ms": 50, "step_timeout_secs": 1,
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
    assert!(tools.len() >= 21, "tools/list looks short: {tools:?}");

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

/// `sudo -n` host, compound command: the whole of it runs as root, as on
/// vault hosts. Before task 018 only `id -u` was elevated and `whoami`
/// ran as the ssh user.
#[tokio::test]
async fn compound_command_runs_entirely_as_root_on_sudo_n_hosts() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_sudo_exec",
        json!({ "host": "runner", "cmd": "id -u; whoami" }),
    )
    .await;
    let out = ok_payload(&resp);
    assert_eq!(out["stdout"], "0\nroot\n", "{out}");
    let argv = s.argv_log();
    assert!(
        argv.lines().any(|l| l.ends_with("sudo -n -- sh -s")),
        "{argv}"
    );
    assert!(!argv.contains("whoami"), "command belongs on stdin: {argv}");
}

/// A redirect is opened by root's shell, not the ssh user's, and the
/// request ID reaches that shell although sudo reset the environment.
#[tokio::test]
async fn redirect_lands_as_root_on_sudo_n_hosts() {
    use std::os::unix::fs::PermissionsExt;
    let s = spawn_server().await;
    let target = s.dir.path().join("as-root");
    let cmd = format!(
        "sh -c 'echo rid=$PROMPTO_REQUEST_ID' > {}",
        target.display()
    );
    let resp = call(&s, "ssh_sudo_exec", json!({ "host": "runner", "cmd": cmd })).await;
    let out = ok_payload(&resp);
    assert_eq!(out["exit_code"], 0, "{out}");
    let rid = out["request_id"].as_str().unwrap();
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        format!("rid={rid}\n")
    );
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "created outside the root shell: {mode:o}");
}

/// A command of plain words keeps `sudo -n -- <cmd>`, so narrow sudoers
/// rules (`NOPASSWD: /usr/bin/systemctl restart nginx`) still match.
#[tokio::test]
async fn simple_command_keeps_plain_sudo_n() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_sudo_exec",
        json!({ "host": "runner", "cmd": "id -u" }),
    )
    .await;
    assert_eq!(ok_payload(&resp)["stdout"], "0\n");
    let argv = s.argv_log();
    assert!(
        argv.lines().any(|l| l.ends_with("sudo -n -- id -u")),
        "{argv}"
    );
}

/// No bash on the host (FreeBSD, OPNsense): `bash_exec` says so instead
/// of the generic `remote_nonzero`.
#[tokio::test]
async fn missing_interpreter_is_classified() {
    let s = spawn_server().await;
    let resp = call(&s, "bash_exec", json!({ "host": "bare", "script": "true" })).await;
    let out = ok_payload(&resp);
    assert_eq!(out["exit_code"], 127, "{out}");
    assert_eq!(out["error_class"], "interpreter_missing", "{out}");
    // The same failure through another tool is that command's own.
    let resp = call(&s, "ssh_exec", json!({ "host": "bare", "cmd": "bash -s" })).await;
    assert_eq!(ok_payload(&resp)["error_class"], "remote_nonzero");
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

/// FreeBSD has no bash: ssh_batch sends its POSIX script to `/bin/sh`
/// (run here by the local /bin/sh) and every command comes back. Before
/// task 017 this was refused with "ssh_batch needs bash".
#[tokio::test]
async fn ssh_batch_on_freebsd_runs_under_sh() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_batch",
        json!({ "host": "bsd", "commands": ["echo one", "echo two; exit 4", "echo never"] }),
    )
    .await;
    let out = ok_payload(&resp);
    let items = out["items"].as_array().unwrap_or_else(|| panic!("{resp}"));
    assert_eq!(items[0]["output"], "one", "{out}");
    assert_eq!(items[1]["output"], "two", "{out}");
    assert_eq!(items[1]["exit_code"], 4, "{out}");
    assert_eq!(items[2]["skipped"], true, "{out}");
    assert_eq!(out["all_ok"], false, "{out}");
    let argv = s.argv_log();
    assert!(argv.lines().any(|l| l == "/bin/sh"), "{argv}");
    assert!(!argv.lines().any(|l| l.contains("bash")), "{argv}");
}

/// No POSIX shell at all: still a clear refusal, nothing sent.
#[tokio::test]
async fn ssh_batch_on_windows_is_refused() {
    let s = spawn_server().await;
    let resp = call(
        &s,
        "ssh_batch",
        json!({ "host": "win", "commands": ["dir"] }),
    )
    .await;
    assert_eq!(
        resp["error"]["data"]["error_class"], "refused_capability",
        "{resp}"
    );
    assert!(s.argv_log().is_empty(), "{}", s.argv_log());
}

/// v0.12.3 merged `vm_state` into `vm_list`: `vm` narrows the list to
/// that domain, same row shape, and a domain that doesn't exist is an
/// error, not an empty list.
#[tokio::test]
async fn vm_list_with_vm_is_that_domains_row() {
    let s = spawn_server().await;
    let resp = call(&s, "vm_list", json!({ "host": "hyper" })).await;
    let all: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        all,
        json!([{ "name": "web", "state": "running" }, { "name": "db", "state": "shut off" }])
    );
    let resp = call(&s, "vm_list", json!({ "host": "hyper", "vm": "db" })).await;
    let one: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(one, json!([{ "name": "db", "state": "shut off" }]));
    assert!(s.argv_log().contains("domstate db"), "{}", s.argv_log());
    let resp = call(&s, "vm_list", json!({ "host": "hyper", "vm": "nope" })).await;
    assert_eq!(
        resp["error"]["data"]["error_class"], "remote_nonzero",
        "{resp}"
    );
    // The name is checked before it reaches a shell.
    let resp = call(&s, "vm_list", json!({ "host": "hyper", "vm": "a;b" })).await;
    assert_eq!(
        resp["error"]["data"]["error_class"], "invalid_args",
        "{resp}"
    );
}

/// v0.12.3 merged `file_stat` into `file_list`: `stat_only` returns what
/// `file_stat` did (plus `path`), and runs `stat`, not `ls`.
#[tokio::test]
async fn file_list_stat_only_is_the_old_file_stat() {
    let s = spawn_server().await;
    let v = ok_payload(
        &call(
            &s,
            "file_list",
            json!({ "host": "hyper", "path": "/etc/x", "stat_only": true }),
        )
        .await,
    );
    assert_eq!(v["host"], "hyper", "{v}");
    assert_eq!(v["path"], "/etc/x", "{v}");
    assert_eq!(v["stat"]["mode"], "640", "{v}");
    assert_eq!(v["stat"]["size"], 12, "{v}");
    assert_eq!(v["stat"]["kind"], "regular file", "{v}");
    assert!(v["raw"].as_str().unwrap().starts_with("640|"), "{v}");
    let argv = s.argv_log();
    assert!(
        argv.contains("stat -c") && !argv.contains("ls -la"),
        "{argv}"
    );
    // A bad path is refused before anything runs, as for a listing.
    let resp = call(
        &s,
        "file_list",
        json!({ "host": "hyper", "path": "/etc/x;id", "stat_only": true }),
    )
    .await;
    assert_eq!(
        resp["error"]["data"]["error_class"], "invalid_args",
        "{resp}"
    );
}
