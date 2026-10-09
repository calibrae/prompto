//! Policy (E3), end to end.
//!
//! The router tests drive `prompto::server::build_router` — the shipping
//! wiring — with a fake `ssh` that only appends its argv to a log and
//! exits 0, so an allowed call succeeds and a refused one provably never
//! reached ssh. The binary tests run the real executable for what only
//! `main` wires: loading per `PROMPTO_AUTH`, SIGHUP reload and the
//! `policy` CLI.
//!
//! Refusals are asserted alongside successes: a policy layer that refuses
//! everything passes every "is X refused?" test, and one that allows
//! everything passes every "does it still work?" test.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use serde_json::{Value, json};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.log"
echo ran
exit 0
"#;

/// `t1` carries every capability, so every tool gets past the capability
/// check and reaches policy. The client connects from 127.0.0.1, which
/// is `loopback`: targeting it is self-targeting.
const INVENTORY: &str = r#"
[host.t1]
ip = "127.0.0.30"
mac = "02:00:00:00:00:30"
ssh_user = "admin"
ssh_key = "/dev/null"
aliases = ["one"]
groups = ["lab"]
apytti_url = "http://127.0.0.1:9"
capabilities = ["wake", "exec", "sudo_exec", "virt", "claude_admin", "claude_exec"]

[host.t2]
ip = "127.0.0.31"
ssh_user = "admin"
ssh_key = "/dev/null"
groups = ["lab"]
sudo_password_vault_path = "lab/t2"
capabilities = ["exec", "sudo_exec"]

[host.loopback]
ip = "127.0.0.1"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]
"#;

// ---------------------------------------------------------------------------
// Log capture (one global subscriber per test binary; tests find their
// own lines by request ID).
// ---------------------------------------------------------------------------

static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;
impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logs() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter("prompto=info")
            .with_writer(|| Capture)
            .with_ansi(false)
            .init();
    });
}

fn log_lines(needle: &str) -> Vec<String> {
    String::from_utf8_lossy(&LOGS.lock().unwrap())
        .lines()
        .filter(|l| l.contains(needle))
        .map(String::from)
        .collect()
}

// ---------------------------------------------------------------------------
// Router harness
// ---------------------------------------------------------------------------

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

fn agents_toml() -> String {
    let h = |t: &str| prompto::agent::hex(&prompto::agent::sha256(t.as_bytes()));
    format!(
        "[agent.alpha]\ngroups = [\"ops\"]\ntoken_sha256 = \"{}\"\n\n\
         [agent.beta]\ntoken_sha256 = \"{}\"\n",
        h("pto_alpha"),
        h("pto_beta")
    )
}

fn policy(toml: &str) -> PolicyStore {
    PolicyStore::new(Policy::from_toml_str(toml, "policy.toml").unwrap(), None)
}

async fn spawn(mode: AuthMode, agents: AgentStore, policy: PolicyStore) -> Server {
    init_logs();
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&ssh, FAKE_SSH).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(SshClient::new(ssh, Duration::from_secs(5))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(1),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth: AuthConfig {
            mode,
            store: agents,
            policy,
        },
        audit: Default::default(),
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

async fn spawn_with(mode: AuthMode, policy_toml: &str) -> Server {
    let agents = AgentStore::new(Agents::from_toml_str(&agents_toml()).unwrap(), None);
    spawn(mode, agents, policy(policy_toml)).await
}

async fn rpc(addr: SocketAddr, token: Option<&str>, method: &str, params: Value) -> Value {
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
        .header("mcp-method", method);
    if let Some(n) = params["name"].as_str() {
        req = req.header("mcp-name", n.to_string());
    }
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
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

async fn call_at(addr: SocketAddr, token: Option<&str>, tool: &str, args: Value) -> Value {
    rpc(
        addr,
        token,
        "tools/call",
        json!({ "name": tool, "arguments": args }),
    )
    .await
}

async fn call(s: &Server, token: Option<&str>, tool: &str, args: Value) -> Value {
    call_at(s.addr, token, tool, args).await
}

/// `error_class` of a failed call, `None` on success.
fn class(resp: &Value) -> Option<&str> {
    if resp.get("result").is_some() {
        return None;
    }
    Some(
        resp["error"]["data"]["error_class"]
            .as_str()
            .unwrap_or_else(|| panic!("unclassified failure: {resp}")),
    )
}

fn assert_ok(resp: &Value, what: &str) {
    assert!(
        resp.get("result").is_some(),
        "{what}: expected success, got {resp}"
    );
}

fn exec(host: &str) -> Value {
    json!({ "host": host, "cmd": "id -u" })
}

/// Arguments that pass every tool's own validation, aimed at `t1`.
fn args_for(tool: &str) -> Value {
    match tool {
        "rsync_sync" => json!({
            "source_host": "t1", "source_path": "/tmp/a/",
            "dest_host": "t2", "dest_path": "/tmp/b/"
        }),
        "inventory_get_host" => json!({ "name": "t1" }),
        "mcp_list" | "mcp_status" | "mcp_restart_claudecli" => json!({ "client": "t1" }),
        "mcp_get" | "mcp_remove" => json!({ "client": "t1", "name": "x" }),
        "mcp_add" => json!({
            "client": "t1", "name": "x", "transport": "http", "url_or_cmd": "http://x"
        }),
        _ => json!({
            "host": "t1", "cmd": "true", "commands": ["true"], "script": "true",
            "path": "/tmp/x", "content": "x", "vm": "v", "unit": "u", "action": "status",
            "ports": [9], "task": "t", "probe_ms": 50, "step_timeout_secs": 1,
            "total_timeout_secs": 1
        }),
    }
}

/// Every tool name `tools/list` advertises.
async fn list_tools(s: &Server) -> Vec<String> {
    let list = rpc(s.addr, Some("pto_alpha"), "tools/list", json!({})).await;
    let tools: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{list}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(tools.len() >= 38, "tools/list looks short: {tools:?}");
    tools
}

// ---------------------------------------------------------------------------
// Router tests
// ---------------------------------------------------------------------------

/// THE default-deny test. With a policy that grants nothing, every tool
/// `tools/list` advertises — host-targeting, hostless and
/// `inventory_get_host` alike — is refused as `refused_policy`, and ssh
/// is never spawned. A new tool is covered the day it appears; removing
/// the policy check from `authorize`, `authorize_tool` or `lookup`, or a
/// handler skipping them, fails here.
#[tokio::test]
async fn every_tool_is_refused_by_default_deny() {
    let s = spawn_with(AuthMode::Required, "").await;
    let tools = list_tools(&s).await;

    let mut wrong = Vec::new();
    for tool in &tools {
        let resp = call(&s, Some("pto_alpha"), tool, args_for(tool)).await;
        let c = resp["error"]["data"]["error_class"].as_str();
        let rule = resp["error"]["data"]["rule"].as_str();
        if c != Some("refused_policy") || rule != Some("default-deny") {
            wrong.push(format!("{tool}: {resp}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "not refused by policy:\n{}",
        wrong.join("\n")
    );
    assert_eq!(s.argv_log(), "", "a refused call reached ssh");

    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1")).await;
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains(
            "error_class=refused_policy] refused_policy: agent alpha has no grant for \
             ssh_exec on t1 (no rule matched). Ask the operator"
        ),
        "{msg}"
    );
}

/// Every tool `tools/list` advertises is in exactly one class: root-
/// capable (`ROOT_TOOLS` ∪ `SUDO_FLAG_TOOLS`), arbitrary exec
/// (`ARBITRARY_EXEC_TOOLS`) or ordinary (`ORDINARY_TOOLS`), and no list
/// names a tool that doesn't exist. A new tool fails here until someone
/// decides what it is, instead of quietly falling under `tools = ["*"]`.
///
/// The lists are then held to what the server does: under `tools =
/// ["*"]` without sudo, exactly the always-root tools are refused (a
/// sudo-gated tool missing from `ROOT_TOOLS` shows up as refused but
/// unlisted), and each exec tool needs the capability it is listed with.
#[tokio::test]
async fn every_tool_is_classified() {
    use prompto::authz::{ARBITRARY_EXEC_TOOLS, ORDINARY_TOOLS, ROOT_TOOLS, SUDO_FLAG_TOOLS};
    let s = spawn_with(
        AuthMode::Required,
        "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"*\"]\ntools = [\"*\"]\n",
    )
    .await;
    let tools = list_tools(&s).await;
    let root: Vec<&str> = ROOT_TOOLS.iter().chain(SUDO_FLAG_TOOLS).copied().collect();
    let exec: Vec<&str> = ARBITRARY_EXEC_TOOLS.iter().map(|(t, _)| *t).collect();
    let classes = [&root[..], &exec[..], ORDINARY_TOOLS];

    let mut wrong = Vec::new();
    for tool in &tools {
        let n = classes
            .iter()
            .filter(|c| c.contains(&tool.as_str()))
            .count();
        // A sudo-flag tool is root-capable with the flag and arbitrary
        // exec without it (`file_write`), so it is in both.
        let want = if SUDO_FLAG_TOOLS.contains(&tool.as_str()) {
            2
        } else {
            1
        };
        if n != want {
            wrong.push(format!("{tool}: in {n} classes, want exactly {want}"));
        }
    }
    for t in classes.concat() {
        if !tools.iter().any(|x| x == t) {
            wrong.push(format!("{t}: classified, but not in tools/list"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    for tool in &tools {
        let resp = call(&s, Some("pto_alpha"), tool, args_for(tool)).await;
        let refused = resp["error"]["data"]["error_class"] == "refused_policy";
        if refused != ROOT_TOOLS.contains(&tool.as_str()) {
            wrong.push(format!("{tool}: refused={refused}: {resp}"));
        }
    }
    // t2 has exec and sudo_exec only.
    for (tool, cap) in ARBITRARY_EXEC_TOOLS {
        let mut args = args_for(tool);
        for k in ["host", "client"] {
            if args.get(k).is_some() {
                args[k] = "t2".into();
            }
        }
        let resp = call(&s, Some("pto_alpha"), tool, args).await;
        let lacks = resp["error"]["data"]["error_class"] == "refused_capability";
        if lacks == (cap.as_str() == "exec") {
            wrong.push(format!("{tool}: listed with {}: {resp}", cap.as_str()));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

const SUDO_SPLIT: &str = r#"
[[rule]]
id = "lab-exec"
agents = ["alpha"]
hosts = ["group:lab"]
tools = ["*"]

[[rule]]
id = "t1-root"
agents = ["alpha"]
hosts = ["t1"]
tools = ["ssh_sudo_exec", "file_write"]
sudo = true
"#;

/// `ssh_sudo_exec` and `file_write` with `sudo=true` need their own
/// grant: `tools = ["*"]` on t2 grants neither. The refusal names the
/// near miss; the allow is logged with its rule.
#[tokio::test]
async fn sudo_is_a_separate_grant() {
    let s = spawn_with(AuthMode::Required, SUDO_SPLIT).await;
    let a = Some("pto_alpha");

    assert_ok(&call(&s, a, "ssh_exec", exec("t2")).await, "ssh_exec t2");
    assert_ok(
        &call(
            &s,
            a,
            "file_write",
            json!({"host": "t2", "path": "/tmp/x", "content": "x"}),
        )
        .await,
        "file_write t2",
    );
    // `one` is t1's alias: the rule names t1, the caller may use either.
    let resp = call(&s, a, "ssh_sudo_exec", exec("one")).await;
    assert_ok(&resp, "ssh_sudo_exec via alias");

    let rid = serde_json::from_str::<Value>(resp["result"]["content"][0]["text"].as_str().unwrap())
        .unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let allow = log_lines(&rid);
    assert!(
        allow.iter().any(|l| l.contains("policy allow")
            && l.contains("rule=policy.toml:8 (t1-root)")
            && l.contains("agent=alpha")
            && l.contains("root=true")),
        "{allow:?}"
    );

    let before = s.argv_log();
    let resp = call(&s, a, "ssh_sudo_exec", exec("t2")).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
    assert_eq!(resp["error"]["data"]["rule"], "default-deny");
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains(
            "agent alpha has no grant for ssh_sudo_exec (root-capable) on t2 (no rule matched; \
             root-capable calls need a rule with sudo = true — policy.toml:2 (lab-exec) grants \
             ssh_sudo_exec on t2 but without sudo)"
        ),
        "{msg}"
    );
    let resp = call(
        &s,
        a,
        "file_write",
        json!({"host": "t2", "path": "/tmp/x", "content": "x", "sudo": true}),
    )
    .await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
    // Root-capable, and not in t1-root's tools.
    let resp = call(
        &s,
        a,
        "service_control",
        json!({"host": "t1", "unit": "u", "action": "status"}),
    )
    .await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
    assert_eq!(s.argv_log(), before, "a refused call reached ssh");

    // beta is in no rule.
    let resp = call(&s, Some("pto_beta"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
}

/// `approval = "ticket" | "human"` cannot be satisfied before E6, so the
/// call is refused — never silently allowed — and the refusal names the
/// rule and the approval it wants.
#[tokio::test]
async fn approval_fails_closed() {
    let s = spawn_with(
        AuthMode::Required,
        r#"
[[rule]]
id = "t1-needs-human"
agents = ["alpha"]
hosts = ["t1"]
tools = ["ssh_sudo_exec"]
sudo = true
approval = "human"

[[rule]]
agents = ["alpha"]
hosts = ["*"]
tools = ["ssh_exec"]
approval = "ticket"
"#,
    )
    .await;
    for (tool, approval, rule) in [
        ("ssh_sudo_exec", "human", "policy.toml:2 (t1-needs-human)"),
        ("ssh_exec", "ticket", "policy.toml:10"),
    ] {
        let resp = call(&s, Some("pto_alpha"), tool, exec("t1")).await;
        assert_eq!(class(&resp), Some("approval_required"), "{resp}");
        assert_eq!(resp["error"]["data"]["rule"], rule);
        let msg = resp["error"]["message"].as_str().unwrap();
        assert!(
            msg.contains(&format!(
                "approval_required: rule {rule} grants agent alpha"
            )) && msg.contains(&format!("approval = \"{approval}\"")),
            "{msg}"
        );
    }
    assert_eq!(s.argv_log(), "", "an unapproved call reached ssh");
}

/// S3.3b: the self-target guard runs before policy, so a policy granting
/// everything, root included, still can't reach the caller's own box.
#[tokio::test]
async fn policy_cannot_grant_self_targeting() {
    let all = r#"
[[rule]]
agents = ["alpha"]
hosts = ["*"]
tools = ["*"]
[[rule]]
agents = ["alpha"]
hosts = ["*"]
tools = ["*"]
sudo = true
"#;
    let s = spawn_with(AuthMode::Required, all).await;
    for tool in ["ssh_exec", "ssh_sudo_exec"] {
        let resp = call(&s, Some("pto_alpha"), tool, exec("loopback")).await;
        assert_eq!(class(&resp), Some("refused_self_target"), "{tool}: {resp}");
    }
    assert_ok(
        &call(&s, Some("pto_alpha"), "ssh_sudo_exec", exec("t1")).await,
        "the same policy does grant other hosts",
    );
}

/// `/log` is the `service_logs` tool over plain HTTP: same policy, root
/// grant included. A refusal is a 403.
#[tokio::test]
async fn log_endpoint_is_policy_gated() {
    let get = |s: &Server| {
        let url = format!("http://{}/log?host=t1&unit=ssh.service", s.addr);
        async move {
            let r = reqwest::Client::new()
                .get(url)
                .header("authorization", "Bearer pto_alpha")
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let s = spawn_with(
        AuthMode::Required,
        "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"t1\"]\ntools = [\"*\"]\n",
    )
    .await;
    let (status, body) = get(&s).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("refused_policy") && body.contains("service_logs (root-capable)"),
        "{body}"
    );
    assert_eq!(s.argv_log(), "");

    let s = spawn_with(
        AuthMode::Required,
        "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"t1\"]\ntools = [\"service_logs\"]\nsudo = true\n",
    )
    .await;
    let (status, body) = get(&s).await;
    assert_eq!(status, 200, "{body}");
}

/// Optional mode: `anonymous` gets exactly what rules name `anonymous`
/// for, and nothing granted to real agents.
#[tokio::test]
async fn anonymous_gets_only_anonymous_grants() {
    let s = spawn_with(
        AuthMode::Optional,
        r#"
[[rule]]
agents = ["anonymous"]
hosts = ["*"]
tools = ["inventory_list"]

[[rule]]
agents = ["alpha"]
hosts = ["*"]
tools = ["ssh_exec"]
"#,
    )
    .await;
    assert_ok(
        &call(&s, None, "inventory_list", json!({})).await,
        "anonymous list",
    );
    let resp = call(&s, None, "ssh_exec", exec("t1")).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("agent anonymous has no grant for ssh_exec on t1"),
        "{resp}"
    );
    // A bad token degrades to anonymous: same answer.
    let resp = call(&s, Some("pto_wrong"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
    assert_ok(
        &call(&s, Some("pto_alpha"), "ssh_exec", exec("t1")).await,
        "alpha",
    );
    let resp = call(&s, Some("pto_alpha"), "inventory_list", json!({})).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
}

/// `PROMPTO_AUTH=off` applies no policy at all, even a deny-all one:
/// behaviour is exactly pre-E3.
#[tokio::test]
async fn auth_off_applies_no_policy() {
    let s = spawn_with(AuthMode::Off, "").await;
    assert_ok(&call(&s, None, "ssh_sudo_exec", exec("t1")).await, "off");
    let resp = call(&s, None, "inventory_list", json!({})).await;
    let hosts = ok_text(&resp)["hosts"].as_array().unwrap().clone();
    // Hosts without groups read exactly as before E3: no `groups` key.
    for h in hosts {
        let expect_groups = h["name"] != "loopback";
        assert_eq!(h.get("groups").is_some(), expect_groups, "{h}");
    }
    let t1 = ok_text(&call(&s, None, "inventory_get_host", json!({"name": "one"})).await);
    assert_eq!(t1["groups"], json!(["lab"]));
}

/// Inventory output with auth off, as captured from the pre-E3-follow-up
/// build (hosts sorted by name, `request_id` dropped): visibility
/// filtering must not change a byte of it.
const GOLDEN_LIST: &str = r#"{"count":3,"hosts":[{"name":"loopback","ip":"127.0.0.1","mac":null,"ssh_user":"admin","ssh_port":22,"platform":"linux","chassis":"cold_iron","aliases":[],"sudo_password_vault_path":null,"hypervisor":null,"request_id_env":"export","extra_ips":[],"capabilities":["exec","sudo_exec"]},{"name":"t1","ip":"127.0.0.30","mac":"02:00:00:00:00:30","ssh_user":"admin","ssh_port":22,"platform":"linux","chassis":"cold_iron","aliases":["one"],"sudo_password_vault_path":null,"hypervisor":null,"request_id_env":"export","extra_ips":[],"capabilities":["wake","exec","sudo_exec","virt","claude_admin","claude_exec"],"groups":["lab"]},{"name":"t2","ip":"127.0.0.31","mac":null,"ssh_user":"admin","ssh_port":22,"platform":"linux","chassis":"cold_iron","aliases":[],"sudo_password_vault_path":"lab/t2","hypervisor":null,"request_id_env":"export","extra_ips":[],"capabilities":["exec","sudo_exec"],"groups":["lab"]}]}"#;
const GOLDEN_GET_T2: &str = r#"{"name":"t2","queried_as":null,"ip":"127.0.0.31","mac":null,"ssh_user":"admin","ssh_port":22,"platform":"linux","chassis":"cold_iron","aliases":[],"sudo_password_vault_path":"lab/t2","hypervisor":null,"request_id_env":"export","extra_ips":[],"capabilities":["exec","sudo_exec"],"groups":["lab"]}"#;

/// A tool result without its `request_id`, hosts sorted by name (the
/// inventory is a hash map, so their order is not stable).
fn normalized(resp: &Value) -> Value {
    let mut v = ok_text(resp);
    v.as_object_mut().unwrap().remove("request_id");
    if let Some(hosts) = v.get_mut("hosts").and_then(Value::as_array_mut) {
        hosts.sort_by_key(|h| h["name"].as_str().unwrap().to_string());
    }
    v
}

#[tokio::test]
async fn auth_off_inventory_output_is_unchanged() {
    let s = spawn_with(AuthMode::Off, "").await;
    let list = normalized(&call(&s, None, "inventory_list", json!({})).await);
    assert_eq!(list.to_string(), GOLDEN_LIST);
    let t2 = normalized(&call(&s, None, "inventory_get_host", json!({"name": "t2"})).await);
    assert_eq!(t2.to_string(), GOLDEN_GET_T2);
}

const VISIBILITY: &str = r#"
[[rule]]
agents = ["alpha", "beta"]
hosts = ["*"]
tools = ["inventory_list"]

[[rule]]
agents = ["alpha"]
hosts = ["t1"]
tools = ["ssh_exec"]

[[rule]]
agents = ["alpha"]
hosts = ["t2"]
tools = ["inventory_get_host"]

[[rule]]
agents = ["alpha"]
hosts = ["t2"]
tools = ["ssh_sudo_exec"]
sudo = true

[[rule]]
agents = ["beta"]
hosts = ["group:lab"]
tools = ["inventory_get_host"]
"#;

/// With policy on, `inventory_list` shows only the hosts the agent has a
/// grant on (`loopback`: none — and `hosts = ["*"]` on the hostless
/// inventory_list grant doesn't count), and `sudo_password_vault_path`
/// only where it has a `sudo = true` grant. `inventory_get_host` hides
/// the vault path the same way.
#[tokio::test]
async fn inventory_shows_only_granted_hosts() {
    let s = spawn_with(AuthMode::Required, VISIBILITY).await;
    let names = |v: &Value| -> Vec<String> {
        v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["name"].as_str().unwrap().to_string())
            .collect()
    };
    let host = |v: &Value, n: &str| {
        v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == n)
            .unwrap()
            .clone()
    };

    let alpha = normalized(&call(&s, Some("pto_alpha"), "inventory_list", json!({})).await);
    assert_eq!(names(&alpha), ["t1", "t2"], "{alpha}");
    assert_eq!(alpha["count"], 2);
    assert_eq!(host(&alpha, "t2")["sudo_password_vault_path"], "lab/t2");
    assert!(host(&alpha, "t1").get("sudo_password_vault_path").is_none());
    // Everything else reads as with auth off.
    let golden: Value = serde_json::from_str(GOLDEN_LIST).unwrap();
    assert_eq!(host(&alpha, "t2"), host(&golden, "t2"));

    let beta = normalized(&call(&s, Some("pto_beta"), "inventory_list", json!({})).await);
    assert_eq!(names(&beta), ["t1", "t2"], "{beta}");
    assert!(host(&beta, "t2").get("sudo_password_vault_path").is_none());

    let get = |token, name| {
        let s = &s;
        async move {
            normalized(
                &call(
                    s,
                    Some(token),
                    "inventory_get_host",
                    json!({ "name": name }),
                )
                .await,
            )
        }
    };
    assert_eq!(get("pto_alpha", "t2").await.to_string(), GOLDEN_GET_T2);
    let t2 = get("pto_beta", "t2").await;
    assert!(t2.get("sudo_password_vault_path").is_none(), "{t2}");
    assert_eq!(t2["ssh_user"], "admin");
    // No grant on loopback: refused, as before.
    let resp = call(
        &s,
        Some("pto_beta"),
        "inventory_get_host",
        json!({"name": "loopback"}),
    )
    .await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
}

fn ok_text(resp: &Value) -> Value {
    serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

/// Groups are resolved from the live agent store at decision time: a
/// reload that drops `alpha` from `ops` (or revokes it) applies to the
/// very next call, with no new token or session.
#[tokio::test]
async fn agent_group_changes_apply_on_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agents.toml");
    std::fs::write(&path, agents_toml()).unwrap();
    let agents = AgentStore::load_from(path.clone()).unwrap();
    let s = spawn(
        AuthMode::Required,
        agents.clone(),
        policy("[[rule]]\nagents = [\"group:ops\"]\nhosts = [\"*\"]\ntools = [\"ssh_exec\"]\n"),
    )
    .await;
    assert_ok(
        &call(&s, Some("pto_alpha"), "ssh_exec", exec("t1")).await,
        "in ops",
    );

    std::fs::write(
        &path,
        agents_toml().replace("groups = [\"ops\"]", "groups = []"),
    )
    .unwrap();
    agents.reload().unwrap();
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
}

// ---------------------------------------------------------------------------
// Binary tests
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_prompto");

struct Proc {
    child: std::process::Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.log")).unwrap_or_default()
    }

    async fn sighup(&self) {
        let ok = std::process::Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Files for the binary: inventory, agents, and `policy.toml` when given.
fn write_files(dir: &Path, policy: Option<&str>) {
    std::fs::write(dir.join("prompto.toml"), INVENTORY).unwrap();
    std::fs::write(dir.join("agents.toml"), agents_toml()).unwrap();
    if let Some(p) = policy {
        std::fs::write(dir.join("policy.toml"), p).unwrap();
    }
}

fn command(dir: &Path, mode: &str) -> std::process::Command {
    let mut c = std::process::Command::new(BIN);
    c.env("PROMPTO_INVENTORY", dir.join("prompto.toml"))
        .env("PROMPTO_AGENTS", dir.join("agents.toml"))
        .env("PROMPTO_POLICY", dir.join("policy.toml"))
        .env("PROMPTO_AUTH", mode)
        .env("PROMPTO_ALLOWED_HOSTS", "127.0.0.1")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_USAGE_LOG", dir.join("usage.jsonl"))
        .env("PROMPTO_AUDIT_LOG", dir.join("audit.jsonl"))
        .env("RUST_LOG", "prompto=info");
    c
}

fn spawn_binary(dir: &Path, mode: &str) -> Proc {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = command(dir, mode)
        .env("PROMPTO_BIND", format!("127.0.0.1:{port}"))
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let p = Proc {
        child,
        port,
        dir: dir.to_path_buf(),
    };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return p;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("prompto did not start listening: {}", p.stderr());
}

const GRANT_LIST: &str =
    "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"*\"]\ntools = [\"inventory_list\"]\n";

/// SIGHUP reloads policy.toml: a new grant applies; a broken file fails
/// closed — deny-all, saying why and since when, not the previous policy
/// — until a valid file is loaded; a removed grant is refused next.
#[tokio::test]
async fn sighup_reloads_policy_fail_safe() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), Some(""));
    let p = spawn_binary(dir.path(), "required");
    let list = || call_at(p.addr(), Some("pto_alpha"), "inventory_list", json!({}));

    assert_eq!(class(&list().await), Some("refused_policy"));
    assert!(p.stderr().contains("policy has no rules"), "{}", p.stderr());

    std::fs::write(dir.path().join("policy.toml"), GRANT_LIST).unwrap();
    p.sighup().await;
    assert_ok(&list().await, "after granting");
    assert!(
        p.stderr().contains("policy reloaded on SIGHUP"),
        "{}",
        p.stderr()
    );

    std::fs::write(dir.path().join("policy.toml"), "[[rule]]\nagents = 1\n").unwrap();
    p.sighup().await;
    let log = p.stderr();
    assert!(
        log.contains("policy reload failed — DENYING every call")
            && log.contains("POLICY FILE INVALID"),
        "{log}"
    );
    let resp = list().await;
    assert_eq!(
        class(&resp),
        Some("refused_policy"),
        "previous policy kept: {resp}"
    );
    let msg = resp["error"]["message"].as_str().unwrap();
    // The agent gets the time only; the parser's detail and the path
    // are in the journal.
    assert!(msg.contains("(policy file invalid since "), "{msg}");
    assert!(
        !msg.contains("parse policy TOML") && !msg.contains("invalid type"),
        "parser detail reached the agent: {msg}"
    );
    assert!(
        !msg.contains(&dir.path().display().to_string()),
        "path reached the agent: {msg}"
    );
    assert!(
        log.contains("parse policy TOML: TOML parse error at line 2, column 10: invalid type"),
        "parser detail missing from the journal: {log}"
    );

    std::fs::write(dir.path().join("policy.toml"), GRANT_LIST).unwrap();
    p.sighup().await;
    assert_ok(&list().await, "valid again");

    std::fs::write(dir.path().join("policy.toml"), "").unwrap();
    p.sighup().await;
    assert_eq!(class(&list().await), Some("refused_policy"));
}

/// `off` doesn't read policy.toml: a broken one neither stops it nor is
/// reloaded on SIGHUP, while the same file stops optional and required.
#[tokio::test]
async fn off_ignores_a_broken_policy_file() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), Some("this is [not toml"));
    let p = spawn_binary(dir.path(), "off");
    assert_ok(
        &call_at(p.addr(), None, "inventory_list", json!({})).await,
        "off with a broken policy",
    );
    p.sighup().await;
    let log = p.stderr();
    assert_eq!(log.matches("policy file ignored").count(), 1, "{log}");
    assert!(log.contains("inventory reloaded on SIGHUP"), "{log}");
    assert!(!log.contains("policy reload"), "SIGHUP read it: {log}");
    drop(p);

    for mode in ["optional", "required"] {
        let out = command(dir.path(), mode)
            .env("PROMPTO_BIND", "127.0.0.1:0")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode} started with a broken policy");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("loading policy"), "{mode}: {err}");
    }
}

/// A missing policy file in optional/required: the server starts, warns
/// loudly, and denies every call (fail closed), naming the reason.
#[tokio::test]
async fn missing_policy_file_denies_everything_loudly() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), None);
    let p = spawn_binary(dir.path(), "optional");
    assert!(p.stderr().contains("POLICY FILE MISSING"), "{}", p.stderr());
    for token in [None, Some("pto_alpha")] {
        let resp = call_at(p.addr(), token, "inventory_list", json!({})).await;
        assert_eq!(class(&resp), Some("refused_policy"), "{resp}");
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("does not exist, so every call is denied"),
            "{resp}"
        );
    }
}

fn policy_cli(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = command(dir, "required")
        .arg("policy")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn policy_check_cli_prints_decision_and_rule() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), Some(SUDO_SPLIT));
    let d = dir.path();

    let (code, out, _) = policy_cli(
        d,
        &[
            "check",
            "--agent",
            "alpha",
            "--host",
            "one",
            "--tool",
            "ssh_sudo_exec",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.starts_with("ALLOW  rule=policy.toml:8 (t1-root)\n"),
        "{out}"
    );

    let (code, out, _) = policy_cli(
        d,
        &[
            "check",
            "--agent",
            "alpha",
            "--host",
            "t2",
            "--tool",
            "ssh_sudo_exec",
        ],
    );
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("DENY  rule=default-deny\n"), "{out}");
    assert!(
        out.contains("no grant for ssh_sudo_exec (root-capable) on t2"),
        "{out}"
    );

    // --sudo selects the root-capable variant of file_write.
    let (code, out, _) = policy_cli(
        d,
        &[
            "check",
            "--agent",
            "alpha",
            "--host",
            "t2",
            "--tool",
            "file_write",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = policy_cli(
        d,
        &[
            "check",
            "--agent",
            "alpha",
            "--host",
            "t2",
            "--tool",
            "file_write",
            "--sudo",
        ],
    );
    assert_eq!(code, 1, "{out}");

    let (code, out, _) = policy_cli(
        d,
        &["check", "--agent", "anonymous", "--tool", "prompto_gain"],
    );
    assert_eq!(code, 1, "{out}");

    for (args, err) in [
        (
            &[
                "check", "--agent", "ghost", "--host", "t1", "--tool", "ssh_exec",
            ][..],
            "unknown agent",
        ),
        (
            &[
                "check", "--agent", "alpha", "--host", "nope", "--tool", "ssh_exec",
            ][..],
            "unknown host",
        ),
        (
            &[
                "check", "--agent", "alpha", "--host", "t1", "--tool", "ssh_exce",
            ][..],
            "unknown tool",
        ),
        (
            &[
                "check", "--agent", "alpha", "--host", "t1", "--tool", "ssh_exec", "--sudo",
            ][..],
            "no sudo variant",
        ),
        (
            &["check", "--agent", "alpha", "--tool", "ssh_exec"][..],
            "--host is required",
        ),
    ] {
        let (code, _, stderr) = policy_cli(d, args);
        assert_ne!(code, 0, "{args:?}");
        assert!(stderr.contains(err), "{args:?}: {stderr}");
    }
}

#[test]
fn policy_lint_cli_fails_on_errors() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path(), Some(SUDO_SPLIT));
    let (code, out, err) = policy_cli(dir.path(), &["lint"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("2 rules, 0 errors"), "{err}");

    std::fs::write(
        dir.path().join("policy.toml"),
        format!("{SUDO_SPLIT}\n[[rule]]\nagents = [\"alhpa\"]\nhosts = [\"t3\"]\ntools = [\"ssh_exec\"]\n"),
    )
    .unwrap();
    let (code, out, _) = policy_cli(dir.path(), &["lint"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("error: policy.toml:15: unknown agent \"alhpa\""),
        "{out}"
    );
    assert!(
        out.contains("error: policy.toml:15: unknown host \"t3\""),
        "{out}"
    );
}
