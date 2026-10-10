//! Kill switches (E5), end to end through the shipping router, plus the
//! `prompto kill` CLI against a running binary.
//!
//! The fake `ssh` only appends its argv to a log and prints `ran`, so a
//! refused call provably never reached it. Every test gets its own temp
//! dir holding the kill files, the audit log and that argv log; nothing
//! is restarted between setting a switch and the call it must stop.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::audit::{Audit, AuditLog};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::kill::{KillSwitch, Scope};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

mod common;

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.log"
echo ran
exit 0
"#;

/// The client connects from 127.0.0.1, which is `loopback`.
const INVENTORY: &str = r#"
[host.t1]
ip = "127.0.0.30"
ssh_user = "admin"
ssh_key = "/dev/null"
aliases = ["one"]
capabilities = ["exec", "sudo_exec"]

[host.t2]
ip = "127.0.0.31"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]

[host.loopback]
ip = "127.0.0.1"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]
"#;

/// alpha and beta may do anything anywhere, anonymous may run ssh_exec;
/// `nogrant` is a valid agent with no grant at all.
const POLICY: &str = r#"
[[rule]]
id = "all"
agents = ["alpha", "beta"]
hosts = ["*"]
tools = ["*"]

[[rule]]
id = "all-root"
agents = ["alpha", "beta"]
hosts = ["*"]
tools = ["*"]
sudo = true

[[rule]]
id = "anon"
agents = ["anonymous"]
hosts = ["*"]
tools = ["ssh_exec", "inventory_list"]
"#;

fn agents_toml() -> String {
    let h = |t: &str| prompto::agent::hex(&prompto::agent::sha256(t.as_bytes()));
    format!(
        "[agent.alpha]\ntoken_sha256 = \"{}\"\n\n[agent.beta]\ntoken_sha256 = \"{}\"\n\n\
         [agent.nogrant]\ntoken_sha256 = \"{}\"\n",
        h("pto_alpha"),
        h("pto_beta"),
        h("pto_nogrant")
    )
}

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    dir: tempfile::TempDir,
    kill: KillSwitch,
    audit: Audit,
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

    fn record(&self, rid: &str) -> Value {
        let text = std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap();
        let found: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|r| r["request_id"] == rid)
            .collect();
        assert_eq!(found.len(), 1, "records for {rid}: {text}");
        found.into_iter().next().unwrap()
    }

    fn token(&self, mode: AuthMode) -> Option<&'static str> {
        (mode != AuthMode::Off).then_some("pto_alpha")
    }
}

fn write_exe(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn spawn(mode: AuthMode) -> Server {
    spawn_with_audit(mode, None).await
}

/// `audit`: `None` for a working log at `<dir>/audit.jsonl`.
async fn spawn_with_audit(mode: AuthMode, audit: Option<Audit>) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    write_exe(&ssh, FAKE_SSH);
    let audit = audit.unwrap_or_else(|| {
        Audit::new(
            AuditLog::open(dir.path().join("audit.jsonl"), None, mode != AuthMode::Off).unwrap(),
        )
    });
    let kill = KillSwitch::in_dir(dir.path());
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
            store: AgentStore::new(Agents::from_toml_str(&agents_toml()).unwrap(), None),
            policy: PolicyStore::new(Policy::from_toml_str(POLICY, "policy.toml").unwrap(), None),
            approvals: Default::default(),
        },
        audit: audit.clone(),
        kill: kill.clone(),
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
        dir,
        kill,
        audit,
    }
}

async fn rpc_at(
    addr: SocketAddr,
    token: Option<&str>,
    session: Option<&str>,
    method: &str,
    params: Value,
) -> Value {
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
    if let Some(s) = session {
        req = req.header("x-prompto-session", s);
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

async fn call_as(
    s: &Server,
    token: Option<&str>,
    session: Option<&str>,
    tool: &str,
    args: Value,
) -> Value {
    rpc_at(
        s.addr,
        token,
        session,
        "tools/call",
        json!({ "name": tool, "arguments": args }),
    )
    .await
}

async fn call(s: &Server, token: Option<&str>, tool: &str, args: Value) -> Value {
    call_as(s, token, None, tool, args).await
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

fn message(resp: &Value) -> &str {
    resp["error"]["message"].as_str().unwrap_or("")
}

fn request_id(resp: &Value) -> String {
    resp["error"]["data"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no request id: {resp}"))
        .to_string()
}

fn assert_ok(resp: &Value, what: &str) {
    assert!(
        resp.get("result").is_some(),
        "{what}: expected success, got {resp}"
    );
}

fn exec(host: &str, cmd: &str) -> Value {
    json!({ "host": host, "cmd": cmd })
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

async fn tool_names(s: &Server, token: Option<&str>) -> Vec<String> {
    let list = rpc_at(s.addr, token, None, "tools/list", json!({})).await;
    let tools: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{list}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(tools.len() >= 38, "tools/list looks short: {tools:?}");
    tools
}

async fn get_log(s: &Server, token: Option<&str>, host: &str) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!(
        "http://{}/log?host={host}&unit=nginx.service",
        s.addr
    ));
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

/// A killed call's record: denied, class `killed`, with the switch.
fn assert_killed_record(s: &Server, resp: &Value, scope: &str, target: Option<&str>) {
    let rec = s.record(&request_id(resp));
    assert_eq!(rec["error_class"], "killed", "{rec}");
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["ok"], false, "{rec}");
    assert_eq!(rec["kill"]["scope"], scope, "{rec}");
    match target {
        Some(t) => assert_eq!(rec["kill"]["target"], t, "{rec}"),
        None => assert!(rec["kill"].get("target").is_none(), "{rec}"),
    }
}

// ---------------------------------------------------------------------------
// Global
// ---------------------------------------------------------------------------

/// THE panic button. In every auth mode, off included: once the file
/// exists, every tool `tools/list` advertises — plus an unknown tool and
/// arguments that don't parse — is refused as `killed`, with the reason
/// and the time it was set, nothing reaches ssh, and each refusal is
/// audited with the scope. Removing the file restores service on the
/// next call. No restart anywhere.
#[tokio::test]
async fn global_kill_stops_every_call_in_every_mode_and_lifts() {
    for mode in [AuthMode::Off, AuthMode::Optional, AuthMode::Required] {
        let s = spawn(mode).await;
        let tok = s.token(mode);
        assert_ok(
            &call(&s, tok, "ssh_exec", exec("t1", "echo before")).await,
            "before",
        );

        s.kill
            .set(Scope::Global, None, "incident 42: rogue loop")
            .unwrap();
        let tools = tool_names(&s, tok).await;
        let before = s.argv_log();
        for tool in &tools {
            let resp = call(&s, tok, tool, args_for(tool)).await;
            assert_eq!(class(&resp), Some("killed"), "{mode:?} {tool}: {resp}");
            let msg = message(&resp);
            assert!(
                msg.contains("every prompto tool call")
                    && msg.contains("reason: incident 42: rogue loop")
                    && msg.contains(", set 20")
                    && msg.contains("prompto kill off"),
                "{mode:?} {tool}: {msg}"
            );
            assert_killed_record(&s, &resp, "global", None);
        }
        // Before rmcp parses anything: an unknown tool, bad arguments.
        for (tool, args) in [
            ("no_such_tool", json!({})),
            ("ssh_exec", json!({ "host": 7 })),
        ] {
            let resp = call(&s, tok, tool, args).await;
            assert_eq!(class(&resp), Some("killed"), "{mode:?} {tool}: {resp}");
            assert_killed_record(&s, &resp, "global", None);
        }
        assert_eq!(s.argv_log(), before, "{mode:?}: a killed call reached ssh");

        // GET /log: the service is off.
        let (status, body) = get_log(&s, tok, "t1").await;
        assert_eq!(status, 503, "{mode:?}: {body}");
        assert!(body.contains("error_class=killed"), "{body}");
        assert_eq!(s.argv_log(), before, "{mode:?}: /log reached ssh");

        s.kill.clear(Scope::Global, None).unwrap();
        assert_ok(
            &call(&s, tok, "ssh_exec", exec("t1", "echo after")).await,
            "lifted",
        );
        assert!(s.argv_log().contains("echo after"));
    }
}

/// A broken audit log refuses every call (`internal`) in strict mode —
/// but never gets in the way of a kill: the kill check comes first, so a
/// killed call says `killed`, and the journal still gets its record.
#[tokio::test]
async fn global_kill_works_with_a_broken_audit_log() {
    // A log that could never be opened.
    let dir = tempfile::tempdir().unwrap();
    let broken = Audit::new(AuditLog::unopened(
        dir.path().join("missing").join("audit.jsonl"),
        None,
        true,
    ));
    let s = spawn_with_audit(AuthMode::Required, Some(broken)).await;
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    assert_eq!(class(&resp), Some("internal"), "audit is broken: {resp}");
    s.kill.set(Scope::Global, None, "stop").unwrap();
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    assert_eq!(class(&resp), Some("killed"), "{resp}");
    let (status, _) = get_log(&s, Some("pto_alpha"), "t1").await;
    assert_eq!(status, 503);

    // A log whose disk filled: same.
    let s = spawn(AuthMode::Required).await;
    s.audit
        .log()
        .unwrap()
        .inject_fault(Some(prompto::audit::Fault::DiskFull));
    call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    assert_eq!(class(&resp), Some("internal"), "disk full: {resp}");
    s.kill.set(Scope::Global, None, "").unwrap();
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    assert_eq!(class(&resp), Some("killed"), "{resp}");
    // Room again: the killed call's record is written.
    s.audit.log().unwrap().inject_fault(None);
    let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await;
    assert_killed_record(&s, &resp, "global", None);
}

// ---------------------------------------------------------------------------
// Agent, host, session
// ---------------------------------------------------------------------------

/// `kill agent alpha`: alpha is refused everywhere, beta is not; unkill
/// restores alpha. No SIGHUP, no token change.
#[tokio::test]
async fn agent_kill_stops_one_agent_until_lifted() {
    let s = spawn(AuthMode::Required).await;
    s.kill.set(Scope::Agent, Some("alpha"), "runaway").unwrap();
    for host in ["t1", "t2"] {
        let resp = call(&s, Some("pto_alpha"), "ssh_exec", exec(host, "echo a")).await;
        assert_eq!(class(&resp), Some("killed"), "{resp}");
        assert!(
            message(&resp).contains("every call by agent alpha"),
            "{resp}"
        );
        assert!(
            message(&resp).contains("prompto unkill agent alpha"),
            "{resp}"
        );
        assert_killed_record(&s, &resp, "agent", Some("alpha"));
    }
    let resp = call(&s, Some("pto_alpha"), "inventory_list", json!({})).await;
    assert_eq!(class(&resp), Some("killed"), "hostless too: {resp}");
    let (status, body) = get_log(&s, Some("pto_alpha"), "t1").await;
    assert_eq!(status, 403, "{body}");
    assert!(!s.argv_log().contains("echo a"));

    assert_ok(
        &call(&s, Some("pto_beta"), "ssh_exec", exec("t1", "echo b")).await,
        "beta is not killed",
    );

    s.kill.clear(Scope::Agent, Some("alpha")).unwrap();
    assert_ok(
        &call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "echo a2")).await,
        "unkilled",
    );
}

/// `kill agent anonymous` stops every unauthenticated caller in
/// `optional` mode, and leaves token holders alone.
#[tokio::test]
async fn agent_kill_can_stop_anonymous_callers() {
    let s = spawn(AuthMode::Optional).await;
    assert_ok(
        &call(&s, None, "ssh_exec", exec("t1", "true")).await,
        "anon",
    );
    s.kill.set(Scope::Agent, Some("anonymous"), "").unwrap();
    let resp = call(&s, None, "ssh_exec", exec("t1", "true")).await;
    assert_eq!(class(&resp), Some("killed"), "{resp}");
    assert_killed_record(&s, &resp, "agent", Some("anonymous"));
    assert_ok(
        &call(&s, Some("pto_alpha"), "ssh_exec", exec("t1", "true")).await,
        "alpha",
    );
}

/// `kill host t1`: every agent is refused on t1 — by name, by alias, as
/// rsync's source or dest, and via /log — in every mode, auth off
/// included; t2 and hostless tools keep working. A switch written under
/// the alias catches the canonical name too.
#[tokio::test]
async fn host_kill_stops_every_agent_on_one_host() {
    for mode in [AuthMode::Off, AuthMode::Required] {
        let s = spawn(mode).await;
        s.kill.set(Scope::Host, Some("t1"), "disk failing").unwrap();
        let tokens: &[Option<&str>] = match mode {
            AuthMode::Off => &[None],
            _ => &[Some("pto_alpha"), Some("pto_beta")],
        };
        for &tok in tokens {
            for host in ["t1", "one"] {
                let resp = call(&s, tok, "ssh_exec", exec(host, "echo k")).await;
                assert_eq!(class(&resp), Some("killed"), "{mode:?} {host}: {resp}");
                assert!(message(&resp).contains("every call to host t1"), "{resp}");
                assert!(message(&resp).contains("reason: disk failing"), "{resp}");
                assert_killed_record(&s, &resp, "host", Some("t1"));
            }
            for (src, dst) in [("t1", "t2"), ("t2", "t1"), ("t2", "one")] {
                let args = json!({
                    "source_host": src, "source_path": "/tmp/a/",
                    "dest_host": dst, "dest_path": "/tmp/b/"
                });
                let resp = call(&s, tok, "rsync_sync", args).await;
                assert_eq!(class(&resp), Some("killed"), "{src}→{dst}: {resp}");
            }
            let resp = call(&s, tok, "service_logs", json!({"host": "t1", "unit": "x"})).await;
            assert_eq!(class(&resp), Some("killed"), "{resp}");
            let (status, body) = get_log(&s, tok, "t1").await;
            assert_eq!(status, 403, "{body}");
            assert!(!s.argv_log().contains("echo k"), "{mode:?}");

            assert_ok(&call(&s, tok, "ssh_exec", exec("t2", "true")).await, "t2");
            assert_ok(
                &call(&s, tok, "inventory_list", json!({})).await,
                "hostless",
            );
        }
        s.kill.clear(Scope::Host, Some("t1")).unwrap();
        assert_ok(
            &call(&s, tokens[0], "ssh_exec", exec("one", "true")).await,
            "unkilled",
        );

        // Set under the alias: the canonical name is caught as well.
        s.kill.set(Scope::Host, Some("one"), "").unwrap();
        let resp = call(&s, tokens[0], "ssh_exec", exec("t1", "true")).await;
        assert_eq!(class(&resp), Some("killed"), "{resp}");
        assert_killed_record(&s, &resp, "host", Some("one"));
    }
}

/// `kill session s-1`: calls carrying that X-Prompto-Session are refused,
/// the same agent in another session or with none is not.
#[tokio::test]
async fn session_kill_stops_one_session() {
    for mode in [AuthMode::Optional, AuthMode::Required] {
        let s = spawn(mode).await;
        s.kill.set(Scope::Session, Some("s-1"), "looping").unwrap();
        for tok in [None, Some("pto_alpha")] {
            if tok.is_none() && mode == AuthMode::Required {
                continue;
            }
            let resp = call_as(&s, tok, Some("s-1"), "ssh_exec", exec("t1", "echo k")).await;
            assert_eq!(class(&resp), Some("killed"), "{mode:?}: {resp}");
            assert!(
                message(&resp).contains("every call from session s-1"),
                "{resp}"
            );
            assert_killed_record(&s, &resp, "session", Some("s-1"));
            assert_ok(
                &call_as(&s, tok, Some("s-2"), "ssh_exec", exec("t1", "true")).await,
                "other session",
            );
            assert_ok(
                &call_as(&s, tok, None, "ssh_exec", exec("t1", "true")).await,
                "no session",
            );
        }
        assert!(!s.argv_log().contains("echo k"));
        s.kill.clear(Scope::Session, Some("s-1")).unwrap();
        assert_ok(
            &call_as(
                &s,
                s.token(mode),
                Some("s-1"),
                "ssh_exec",
                exec("t1", "true"),
            )
            .await,
            "unkilled",
        );
    }
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/// A kill answers before the host lookup, the self-target guard and
/// policy: the caller learns it is stopped, not why the call would have
/// failed anyway. Each pair checks the other refusal first, so the test
/// can't pass on a kill that refuses for the wrong reason.
#[tokio::test]
async fn kill_comes_before_lookup_self_target_and_policy() {
    let s = spawn(AuthMode::Required).await;
    let alpha = Some("pto_alpha");
    let cases: [(Option<&str>, &str, &str); 3] = [
        (alpha, "ghost", "unknown_host"),
        (alpha, "loopback", "refused_self_target"),
        (Some("pto_nogrant"), "t1", "refused_policy"),
    ];
    for (tok, host, without) in cases {
        let resp = call(&s, tok, "ssh_exec", exec(host, "true")).await;
        assert_eq!(class(&resp), Some(without), "{host}: {resp}");
    }
    s.kill.set(Scope::Global, None, "").unwrap();
    for (tok, host, _) in cases {
        let resp = call(&s, tok, "ssh_exec", exec(host, "true")).await;
        assert_eq!(class(&resp), Some("killed"), "global, {host}: {resp}");
    }
    s.kill.clear(Scope::Global, None).unwrap();

    // Scoped kills too.
    s.kill.set(Scope::Host, Some("loopback"), "").unwrap();
    s.kill.set(Scope::Host, Some("ghost"), "").unwrap();
    s.kill.set(Scope::Agent, Some("nogrant"), "").unwrap();
    for (tok, host, _) in cases {
        let resp = call(&s, tok, "ssh_exec", exec(host, "true")).await;
        assert_eq!(class(&resp), Some("killed"), "scoped, {host}: {resp}");
    }
}

/// A switch that was checkable at startup and isn't any more fails
/// CLOSED: calls that need it are refused as `killed`, reason `kill
/// switch unreadable: …`, `/log` too, and the record says `unreadable`.
/// A symlink loop (`ELOOP`) stands in for a permission error, which
/// root (and so a test run as root) never gets.
#[tokio::test]
async fn an_unreadable_switch_refuses_calls() {
    for mode in [AuthMode::Off, AuthMode::Required] {
        let s = spawn(mode).await;
        let tok = s.token(mode);
        assert_ok(
            &call(&s, tok, "ssh_exec", exec("t1", "true")).await,
            "before",
        );
        let before = s.argv_log();

        std::os::unix::fs::symlink("kill", s.kill.file()).unwrap();
        let resp = call(&s, tok, "ssh_exec", exec("t1", "true")).await;
        assert_eq!(class(&resp), Some("killed"), "{mode:?}: {resp}");
        let msg = message(&resp);
        assert!(
            msg.contains("kill switch unreadable") && msg.contains("fails closed"),
            "{mode:?}: {msg}"
        );
        assert_killed_record(&s, &resp, "global", None);
        let rec = s.record(&request_id(&resp));
        assert_eq!(rec["kill"]["unreadable"], true, "{rec}");
        assert!(
            rec["kill"]["reason"]
                .as_str()
                .unwrap()
                .starts_with("kill switch unreadable: "),
            "{rec}"
        );
        let (status, _) = get_log(&s, tok, "t1").await;
        assert_eq!(status, 503, "{mode:?}");
        std::fs::remove_file(s.kill.file()).unwrap();
        assert_ok(
            &call(&s, tok, "ssh_exec", exec("t1", "true")).await,
            "fixed",
        );

        // kill.d: every call that names a host (or, with auth on, has an
        // agent) needs it, and is refused.
        std::os::unix::fs::symlink("kill.d", s.kill.dir()).unwrap();
        let resp = call(&s, tok, "ssh_exec", exec("t2", "true")).await;
        assert_eq!(class(&resp), Some("killed"), "{mode:?}: {resp}");
        assert!(message(&resp).contains("kill switch unreadable"), "{resp}");
        let scope = if mode == AuthMode::Off {
            "host"
        } else {
            "agent"
        };
        let rec = s.record(&request_id(&resp));
        assert_eq!(rec["kill"]["scope"], scope, "{rec}");
        assert_eq!(rec["kill"]["unreadable"], true, "{rec}");
        std::fs::remove_file(s.kill.dir()).unwrap();
        assert_ok(
            &call(&s, tok, "ssh_exec", exec("t2", "true")).await,
            "fixed",
        );
        assert_eq!(
            s.argv_log().lines().count(),
            before.lines().count() + 2,
            "{mode:?}: an unreadable switch let a call through"
        );
    }
}

// ---------------------------------------------------------------------------
// CLI + binary
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_prompto");

struct Proc {
    child: std::process::Child,
    port: u16,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kill_cli(dir: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(BIN)
        .args(args)
        .env("PROMPTO_KILL_FILE", dir.join("kill"))
        .env("PROMPTO_INVENTORY", dir.join("prompto.toml"))
        .env("PROMPTO_AUDIT_LOG", dir.join("audit.jsonl"))
        .env_remove("PROMPTO_AUDIT_GROUP")
        .env("SUDO_USER", "test-operator")
        .output()
        .unwrap()
}

fn spawn_binary(dir: &Path) -> Proc {
    std::fs::write(dir.join("prompto.toml"), INVENTORY).unwrap();
    write_exe(&dir.join("ssh"), FAKE_SSH);
    let child = std::process::Command::new(BIN)
        .env("PROMPTO_INVENTORY", dir.join("prompto.toml"))
        .env("PROMPTO_AUTH", "off")
        .env("PROMPTO_SSH_BIN", dir.join("ssh"))
        .env("PROMPTO_BIND", "127.0.0.1:0")
        .env("PROMPTO_ALLOWED_HOSTS", "127.0.0.1")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_USAGE_LOG", dir.join("usage.jsonl"))
        .env("PROMPTO_AUDIT_LOG", dir.join("audit.jsonl"))
        .env("PROMPTO_KILL_FILE", dir.join("kill"))
        .env("RUST_LOG", "prompto=info")
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut p = Proc { child, port: 0 };
    p.port = common::bound_port(&mut p.child, &dir.join("stderr.log"));
    p
}

fn out_text(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// The real binary, auth off (prod's mode): `prompto kill on|off`,
/// `kill host`, `unkill host` apply to the running server's next call;
/// `kill status` lists them; traversal names are rejected and write
/// nothing.
#[tokio::test]
async fn cli_switches_a_running_server_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let p = spawn_binary(dir.path());
    let addr = SocketAddr::from(([127, 0, 0, 1], p.port));
    let ssh = |host: &str| {
        rpc_at(
            addr,
            None,
            None,
            "tools/call",
            json!({ "name": "ssh_exec", "arguments": exec(host, "true") }),
        )
    };
    assert_ok(&ssh("t1").await, "before");

    let o = kill_cli(dir.path(), &["kill", "on", "maintenance", "window"]);
    assert!(o.status.success(), "{}", out_text(&o));
    let resp = ssh("t1").await;
    assert_eq!(class(&resp), Some("killed"), "{resp}");
    assert!(
        message(&resp).contains("reason: maintenance window"),
        "{resp}"
    );
    let o = kill_cli(dir.path(), &["kill", "status"]);
    let text = out_text(&o);
    assert!(
        text.contains("global") && text.contains("maintenance window"),
        "{text}"
    );
    let o = kill_cli(dir.path(), &["kill", "off"]);
    assert!(o.status.success(), "{}", out_text(&o));
    assert_ok(&ssh("t1").await, "global lifted");

    let o = kill_cli(dir.path(), &["kill", "host", "t2", "bad", "disk"]);
    assert!(o.status.success(), "{}", out_text(&o));
    assert_eq!(class(&ssh("t2").await), Some("killed"));
    assert_ok(&ssh("t1").await, "t1 untouched");
    let o = kill_cli(dir.path(), &["kill", "host", "nosuch"]);
    assert!(
        out_text(&o).contains("is not a host or alias"),
        "{}",
        out_text(&o)
    );
    let o = kill_cli(dir.path(), &["kill", "status"]);
    let text = out_text(&o);
    assert!(
        text.contains("host") && text.contains("t2") && text.contains("bad disk"),
        "{text}"
    );
    let o = kill_cli(dir.path(), &["unkill", "host", "t2"]);
    assert!(o.status.success(), "{}", out_text(&o));
    assert_ok(&ssh("t2").await, "t2 lifted");
    kill_cli(dir.path(), &["unkill", "host", "nosuch"]);

    for bad in [
        &["kill", "host", "../kill"][..],
        &["kill", "agent", "../../etc/x"],
        &["kill", "session", "a/b"],
        &["unkill", "host", "../kill"],
        &["kill", "bogus", "x"],
    ] {
        let o = kill_cli(dir.path(), bad);
        assert!(!o.status.success(), "{bad:?} accepted: {}", out_text(&o));
    }
    assert!(
        !dir.path().join("kill").exists(),
        "traversal reached the global file"
    );
    let left: Vec<_> = std::fs::read_dir(dir.path().join("kill.d"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
    let o = kill_cli(dir.path(), &["kill", "status"]);
    assert!(
        out_text(&o).contains("no kill switch is on"),
        "{}",
        out_text(&o)
    );

    // The audit file has the killed calls with their scope.
    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    let killed: Vec<Value> = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|r| r["error_class"] == "killed")
        .collect();
    let scopes: Vec<&str> = killed
        .iter()
        .map(|r| r["kill"]["scope"].as_str().unwrap())
        .collect();
    assert_eq!(scopes, ["global", "host"], "{audit}");

    // Every change made with the CLI is recorded, with who made it; the
    // refused names and the no-op unkill are not.
    let changes: Vec<(String, String, String, String)> = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|r| r["type"] == "kill")
        .map(|r| {
            assert_eq!(r["by"]["uid"], unsafe { libc::getuid() }, "{r}");
            assert_eq!(r["by"]["sudo_user"], "test-operator", "{r}");
            assert!(
                r["request_id"].as_str().is_some_and(|i| i.len() == 26),
                "{r}"
            );
            let f = |k: &str| r[k].as_str().unwrap_or("-").to_string();
            (f("action"), f("scope"), f("target"), f("reason"))
        })
        .collect();
    let want = [
        ("on", "global", "-", "maintenance window"),
        ("off", "global", "-", "-"),
        ("on", "host", "t2", "bad disk"),
        ("on", "host", "nosuch", "-"),
        ("off", "host", "t2", "-"),
        ("off", "host", "nosuch", "-"),
    ];
    let want: Vec<_> = want
        .iter()
        .map(|(a, b, c, d)| (a.to_string(), b.to_string(), c.to_string(), d.to_string()))
        .collect();
    assert_eq!(changes, want, "{audit}");
    let o = kill_cli(dir.path(), &["audit", "--host", "t2"]);
    let table = out_text(&o);
    assert!(o.status.success(), "{table}");
    let rows: Vec<&str> = table.lines().filter(|l| l.contains("(kill)")).collect();
    assert_eq!(rows.len(), 2, "{table}");
    assert!(
        rows[0].contains("(sudo: test-operator)")
            && rows[0].contains("kill on")
            && rows[0].contains("kill=host t2 reason: bad disk"),
        "{table}"
    );
    assert!(rows[1].contains("kill off"), "{table}");
    // The host filter keeps the calls to t2 and drops the global switch.
    assert!(!table.contains("kill=global maintenance"), "{table}");
    drop(p);
    let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
    assert!(log.contains("kill switches checked on every call"), "{log}");
}

/// A server started with a switch already on says so at startup.
#[tokio::test]
async fn startup_warns_about_active_switches() {
    let dir = tempfile::tempdir().unwrap();
    let ks = KillSwitch::in_dir(dir.path());
    ks.set(Scope::Host, Some("t1"), "left on").unwrap();
    let p = spawn_binary(dir.path());
    drop(p);
    let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
    assert!(
        log.contains("KILL SWITCH ON") && log.contains("left on"),
        "{log}"
    );
}

/// A kill switch the server can't check at startup stops it, with an
/// error that names the path and the way out — not a server whose panic
/// button silently does nothing.
#[test]
fn startup_refuses_an_uncheckable_switch() {
    for which in ["kill", "kill.d"] {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(which, dir.path().join(which)).unwrap();
        std::fs::write(dir.path().join("prompto.toml"), INVENTORY).unwrap();
        let o = std::process::Command::new(BIN)
            .env("PROMPTO_INVENTORY", dir.path().join("prompto.toml"))
            .env("PROMPTO_AUTH", "off")
            .env("PROMPTO_BIND", "127.0.0.1:0")
            .env("PROMPTO_GAIN_ENABLED", "false")
            .env("PROMPTO_USAGE_LOG", dir.path().join("usage.jsonl"))
            .env("PROMPTO_AUDIT_LOG", dir.path().join("audit.jsonl"))
            .env("PROMPTO_KILL_FILE", dir.path().join("kill"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // A server that does start would run forever: give it 10 s.
        let mut child = o;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let o = child.wait_with_output().unwrap();
        let text = out_text(&o);
        assert!(!o.status.success(), "{which}: started anyway: {text}");
        assert!(
            text.contains("cannot check the kill switches")
                && text.contains("PROMPTO_KILL_FILE")
                && text.contains(which),
            "{which}: {text}"
        );
    }
}

/// The panic button wins: when the audit record can't be written, the
/// switch is still set (and lifted), the command still succeeds, and it
/// says the change went unrecorded.
#[test]
fn cli_applies_the_kill_even_if_it_cannot_audit_it() {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(BIN)
            .args(args)
            .env("PROMPTO_KILL_FILE", dir.path().join("kill"))
            .env("PROMPTO_INVENTORY", dir.path().join("prompto.toml"))
            .env(
                "PROMPTO_AUDIT_LOG",
                dir.path().join("no-such-dir").join("audit.jsonl"),
            )
            .output()
            .unwrap()
    };
    let o = run(&["kill", "on", "fire"]);
    let text = out_text(&o);
    assert!(o.status.success(), "{text}");
    assert!(dir.path().join("kill").exists(), "{text}");
    assert!(
        text.contains("IS in effect") && text.contains("could not be recorded"),
        "{text}"
    );
    let o = run(&["kill", "off"]);
    assert!(o.status.success(), "{}", out_text(&o));
    assert!(!dir.path().join("kill").exists());
    assert!(out_text(&o).contains("could not be recorded"));
}

/// An audit file that exists keeps its mode when the CLI appends to it
/// (the CLI runs as root; the file is the server's); a missing one is
/// created 0640, the server's mode.
#[test]
fn cli_audit_record_keeps_the_files_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let o = kill_cli(dir.path(), &["kill", "agent", "dev", "why"]);
    assert!(o.status.success(), "{}", out_text(&o));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&audit), 0o640);
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o600)).unwrap();
    let o = kill_cli(dir.path(), &["unkill", "agent", "dev"]);
    assert!(o.status.success(), "{}", out_text(&o));
    assert_eq!(mode(&audit), 0o600, "the CLI changed the audit file's mode");
    let text = std::fs::read_to_string(&audit).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(!out_text(&o).contains("could not be recorded"));
}
