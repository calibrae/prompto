//! Precheck, approvals and tickets (E6), end to end.
//!
//! The shipping router (`prompto::server::build_router`) with a fake
//! `ssh` that appends its argv to a log and exits 0: a call that ran
//! leaves a line, a refused one (or a precheck) none. Tickets are signed
//! with a key generated per test; approvers' TOTP secrets are files in
//! the test's directory, and codes are computed here like a phone would.
//!
//! Every refusal is asserted next to the success it guards: a ticket
//! check that refuses everything passes every "is X refused?" test.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::approval::{ApprovalConfig, Approvals};
use prompto::audit::{Audit, AuditLog};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Approval, Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use prompto::ticket::{self, Claims, Key, KeySet};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.log"
echo ran
exit 0
"#;

/// No `wake` on `t1` (a test must never send a magic packet), and no
/// `mac`. `loopback` is the test client's own address.
const INVENTORY: &str = r#"
[host.t1]
ip = "127.0.0.30"
ssh_user = "admin"
ssh_key = "/dev/null"
aliases = ["one"]
apytti_url = "http://127.0.0.1:9"
capabilities = ["exec", "sudo_exec", "virt", "claude_admin", "claude_exec"]

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

/// alpha: ordinary calls need a ticket, root ones a human; plain
/// `ssh_exec` on t2 needs nothing. beta: the same grants, so a ticket
/// minted for alpha can be tried as beta.
const POLICY: &str = r#"
[[rule]]
id = "t2-free"
agents = ["alpha", "beta"]
hosts = ["t2"]
tools = ["ssh_exec"]

[[rule]]
id = "ticketed"
agents = ["alpha", "beta"]
hosts = ["t1", "t2", "loopback"]
tools = ["*"]
approval = "ticket"

[[rule]]
id = "human-root"
agents = ["alpha", "beta"]
hosts = ["t1", "t2", "loopback"]
tools = ["*"]
sudo = true
approval = "human"
"#;

const SECRET: &[u8] = b"12345678901234567890";
const ALPHA: &str = "pto_alpha";
const BETA: &str = "pto_beta";
const SESSION: &str = "sess-1";

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    dir: tempfile::TempDir,
    approvals: Approvals,
    keys: KeySet,
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
    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn record(&self, request_id: &str) -> Value {
        self.audit()
            .into_iter()
            .find(|r| r["request_id"] == request_id)
            .unwrap_or_else(|| panic!("no audit record {request_id}"))
    }
}

fn keyset(seed: u8) -> KeySet {
    KeySet {
        current: Key::new(vec![seed; 32]).unwrap(),
        previous: None,
        source: "test".into(),
    }
}

/// `n` approvers `ap0`… sharing one secret (steps are tracked per name,
/// so each can approve up to three times in a 30 s window).
fn write_approvers(dir: &std::path::Path, n: usize) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let secret = dir.join("ap.totp");
    std::fs::write(&secret, prompto::totp::base32_encode(SECRET)).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut toml = String::new();
    for i in 0..n {
        toml.push_str(&format!(
            "[approver.ap{i}]\ntotp_file = \"{}\"\n\n",
            secret.display()
        ));
    }
    toml.push_str(&format!(
        "[approver.gone]\ntotp_file = \"{}\"\ndisabled = true\n",
        secret.display()
    ));
    let path = dir.join("approvers.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

struct Opts {
    tickets: bool,
    policy: &'static str,
}

async fn spawn() -> Server {
    spawn_opts(Opts {
        tickets: true,
        policy: POLICY,
    })
    .await
}

async fn spawn_opts(o: Opts) -> Server {
    let dir = tempfile::tempdir().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let ssh = dir.path().join("ssh");
        std::fs::write(&ssh, FAKE_SSH).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let h = |t: &str| prompto::agent::hex(&prompto::agent::sha256(t.as_bytes()));
    let agents = format!(
        "[agent.alpha]\ntoken_sha256 = \"{}\"\n\n[agent.beta]\ntoken_sha256 = \"{}\"\n",
        h(ALPHA),
        h(BETA)
    );
    let keys = keyset(7);
    let cfg = ApprovalConfig {
        key_vault_path: None,
        key_file: None,
        approvers_path: write_approvers(dir.path(), 12),
        state_path: dir.path().join("approval-state"),
    };
    let approvals = if o.tickets {
        Approvals::with_keys(cfg, keys.clone())
    } else {
        Approvals::default()
    };
    let audit =
        Audit::new(AuditLog::open(dir.path().join("audit.jsonl"), None, true).expect("audit log"));
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(SshClient::new(
            dir.path().join("ssh"),
            Duration::from_secs(5),
        )),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(1),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth: AuthConfig {
            mode: AuthMode::Required,
            store: AgentStore::new(Agents::from_toml_str(&agents).unwrap(), None),
            policy: PolicyStore::new(
                Policy::from_toml_str(o.policy, "policy.toml").unwrap(),
                None,
            ),
            approvals: approvals.clone(),
        },
        audit,
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
    Server {
        addr,
        cancel,
        dir,
        approvals,
        keys,
    }
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

/// An MCP request as `token`, in `session` (if any).
async fn rpc(s: &Server, token: &str, session: Option<&str>, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/mcp", s.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("authorization", format!("Bearer {token}"));
    if let Some(n) = params["name"].as_str() {
        req = req.header("mcp-name", n.to_string());
    }
    if let Some(sess) = session {
        req = req.header("x-prompto-session", sess);
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

/// A tool call as alpha in [`SESSION`].
async fn call(s: &Server, tool: &str, args: Value) -> Value {
    call_as(s, ALPHA, Some(SESSION), tool, args).await
}

async fn call_as(s: &Server, token: &str, session: Option<&str>, tool: &str, args: Value) -> Value {
    rpc(
        s,
        token,
        session,
        "tools/call",
        json!({ "name": tool, "arguments": args }),
    )
    .await
}

/// `POST /v1/<path>` as `token`, in `session`; `(status, body)`.
async fn post(
    s: &Server,
    path: &str,
    token: &str,
    session: Option<&str>,
    body: Value,
) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/v1/{path}", s.addr))
        .header("authorization", format!("Bearer {token}"));
    if let Some(sess) = session {
        req = req.header("x-prompto-session", sess);
    }
    let resp = req.json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let v = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {status} {text}"));
    (status, v)
}

async fn precheck(s: &Server, tool: &str, args: Value) -> Value {
    let (status, v) = post(
        s,
        "precheck",
        ALPHA,
        Some(SESSION),
        json!({ "tool": tool, "arguments": args }),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    v
}

/// The TOTP code `steps` steps away from now.
fn code(steps: i64) -> String {
    let now = ticket::unix_now() as i64 + steps * prompto::totp::STEP_SECS as i64;
    prompto::totp::code_at(SECRET, now as u64)
}

async fn approve(s: &Server, approver: &str, totp: &str, tool: &str, args: Value) -> (u16, Value) {
    post(
        s,
        "approve",
        ALPHA,
        Some(SESSION),
        json!({ "tool": tool, "arguments": args, "approver": approver, "totp_code": totp }),
    )
    .await
}

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
    resp["error"]["message"].as_str().unwrap_or_default()
}

fn request_id(resp: &Value) -> String {
    if let Some(r) = resp["error"]["data"]["request_id"].as_str() {
        return r.into();
    }
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    v["request_id"].as_str().unwrap().into()
}

fn with_ticket(mut args: Value, t: &str) -> Value {
    args["ticket"] = t.into();
    args
}

fn exec(host: &str) -> Value {
    json!({ "host": host, "cmd": "id -u" })
}

fn sha256_hex(s: &str) -> String {
    prompto::agent::hex(&prompto::agent::sha256(s.as_bytes()))
}

/// A ticket precheck minted for alpha's `ssh_exec` on t1.
async fn ticket_for(s: &Server, tool: &str, args: Value) -> String {
    let v = precheck(s, tool, args).await;
    assert_eq!(v["decision"], "allow", "{v}");
    v["ticket"].as_str().unwrap_or_else(|| panic!("{v}")).into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Without a ticket the call is refused (as before E6), and the refusal
/// says how to get one. Nothing runs.
#[tokio::test]
async fn no_ticket_is_approval_required_with_instructions() {
    let s = spawn().await;
    let r = call(&s, "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), Some("approval_required"), "{r}");
    assert!(message(&r).contains("POST /v1/precheck"), "{r}");
    assert_eq!(r["error"]["data"]["rule"], "policy.toml:8 (ticketed)");
    let r = call(&s, "ssh_sudo_exec", exec("t1")).await;
    assert_eq!(class(&r), Some("approval_required"), "{r}");
    assert!(message(&r).contains("POST /v1/approve"), "{r}");
    assert!(message(&r).contains("TOTP"), "{r}");
    assert_eq!(s.argv_log(), "");
    // A rule without approval doesn't look at tickets at all.
    let r = call(&s, "ssh_exec", exec("t2")).await;
    assert_eq!(class(&r), None, "{r}");
    let r = call(&s, "ssh_exec", with_ticket(exec("t2"), "garbage")).await;
    assert_eq!(class(&r), None, "{r}");
}

/// The basic flow: precheck mints, the call runs once with it, a replay
/// is refused. Precheck itself runs nothing.
#[tokio::test]
async fn precheck_ticket_runs_the_call_exactly_once() {
    let s = spawn().await;
    let v = precheck(&s, "ssh_exec", exec("t1")).await;
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["approval"], "ticket");
    assert_eq!(v["rule"], "policy.toml:8 (ticketed)");
    let t = v["ticket"].as_str().unwrap().to_string();
    assert!(t.starts_with("pt1."), "{t}");
    assert!(v["expires_at"].as_u64().unwrap() > ticket::unix_now());
    assert_eq!(s.argv_log(), "", "precheck ran something");

    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(class(&r), None, "{r}");
    assert_eq!(s.argv_log().lines().count(), 1);

    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("already used"), "{r}");
    assert_eq!(s.argv_log().lines().count(), 1, "the replay ran");
}

/// Every binding: a ticket for one call doesn't open another.
#[tokio::test]
async fn a_ticket_fits_only_its_own_call() {
    let s = spawn().await;
    // (label, token, session, tool, args, expected message part)
    type Case = (
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static str,
        Value,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        // (label, token, session, tool, args, expected message part)
        (
            "args",
            ALPHA,
            Some(SESSION),
            "ssh_exec",
            json!({"host": "t1", "cmd": "id -un"}),
            "different arguments",
        ),
        (
            "extra arg",
            ALPHA,
            Some(SESSION),
            "ssh_exec",
            json!({"host": "t1", "cmd": "id -u", "timeout_secs": 5}),
            "different arguments",
        ),
        (
            "host",
            ALPHA,
            Some(SESSION),
            "ssh_exec",
            exec("loopback"),
            "for host",
        ),
        (
            "tool",
            ALPHA,
            Some(SESSION),
            "file_read",
            json!({"host": "t1", "cmd": "id -u", "path": "/etc/hostname"}),
            "for tool",
        ),
        (
            "agent",
            BETA,
            Some(SESSION),
            "ssh_exec",
            exec("t1"),
            "for agent",
        ),
        (
            "session",
            ALPHA,
            Some("sess-2"),
            "ssh_exec",
            exec("t1"),
            "for session",
        ),
        (
            "no session",
            ALPHA,
            None,
            "ssh_exec",
            exec("t1"),
            "for session",
        ),
    ];
    for (label, token, session, tool, args, want) in cases {
        let t = ticket_for(&s, "ssh_exec", exec("t1")).await;
        let r = call_as(&s, token, session, tool, with_ticket(args, &t)).await;
        // `loopback` is the caller's own machine: the self-target guard
        // refuses it before any ticket is looked at.
        if label == "host" {
            assert_eq!(class(&r), Some("refused_self_target"), "{label}: {r}");
            continue;
        }
        assert_eq!(class(&r), Some("refused_ticket"), "{label}: {r}");
        assert!(message(&r).contains(want), "{label}: {r}");
        // Still good for its own call: a mismatch spends nothing.
        let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
        assert_eq!(class(&r), None, "{label}: own call refused: {r}");
    }
    assert_eq!(s.argv_log().lines().count(), 6);

    // An alias is the same host: the ticket binds the canonical name.
    let t = ticket_for(&s, "ssh_exec", exec("one")).await;
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(
        class(&r),
        Some("refused_ticket"),
        "args differ (host string): {r}"
    );
    let t = ticket_for(&s, "ssh_exec", exec("one")).await;
    let r = call(&s, "ssh_exec", with_ticket(exec("one"), &t)).await;
    assert_eq!(class(&r), None, "{r}");
}

/// A different host, with the host binding itself checked: t2's
/// file_read needs a ticket too, and alpha's ticket for t1 must not open
/// it even with arguments that differ only in the host.
#[tokio::test]
async fn host_binding_is_checked() {
    let s = spawn().await;
    let t1 = json!({"host": "t1", "path": "/etc/hostname"});
    let t = ticket_for(&s, "file_read", t1.clone()).await;
    let r = call(
        &s,
        "file_read",
        with_ticket(json!({"host": "t2", "path": "/etc/hostname"}), &t),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("for host"), "{r}");
    let r = call(&s, "file_read", with_ticket(t1, &t)).await;
    assert_eq!(class(&r), None, "{r}");
}

/// Tampering: anything but the exact signed bytes is refused.
#[tokio::test]
async fn tampered_and_forged_tickets_are_refused() {
    let s = spawn().await;
    let t = ticket_for(&s, "ssh_exec", exec("t1")).await;
    let parts: Vec<&str> = t.split('.').collect();
    let raw = base64_url_decode(parts[2]);
    let mut claims: Claims = serde_json::from_slice(&raw).unwrap();
    claims.host = Some("t2".into());
    let forged_body = base64_url_encode(&serde_json::to_vec(&claims).unwrap());
    let forged = format!("{}.{}.{forged_body}.{}", parts[0], parts[1], parts[3]);
    let r = call(
        &s,
        "file_read",
        with_ticket(json!({"host": "t2", "path": "/x"}), &forged),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("signature"), "{r}");
    // A ticket signed with a key prompto doesn't hold.
    let foreign = ticket::mint(
        &keyset(9),
        &claims_for(&s, "ssh_exec", &exec("t1"), Approval::Human),
    );
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &foreign)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    for junk in ["", "pt1.x", "pt1.a.b.c", &format!("{t}x")] {
        let r = call(&s, "ssh_exec", with_ticket(exec("t1"), junk)).await;
        assert_eq!(class(&r), Some("refused_ticket"), "{junk:?}: {r}");
    }
    let r = call(
        &s,
        "ssh_exec",
        json!({"host": "t1", "cmd": "id -u", "ticket": 5}),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert_eq!(s.argv_log(), "");
    // The genuine one is still good.
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(class(&r), None, "{r}");
}

/// Claims for alpha's call in [`SESSION`], valid now.
fn claims_for(s: &Server, tool: &str, args: &Value, approval: Approval) -> Claims {
    let inv = Inventory::from_toml_str(INVENTORY).unwrap();
    let (host, dest_host) = prompto::authz::bound_hosts(tool, args, Some(&inv));
    let _ = s;
    let now = ticket::unix_now();
    Claims {
        agent: "alpha".into(),
        session: Some(SESSION.into()),
        tool: tool.into(),
        host,
        dest_host,
        args_sha256: Some(prompto::canon::args_sha256(args)),
        approval,
        approved_by: Some("ap0".into()),
        iat: now,
        exp: now + ticket::TTL_SECS,
        nonce: ticket::nonce().unwrap(),
        scoped: false,
    }
}

fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn base64_url_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Expiry, with a ticket signed by the real key (so only time is wrong).
#[tokio::test]
async fn expired_ticket_is_refused() {
    let s = spawn().await;
    let mut c = claims_for(&s, "ssh_exec", &exec("t1"), Approval::Ticket);
    c.iat -= 300;
    c.exp = c.iat + ticket::TTL_SECS;
    let t = ticket::mint(&s.keys, &c);
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("expired"), "{r}");
    // The same claims, unexpired, pass: it is the time.
    let c = claims_for(&s, "ssh_exec", &exec("t1"), Approval::Ticket);
    let r = call(
        &s,
        "ssh_exec",
        with_ticket(exec("t1"), &ticket::mint(&s.keys, &c)),
    )
    .await;
    assert_eq!(class(&r), None, "{r}");
}

/// Rotation: tickets signed with the previous key still verify; with a
/// key rotated out, they don't.
#[tokio::test]
async fn key_rotation_accepts_current_and_previous() {
    let s = spawn().await;
    let t_old = ticket_for(&s, "ssh_exec", exec("t1")).await;
    let t_old2 = ticket_for(&s, "ssh_exec", exec("t1")).await;
    let rotated = KeySet {
        current: Key::new(vec![8; 32]).unwrap(),
        previous: Some(s.keys.current.clone()),
        source: "test".into(),
    };
    s.approvals.set_keys(rotated.clone());
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t_old)).await;
    assert_eq!(class(&r), None, "previous key refused: {r}");
    let t_new = ticket_for(&s, "ssh_exec", exec("t1")).await;
    assert!(
        t_new.contains(&rotated.current.id),
        "not signed with the new key"
    );
    s.approvals.set_keys(KeySet {
        current: Key::new(vec![10; 32]).unwrap(),
        previous: Some(rotated.current.clone()),
        source: "test".into(),
    });
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t_old2)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("rotated out"), "{r}");
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t_new)).await;
    assert_eq!(class(&r), None, "{r}");
}

/// Arguments that pass every tool's own validation, aimed at `t1`.
fn args_for(tool: &str) -> Value {
    match tool {
        "rsync_sync" => json!({
            "source_host": "t1", "source_path": "/tmp/a/",
            "dest_host": "t2", "dest_path": "/tmp/b/"
        }),
        "inventory_get_host" => json!({ "name": "t1" }),
        "inventory_list" | "prompto_gain" | "mcp_reconnect_hint" => json!({}),
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

/// THE consistency test. For every tool `tools/list` advertises (and
/// `file_write` both with and without `sudo`), with a policy where every
/// ordinary call needs a ticket and every root-capable one a human:
///
/// - the call without a ticket is refused, as precheck predicts;
/// - precheck answers `allow` + ticket or `ask` exactly where the
///   handler's own authorization demands it, and runs nothing (no ssh);
/// - the call then succeeds past authorization with the ticket precheck
///   (or approve) minted.
///
/// So `authz::requirements` (precheck's view of each tool) can't drift
/// from the handlers: a wrong host field, capability or root-ness shows
/// up as a refused ticket or a wrong decision here.
#[tokio::test]
async fn precheck_agrees_with_every_tool_and_runs_nothing() {
    let s = spawn().await;
    let list = rpc(&s, ALPHA, Some(SESSION), "tools/list", json!({})).await;
    let mut tools: Vec<(String, Value)> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{list}"))
        .iter()
        .map(|t| {
            let name = t["name"].as_str().unwrap().to_string();
            let args = args_for(&name);
            (name, args)
        })
        .collect();
    assert!(tools.len() >= 38, "tools/list looks short");
    let mut sudo_write = args_for("file_write");
    sudo_write["sudo"] = true.into();
    tools.push(("file_write".into(), sudo_write));

    let mut approver = 0;
    let (mut ticketed, mut asked) = (0, 0);
    let mut wrong = Vec::new();
    for (tool, args) in &tools {
        let before = s.argv_log();
        let refused = call(&s, tool, args.clone()).await;
        let v = precheck(&s, tool, args.clone()).await;
        if s.argv_log() != before {
            wrong.push(format!("{tool}: precheck or a refused call ran ssh"));
        }
        let ticket = match (class(&refused), v["decision"].as_str()) {
            (Some("approval_required"), Some("allow")) if v["approval"] == "ticket" => {
                ticketed += 1;
                v["ticket"].as_str().unwrap().to_string()
            }
            (Some("approval_required"), Some("ask")) if v["approval"] == "human" => {
                asked += 1;
                let name = format!("ap{}", approver / 3);
                let c = code((approver % 3) as i64 - 1);
                approver += 1;
                let (st, a) = approve(&s, &name, &c, tool, args.clone()).await;
                if st != 200 {
                    wrong.push(format!("{tool}: approve {st} {a}"));
                    continue;
                }
                a["ticket"].as_str().unwrap().to_string()
            }
            // Refused before policy (no capability): precheck must say so.
            (Some(c), Some("deny")) if v["error_class"] == c => continue,
            (c, d) => {
                wrong.push(format!("{tool}: call {c:?}, precheck {d:?}: {v}"));
                continue;
            }
        };
        let r = call(&s, tool, with_ticket(args.clone(), &ticket)).await;
        if let Some(c @ ("approval_required" | "refused_ticket" | "refused_policy")) = class(&r) {
            wrong.push(format!("{tool}: with its ticket: {c}: {}", message(&r)));
        }
    }
    assert!(
        wrong.is_empty(),
        "precheck vs handlers:\n{}",
        wrong.join("\n")
    );
    // Not vacuous: nearly every tool went through both paths.
    assert!(
        ticketed >= 28 && asked >= 7,
        "ticketed {ticketed}, asked {asked}"
    );
}

/// Precheck's other answers: deny with the refusing step, nothing run.
#[tokio::test]
async fn precheck_denies_like_the_call_would() {
    let s = spawn().await;
    for (tool, args, class, rule) in [
        ("ssh_exec", exec("nope"), "unknown_host", Value::Null),
        (
            "ssh_exec",
            exec("loopback"),
            "refused_self_target",
            Value::Null,
        ),
        (
            "host_wake",
            json!({"host": "t1"}),
            "refused_capability",
            Value::Null,
        ),
        (
            "vm_list",
            json!({"host": "t2"}),
            "refused_capability",
            Value::Null,
        ),
        ("no_such_tool", json!({}), "invalid_args", Value::Null),
        (
            "ssh_exec",
            json!({"cmd": "id"}),
            "invalid_args",
            Value::Null,
        ),
    ] {
        let v = precheck(&s, tool, args).await;
        assert_eq!(v["decision"], "deny", "{tool}: {v}");
        assert_eq!(v["error_class"], class, "{tool}: {v}");
        assert_eq!(v["rule"], rule, "{tool}: {v}");
    }
    // Policy: beta has no rule for ssh_batch on t2? It has (ticketed);
    // gamma doesn't exist, so use a tool no rule grants on t2 with a
    // policy that lists only t2-free.
    let s2 = spawn_opts(Opts {
        tickets: true,
        policy: "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"t2\"]\ntools = [\"ssh_exec\"]\n",
    })
    .await;
    let v = precheck(&s2, "ssh_batch", json!({"host": "t2", "commands": ["id"]})).await;
    assert_eq!(v["decision"], "deny", "{v}");
    assert_eq!(v["error_class"], "refused_policy", "{v}");
    assert_eq!(v["rule"], "default-deny", "{v}");
    let v = precheck(&s2, "ssh_exec", exec("t2")).await;
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["approval"], "none", "{v}");
    assert!(v.get("ticket").is_none(), "{v}");
    // A kill switch denies first.
    std::fs::create_dir_all(s.dir.path().join("kill.d")).unwrap();
    std::fs::write(s.dir.path().join("kill.d").join("host-t1"), "maintenance\n").unwrap();
    let v = precheck(&s, "ssh_exec", exec("t1")).await;
    assert_eq!(v["decision"], "deny", "{v}");
    assert_eq!(v["error_class"], "killed", "{v}");
    assert_eq!(s.argv_log(), "");
    assert_eq!(s2.argv_log(), "");
}

/// A ticket given to precheck is checked, not spent: the dry run
/// leaves it good for the real call.
#[tokio::test]
async fn precheck_checks_a_ticket_without_spending_it() {
    let s = spawn().await;
    let t = ticket_for(&s, "ssh_exec", exec("t1")).await;
    for _ in 0..2 {
        let v = precheck(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
        assert_eq!(v["decision"], "allow", "{v}");
        assert!(v.get("ticket").is_none(), "{v}");
        assert!(v["reason"].as_str().unwrap().contains("ticket"), "{v}");
    }
    let v = precheck(
        &s,
        "ssh_exec",
        with_ticket(json!({"host": "t1", "cmd": "x"}), &t),
    )
    .await;
    assert_eq!(v["decision"], "deny", "{v}");
    assert_eq!(v["error_class"], "refused_ticket", "{v}");
    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(class(&r), None, "{r}");
    let v = precheck(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    assert_eq!(v["error_class"], "refused_ticket", "{v}");
    assert!(
        v["reason"].as_str().unwrap().contains("already used"),
        "{v}"
    );
}

/// No ticket key configured: approval rules still refuse, precheck can't
/// mint and says why.
#[tokio::test]
async fn without_a_key_nothing_is_minted() {
    let s = spawn_opts(Opts {
        tickets: false,
        policy: POLICY,
    })
    .await;
    let r = call(&s, "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), Some("approval_required"), "{r}");
    assert!(message(&r).contains("no ticket key configured"), "{r}");
    let v = precheck(&s, "ssh_exec", exec("t1")).await;
    assert_eq!(v["decision"], "deny", "{v}");
    assert_eq!(v["error_class"], "refused_ticket", "{v}");
    let (st, v) = approve(&s, "ap0", &code(0), "ssh_sudo_exec", exec("t1")).await;
    assert_eq!(st, 503, "{v}");
    // A ticket made elsewhere is refused, not ignored.
    let c = claims_for(&s, "ssh_exec", &exec("t1"), Approval::Ticket);
    let r = call(
        &s,
        "ssh_exec",
        with_ticket(exec("t1"), &ticket::mint(&s.keys, &c)),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
}

/// THE human-approval guarantee: the agent's token alone never yields an
/// `approval = "human"` ticket.
#[tokio::test]
async fn an_agent_token_alone_never_gets_a_human_ticket() {
    let s = spawn().await;
    let sudo = exec("t1");
    // Precheck asks, and mints nothing.
    let v = precheck(&s, "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(v["decision"], "ask", "{v}");
    assert_eq!(v["approval"], "human", "{v}");
    assert!(v.get("ticket").is_none(), "{v}");
    // A precheck ticket (approval = ticket) for the same call is refused.
    let c = claims_for(&s, "ssh_sudo_exec", &sudo, Approval::Ticket);
    let r = call(
        &s,
        "ssh_sudo_exec",
        with_ticket(sudo.clone(), &ticket::mint(&s.keys, &c)),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("requires \"human\""), "{r}");
    // Approve without a code, with a wrong one, a revoked or unknown
    // approver: all refused, no ticket.
    let (st, v) = post(
        &s,
        "approve",
        ALPHA,
        Some(SESSION),
        json!({ "tool": "ssh_sudo_exec", "arguments": sudo, "approver": "ap0" }),
    )
    .await;
    assert_eq!(st, 400, "{v}");
    for (who, totp) in [
        ("ap0", "000000".to_string()),
        ("ap0", "12345".to_string()),
        ("gone", code(0)),
        ("nobody", code(0)),
    ] {
        let (st, v) = approve(&s, who, &totp, "ssh_sudo_exec", sudo.clone()).await;
        assert_eq!(st, 403, "{who} {totp}: {v}");
        assert!(v.get("ticket").is_none(), "{v}");
        assert_eq!(v["error_class"], "refused_ticket", "{v}");
    }
    // Forged human claims need the key: signed with another, refused.
    let mut c = claims_for(&s, "ssh_sudo_exec", &sudo, Approval::Human);
    c.approved_by = Some("ap0".into());
    let r = call(
        &s,
        "ssh_sudo_exec",
        with_ticket(sudo.clone(), &ticket::mint(&keyset(3), &c)),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert_eq!(s.argv_log(), "");
    // With the code: a human ticket that runs it once.
    let (st, v) = approve(&s, "ap1", &code(0), "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["approved_by"], "ap1");
    let t = v["ticket"].as_str().unwrap();
    let r = call(&s, "ssh_sudo_exec", with_ticket(sudo.clone(), t)).await;
    assert_eq!(class(&r), None, "{r}");
    let r = call(&s, "ssh_sudo_exec", with_ticket(sudo, t)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    // A human ticket also satisfies a ticket rule.
    let (st, v) = approve(&s, "ap2", &code(0), "ssh_exec", exec("t1")).await;
    assert_eq!(st, 200, "{v}");
    let r = call(
        &s,
        "ssh_exec",
        with_ticket(exec("t1"), v["ticket"].as_str().unwrap()),
    )
    .await;
    assert_eq!(class(&r), None, "{r}");
}

/// TOTP: ±1 step, single-use, lockout after repeated failures.
#[tokio::test]
async fn totp_codes_are_single_use_and_guessing_locks_out() {
    let s = spawn().await;
    let sudo = exec("t1");
    for step in [-2i64, 2] {
        let (st, v) = approve(&s, "ap0", &code(step), "ssh_sudo_exec", sudo.clone()).await;
        assert_eq!(st, 403, "step {step}: {v}");
    }
    let (st, v) = approve(&s, "ap0", &code(0), "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(st, 200, "{v}");
    // The same code again, and an older one: used.
    for step in [0, -1] {
        let (st, v) = approve(&s, "ap0", &code(step), "ssh_sudo_exec", sudo.clone()).await;
        assert_eq!(st, 403, "{v}");
        assert!(
            v["reason"].as_str().unwrap().contains("already used"),
            "{v}"
        );
    }
    // A newer step is fine.
    let (st, v) = approve(&s, "ap0", &code(1), "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(st, 200, "{v}");

    // Lockout: ap3 gets MAX_FAILURES wrong codes, then is locked — even
    // the right code is refused. Other approvers are unaffected.
    for _ in 0..prompto::approvers::MAX_FAILURES {
        let (st, _) = approve(&s, "ap3", "000000", "ssh_sudo_exec", sudo.clone()).await;
        assert_eq!(st, 403);
    }
    let (st, v) = approve(&s, "ap3", "000000", "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(st, 429, "{v}");
    let (st, v) = approve(&s, "ap3", &code(0), "ssh_sudo_exec", sudo.clone()).await;
    assert_eq!(st, 429, "{v}");
    assert!(v["reason"].as_str().unwrap().contains("locked out"), "{v}");
    let (st, v) = approve(&s, "ap4", &code(0), "ssh_sudo_exec", sudo).await;
    assert_eq!(st, 200, "{v}");
}

/// Approve re-runs authorization: no approval for a call policy denies,
/// none needed where policy asks for none.
#[tokio::test]
async fn approve_mints_only_for_calls_that_need_it() {
    let s = spawn().await;
    let (st, v) = approve(&s, "ap0", &code(0), "ssh_exec", exec("nope")).await;
    assert_eq!(st, 403, "{v}");
    assert_eq!(v["error_class"], "unknown_host", "{v}");
    let (st, v) = approve(&s, "ap0", &code(0), "ssh_exec", exec("t2")).await;
    assert_eq!(st, 409, "{v}");
    assert!(
        v["reason"].as_str().unwrap().contains("no approval needed"),
        "{v}"
    );
    // Neither attempt spent the code.
    let (st, v) = approve(&s, "ap0", &code(0), "ssh_sudo_exec", exec("t1")).await;
    assert_eq!(st, 200, "{v}");
}

/// "Approve similar calls": same agent, session, tool and host, any
/// arguments, many times, until it expires. Nothing else.
#[tokio::test]
async fn scoped_approval_covers_similar_calls_only() {
    let s = spawn().await;
    let (st, v) = post(
        &s,
        "approve",
        ALPHA,
        Some(SESSION),
        json!({
            "tool": "ssh_sudo_exec", "arguments": exec("t1"),
            "approver": "ap0", "totp_code": code(0), "scope_minutes": 10
        }),
    )
    .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["scoped"], true);
    let t = v["ticket"].as_str().unwrap().to_string();
    let exp = v["expires_at"].as_u64().unwrap();
    assert!(
        exp >= ticket::unix_now() + 9 * 60 && exp <= ticket::unix_now() + 600,
        "{v}"
    );
    for cmd in ["id -u", "uptime", "id -u"] {
        let r = call(
            &s,
            "ssh_sudo_exec",
            json!({"host": "t1", "cmd": cmd, "ticket": t}),
        )
        .await;
        assert_eq!(class(&r), None, "{cmd}: {r}");
    }
    assert_eq!(s.argv_log().lines().count(), 3);
    for (label, token, session, tool, args) in [
        ("host", ALPHA, Some(SESSION), "ssh_sudo_exec", exec("t2")),
        (
            "tool",
            ALPHA,
            Some(SESSION),
            "service_control",
            json!({"host": "t1", "unit": "u", "action": "status"}),
        ),
        (
            "session",
            ALPHA,
            Some("sess-2"),
            "ssh_sudo_exec",
            exec("t1"),
        ),
        ("agent", BETA, Some(SESSION), "ssh_sudo_exec", exec("t1")),
    ] {
        let r = call_as(&s, token, session, tool, with_ticket(args, &t)).await;
        assert_eq!(class(&r), Some("refused_ticket"), "{label}: {r}");
    }
    assert_eq!(s.argv_log().lines().count(), 3);
    // rsync_sync binds both hosts: a scoped approval for t1 → t2 doesn't
    // stretch to t1 → t1, whatever else may vary.
    let rsync = |dest: &str, path: &str| json!({"source_host": "t1", "source_path": path, "dest_host": dest, "dest_path": "/b/"});
    let (st, v) = post(
        &s,
        "approve",
        ALPHA,
        Some(SESSION),
        json!({
            "tool": "rsync_sync", "arguments": rsync("t2", "/a/"),
            "approver": "ap5", "totp_code": code(0), "scope_minutes": 5
        }),
    )
    .await;
    assert_eq!(st, 200, "{v}");
    let t = v["ticket"].as_str().unwrap().to_string();
    let r = call(&s, "rsync_sync", with_ticket(rsync("t2", "/other/"), &t)).await;
    assert!(
        !matches!(class(&r), Some("refused_ticket" | "approval_required")),
        "{r}"
    );
    let r = call(&s, "rsync_sync", with_ticket(rsync("t1", "/a/"), &t)).await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("dest_host"), "{r}");
    let before = s.argv_log().lines().count();
    // Bounds: no session, too long, zero.
    for (session, minutes, want) in [
        (None, 10, 400),
        (Some(SESSION), 61, 400),
        (Some(SESSION), 0, 400),
    ] {
        let (st, v) = post(
            &s,
            "approve",
            ALPHA,
            session,
            json!({
                "tool": "ssh_sudo_exec", "arguments": exec("t1"),
                "approver": "ap1", "totp_code": code(0), "scope_minutes": minutes
            }),
        )
        .await;
        assert_eq!(st, want, "{session:?} {minutes}: {v}");
        assert!(v.get("ticket").is_none());
    }
    assert_eq!(s.argv_log().lines().count(), before);
}

/// S6.5: the audit has the ticket's hash, never the ticket; precheck and
/// approve are audited with what they minted.
#[tokio::test]
async fn audit_records_ticket_hashes_not_tickets() {
    let s = spawn().await;
    let v = precheck(&s, "ssh_exec", exec("t1")).await;
    let t = v["ticket"].as_str().unwrap().to_string();
    let rec = s.record(v["request_id"].as_str().unwrap());
    assert_eq!(rec["type"], "precheck");
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["agent"], "alpha");
    assert_eq!(rec["session_id"], SESSION);
    assert_eq!(rec["host"], "t1");
    assert_eq!(rec["ticket_sha256"], sha256_hex(&t));
    assert_eq!(rec["rule"], "policy.toml:8 (ticketed)");

    let r = call(&s, "ssh_exec", with_ticket(exec("t1"), &t)).await;
    let rec = s.record(&request_id(&r));
    assert_eq!(rec["type"], "tool");
    assert_eq!(rec["ticket_sha256"], sha256_hex(&t));
    assert_eq!(rec["approval"], "ticket");
    assert!(rec["args"].get("ticket").is_none(), "{rec}");
    assert_eq!(rec["args"]["cmd"], "id -u");

    let v = precheck(&s, "ssh_sudo_exec", exec("t1")).await;
    let rec = s.record(v["request_id"].as_str().unwrap());
    assert_eq!(rec["decision"], "ask");
    assert!(rec.get("ticket_sha256").is_none(), "{rec}");

    let (_, v) = approve(&s, "ap0", "000000", "ssh_sudo_exec", exec("t1")).await;
    let rec = s.record(v["request_id"].as_str().unwrap());
    assert_eq!(rec["type"], "approve");
    assert_eq!(rec["decision"], "deny");
    assert_eq!(rec["error_class"], "refused_ticket");
    assert_eq!(rec["approved_by"], "ap0");

    let (_, v) = approve(&s, "ap0", &code(0), "ssh_sudo_exec", exec("t1")).await;
    let t = v["ticket"].as_str().unwrap().to_string();
    let rec = s.record(v["request_id"].as_str().unwrap());
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["ticket_sha256"], sha256_hex(&t));
    let r = call(&s, "ssh_sudo_exec", with_ticket(exec("t1"), &t)).await;
    let rec = s.record(&request_id(&r));
    assert_eq!(rec["approval"], "human");
    assert_eq!(rec["approved_by"], "ap0");
    assert_eq!(rec["ticket_sha256"], sha256_hex(&t));

    let text = std::fs::read_to_string(s.dir.path().join("audit.jsonl")).unwrap();
    assert!(!text.contains("pt1."), "a ticket reached the audit log");
}

/// E11: used nonces and TOTP steps survive a restart (the state file),
/// and so does the key, so a ticket minted before a restart still works
/// after it — once.
#[tokio::test]
async fn restart_keeps_tickets_valid_and_spent_ones_spent() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ApprovalConfig {
        key_vault_path: None,
        key_file: None,
        approvers_path: write_approvers(dir.path(), 1),
        state_path: dir.path().join("approval-state"),
    };
    let ctx_for = |args: Value| {
        let mut ctx = prompto::ctx::CallCtx::new(None).with_identity(prompto::agent::Identity {
            agent: Some(prompto::ctx::Agent {
                name: "alpha".into(),
                groups: vec![],
            }),
            session_id: Some(SESSION.into()),
            auth_note: None,
        });
        ctx.call = Some(prompto::audit::CallScope::new(
            "ssh_exec",
            args.as_object().cloned(),
        ));
        ctx
    };
    let before = Approvals::with_keys(cfg.clone(), keyset(7));
    let (spent, _) = before
        .mint(None, &ctx_for(exec("t1")), Approval::Ticket, None, None)
        .unwrap();
    let (fresh, _) = before
        .mint(None, &ctx_for(exec("t1")), Approval::Ticket, None, None)
        .unwrap();
    let use_it = |a: &Approvals, t: &str| {
        a.require(
            None,
            &ctx_for(with_ticket(exec("t1"), t)),
            "ssh_exec",
            "r",
            Some("t1"),
            Approval::Ticket,
        )
    };
    use_it(&before, &spent).unwrap();
    before.verify_approver("ap0", &code(0)).await.unwrap();
    drop(before);

    let after = Approvals::with_keys(cfg, keyset(7));
    let e = use_it(&after, &spent).unwrap_err();
    assert!(e.message.contains("already used"), "{}", e.message);
    use_it(&after, &fresh).unwrap();
    assert!(use_it(&after, &fresh).is_err());
    assert!(after.verify_approver("ap0", &code(0)).await.is_err());
    after.verify_approver("ap0", &code(1)).await.unwrap();
}

/// An unwritable state file refuses ticketed calls (never accept a
/// ticket whose use can't be recorded) and leaves the rest alone.
#[tokio::test]
async fn unwritable_state_refuses_only_ticketed_calls() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ApprovalConfig {
        key_vault_path: None,
        key_file: None,
        approvers_path: write_approvers(dir.path(), 1),
        // A directory can't be opened for appending.
        state_path: dir.path().to_path_buf(),
    };
    let a = Approvals::with_keys(cfg, keyset(7));
    let why = a.unavailable().expect("unavailable");
    assert!(why.contains("state file"), "{why}");
}

/// One call, two rules: `rsync_sync` from t1 (ticket) to t2 (human).
/// The strictest wins — precheck asks, and a ticket-level ticket that
/// satisfies the source's rule is refused at the dest's.
#[tokio::test]
async fn mixed_rules_take_the_strictest_approval() {
    let s = spawn_opts(Opts {
        tickets: true,
        policy: "[[rule]]\nagents = [\"alpha\"]\nhosts = [\"t1\"]\ntools = [\"rsync_sync\"]\napproval = \"ticket\"\n\
                 [[rule]]\nagents = [\"alpha\"]\nhosts = [\"t2\"]\ntools = [\"rsync_sync\"]\napproval = \"human\"\n",
    })
    .await;
    let args =
        json!({"source_host": "t1", "source_path": "/a/", "dest_host": "t2", "dest_path": "/b/"});
    let v = precheck(&s, "rsync_sync", args.clone()).await;
    assert_eq!(v["decision"], "ask", "{v}");
    assert_eq!(v["approval"], "human", "{v}");
    let c = claims_for(&s, "rsync_sync", &args, Approval::Ticket);
    let r = call(
        &s,
        "rsync_sync",
        with_ticket(args.clone(), &ticket::mint(&s.keys, &c)),
    )
    .await;
    assert_eq!(class(&r), Some("refused_ticket"), "{r}");
    assert!(message(&r).contains("requires \"human\""), "{r}");
    assert_eq!(s.argv_log(), "");
    let (st, v) = approve(&s, "ap0", &code(0), "rsync_sync", args.clone()).await;
    assert_eq!(st, 200, "{v}");
    let r = call(
        &s,
        "rsync_sync",
        with_ticket(args, v["ticket"].as_str().unwrap()),
    )
    .await;
    assert!(
        !matches!(class(&r), Some("refused_ticket" | "approval_required")),
        "{r}"
    );
}
