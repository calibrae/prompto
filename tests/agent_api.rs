//! `GET /v1/whoami`, `GET /v1/audit` and `POST /v1/kill` (E7: what the
//! Claude Code plugin asks prompto about itself), end to end over the
//! shipping router, with a fake `ssh` and approvers whose TOTP codes are
//! computed here like a phone would.
//!
//! Each refusal is asserted next to the success it guards.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::approval::{ApprovalConfig, Approvals};
use prompto::audit::{Audit, AuditLog};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use prompto::ticket::{Key, KeySet};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.log"
echo ran
exit 0
"#;

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
"#;

/// alpha: plain calls on t1, root on t1 with a human approval, nothing on
/// t2. beta: plain calls on t1 and t2.
const POLICY: &str = r#"
[[rule]]
id = "alpha-t1"
agents = ["alpha"]
hosts = ["t1"]
tools = ["*"]

[[rule]]
id = "alpha-root"
agents = ["alpha"]
hosts = ["t1"]
tools = ["*"]
sudo = true
approval = "human"

[[rule]]
id = "beta"
agents = ["beta"]
hosts = ["t1", "t2"]
tools = ["*"]
"#;

const SECRET: &[u8] = b"12345678901234567890";
const ALPHA: &str = "pto_alpha";
const BETA: &str = "pto_beta";

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
    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn ran(&self) -> usize {
        std::fs::read_to_string(self.dir.path().join("argv.log"))
            .unwrap_or_default()
            .lines()
            .count()
    }
    fn kill(&self) -> prompto::kill::KillSwitch {
        prompto::kill::KillSwitch::in_dir(self.dir.path())
    }
}

async fn spawn(mode: AuthMode) -> Server {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    let ssh = dir.path().join("ssh");
    std::fs::write(&ssh, FAKE_SSH).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let secret = dir.path().join("ap.totp");
    std::fs::write(&secret, prompto::totp::base32_encode(SECRET)).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let approvers = dir.path().join("approvers.toml");
    std::fs::write(
        &approvers,
        format!(
            "[approver.ap0]\ntotp_file = \"{0}\"\n\n[approver.ap1]\ntotp_file = \"{0}\"\n",
            secret.display()
        ),
    )
    .unwrap();
    let h = |t: &str| prompto::agent::hex(&prompto::agent::sha256(t.as_bytes()));
    let agents = format!(
        "[agent.alpha]\ngroups = [\"ops\"]\ntoken_sha256 = \"{}\"\n\n\
         [agent.beta]\ntoken_sha256 = \"{}\"\n",
        h(ALPHA),
        h(BETA)
    );
    let cfg = ApprovalConfig {
        key_vault_path: None,
        key_file: None,
        approvers_path: approvers,
        state_path: dir.path().join("approval-state"),
        ..Default::default()
    };
    let keys = KeySet {
        current: Key::new(vec![7; 32]).unwrap(),
        previous: None,
        source: "test".into(),
    };
    let audit =
        Audit::new(AuditLog::open(dir.path().join("audit.jsonl"), None, true).expect("audit log"));
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
            store: AgentStore::new(Agents::from_toml_str(&agents).unwrap(), None),
            policy: PolicyStore::new(Policy::from_toml_str(POLICY, "policy.toml").unwrap(), None),
            approvals: Approvals::with_keys(cfg, keys),
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
    Server { addr, cancel, dir }
}

/// A tool call as `token` in `session`.
async fn call(s: &Server, token: &str, session: Option<&str>, tool: &str, args: Value) -> Value {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/mcp", s.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("authorization", format!("Bearer {token}"));
    if let Some(sess) = session {
        req = req.header("x-prompto-session", sess);
    }
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": { "name": tool, "arguments": args } });
    let text = req.json(&body).send().await.unwrap().text().await.unwrap();
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(&text);
    serde_json::from_str(raw).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn class(resp: &Value) -> Option<&str> {
    resp.get("error")
        .map(|e| e["data"]["error_class"].as_str().unwrap_or("?"))
}

/// `GET /v1/<path>` or, with a body, `POST`; `(status, body)`.
async fn v1(
    s: &Server,
    path: &str,
    token: &str,
    session: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let url = format!("http://{}/v1/{path}", s.addr);
    let c = reqwest::Client::new();
    let mut req = match &body {
        Some(b) => c.post(url).json(b),
        None => c.get(url),
    }
    .header("authorization", format!("Bearer {token}"));
    if let Some(sess) = session {
        req = req.header("x-prompto-session", sess);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let v = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {status} {text}"));
    (status, v)
}

fn code() -> String {
    prompto::totp::code_at(SECRET, prompto::ticket::unix_now())
}

fn exec(host: &str) -> Value {
    json!({ "host": host, "cmd": "id -u" })
}

// ---------------------------------------------------------------------------
// whoami
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_names_the_agent_its_groups_and_session() {
    let s = spawn(AuthMode::Required).await;
    let (st, v) = v1(&s, "whoami", ALPHA, Some("sess-a"), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["agent"], "alpha");
    assert_eq!(v["groups"], json!(["ops"]));
    assert_eq!(v["session"], "sess-a");
    assert_eq!(v["auth"], "required");
    let (_, v) = v1(&s, "whoami", BETA, None, None).await;
    assert_eq!(v["agent"], "beta");
    assert_eq!(v["session"], Value::Null);
}

#[tokio::test]
async fn whoami_with_auth_off_has_no_agent() {
    let s = spawn(AuthMode::Off).await;
    let (st, v) = v1(&s, "whoami", ALPHA, Some("sess-a"), None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["agent"], Value::Null);
    assert_eq!(v["auth"], "off");
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_shows_only_the_callers_own_records() {
    let s = spawn(AuthMode::Required).await;
    let a = call(&s, ALPHA, Some("sa"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&a), None, "{a}");
    let b = call(&s, BETA, Some("sb"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&b), None, "{b}");
    assert_eq!(s.audit().len(), 2);

    let (st, v) = v1(&s, "audit", ALPHA, Some("sa"), None).await;
    assert_eq!(st, 200, "{v}");
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 1, "{v}");
    assert_eq!(recs[0]["agent"], "alpha");
    assert_eq!(recs[0]["tool"], "ssh_exec");
    let (_, v) = v1(&s, "audit", BETA, None, None).await;
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 1, "{v}");
    assert_eq!(recs[0]["agent"], "beta");
}

#[tokio::test]
async fn audit_filters_by_session_and_limit() {
    let s = spawn(AuthMode::Required).await;
    for sess in ["s1", "s2", "s1"] {
        let r = call(&s, ALPHA, Some(sess), "ssh_exec", exec("t1")).await;
        assert_eq!(class(&r), None, "{r}");
    }
    let (_, v) = v1(&s, "audit?session=s1", ALPHA, Some("s1"), None).await;
    assert_eq!(v["count"], 2, "{v}");
    assert!(
        v["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["session_id"] == "s1")
    );
    let (_, v) = v1(&s, "audit?limit=1", ALPHA, None, None).await;
    assert_eq!(v["count"], 1, "{v}");
    // The newest one.
    assert_eq!(v["records"][0]["session_id"], "s1");
    let (st, _) = v1(&s, "audit?session=bad%20id", ALPHA, None, None).await;
    assert_eq!(st, 400);
}

#[tokio::test]
async fn audit_for_a_host_needs_a_grant_there() {
    let s = spawn(AuthMode::Required).await;
    // alpha has no grant on t2: refused, but recorded under t2.
    let r = call(&s, ALPHA, Some("sa"), "ssh_exec", exec("t2")).await;
    assert_eq!(class(&r), Some("refused_policy"), "{r}");
    let r = call(&s, ALPHA, Some("sa"), "ssh_exec", exec("one")).await;
    assert_eq!(class(&r), None, "{r}");
    assert!(s.audit().iter().any(|r| r["host"] == "t2"));

    let (st, v) = v1(&s, "audit?host=t2", ALPHA, None, None).await;
    assert_eq!(st, 403, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("refused_policy"),
        "{v}"
    );
    // An unknown host is refused the same way.
    let (st, v2) = v1(&s, "audit?host=nope", ALPHA, None, None).await;
    assert_eq!(st, 403, "{v2}");
    // A host it can see, by alias too.
    let (st, v) = v1(&s, "audit?host=one", ALPHA, None, None).await;
    assert_eq!(st, 200, "{v}");
    let recs = v["records"].as_array().unwrap();
    assert_eq!(recs.len(), 1, "{v}");
    assert_eq!(recs[0]["host"], "t1");
    // beta may see t2: it has no records there, but it isn't refused.
    let (st, v) = v1(&s, "audit?host=t2", BETA, None, None).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["count"], 0);
}

#[tokio::test]
async fn audit_needs_an_identity() {
    let s = spawn(AuthMode::Off).await;
    let r = call(&s, ALPHA, None, "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), None, "{r}");
    let (st, v) = v1(&s, "audit", ALPHA, None, None).await;
    assert_eq!(st, 403, "{v}");
    assert!(v["error"].as_str().unwrap().contains("PROMPTO_AUTH=off"));
}

#[tokio::test]
async fn audit_is_behind_authentication() {
    let s = spawn(AuthMode::Required).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{}/v1/audit", s.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let resp = reqwest::Client::new()
        .get(format!("http://{}/v1/whoami", s.addr))
        .header("authorization", "Bearer pto_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_agent_kills_its_own_session_and_nothing_else() {
    let s = spawn(AuthMode::Required).await;
    let (st, v) = v1(
        &s,
        "kill",
        ALPHA,
        Some("sa"),
        Some(json!({ "scope": "session", "reason": "runaway loop" })),
    )
    .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["killed"]["scope"], "agent_session");
    assert_eq!(v["killed"]["session"], "sa");

    let before = s.ran();
    // alpha in that session: killed, nothing ran.
    let r = call(&s, ALPHA, Some("sa"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), Some("killed"), "{r}");
    let msg = r["error"]["message"].as_str().unwrap();
    assert!(msg.contains("agent alpha in session sa"), "{msg}");
    assert!(msg.contains("prompto unkill session sa"), "{msg}");
    assert_eq!(s.ran(), before);
    // Precheck says so too.
    let (_, p) = v1(
        &s,
        "precheck",
        ALPHA,
        Some("sa"),
        Some(json!({ "tool": "ssh_exec", "arguments": exec("t1") })),
    )
    .await;
    assert_eq!(p["decision"], "deny");
    assert_eq!(p["error_class"], "killed");
    // alpha in another session, and beta claiming the same session: run.
    let r = call(&s, ALPHA, Some("other"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), None, "{r}");
    let r = call(&s, BETA, Some("sa"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), None, "{r}");
    assert_eq!(s.ran(), before + 2);

    // Audited, with who did it.
    let rec = s
        .audit()
        .into_iter()
        .find(|r| r["type"] == "kill")
        .expect("kill record");
    assert_eq!(rec["action"], "on");
    assert_eq!(rec["scope"], "agent_session");
    assert_eq!(rec["agent"], "alpha");
    assert_eq!(rec["target"], "sa");
    assert_eq!(rec["by"]["agent"], "alpha");
    // And it shows in the agent's own audit view.
    let (_, v) = v1(&s, "audit?session=sa", ALPHA, Some("sa"), None).await;
    assert!(
        v["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "kill"),
        "{v}"
    );

    // The operator lifts it.
    assert_eq!(s.kill().clear_agent_sessions("sa").unwrap(), vec!["alpha"]);
    let r = call(&s, ALPHA, Some("sa"), "ssh_exec", exec("t1")).await;
    assert_eq!(class(&r), None, "{r}");
}

#[tokio::test]
async fn a_session_kill_needs_a_session_and_an_agent() {
    let s = spawn(AuthMode::Required).await;
    let (st, v) = v1(&s, "kill", ALPHA, None, Some(json!({ "scope": "session" }))).await;
    assert_eq!(st, 400, "{v}");
    // The body's session must agree with the header.
    let (st, _) = v1(
        &s,
        "kill",
        ALPHA,
        Some("sa"),
        Some(json!({ "scope": "session", "session": "sb" })),
    )
    .await;
    assert_eq!(st, 400);
    let (st, _) = v1(&s, "kill", ALPHA, None, Some(json!({ "scope": "host" }))).await;
    assert_eq!(st, 400);
    // Auth off: there is no agent to own a session.
    let off = spawn(AuthMode::Off).await;
    let (st, v) = v1(
        &off,
        "kill",
        ALPHA,
        Some("sa"),
        Some(json!({ "scope": "session" })),
    )
    .await;
    assert_eq!(st, 403, "{v}");
    assert!(off.kill().list().unwrap().0.is_empty());
    assert!(s.kill().list().unwrap().0.is_empty());
}

#[tokio::test]
async fn a_global_kill_needs_an_approvers_code() {
    let s = spawn(AuthMode::Required).await;
    // No code.
    let (st, v) = v1(
        &s,
        "kill",
        ALPHA,
        Some("sa"),
        Some(json!({ "scope": "global" })),
    )
    .await;
    assert_eq!(st, 400, "{v}");
    // A wrong one.
    let wrong = if code() == "000000" {
        "111111"
    } else {
        "000000"
    };
    let (st, v) = v1(
        &s,
        "kill",
        ALPHA,
        Some("sa"),
        Some(json!({ "scope": "global", "approver": "ap0", "totp_code": wrong })),
    )
    .await;
    assert_eq!(st, 403, "{v}");
    assert!(s.kill().list().unwrap().0.is_empty());
    let r = call(&s, BETA, Some("sb"), "ssh_exec", exec("t2")).await;
    assert_eq!(class(&r), None, "{r}");
    let refused = s
        .audit()
        .into_iter()
        .find(|r| r["type"] == "kill")
        .expect("refused kill recorded");
    assert_eq!(refused["action"], "refused");
    assert_eq!(refused["approved_by"], "ap0");

    // The right one: every call, every agent.
    let (st, v) = v1(
        &s,
        "kill",
        ALPHA,
        Some("sa"),
        Some(
            json!({ "scope": "global", "approver": "ap1", "totp_code": code(),
                     "reason": "panic button" }),
        ),
    )
    .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["killed"]["scope"], "global");
    let r = call(&s, BETA, Some("sb"), "ssh_exec", exec("t2")).await;
    assert_eq!(class(&r), Some("killed"), "{r}");
    let msg = r["error"]["message"].as_str().unwrap();
    assert!(msg.contains("panic button"), "{msg}");
    assert!(msg.contains("approver ap1"), "{msg}");
    let kills = s.kill().list().unwrap().0;
    assert_eq!(kills.len(), 1);
    assert_eq!(kills[0].scope, prompto::kill::Scope::Global);

    // The same code can't be used twice.
    let (st, _) = v1(
        &s,
        "kill",
        BETA,
        None,
        Some(json!({ "scope": "global", "approver": "ap1", "totp_code": code() })),
    )
    .await;
    assert_eq!(st, 403);

    // The operator lifts it.
    assert!(s.kill().clear_api_global().unwrap());
    let r = call(&s, BETA, Some("sb"), "ssh_exec", exec("t2")).await;
    assert_eq!(class(&r), None, "{r}");
}

// ---------------------------------------------------------------------------
// precheck: root
// ---------------------------------------------------------------------------

#[tokio::test]
async fn precheck_says_whether_the_call_is_root_capable() {
    let s = spawn(AuthMode::Required).await;
    let (_, v) = v1(
        &s,
        "precheck",
        ALPHA,
        Some("sa"),
        Some(json!({ "tool": "ssh_sudo_exec", "arguments": exec("t1") })),
    )
    .await;
    assert_eq!(v["decision"], "ask", "{v}");
    assert_eq!(v["root"], true, "{v}");
    let (_, v) = v1(
        &s,
        "precheck",
        ALPHA,
        Some("sa"),
        Some(json!({ "tool": "ssh_exec", "arguments": exec("t1") })),
    )
    .await;
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["root"], false, "{v}");
}

#[tokio::test]
async fn anonymous_callers_get_no_records_and_kill_nothing() {
    let s = spawn(AuthMode::Optional).await;
    let anon = |path: &str, body: Option<Value>| {
        let c = reqwest::Client::new();
        let url = format!("http://{}/v1/{path}", s.addr);
        let req = match body {
            Some(b) => c.post(url).json(&b),
            None => c.get(url),
        };
        async move {
            let r = req.header("x-prompto-session", "sa").send().await.unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let (st, body) = anon("whoami", None).await;
    assert_eq!(st, 200);
    assert!(body.contains("anonymous"), "{body}");
    let (st, body) = anon("audit", None).await;
    assert_eq!(st, 403, "{body}");
    let (st, body) = anon("kill", Some(json!({ "scope": "session" }))).await;
    assert_eq!(st, 403, "{body}");
    assert!(s.kill().list().unwrap().0.is_empty());
    // A named agent is fine in the same mode.
    let (st, v) = v1(&s, "audit", ALPHA, None, None).await;
    assert_eq!(st, 200, "{v}");
}
