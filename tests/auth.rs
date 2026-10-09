//! Agent authentication (`PROMPTO_AUTH`, role tokens), end to end.
//!
//! The router tests drive `prompto::server::build_router` — the shipping
//! middleware chain — and read the agent back from the journald warn line
//! that every classified failure emits, which is where attribution lives
//! until the audit log (E4). The binary tests run the real `prompto`
//! executable for what only `main` wires: the `agent` CLI, SIGHUP reload
//! and the stdio identity.
//!
//! Refusals are asserted, not just successes: an auth layer that lets
//! everything through passes every "does it still work?" test.

use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

mod common;

/// `bare` has no capabilities, so `ssh_exec` on it is a classified
/// refusal (and a warn line) without any network. `multi` answers from a
/// second address, for the `extra_ips` guard.
const INVENTORY: &str = r#"
[host.bare]
ip = "192.0.2.77"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = []

[host.multi]
ip = "192.0.2.78"
extra_ips = ["198.51.100.9", "2001:db8::9"]
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]
"#;

// ---------------------------------------------------------------------------
// Log capture: one global subscriber for this test binary. Tests run in
// parallel, so each one tags its calls with a unique session ID and
// looks only at lines carrying it.
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
        // Audit records repeat the call's fields; these tests are about
        // the operational log lines.
        .filter(|l| l.contains(needle) && !l.contains(" prompto::audit: "))
        .map(String::from)
        .collect()
}

fn unique(tag: &str) -> String {
    format!("{tag}-{}", ulid::Ulid::generate())
}

// ---------------------------------------------------------------------------
// Router harness
// ---------------------------------------------------------------------------

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn spawn_server_with(auth: AuthConfig) -> Server {
    spawn_server_full(auth, false).await
}

async fn spawn_server_full(auth: AuthConfig, legacy_session_mode: bool) -> Server {
    init_logs();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(SshClient::new("ssh".into(), Duration::from_secs(5))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(5),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode,
        auth,
        audit: Default::default(),
        kill: Default::default(),
        cancel: cancel.clone(),
    });
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
    Server { addr, cancel }
}

/// A store holding `alpha` (token `pto_alpha`), `beta` (`pto_beta`), both
/// in group `ops`, and the revoked `retired` (token `pto_retired`).
fn store() -> AgentStore {
    let mut a = Agents::default();
    for (name, token, disabled) in [
        ("alpha", "pto_alpha", false),
        ("beta", "pto_beta", false),
        ("retired", "pto_retired", true),
    ] {
        a.agents.insert(
            name.into(),
            prompto::agent::AgentEntry {
                groups: vec!["ops".into()],
                token_sha256: prompto::agent::hex(&prompto::agent::sha256(token.as_bytes())),
                created: None,
                disabled,
            },
        );
    }
    AgentStore::new(
        Agents::from_toml_str(&a.to_toml_string().unwrap()).unwrap(),
        None,
    )
}

/// Grants every agent in [`store`] (and `anonymous`) everything, root
/// included, so these tests see authentication and nothing else.
/// Policy itself is tested in `tests/policy.rs`.
fn allow_all() -> PolicyStore {
    let rule = |sudo: bool| {
        format!(
            "[[rule]]\nagents = [\"alpha\", \"beta\", \"retired\", \"anonymous\"]\n\
             hosts = [\"*\"]\ntools = [\"*\"]\nsudo = {sudo}\n"
        )
    };
    let toml = format!("{}{}", rule(false), rule(true));
    PolicyStore::new(Policy::from_toml_str(&toml, "policy.toml").unwrap(), None)
}

async fn server(mode: AuthMode) -> Server {
    spawn_server_with(AuthConfig {
        mode,
        store: store(),
        policy: allow_all(),
    })
    .await
}

/// `tools/call` over the stateless path. Returns (status, parsed body).
async fn call(server: &Server, tool: &str, args: Value, headers: &[(&str, &str)]) -> (u16, Value) {
    let (status, text) = post_call(server.addr, tool, args, headers)
        .await
        .unwrap_or_else(|e| panic!("POST /mcp on {}: {e:?}", server.addr));
    (status, parse_body(status, &text))
}

/// The request [`call`] sends. Returns (status, raw body).
async fn post_call(
    addr: SocketAddr,
    tool: &str,
    args: Value,
    headers: &[(&str, &str)],
) -> reqwest::Result<(u16, String)> {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", tool);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await?;
    let status = resp.status().as_u16();
    Ok((status, resp.text().await?))
}

/// A JSON body, or the JSON-RPC message of an SSE one. Panics with the
/// status and the raw body when it is neither.
fn parse_body(status: u16, text: &str) -> Value {
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(text);
    serde_json::from_str(raw)
        .unwrap_or_else(|e| panic!("HTTP {status}, body is not JSON-RPC ({e}): {text:?}"))
}

/// `ssh_exec` on `bare`: refused for capability, so the server logs a
/// warn line carrying agent and session. Returns (status, warn lines for
/// this session).
async fn refused_call(server: &Server, session: &str, auth: Option<&str>) -> (u16, Vec<String>) {
    let bearer = auth.map(|t| format!("Bearer {t}"));
    let mut headers = vec![("x-prompto-session", session)];
    if let Some(b) = &bearer {
        headers.push(("authorization", b.as_str()));
    }
    let (status, body) = call(
        server,
        "ssh_exec",
        json!({ "host": "bare", "cmd": "true" }),
        &headers,
    )
    .await;
    if status == 200 {
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("refused_capability"),
            "{body}"
        );
    }
    (status, log_lines(&format!("session_id=\"{session}\"")))
}

fn assert_401_jsonrpc(status: u16, body: &Value, reason: &str) {
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["jsonrpc"], "2.0");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(msg.starts_with("unauthorized: "), "{msg}");
    assert!(msg.contains(reason), "{msg}");
}

async fn get_log(server: &Server, auth: Option<&str>) -> (u16, String) {
    let mut req = reqwest::Client::new().get(format!(
        "http://{}/log?host=bare&unit=ssh.service",
        server.addr
    ));
    if let Some(t) = auth {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

/// Default (off): no token needed, any token ignored, no agent attached,
/// and `X-Prompto-Session` neither parsed nor warned about — the existing
/// deployment's behaviour, logs included. The session can't tag the log
/// lines here, so they are found by the call's request ID.
#[tokio::test]
async fn off_needs_no_token_and_attributes_nothing() {
    let s = spawn_server_with(AuthConfig::default()).await;
    let tag = unique("off");
    let bad = format!("{tag} not=valid");
    for (token, sess) in [(None, tag.as_str()), (Some("Bearer garbage"), bad.as_str())] {
        let mut headers = vec![("x-prompto-session", sess)];
        if let Some(t) = token {
            headers.push(("authorization", t));
        }
        let (status, body) = call(
            &s,
            "ssh_exec",
            json!({ "host": "bare", "cmd": "true" }),
            &headers,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let rid = body["error"]["data"]["request_id"].as_str().unwrap();
        let lines = log_lines(&format!("request_id=\"{rid}\""));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("agent=\"-\""), "{}", lines[0]);
        assert!(!lines[0].contains("session_id"), "{}", lines[0]);
    }
    assert!(
        log_lines(&tag).is_empty(),
        "off logged the session header: {:?}",
        log_lines(&tag)
    );
    let (status, body) = get_log(&s, None).await;
    assert_eq!(status, 400, "past auth, refused for capability: {body}");
}

#[tokio::test]
async fn optional_without_token_is_anonymous() {
    let s = server(AuthMode::Optional).await;
    let sess = unique("anon");
    let (status, lines) = refused_call(&s, &sess, None).await;
    assert_eq!(status, 200);
    assert!(lines[0].contains("agent=\"anonymous\""), "{lines:?}");
}

#[tokio::test]
async fn optional_with_invalid_token_is_anonymous_and_warned() {
    let s = server(AuthMode::Optional).await;
    let sess = unique("bad");
    let (status, lines) = refused_call(&s, &sess, Some("pto_wrong_secret_value")).await;
    assert_eq!(status, 200);
    let warn = lines
        .iter()
        .find(|l| l.contains("invalid bearer token presented"))
        .unwrap_or_else(|| panic!("{lines:?}"));
    assert!(warn.contains("caller_ip=Some(127.0.0.1)"), "{warn}");
    assert!(
        lines.iter().any(|l| l.contains("agent=\"anonymous\"")),
        "{lines:?}"
    );
    assert!(
        log_lines("pto_wrong_secret_value").is_empty(),
        "a presented token must never be logged"
    );
}

#[tokio::test]
async fn optional_with_valid_token_names_the_agent() {
    let s = server(AuthMode::Optional).await;
    let sess = unique("valid");
    let (status, lines) = refused_call(&s, &sess, Some("pto_alpha")).await;
    assert_eq!(status, 200);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("agent=\"alpha\""), "{}", lines[0]);
}

#[tokio::test]
async fn optional_with_revoked_token_is_anonymous_and_warned() {
    let s = server(AuthMode::Optional).await;
    let sess = unique("revoked-opt");
    let (status, lines) = refused_call(&s, &sess, Some("pto_retired")).await;
    assert_eq!(status, 200);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("revoked agent token presented") && l.contains("retired")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("tool call failed") && l.contains("agent=\"anonymous\"")),
        "{lines:?}"
    );
}

#[tokio::test]
async fn required_without_or_with_bad_token_is_401() {
    let s = server(AuthMode::Required).await;
    let args = json!({});
    let (status, body) = call(&s, "inventory_list", args.clone(), &[]).await;
    assert_401_jsonrpc(status, &body, "missing bearer token");
    for bad in [
        "Bearer pto_nope",
        "Basic YWxwaGE6eA==",
        "Bearer",
        "pto_alpha",
    ] {
        let (status, body) = call(
            &s,
            "inventory_list",
            args.clone(),
            &[("authorization", bad)],
        )
        .await;
        assert_401_jsonrpc(status, &body, "invalid bearer token");
    }
}

#[tokio::test]
async fn required_with_revoked_token_is_401() {
    let s = server(AuthMode::Required).await;
    let (status, body) = call(
        &s,
        "inventory_list",
        json!({}),
        &[("authorization", "Bearer pto_retired")],
    )
    .await;
    assert_401_jsonrpc(status, &body, "revoked token");
    let (status, _) = get_log(&s, Some("pto_retired")).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn required_with_valid_token_works_and_names_the_agent() {
    let s = server(AuthMode::Required).await;
    let (status, body) = call(
        &s,
        "inventory_list",
        json!({}),
        &[("authorization", "Bearer pto_alpha")],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    let sess = unique("req-valid");
    let (status, lines) = refused_call(&s, &sess, Some("pto_alpha")).await;
    assert_eq!(status, 200);
    assert!(lines[0].contains("agent=\"alpha\""), "{lines:?}");
}

#[tokio::test]
async fn log_endpoint_is_gated_the_same_way() {
    let s = server(AuthMode::Required).await;
    let (status, body) = get_log(&s, None).await;
    assert_eq!(status, 401);
    assert_eq!(body, "unauthorized: missing bearer token\n");
    let (status, _) = get_log(&s, Some("pto_nope")).await;
    assert_eq!(status, 401);
    // Past auth; `bare` lacks sudo_exec, so the request is then refused
    // by the same gate as service_logs.
    let (status, body) = get_log(&s, Some("pto_alpha")).await;
    assert_eq!(status, 400, "{body}");
}

// ---------------------------------------------------------------------------
// X-Prompto-Session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_header_is_bounded_and_charset_checked() {
    let s = server(AuthMode::Optional).await;

    // 128 chars of the allowed charset: kept.
    let max = format!("{}{}", unique("s"), "x".repeat(128))[..128].to_string();
    let (_, lines) = refused_call(&s, &max, Some("pto_alpha")).await;
    assert_eq!(lines.len(), 1, "{lines:?}");

    // 129 chars: dropped, the call proceeds without a session.
    let long = format!("{max}x");
    let (status, lines) = refused_call(&s, &long, Some("pto_alpha")).await;
    assert_eq!(status, 200);
    assert!(
        lines.is_empty(),
        "overlong session id was logged: {lines:?}"
    );

    // Outside the charset: dropped too.
    let tag = unique("charset");
    let bad = format!("{tag} \"injected=1");
    let (status, _) = refused_call(&s, &bad, Some("pto_alpha")).await;
    assert_eq!(status, 200);
    assert!(log_lines(&tag).is_empty(), "{:?}", log_lines(&tag));
}

// ---------------------------------------------------------------------------
// Legacy sessions (PROMPTO_LEGACY_SESSION_MODE=true)
// ---------------------------------------------------------------------------

/// POST one legacy-session message. Returns (status, response headers,
/// parsed body or Null).
async fn legacy_post(
    server: &Server,
    msg: Value,
    mcp_session: Option<&str>,
    token: Option<&str>,
    prompto_session: &str,
) -> (u16, reqwest::header::HeaderMap, Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/mcp", server.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("x-prompto-session", prompto_session);
    if let Some(sid) = mcp_session {
        req = req
            .header("mcp-session-id", sid)
            .header("mcp-protocol-version", "2025-11-25");
    }
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req.json(&msg).send().await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    let body = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .or_else(|| Some(text.as_str()).filter(|t| t.starts_with('{')))
        .map(|raw| serde_json::from_str(raw).unwrap())
        .unwrap_or(Value::Null);
    (status, headers, body)
}

/// Handshake a legacy session as `token`; returns its `Mcp-Session-Id`.
async fn legacy_open(server: &Server, token: Option<&str>, tag: &str) -> String {
    let (status, headers, body) = legacy_post(
        server,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"prompto-tests","version":"0"}}}),
        None,
        token,
        tag,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let sid = headers
        .get("mcp-session-id")
        .expect("legacy mode must hand out a session")
        .to_str()
        .unwrap()
        .to_string();
    let (status, _, _) = legacy_post(
        server,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        Some(&sid),
        token,
        tag,
    )
    .await;
    assert_eq!(status, 202);
    sid
}

/// `ssh_exec` on `bare` inside the session (refused for capability).
async fn legacy_refused_call(
    server: &Server,
    sid: &str,
    token: Option<&str>,
    tag: &str,
) -> (u16, Value) {
    let (status, _, body) = legacy_post(
        server,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"ssh_exec","arguments":{"host":"bare","cmd":"true"}}}),
        Some(sid),
        token,
        tag,
    )
    .await;
    (status, body)
}

/// A legacy session runs as whoever created it, so it is bound to them:
/// another agent, or nobody, presenting its `Mcp-Session-Id` gets a 401
/// — in optional mode too — and the creator keeps working.
#[tokio::test]
async fn legacy_session_is_bound_to_its_creator() {
    for mode in [AuthMode::Optional, AuthMode::Required] {
        let s = spawn_server_full(
            AuthConfig {
                mode,
                store: store(),
                policy: allow_all(),
            },
            true,
        )
        .await;
        let tag = unique("legacy");
        let sid = legacy_open(&s, Some("pto_alpha"), &tag).await;

        let mut intruders = vec![Some("pto_beta")];
        if mode == AuthMode::Optional {
            intruders.push(None); // anonymous riding alpha's session
            intruders.push(Some("pto_garbage")); // degrades to anonymous
        }
        for who in intruders {
            let (status, body) = legacy_refused_call(&s, &sid, who, &tag).await;
            assert_401_jsonrpc(status, &body, "session belongs to another agent");
            let ran = tool_lines(&tag);
            assert!(ran.is_empty(), "{mode:?}/{who:?}: the call ran: {ran:?}");
        }
        let warns = log_lines(&sessions_redacted(&sid));
        assert!(
            warns.iter().any(|l| l.contains("belongs to another agent")),
            "{warns:?}"
        );
        assert!(
            !String::from_utf8_lossy(&LOGS.lock().unwrap()).contains(&sid),
            "full Mcp-Session-Id logged (journal line or audit record)"
        );
        // The audit record names the session, shortened like the journal.
        let short = sessions_redacted(&sid);
        assert!(
            String::from_utf8_lossy(&LOGS.lock().unwrap())
                .lines()
                .any(|l| l.contains(" prompto::audit: ")
                    && l.contains("session belongs to another agent")
                    && l.contains(&format!("mcp_session=\"{short}\""))),
            "no audit record with mcp_session={short}"
        );

        // The creator is unaffected and still attributed.
        let (status, body) = legacy_refused_call(&s, &sid, Some("pto_alpha"), &tag).await;
        assert_eq!(status, 200, "{mode:?}: {body}");
        let lines = tool_lines(&tag);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("agent=\"alpha\""), "{}", lines[0]);
    }
}

/// An anonymous creator (optional mode) can't be ridden by an agent
/// either: the binding is to the name, `anonymous` included.
#[tokio::test]
async fn legacy_anonymous_session_refuses_an_agent() {
    let s = spawn_server_full(
        AuthConfig {
            mode: AuthMode::Optional,
            store: store(),
            policy: allow_all(),
        },
        true,
    )
    .await;
    let tag = unique("legacy-anon");
    let sid = legacy_open(&s, None, &tag).await;
    let (status, body) = legacy_refused_call(&s, &sid, Some("pto_alpha"), &tag).await;
    assert_401_jsonrpc(status, &body, "session belongs to another agent");
    let (status, _) = legacy_refused_call(&s, &sid, None, &tag).await;
    assert_eq!(status, 200);
    let lines = log_lines(&tag);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("agent=\"anonymous\""), "{}", lines[0]);
}

/// With auth off nobody is identified and sessions work as today.
#[tokio::test]
async fn legacy_session_with_auth_off_is_unchanged() {
    let s = spawn_server_full(AuthConfig::default(), true).await;
    let sid = legacy_open(&s, None, "x").await;
    let (status, body) = legacy_refused_call(&s, &sid, Some("anything"), "x").await;
    assert_eq!(status, 200, "{body}");
}

/// The "tool call failed" lines for `tag`: proof a call actually ran.
fn tool_lines(tag: &str) -> Vec<String> {
    log_lines(tag)
        .into_iter()
        .filter(|l| l.contains("tool call failed"))
        .collect()
}

fn sessions_redacted(sid: &str) -> String {
    prompto::sessions::redact(sid)
}

// ---------------------------------------------------------------------------
// extra_ips
// ---------------------------------------------------------------------------

/// A machine calling from a second address (Wi-Fi, VPN, IPv6) is still
/// itself. The test client's TCP peer is loopback, a trusted proxy, so
/// X-Real-IP sets the caller.
#[tokio::test]
async fn extra_ips_are_self_targeting() {
    let s = spawn_server_with(AuthConfig::default()).await;
    for ip in ["198.51.100.9", "::ffff:198.51.100.9", "2001:db8::9"] {
        let (_, body) = call(
            &s,
            "ssh_exec",
            json!({ "host": "multi", "cmd": "true" }),
            &[("x-real-ip", ip)],
        )
        .await;
        let msg = body["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains("refused_self_target"), "{ip}: {body}");
    }
}

// ---------------------------------------------------------------------------
// The real binary: CLI, SIGHUP reload, stdio, startup config
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_prompto");

struct Proc {
    child: std::process::Child,
    port: u16,
    dir: PathBuf,
}

impl Proc {
    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.log")).unwrap_or_default()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_inventory(dir: &Path) -> PathBuf {
    let p = dir.join("prompto.toml");
    std::fs::write(&p, INVENTORY).unwrap();
    p
}

fn agent_cli(agents: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(BIN)
        .arg("agent")
        .args(args)
        .env("PROMPTO_AGENTS", agents)
        .output()
        .unwrap()
}

fn spawn_binary(dir: &Path, agents: &Path) -> Proc {
    spawn_binary_mode(dir, agents, "required")
}

/// The server on a free port; its stderr goes to `dir/stderr.log`.
fn spawn_binary_mode(dir: &Path, agents: &Path, mode: &str) -> Proc {
    let child = std::process::Command::new(BIN)
        .env("PROMPTO_INVENTORY", write_inventory(dir))
        .env("PROMPTO_AGENTS", agents)
        .env("PROMPTO_AUTH", mode)
        // Absent: deny-all, and never whatever /etc holds on the test box.
        .env("PROMPTO_POLICY", dir.join("policy.toml"))
        .env("PROMPTO_BIND", "127.0.0.1:0")
        .env("PROMPTO_ALLOWED_HOSTS", "127.0.0.1")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_AUDIT_LOG", dir.join("audit.jsonl"))
        .env("PROMPTO_KILL_FILE", dir.join("kill"))
        .env("PROMPTO_USAGE_LOG", dir.join("usage.jsonl"))
        .env("RUST_LOG", "prompto=info")
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    // Owned by `Proc` from here, whose Drop kills and reaps it.
    let mut p = Proc {
        child,
        port: 0,
        dir: dir.to_path_buf(),
    };
    p.port = common::bound_port(&mut p.child, &dir.join("stderr.log"));
    p
}

/// The status of `inventory_list` on the binary. The body must be
/// JSON-RPC whatever the status; a failed request shows the server's
/// stderr.
async fn status_with(p: &Proc, token: Option<&str>) -> u16 {
    let addr = SocketAddr::from(([127, 0, 0, 1], p.port));
    let headers: Vec<(&str, String)> = token
        .map(|t| vec![("authorization", format!("Bearer {t}"))])
        .unwrap_or_default();
    let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (status, text) = post_call(addr, "inventory_list", json!({}), &h)
        .await
        .unwrap_or_else(|e| panic!("POST /mcp on {addr}: {e:?}\nserver stderr:\n{}", p.stderr()));
    let body = parse_body(status, &text);
    assert_eq!(body["jsonrpc"], "2.0", "HTTP {status}: {text}");
    status
}

async fn sighup(p: &Proc) {
    let ok = std::process::Command::new("kill")
        .args(["-HUP", &p.child.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok);
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// The whole lifecycle without a restart or a signal (S5.2): no agents
/// → 401; `agent add` works on the next request; a broken file fails
/// closed (401, not the previous agents) until it is fixed; `agent
/// revoke` → 401 on the next request. SIGHUP still re-reads too.
#[tokio::test]
async fn cli_add_and_revoke_take_effect_on_the_next_request() {
    let dir = tempfile::tempdir().unwrap();
    let agents = dir.path().join("agents.toml");
    let p = spawn_binary(dir.path(), &agents);

    assert_eq!(status_with(&p, None).await, 401);

    let out = agent_cli(&agents, &["add", "sbx-tester", "--groups", "ops,build"]);
    assert!(out.status.success(), "{out:?}");
    let token = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(token.starts_with("pto_"), "stdout must be just the token");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("next request"),
        "CLI must say when it applies: {stderr}"
    );
    let file = std::fs::read_to_string(&agents).unwrap();
    assert!(!file.contains(&token), "token written to disk");

    assert_eq!(status_with(&p, Some(&token)).await, 200, "no SIGHUP needed");

    // Fail-closed: a broken file refuses every token, the previous
    // agents included, until it is fixed.
    std::fs::write(&agents, "[agent.x]\ntoken_sha256 = \"short\"\n").unwrap();
    assert_eq!(status_with(&p, Some(&token)).await, 401);
    let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
    assert!(log.contains("AGENTS FILE INVALID"), "{log}");
    std::fs::write(&agents, &file).unwrap();
    assert_eq!(status_with(&p, Some(&token)).await, 200, "fixed");

    let out = agent_cli(&agents, &["revoke", "sbx-tester"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        status_with(&p, Some(&token)).await,
        401,
        "revoked, no SIGHUP"
    );
    sighup(&p).await;
    assert_eq!(status_with(&p, Some(&token)).await, 401);

    let out = agent_cli(&agents, &["list"]);
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(
        list.contains("sbx-tester") && list.contains("revoked"),
        "{list}"
    );
    let hash = prompto::agent::hex(&prompto::agent::sha256(token.as_bytes()));
    assert!(list.contains(&hash[..8]) && !list.contains(&hash), "{list}");
}

#[test]
fn cli_refuses_duplicates_reserved_names_and_unknown_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let agents = dir.path().join("agents.toml");
    assert!(agent_cli(&agents, &["add", "one"]).status.success());
    assert!(!agent_cli(&agents, &["add", "one"]).status.success());
    assert!(!agent_cli(&agents, &["add", "anonymous"]).status.success());
    assert!(!agent_cli(&agents, &["add", "Bad Name"]).status.success());
    assert!(!agent_cli(&agents, &["revoke", "two"]).status.success());
}

/// `PROMPTO_AUTH=off` must not depend on agents.toml: a malformed or
/// unreadable file neither stops startup nor is touched on SIGHUP, and
/// its presence is mentioned once. The same files are fatal in
/// optional/required.
#[tokio::test]
async fn off_ignores_a_broken_agents_file() {
    for broken in ["malformed", "unreadable"] {
        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("agents.toml");
        if broken == "malformed" {
            std::fs::write(&agents, "[agent.x]\ntoken_sha256 = \"short\"\n").unwrap();
        } else {
            // A directory: read_to_string fails whoever runs the test.
            std::fs::create_dir(&agents).unwrap();
        }

        let p = spawn_binary_mode(dir.path(), &agents, "off");
        assert_eq!(status_with(&p, None).await, 200, "{broken}");
        sighup(&p).await;
        assert_eq!(status_with(&p, None).await, 200, "{broken}: after SIGHUP");
        let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
        assert_eq!(
            log.matches("agents file ignored").count(),
            1,
            "{broken}: {log}"
        );
        assert!(log.contains("inventory reloaded on SIGHUP"), "{log}");
        assert!(
            !log.contains("agents reload"),
            "{broken}: SIGHUP read it: {log}"
        );
        drop(p);

        for mode in ["optional", "required"] {
            let out = std::process::Command::new(BIN)
                .env("PROMPTO_INVENTORY", write_inventory(dir.path()))
                .env("PROMPTO_AGENTS", &agents)
                .env("PROMPTO_AUTH", mode)
                .env("PROMPTO_BIND", "127.0.0.1:0")
                .env("PROMPTO_GAIN_ENABLED", "false")
                .env("PROMPTO_AUDIT_LOG", dir.path().join("audit.jsonl"))
                .env("PROMPTO_KILL_FILE", dir.path().join("kill"))
                .output()
                .unwrap();
            assert!(!out.status.success(), "{broken}/{mode} started");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("loading agents"),
                "{broken}/{mode}: {out:?}"
            );
        }
    }
}

#[test]
fn unknown_auth_mode_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(BIN)
        .env("PROMPTO_INVENTORY", write_inventory(dir.path()))
        .env("PROMPTO_AGENTS", dir.path().join("agents.toml"))
        .env("PROMPTO_AUTH", "requried")
        .env("PROMPTO_BIND", "127.0.0.1:0")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_AUDIT_LOG", dir.path().join("audit.jsonl"))
        .env("PROMPTO_KILL_FILE", dir.path().join("kill"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("PROMPTO_AUTH"));
}

/// stdio is agent `local`, whatever PROMPTO_AUTH says.
#[test]
fn stdio_is_agent_local() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(BIN)
        .arg("--stdio")
        .env("PROMPTO_INVENTORY", write_inventory(dir.path()))
        .env("PROMPTO_AGENTS", dir.path().join("agents.toml"))
        .env("PROMPTO_AUTH", "required")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_AUDIT_LOG", dir.path().join("audit.jsonl"))
        .env("PROMPTO_KILL_FILE", dir.path().join("kill"))
        .env("RUST_LOG", "prompto=info")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for msg in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"t","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"ssh_exec","arguments":{"host":"bare","cmd":"true"}}}),
    ] {
        writeln!(stdin, "{msg}").unwrap();
    }
    stdin.flush().unwrap();
    let stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let line = stderr
        .lines()
        .map_while(Result::ok)
        .find(|l| l.contains("tool call failed"));
    let _ = child.kill();
    let _ = child.wait();
    // The subscriber colours its output; drop the escape sequences.
    let line: String = {
        let raw = line.expect("no warn line from the stdio call");
        let mut out = String::new();
        let mut esc = false;
        for c in raw.chars() {
            match (esc, c) {
                (_, '\x1b') => esc = true,
                (true, 'm') => esc = false,
                (true, _) => {}
                (false, c) => out.push(c),
            }
        }
        out
    };
    assert!(line.contains("agent=\"local\""), "{line}");
}

// ---------------------------------------------------------------------------
// Auto-reload under non-atomic writes
// ---------------------------------------------------------------------------

/// agents.toml and policy.toml are reloaded on the request after they
/// change, and editors (or `echo >`) rewrite them in place: truncate,
/// then write. A request that lands mid-write must still get a
/// well-formed answer — a JSON-RPC 401 or tool error if the half file
/// it read fails closed, never an empty body, a 500 or a reset — and
/// once the writes stop the next request sees the finished file.
#[tokio::test]
async fn torn_config_writes_never_break_a_response() {
    let dir = tempfile::tempdir().unwrap();
    let agents_path = dir.path().join("agents.toml");
    let policy_path = dir.path().join("policy.toml");
    let agents_toml = store().snapshot().to_toml_string().unwrap();
    // Two versions of each file, so every rewrite changes the stamp.
    let versions = |base: &str| [base.to_string(), format!("# edited\n{base}")];
    let agents_v = versions(&agents_toml);
    let policy_v =
        versions("[[rule]]\nagents = [\"alpha\"]\nhosts = [\"*\"]\ntools = [\"inventory_list\"]\n");
    std::fs::write(&agents_path, &agents_v[0]).unwrap();
    std::fs::write(&policy_path, &policy_v[0]).unwrap();
    let s = spawn_server_with(AuthConfig {
        mode: AuthMode::Required,
        store: AgentStore::load_from(agents_path.clone()).unwrap(),
        policy: PolicyStore::load_from(policy_path.clone()).unwrap(),
    })
    .await;

    // In place, in two writes with a pause between: the window an
    // editor leaves open.
    fn rewrite(path: &Path, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        let (a, b) = text.split_at(text.len() / 2);
        f.write_all(a.as_bytes()).unwrap();
        std::thread::sleep(Duration::from_micros(200));
        f.write_all(b.as_bytes()).unwrap();
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let stop = stop.clone();
        let (agents_v, policy_v) = (agents_v.clone(), policy_v.clone());
        let (ap, pp) = (agents_path.clone(), policy_path.clone());
        std::thread::spawn(move || {
            let mut i = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                rewrite(&ap, &agents_v[i % 2]);
                rewrite(&pp, &policy_v[i % 2]);
                std::thread::sleep(Duration::from_millis(1));
                i += 1;
            }
        })
    };

    let mut refused = 0;
    for _ in 0..300 {
        let (status, body) = call(
            &s,
            "inventory_list",
            json!({}),
            &[("authorization", "Bearer pto_alpha")],
        )
        .await;
        match status {
            401 => {
                assert_401_jsonrpc(status, &body, "");
                refused += 1;
            }
            200 if body.get("result").is_some() => {}
            200 => {
                let msg = body["error"]["message"].as_str().unwrap_or_default();
                assert!(msg.contains("refused_policy"), "{body}");
                refused += 1;
            }
            _ => panic!("HTTP {status}: {body}"),
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
    eprintln!("refused mid-write: {refused}/300");

    // The writes have stopped on a valid pair: the next call reads it.
    let (status, body) = call(
        &s,
        "inventory_list",
        json!({}),
        &[("authorization", "Bearer pto_alpha")],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("result").is_some(), "{body}");
}
