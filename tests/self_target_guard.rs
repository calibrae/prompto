//! The self-targeting guard, tested end-to-end through the real HTTP stack.
//!
//! These tests exist because the guard has failed **open** twice:
//!
//!   * v0.6.19 — the caller IP was read per-request, but rmcp spawns the
//!     service task, so the task-local was already gone. Fixed by
//!     snapshotting in the service factory.
//!   * v0.6.20 — `ip` was a `String` parsed inside the guard; an
//!     unparseable value made the `if let` chain fall through and ALLOW
//!     the call. Fixed by typing the field as `IpAddr`.
//!
//! Both failures were silent: no error, no log, and every "does it still
//! work?" test kept passing because calls continued to succeed. A test
//! that only asserts success is worthless here. **Every test below
//! asserts a REFUSAL**, and drives the shipping router from
//! `prompto::server::build_router` rather than a hand-rolled stand-in, so
//! the middleware → factory → guard chain is the thing under test.

use mcp_gain::Tracker;
use prompto::inventory::{Inventory, InventoryStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Inventory whose `loopback` host IS the address the test client
/// connects from, so a call targeting it is by definition self-targeting.
const INVENTORY: &str = r#"
[host.loopback]
ip = "127.0.0.1"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]

[host.elsewhere]
ip = "192.0.2.77"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]
"#;

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Boot the real router on an ephemeral loopback port, sessionless
/// (production default).
async fn spawn_server() -> Server {
    spawn_server_with(false).await
}

/// Boot the real router with an explicit `legacy_session_mode`.
async fn spawn_server_with(legacy_session_mode: bool) -> Server {
    let inv = Inventory::from_toml_str(INVENTORY).unwrap();
    let store = InventoryStore::new(inv, None);
    let cancel = CancellationToken::new();

    let app = build_router(HttpParams {
        store,
        ssh: Arc::new(SshClient::new("ssh".into(), Duration::from_secs(5))),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(5),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        // The test client sends Host: 127.0.0.1:<port>; keep rmcp's
        // default allowlist behaviour rather than disabling it, so we
        // aren't testing a laxer config than production.
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode,
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
    // Give the listener a moment to come up.
    tokio::time::sleep(Duration::from_millis(80)).await;
    Server { addr, cancel }
}

/// `_meta` block required by the 2026-07-28 stateless lifecycle: there is
/// no `initialize`, so every request carries the protocol version and
/// client capabilities itself.
fn stateless_meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "prompto-tests", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn tool_call_body(tool: &str, host_arg: &str, meta: Option<serde_json::Value>) -> serde_json::Value {
    let mut params = serde_json::json!({
        "name": tool,
        "arguments": { "host": host_arg, "cmd": "echo hello" }
    });
    if let Some(m) = meta {
        params["_meta"] = m;
    }
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params })
}

/// Fire a `tools/call` over the **2026-07-28 stateless** path — no
/// session, no handshake. This is the modern dialect.
async fn call_tool(server: &Server, host_arg: &str, extra_headers: &[(&str, &str)]) -> String {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/mcp", server.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        // SEP-2243 standard headers, mandatory from 2026-07-28 and
        // validated against the body.
        .header("mcp-method", "tools/call")
        .header("mcp-name", "ssh_exec");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let resp = req
        .json(&tool_call_body("ssh_exec", host_arg, Some(stateless_meta())))
        .send()
        .await
        .expect("request failed");
    resp.text().await.expect("body read failed")
}

/// Fire a `tools/call` over the **legacy** path: a real `initialize`
/// handshake, then the call bound to the returned `Mcp-Session-Id`.
///
/// This path matters because `legacy_session_mode` is left ON, and it
/// snapshots the caller IP once at session creation rather than
/// per-request — a different code path through the same guard.
async fn call_tool_legacy(server: &Server, host_arg: &str) -> String {
    call_tool_legacy_inner(server, host_arg, true).await
}

/// `require_session`: assert the server issued an `Mcp-Session-Id`. False
/// when running sessionless, where legacy clients are served statelessly
/// and no session id comes back.
async fn call_tool_legacy_inner(
    server: &Server,
    host_arg: &str,
    require_session: bool,
) -> String {
    let client = reqwest::Client::new();
    let url = format!("http://{}/mcp", server.addr);

    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "prompto-tests-legacy", "version": "0" }
        }
    });
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .json(&init)
        .send()
        .await
        .expect("initialize failed");
    let session = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if require_session {
        assert!(
            session.is_some(),
            "server did not issue a session id on the legacy path"
        );
    }
    // Drain the initialize response before continuing.
    let _ = resp.text().await;

    let mut call = client
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(sid) = session {
        call = call.header("mcp-session-id", sid);
    }
    call.json(&tool_call_body("ssh_exec", host_arg, None))
        .send()
        .await
        .expect("tools/call failed")
        .text()
        .await
        .expect("body read failed")
}

/// THE test. A call targeting the caller's own host must be REFUSED.
///
/// If the caller-IP plumbing regresses — task-local timing, proxy
/// resolution, field typing — this is what catches it. Asserting that
/// calls merely succeed would not.
#[tokio::test]
async fn self_targeted_call_is_refused() {
    let server = spawn_server().await;
    let body = call_tool(&server, "loopback", &[]).await;

    assert!(
        body.contains("calling agent's own host"),
        "self-targeted call was NOT refused — the guard is failing open.\nresponse: {body}"
    );
    // And make sure it didn't "refuse" merely by failing to reach the tool.
    assert!(
        !body.contains("unknown host"),
        "refusal came from host lookup, not the guard: {body}"
    );
}

/// An untrusted peer must not be able to dodge the guard by claiming a
/// different source address. Here the client IS loopback (trusted by
/// default), so we instead prove the inverse below; this test pins the
/// behaviour that a *forged* header on the trusted path still resolves
/// through `resolve_client_ip` rather than being ignored wholesale.
///
/// A trusted proxy legitimately rewrites the caller, so supplying
/// `X-Real-IP: 192.0.2.77` makes the call look like it came from
/// `elsewhere` — which means targeting `elsewhere` must now be refused
/// even though the TCP peer is 127.0.0.1.
#[tokio::test]
async fn trusted_proxy_header_moves_the_guard_target() {
    let server = spawn_server().await;
    let body = call_tool(&server, "elsewhere", &[("x-real-ip", "192.0.2.77")]).await;

    assert!(
        body.contains("calling agent's own host"),
        "guard did not follow the trusted proxy's X-Real-IP.\nresponse: {body}"
    );
}

/// With the proxy claiming a different client, a call to loopback is no
/// longer self-targeting and must get PAST the guard. It will fail later
/// (ssh to /dev/null key), and that's fine — we assert only that the
/// failure is not the guard's. This is the counterweight that stops the
/// guard from being trivially satisfied by refusing everything.
#[tokio::test]
async fn guard_does_not_refuse_a_genuinely_remote_target() {
    let server = spawn_server().await;
    let body = call_tool(&server, "loopback", &[("x-real-ip", "192.0.2.77")]).await;

    assert!(
        !body.contains("calling agent's own host"),
        "guard refused a call whose caller differs from the target: {body}"
    );
}

/// The guard must hold on the **legacy** session path too, not just the
/// modern stateless one. That path snapshots the caller IP once at
/// session creation, so it is a genuinely different route to the same
/// check — and `legacy_session_mode` is left ON in production.
#[tokio::test]
async fn self_targeted_call_is_refused_on_legacy_path_too() {
    let server = spawn_server_with(true).await;
    let body = call_tool_legacy(&server, "loopback").await;

    assert!(
        body.contains("calling agent's own host"),
        "self-targeted call was NOT refused over the legacy session path.\nresponse: {body}"
    );
}

/// THE compatibility test for the sessionless decision.
///
/// A pre-2026-07-28 client — old handshake, no per-request `_meta`, no
/// SEP-2243 headers — must still be able to call a tool when
/// `legacy_session_mode` is OFF. rmcp routes it down the stateless path;
/// this asserts that actually works rather than trusting the doc comment.
/// If this ever fails, prompto must not ship sessionless.
#[tokio::test]
async fn legacy_dialect_client_still_works_when_sessionless() {
    let server = spawn_server_with(false).await;
    let body = call_tool_legacy_inner(&server, "elsewhere", false).await;

    assert!(
        !body.contains("Unexpected message"),
        "legacy client was rejected in sessionless mode: {body}"
    );
    assert!(
        !body.contains("missing required"),
        "legacy client was held to modern header rules: {body}"
    );
    // It reached the tool: the only failure left is the SSH attempt to a
    // TEST-NET address with a /dev/null key.
    assert!(
        body.contains("result") || body.contains("ssh"),
        "legacy call did not reach the tool: {body}"
    );
}

/// And the guard still refuses self-targeting for a legacy client on the
/// stateless path — the combination that will actually run in production.
#[tokio::test]
async fn legacy_dialect_self_target_refused_when_sessionless() {
    let server = spawn_server_with(false).await;
    let body = call_tool_legacy_inner(&server, "loopback", false).await;

    assert!(
        body.contains("calling agent's own host"),
        "sessionless legacy path failed to refuse self-targeting: {body}"
    );
}

/// Capability gating must remain independent of all the above: a host
/// without `sudo_exec` is refused on that ground regardless of caller IP.
#[tokio::test]
async fn capability_gate_still_refuses_independently() {
    let server = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{}/mcp", server.addr))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "ssh_sudo_exec")
        .json(&tool_call_body(
            "ssh_sudo_exec",
            "elsewhere",
            Some(stateless_meta()),
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        resp.contains("lacks capability"),
        "capability gate did not fire: {resp}"
    );
}
