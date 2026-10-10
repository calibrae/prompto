//! Audit log (E4), end to end through the shipping router.
//!
//! A fake `ssh` appends its argv to `argv.log`; for the "runner" IPs it
//! runs the remote command locally under /bin/sh with a fake `sudo` that
//! eats the password line like `sudo -S`, so the vault sudo path runs for
//! real. `127.0.0.40` behaves like an unreachable host (ssh exit 255) and
//! `127.0.0.41` like a command that fails (exit 1). Everything else exits
//! 0 without running anything.
//!
//! Each test reads its own `audit.jsonl` in a temp dir.

use axum::{Json, Router, routing::get};
use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode};
use prompto::audit::{Audit, AuditLog};
use prompto::inventory::{Inventory, InventoryStore};
use prompto::policy::{Policy, PolicyStore};
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use prompto::vault::VaultClient;
use serde_json::{Value, json};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "canary-vault-pw-7f3a9c";

const FAKE_SSH: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
printf '%s\n' "$*" >> "$dir/argv.log"
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
  127.0.0.40) echo "ssh: connect to host 127.0.0.40 port 22: Connection refused" >&2; exit 255 ;;
  127.0.0.41) echo "boom" >&2; exit 1 ;;
esac
exit 0
"#;

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
[host.runner]
ip = "127.0.0.20"
ssh_user = "admin"
ssh_key = "/dev/null"
aliases = ["run"]
capabilities = ["exec", "sudo_exec"]

[host.vaulted]
ip = "127.0.0.21"
ssh_user = "admin"
ssh_key = "/dev/null"
sudo_password_vault_path = "infra/default"
capabilities = ["exec", "sudo_exec"]

[host.noop]
ip = "127.0.0.22"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.down]
ip = "127.0.0.40"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]

[host.failing]
ip = "127.0.0.41"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec"]

# The test client connects from 127.0.0.1: this is its own machine.
[host.loopback]
ip = "127.0.0.1"
ssh_user = "admin"
ssh_key = "/dev/null"
capabilities = ["exec", "sudo_exec"]
"#;

const POLICY: &str = r#"
[[rule]]
id = "dev-exec"
agents = ["dev"]
hosts = ["runner", "vaulted", "noop", "down", "failing", "loopback"]
tools = ["*"]

[[rule]]
id = "dev-root"
agents = ["dev"]
hosts = ["vaulted"]
tools = ["ssh_sudo_exec", "service_logs"]
sudo = true

[[rule]]
id = "dev-approval"
agents = ["dev"]
hosts = ["runner"]
tools = ["ssh_sudo_exec"]
sudo = true
approval = "human"
"#;

const DEV_TOKEN: &str = "pto_dev_test_token";
/// The token of `retired`, a revoked agent.
const RETIRED_TOKEN: &str = "pto_retired_test_token";

struct Server {
    addr: SocketAddr,
    cancel: CancellationToken,
    dir: tempfile::TempDir,
    audit_path: PathBuf,
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

    fn audit_text(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }

    /// Every record in the audit file.
    fn records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
            .collect()
    }

    /// The one record with this request ID.
    fn record(&self, rid: &str) -> Value {
        let mut found: Vec<Value> = self
            .records()
            .into_iter()
            .filter(|r| r["request_id"] == rid)
            .collect();
        assert_eq!(found.len(), 1, "records for {rid}: {found:?}");
        found.remove(0)
    }
}

fn write_exe(path: &Path, body: &str) {
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

struct Opts {
    mode: AuthMode,
    /// `None`: `<dir>/audit.jsonl`.
    audit_path: Option<PathBuf>,
}

async fn spawn(mode: AuthMode) -> Server {
    spawn_opts(Opts {
        mode,
        audit_path: None,
    })
    .await
}

async fn spawn_opts(o: Opts) -> Server {
    let dir = tempfile::tempdir().unwrap();
    write_exe(&dir.path().join("ssh"), FAKE_SSH);
    write_exe(&dir.path().join("sudo"), FAKE_SUDO);
    let audit_path = o
        .audit_path
        .unwrap_or_else(|| dir.path().join("audit.jsonl"));
    let strict = o.mode != AuthMode::Off;
    let audit = Audit::new(AuditLog::unopened(audit_path.clone(), None, strict));

    let h = |t: &str| prompto::agent::hex(&prompto::agent::sha256(t.as_bytes()));
    let agents = format!(
        "[agent.dev]\ngroups = [\"devs\"]\ntoken_sha256 = \"{}\"\n\n\
         [agent.retired]\ntoken_sha256 = \"{}\"\ndisabled = true\n",
        h(DEV_TOKEN),
        h(RETIRED_TOKEN)
    );
    let auth = AuthConfig {
        mode: o.mode,
        store: AgentStore::new(Agents::from_toml_str(&agents).unwrap(), None),
        policy: PolicyStore::new(Policy::from_toml_str(POLICY, "policy.toml").unwrap(), None),
        approvals: Default::default(),
    };
    let vault = VaultClient::new(spawn_fake_vault().await, "secret", "tok");
    let cancel = CancellationToken::new();
    let app = build_router(HttpParams {
        store: InventoryStore::new(Inventory::from_toml_str(INVENTORY).unwrap(), None),
        ssh: Arc::new(
            SshClient::new(dir.path().join("ssh"), Duration::from_secs(10))
                .with_vault(Arc::new(vault)),
        ),
        tracker: Arc::new(Tracker::disabled()),
        stop_vm_step: Duration::from_secs(1),
        trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        allowed_hosts: AllowedHosts::List(vec!["127.0.0.1".into(), "localhost".into()]),
        legacy_session_mode: false,
        auth,
        audit: audit.clone(),
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
        dir,
        audit_path,
        audit,
    }
}

async fn rpc_with(
    addr: SocketAddr,
    token: Option<&str>,
    method: &str,
    params: Value,
) -> (u16, Value) {
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
        .header("user-agent", "audit-tests/1.0")
        .header("x-prompto-session", "sess-audit-1");
    if let Some(n) = params["name"].as_str() {
        req = req.header("mcp-name", n.to_string());
    }
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(&text);
    (
        status,
        serde_json::from_str(raw).unwrap_or_else(|e| panic!("{e}: {text}")),
    )
}

async fn call(s: &Server, tool: &str, args: Value) -> Value {
    call_as(s, Some(DEV_TOKEN), tool, args).await
}

async fn call_as(s: &Server, token: Option<&str>, tool: &str, args: Value) -> Value {
    rpc_with(
        s.addr,
        token,
        "tools/call",
        json!({ "name": tool, "arguments": args }),
    )
    .await
    .1
}

/// The request ID the caller got back, on success or error.
fn rid(resp: &Value) -> String {
    if let Some(e) = resp.get("error") {
        return e["data"]["request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{resp}"))
            .to_string();
    }
    let blocks = resp["result"]["content"].as_array().unwrap();
    for b in blocks {
        let t = b["text"].as_str().unwrap();
        if let Ok(v) = serde_json::from_str::<Value>(t)
            && let Some(id) = v.get("request_id").and_then(Value::as_str)
        {
            return id.to_string();
        }
        if let Some(id) = t
            .strip_prefix("[request_id=")
            .and_then(|r| r.strip_suffix(']'))
        {
            return id.to_string();
        }
    }
    panic!("no request_id in {resp}")
}

/// The tool result's JSON payload.
fn result(resp: &Value) -> Value {
    let t = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{resp}"));
    serde_json::from_str(t).unwrap_or_else(|_| panic!("{resp}"))
}

fn assert_ok(resp: &Value) {
    assert!(resp.get("result").is_some(), "expected success: {resp}");
}

// ---------------------------------------------------------------------------
// Record shape
// ---------------------------------------------------------------------------

/// The full record of an allowed exec call: who, from where, what, which
/// rule, and the request ID the caller got back.
#[tokio::test]
async fn exec_record_names_who_what_where_and_the_rule() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(
        &s,
        "ssh_exec",
        json!({ "host": "run", "cmd": "echo hi && id" }),
    )
    .await;
    assert_ok(&resp);
    let id = rid(&resp);
    let r = s.record(&id);
    assert_eq!(r["type"], "tool");
    assert_eq!(r["request_id"], id, "request_id must equal the caller's");
    assert_eq!(r["agent"], "dev");
    assert_eq!(r["agent_groups"], json!(["devs"]));
    assert_eq!(r["session_id"], "sess-audit-1");
    assert_eq!(r["client_ip"], "127.0.0.1");
    assert_eq!(r["user_agent"], "audit-tests/1.0");
    assert_eq!(r["tool"], "ssh_exec");
    assert_eq!(r["host"], "runner", "canonical name");
    assert_eq!(r["queried_as"], "run", "what the caller typed");
    assert_eq!(r["args"], json!({ "host": "run", "cmd": "echo hi && id" }));
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["rule"], "policy.toml:2 (dev-exec)");
    assert_eq!(r["approval"], "none");
    assert_eq!(r["approved_by"], Value::Null);
    assert_eq!(r["exit_code"], 0);
    assert_eq!(r["ok"], true);
    assert_eq!(r["error_class"], Value::Null);
    assert!(r["duration_ms"].is_u64());
    assert!(r["bytes"].as_u64().unwrap() > 0);
    assert!(
        chrono::DateTime::parse_from_rfc3339(r["ts"].as_str().unwrap()).is_ok(),
        "{r}"
    );
    // Key order is part of the format (operators grep and eyeball it).
    let keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "ts",
            "type",
            "request_id",
            "agent",
            "agent_groups",
            "session_id",
            "client_ip",
            "user_agent",
            "tool",
            "host",
            "queried_as",
            "args",
            "decision",
            "rule",
            "approval",
            "approved_by",
            "exit_code",
            "ok",
            "error_class",
            "duration_ms",
            "bytes",
        ]
    );
}

/// A command that ran and failed is recorded as a failure with its exit
/// code, though the tool call itself returned a result.
#[tokio::test]
async fn failed_command_is_not_ok_and_has_a_class() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(&s, "ssh_exec", json!({ "host": "failing", "cmd": "false" })).await;
    assert_ok(&resp);
    let r = s.record(&rid(&resp));
    assert_eq!(
        (r["ok"].clone(), r["exit_code"].clone()),
        (json!(false), json!(1))
    );
    assert_eq!(r["error_class"], "remote_nonzero");
    assert_eq!(r["decision"], "allow");
    // The result carries the same class (it used to be audit-only).
    assert_eq!(result(&resp)["error_class"], "remote_nonzero");
    assert_eq!(result(&resp)["exit_code"], 1);

    let resp = call(&s, "ssh_exec", json!({ "host": "down", "cmd": "true" })).await;
    let r = s.record(&rid(&resp));
    assert_eq!(r["error_class"], "ssh_connect", "{r}");
    assert_eq!(r["exit_code"], 255);
    assert_eq!(result(&resp)["error_class"], "ssh_connect");
}

/// Exit 0: `error_class` is present and null, on every exec-style tool.
#[tokio::test]
async fn successful_exec_results_have_a_null_error_class() {
    let s = spawn(AuthMode::Required).await;
    for (tool, args) in [
        ("ssh_exec", json!({ "host": "runner", "cmd": "true" })),
        ("bash_exec", json!({ "host": "runner", "script": "true" })),
        (
            "ssh_batch",
            json!({ "host": "runner", "commands": ["true"] }),
        ),
    ] {
        let resp = call(&s, tool, args).await;
        assert_ok(&resp);
        let v = result(&resp);
        assert_eq!(v.get("error_class"), Some(&Value::Null), "{tool}: {v}");
        assert_eq!(s.record(&rid(&resp))["error_class"], Value::Null);
    }
    // Not an exec-style result: no field added.
    let resp = call(&s, "inventory_list", json!({})).await;
    assert_eq!(result(&resp).get("error_class"), None, "{resp}");
}

/// ssh_batch: one record, with the whole command list.
#[tokio::test]
async fn batch_is_one_record_with_every_command() {
    let s = spawn(AuthMode::Required).await;
    let cmds = json!(["echo one", "echo two", "exit 3", "echo never"]);
    let resp = call(
        &s,
        "ssh_batch",
        json!({ "host": "runner", "commands": cmds }),
    )
    .await;
    assert_ok(&resp);
    let id = rid(&resp);
    let r = s.record(&id);
    assert_eq!(r["args"]["commands"], cmds);
    assert_eq!(r["ok"], false, "a command failed: {r}");
    assert_eq!(r["exit_code"], 3);
    assert_eq!(r["error_class"], "remote_nonzero");
    assert_eq!(result(&resp)["error_class"], "remote_nonzero");
    assert_eq!(
        s.records()
            .iter()
            .filter(|r| r["tool"] == "ssh_batch")
            .count(),
        1
    );
}

/// rsync_sync names both hosts, canonically.
#[tokio::test]
async fn rsync_records_both_hosts() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(
        &s,
        "rsync_sync",
        json!({ "source_host": "run", "source_path": "/tmp/a/", "dest_host": "noop", "dest_path": "/tmp/b/" }),
    )
    .await;
    let r = s.record(&rid(&resp));
    assert_eq!(r["host"], "runner");
    assert_eq!(r["queried_as"], "run");
    assert_eq!(r["dest_host"], "noop");
    assert_eq!(r.get("dest_queried_as"), None, "same as typed: left out");
    assert_eq!(r["args"]["dest_path"], "/tmp/b/");
}

/// File contents become digests; commands, paths and every
/// interpreter's script stay whole (scrubbed), up to the size cap.
#[tokio::test]
async fn contents_are_digests_and_scripts_stay_whole_in_the_record() {
    let s = spawn(AuthMode::Required).await;
    let secret_body = "API_SECRET=do-not-log-me-91c2\n";
    let resp = call(
        &s,
        "file_write",
        json!({ "host": "noop", "path": "/tmp/x.env", "content": secret_body, "mode": "0600" }),
    )
    .await;
    let r = s.record(&rid(&resp));
    assert_eq!(r["args"]["path"], "/tmp/x.env");
    assert_eq!(r["args"]["content"]["len"], secret_body.len());
    assert_eq!(
        r["args"]["content"]["sha256"],
        prompto::agent::hex(&prompto::agent::sha256(secret_body.as_bytes()))
    );

    let code = "set -e\ntoken = \"tok-in-code-55\"\necho 'code-body-kept'\n";
    let resp = call(
        &s,
        "bash_exec",
        json!({ "host": "noop", "script": code, "args": ["--password", "argv-pw-66"] }),
    )
    .await;
    let r = s.record(&rid(&resp));
    assert_eq!(
        r["args"]["script"],
        "set -e\ntoken = \"***\"\necho 'code-body-kept'\n"
    );
    assert_eq!(r["args"]["args"], json!(["--password", "***"]));

    let bash = "echo bash-body-kept-whole";
    let resp = call(&s, "bash_exec", json!({ "host": "noop", "script": bash })).await;
    assert_eq!(s.record(&rid(&resp))["args"]["script"], bash);

    let big = format!("# {}\necho 1\n", "x".repeat(prompto::audit::MAX_ARG_STRING));
    let resp = call(&s, "bash_exec", json!({ "host": "noop", "script": big })).await;
    let r = s.record(&rid(&resp));
    assert_eq!(r["args"]["script"]["len"], big.len());
    assert_eq!(r["args"]["script"]["truncated"], true);

    let resp = call(
        &s,
        "ssh_exec",
        json!({ "host": "noop", "cmd": "curl -H 'Authorization: Bearer hdr-tok-77' https://u:url-pw-88@h/x?api_key=q-99" }),
    )
    .await;
    assert_eq!(
        s.record(&rid(&resp))["args"]["cmd"],
        "curl -H 'Authorization: ***' https://***@h/x?api_key=***"
    );

    let text = s.audit_text();
    for leaked in [
        "do-not-log-me-91c2",
        "tok-in-code-55",
        "argv-pw-66",
        "hdr-tok-77",
        "url-pw-88",
        "q-99",
    ] {
        assert!(!text.contains(leaked), "{leaked} leaked: {text}");
    }
}

/// The vault sudo password is fetched inside the SSH layer and never
/// becomes an argument: after a real vault-sudo call (password fetched,
/// fed to the fake `sudo -S`), it is nowhere in the audit file.
#[tokio::test]
async fn vault_sudo_password_never_reaches_the_audit() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(
        &s,
        "ssh_sudo_exec",
        json!({ "host": "vaulted", "cmd": "echo root-ran" }),
    )
    .await;
    assert_ok(&resp);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("root-ran"),
        "the vault path must have run: {resp}"
    );
    let r = s.record(&rid(&resp));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["rule"], "policy.toml:8 (dev-root)");
    let audit = s.audit_text();
    assert!(!audit.is_empty());
    assert!(
        !audit.contains(PASSWORD),
        "vault password in the audit log: {audit}"
    );
}

/// Hostless tools: no host. Inventory lookups by alias: canonical +
/// queried_as.
#[tokio::test]
async fn hostless_and_lookup_records() {
    let s = spawn(AuthMode::Required).await;
    let r = s.record(&rid(&call(&s, "inventory_list", json!({})).await));
    assert_eq!(
        (r["host"].clone(), r["decision"].clone()),
        (Value::Null, json!("allow"))
    );
    let r = s.record(&rid(&call(
        &s,
        "inventory_get_host",
        json!({ "name": "run" }),
    )
    .await));
    assert_eq!(
        (r["host"].clone(), r["queried_as"].clone()),
        (json!("runner"), json!("run"))
    );
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Every kind of refusal is audited as a denial, nothing ran, and policy
/// refusals name their rule.
#[tokio::test]
async fn refusals_are_audited_with_their_class_and_rule() {
    let s = spawn(AuthMode::Required).await;
    /// tool, args, error_class, rule, approval
    type Case<'a> = (&'a str, Value, &'a str, Option<&'a str>, Option<&'a str>);
    let cases: &[Case] = &[
        (
            "ssh_exec",
            json!({"host": "ghost", "cmd": "true"}),
            "unknown_host",
            None,
            None,
        ),
        // noop has no sudo_exec.
        (
            "ssh_sudo_exec",
            json!({"host": "noop", "cmd": "id"}),
            "refused_capability",
            None,
            None,
        ),
        (
            "ssh_exec",
            json!({"host": "loopback", "cmd": "id"}),
            "refused_self_target",
            None,
            None,
        ),
        // No sudo grant on `down`.
        (
            "ssh_sudo_exec",
            json!({"host": "down", "cmd": "id"}),
            "refused_policy",
            Some("default-deny"),
            None,
        ),
        (
            "ssh_sudo_exec",
            json!({"host": "runner", "cmd": "id"}),
            "approval_required",
            Some("policy.toml:15 (dev-approval)"),
            Some("human"),
        ),
    ];
    for (tool, args, class, rule, approval) in cases {
        let resp = call(&s, tool, args.clone()).await;
        assert_eq!(resp["error"]["data"]["error_class"], *class, "{resp}");
        let r = s.record(&rid(&resp));
        assert_eq!(r["decision"], "deny", "{class}: {r}");
        assert_eq!(r["error_class"], *class, "{r}");
        assert_eq!(r["ok"], false);
        assert_eq!(r["rule"].as_str(), *rule, "{class}: {r}");
        assert_eq!(r["approval"].as_str(), *approval, "{class}: {r}");
        assert_eq!(r["args"], *args);
    }
    assert_eq!(s.argv_log(), "", "a refused call reached ssh");
    // An unknown host has no canonical name: what was typed is kept.
    let r = s
        .records()
        .into_iter()
        .find(|r| r["error_class"] == "unknown_host")
        .unwrap();
    assert_eq!(
        (r["host"].clone(), r["queried_as"].clone()),
        (Value::Null, json!("ghost"))
    );
}

/// Arguments that don't parse never reach a handler; the call is still
/// recorded. So is a tool that doesn't exist.
#[tokio::test]
async fn unparseable_calls_are_recorded_too() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(&s, "ssh_exec", json!({ "host": "runner" })).await; // no cmd
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let resp = call(&s, "no_such_tool", json!({ "host": "runner" })).await;
    assert!(resp.get("error").is_some(), "{resp}");
    let recs = s.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0]["tool"], "ssh_exec");
    assert_eq!(recs[0]["error_class"], "invalid_args");
    assert_eq!(recs[0]["host"], "runner");
    assert_eq!(recs[0]["decision"], Value::Null);
    assert_eq!(recs[1]["tool"], "no_such_tool");
    assert_eq!(recs[1]["agent"], "dev");
}

/// A 401 has no tool call; it is an `auth` record, with the reason.
#[tokio::test]
async fn unauthorized_requests_are_audited_as_auth_records() {
    let s = spawn(AuthMode::Required).await;
    let (status, _) = rpc_with(s.addr, None, "tools/list", json!({})).await;
    assert_eq!(status, 401);
    let (status, _) = rpc_with(s.addr, Some("pto_wrong"), "tools/list", json!({})).await;
    assert_eq!(status, 401);
    let recs = s.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    for (r, reason) in recs
        .iter()
        .zip(["missing bearer token", "invalid bearer token"])
    {
        assert_eq!(r["type"], "auth");
        assert_eq!(r["reason"], reason);
        assert_eq!(r["decision"], "deny");
        assert_eq!(r["path"], "/mcp");
        assert_eq!(r["client_ip"], "127.0.0.1");
        assert_eq!(r["user_agent"], "audit-tests/1.0");
        assert_eq!(r["session_id"], "sess-audit-1");
        assert_eq!(r["tool"], Value::Null);
    }
    assert!(
        !s.audit_text().contains("pto_wrong"),
        "a token reached the audit"
    );
}

/// A 401 from a client behind the trusted (loopback) proxy, as `ip`.
async fn unauthorized_from(s: &Server, ip: &str, token: Option<&str>, path: &str) -> u16 {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}{path}", s.addr))
        .header("x-real-ip", ip)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.body("{}").send().await.unwrap().status().as_u16()
}

/// One flooding client can't hide another client's revoked-token 401,
/// and a huge request path is stored cut.
#[tokio::test]
async fn a_401_flood_from_one_client_does_not_hide_another() {
    let s = spawn(AuthMode::Required).await;
    for _ in 0..200 {
        assert_eq!(unauthorized_from(&s, "192.0.2.66", None, "/mcp").await, 401);
    }
    assert_eq!(
        unauthorized_from(&s, "198.51.100.5", Some(RETIRED_TOKEN), "/mcp").await,
        401
    );
    let recs = s.records();
    let flood = recs
        .iter()
        .filter(|r| r["client_ip"] == "192.0.2.66")
        .count();
    assert!(flood <= prompto::audit::AUTH_IP_BURST as usize, "{flood}");
    let other: Vec<&Value> = recs
        .iter()
        .filter(|r| r["client_ip"] == "198.51.100.5")
        .collect();
    assert_eq!(other.len(), 1, "{recs:?}");
    assert_eq!(other[0]["reason"], "revoked token");
    assert!(other[0]["suppressed"].as_u64().unwrap() > 0);

    let long = format!("/mcp/{}", "a".repeat(50_000));
    assert_eq!(unauthorized_from(&s, "203.0.113.9", None, &long).await, 401);
    let r = s
        .records()
        .into_iter()
        .find(|r| r["client_ip"] == "203.0.113.9")
        .unwrap();
    let path = r["path"].as_str().unwrap();
    assert!(
        path.chars().count() <= prompto::audit::MAX_PATH + 1,
        "{}",
        path.len()
    );
    assert!(s.audit_text().len() < 64 * 1024);
}

/// Optional mode: a revoked or invalid token runs as `anonymous`, and the
/// record says why, so it can be queried.
#[tokio::test]
async fn optional_mode_notes_a_revoked_or_invalid_token() {
    let s = spawn(AuthMode::Optional).await;
    let args = json!({ "host": "runner", "cmd": "true" });
    let revoked = call_as(&s, Some(RETIRED_TOKEN), "ssh_exec", args.clone()).await;
    let invalid = call_as(&s, Some("pto_nonsense"), "ssh_exec", args.clone()).await;
    let none = call_as(&s, None, "ssh_exec", args).await;
    let r = s.record(&rid(&revoked));
    assert_eq!(r["agent"], "anonymous");
    assert_eq!(r["auth_note"], "revoked token for retired");
    assert_eq!(s.record(&rid(&invalid))["auth_note"], "invalid token");
    assert!(s.record(&rid(&none)).get("auth_note").is_none());
    assert!(!s.audit_text().contains("pto_nonsense"));
}

/// A call cut off mid-run — here prompto's runtime shuts down under it,
/// as on a stop or a crash-restart; a handler panic unwinds the same way
/// — still leaves a record: `aborted`, with the request's agent and the
/// rule that let it run.
#[test]
fn a_call_cut_off_mid_run_is_recorded_as_aborted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let s = rt.block_on(spawn(AuthMode::Required));
    let addr = s.addr;
    rt.spawn(async move {
        rpc_with(
            addr,
            Some(DEV_TOKEN),
            "tools/call",
            json!({ "name": "ssh_exec", "arguments": { "host": "runner", "cmd": "sleep 5" } }),
        )
        .await
    });
    rt.block_on(async {
        for _ in 0..50 {
            if s.argv_log().contains("sleep 5") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    assert!(s.argv_log().contains("sleep 5"), "the call never started");
    assert!(s.records().is_empty(), "recorded before the end");
    rt.shutdown_timeout(Duration::from_secs(2));
    let recs = s.records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["error_class"], "aborted");
    assert_eq!(r["ok"], false);
    assert_eq!(r["tool"], "ssh_exec");
    assert_eq!(r["agent"], "dev");
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["rule"], "policy.toml:2 (dev-exec)");
    assert_eq!(r["args"]["cmd"], "sleep 5");
}

/// `GET /log` is the `service_logs` tool over plain HTTP, and audited as
/// such, with the request ID it returned.
#[tokio::test]
async fn log_endpoint_is_audited_as_service_logs() {
    let s = spawn(AuthMode::Required).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{}/log?host=ghost&unit=nginx", s.addr))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let id = resp.headers()["x-prompto-request-id"]
        .to_str()
        .unwrap()
        .to_string();
    let r = s.record(&id);
    assert_eq!(r["tool"], "service_logs");
    assert_eq!(r["path"], "/log");
    assert_eq!(r["error_class"], "unknown_host");
    assert_eq!(r["decision"], "deny");
    assert_eq!(
        r["args"],
        json!({ "host": "ghost", "unit": "nginx", "lines": null })
    );
}

// ---------------------------------------------------------------------------
// Failure policy
// ---------------------------------------------------------------------------

/// Required mode: an audit log that can't be written refuses the call
/// before it runs — `internal`, and nothing reaches ssh. Off mode: the
/// same broken log only warns, and the call runs.
#[tokio::test]
async fn unwritable_audit_refuses_in_required_and_warns_in_off() {
    // A path under a regular file can't be created, whoever runs the test.
    let broken = PathBuf::from("/dev/null/audit.jsonl");
    let s = spawn_opts(Opts {
        mode: AuthMode::Required,
        audit_path: Some(broken.clone()),
    })
    .await;
    for (tool, args) in [
        (
            "ssh_exec",
            json!({ "host": "runner", "cmd": "echo must-not-run" }),
        ),
        ("inventory_list", json!({})),
        ("inventory_get_host", json!({ "name": "runner" })),
    ] {
        let resp = call(&s, tool, args).await;
        assert_eq!(
            resp["error"]["data"]["error_class"], "internal",
            "{tool}: {resp}"
        );
        let msg = resp["error"]["message"].as_str().unwrap();
        assert!(msg.contains("cannot write its audit log"), "{msg}");
        assert!(
            !msg.contains("/dev/null"),
            "the path reached the agent: {msg}"
        );
    }
    let resp = reqwest::Client::new()
        .get(format!("http://{}/log?host=vaulted&unit=nginx", s.addr))
        .header("authorization", format!("Bearer {DEV_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503, "/log ran unaudited");
    assert_eq!(s.argv_log(), "", "a call ran without an audit record");

    let s = spawn_opts(Opts {
        mode: AuthMode::Off,
        audit_path: Some(broken),
    })
    .await;
    let resp = call_as(
        &s,
        None,
        "ssh_exec",
        json!({ "host": "runner", "cmd": "true" }),
    )
    .await;
    assert_ok(&resp);
    assert!(
        s.argv_log().contains("true"),
        "off must not break on the audit"
    );
}

/// The disk fills mid-call: the call that was running finishes (it can't
/// be undone; its record is in the journal), and every later call is
/// refused, naming the full disk, until a write succeeds. The failure is
/// injected (`/dev/full` is Linux-only).
#[tokio::test]
async fn a_failed_write_refuses_later_calls_in_required_mode() {
    let s = spawn(AuthMode::Required).await;
    s.audit
        .log()
        .unwrap()
        .inject_fault(Some(prompto::audit::Fault::DiskFull));
    assert_ok(
        &call(
            &s,
            "ssh_exec",
            json!({ "host": "runner", "cmd": "echo first" }),
        )
        .await,
    );
    let resp = call(
        &s,
        "ssh_exec",
        json!({ "host": "runner", "cmd": "echo second" }),
    )
    .await;
    assert_eq!(resp["error"]["data"]["error_class"], "internal", "{resp}");
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("the audit disk is full"), "{msg}");
    let argv = s.argv_log();
    assert!(
        argv.contains("echo first") && !argv.contains("echo second"),
        "{argv}"
    );
    // Room again: the refusal's own record is the probe that heals, so
    // the next call runs.
    s.audit.log().unwrap().inject_fault(None);
    call(
        &s,
        "ssh_exec",
        json!({ "host": "runner", "cmd": "echo probe" }),
    )
    .await;
    assert_ok(
        &call(
            &s,
            "ssh_exec",
            json!({ "host": "runner", "cmd": "echo third" }),
        )
        .await,
    );
}

/// Off mode still audits, with agent `-`.
#[tokio::test]
async fn off_mode_audits_with_agent_dash() {
    let s = spawn(AuthMode::Off).await;
    let resp = call_as(
        &s,
        None,
        "ssh_exec",
        json!({ "host": "runner", "cmd": "true" }),
    )
    .await;
    let r = s.record(&rid(&resp));
    assert_eq!(r["agent"], "-");
    assert_eq!(r["agent_groups"], json!([]));
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["rule"], Value::Null, "no policy with auth off");
    assert_eq!(r["approval"], Value::Null);
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

/// Many calls at once: one whole, parseable line per call.
#[tokio::test]
async fn concurrent_calls_write_whole_lines() {
    let s = Arc::new(spawn(AuthMode::Required).await);
    // Long arguments make a torn write likely if lines could interleave.
    let pad = "x".repeat(6000);
    let mut tasks = Vec::new();
    for i in 0..48 {
        let s = s.clone();
        let cmd = format!("echo {i} {pad}");
        tasks.push(tokio::spawn(async move {
            rid(&call(&s, "ssh_exec", json!({ "host": "noop", "cmd": cmd })).await)
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    let recs = s.records(); // panics on a torn line
    assert_eq!(recs.len(), 48);
    for id in &ids {
        assert_eq!(recs.iter().filter(|r| r["request_id"] == *id).count(), 1);
    }
}

/// Independent writers on one file (each with its own descriptor, as two
/// prompto processes would have): `O_APPEND` and one write per line keep
/// every line whole.
#[test]
fn separate_writers_on_one_file_never_interleave() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let threads: Vec<_> = (0..8)
        .map(|w| {
            let path = path.clone();
            std::thread::spawn(move || {
                let audit = Audit::new(AuditLog::open(path, None, true).unwrap());
                let ctx = prompto::ctx::CallCtx::new(None);
                for i in 0..200 {
                    let args = json!({ "cmd": format!("{w}-{i}-{}", "y".repeat(3000)) });
                    let rec = prompto::audit::tool_record(&ctx, "ssh_exec", args);
                    assert!(audit.write(rec));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let mut n = 0;
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("torn line: {e}"));
        assert_eq!(v["tool"], "ssh_exec");
        n += 1;
    }
    assert_eq!(n, 8 * 200);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_prompto");

fn audit_cli(path: &Path, args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new(BIN)
        .arg("audit")
        .args(args)
        .env("PROMPTO_AUDIT_LOG", path)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_filters_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let now = chrono::Utc::now();
    let ts = |mins: i64| {
        (now - chrono::Duration::minutes(mins)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    };
    let rec = |ts: String, id: &str, agent: &str, tool: &str, host: &str, decision: &str| {
        json!({
            "ts": ts, "type": "tool", "request_id": id, "agent": agent, "agent_groups": [],
            "session_id": null, "client_ip": "192.0.2.9", "user_agent": null, "tool": tool,
            "host": host, "queried_as": null, "args": { "host": host, "cmd": format!("cmd-{id}") },
            "decision": decision, "rule": if decision == "deny" { "default-deny" } else { "policy.toml:1" },
            "approval": null, "approved_by": null, "exit_code": 0, "ok": decision == "allow",
            "error_class": if decision == "deny" { json!("refused_policy") } else { Value::Null },
            "duration_ms": 5, "bytes": 10,
        })
        .to_string()
    };
    // Rotated sibling with an older record.
    std::fs::write(
        dir.path().join("audit.jsonl.1"),
        rec(ts(300), "R0", "ops", "ssh_exec", "alpha", "allow") + "\n",
    )
    .unwrap();
    let lines = [
        rec(ts(30), "R1", "dev", "ssh_exec", "alpha", "allow"),
        rec(ts(5), "R2", "dev", "ssh_sudo_exec", "bravo", "deny"),
        rec(ts(1), "R3", "ops", "file_read", "alpha", "allow"),
        "not json".to_string(),
    ];
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let ids = |args: &[&str]| -> Vec<String> {
        let mut a = args.to_vec();
        a.push("--json");
        let (ok, out, err) = audit_cli(&path, &a);
        assert!(ok, "{err}");
        out.lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["request_id"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    assert_eq!(
        ids(&[]),
        ["R0", "R1", "R2", "R3"],
        "rotated first, oldest first"
    );
    assert_eq!(ids(&["--agent", "dev"]), ["R1", "R2"]);
    assert_eq!(ids(&["--host", "alpha"]), ["R0", "R1", "R3"]);
    assert_eq!(ids(&["--tool", "ssh_sudo_exec"]), ["R2"]);
    assert_eq!(ids(&["--decision", "deny"]), ["R2"]);
    assert_eq!(ids(&["--request-id", "R3"]), ["R3"]);
    assert_eq!(ids(&["--since", "10m"]), ["R2", "R3"]);
    assert_eq!(ids(&["--since=10m", "--agent=ops"]), ["R3"]);
    let iso = ts(60);
    assert_eq!(ids(&["--since", &iso]), ["R1", "R2", "R3"]);

    // The table: a header, one row per record, the rule on a denial.
    let (ok, out, err) = audit_cli(&path, &["--decision", "deny"]);
    assert!(ok, "{err}");
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 2, "{out}");
    assert!(rows[0].starts_with("TIME (UTC)"), "{out}");
    for want in [
        "dev",
        "ssh_sudo_exec",
        "bravo",
        "deny",
        "refused_policy",
        "rule=default-deny",
        "cmd-R2",
    ] {
        assert!(rows[1].contains(want), "{want} missing: {out}");
    }
    assert!(err.contains("1 of 4 records"), "{err}");
    assert!(err.contains("skipped 1 unreadable fragments"), "{err}");

    // A fragment glued to the next record (an older build after a short
    // write) costs only the fragment; a hostile tool name can't drive the
    // terminal, in the table or with --json.
    let evil = json!({
        "ts": ts(0), "type": "tool", "request_id": "R4", "agent": "dev\u{7}",
        "tool": "\u{1b}]0;owned\u{7}\u{1b}[2Jssh_exec\r", "host": "h\u{202e}x",
        "args": { "cmd": "echo \u{1b}[31mred\u{9b}" }, "decision": "allow", "ok": true,
        "duration_ms": 1,
    });
    let glued = format!(
        "{}{}\n",
        &rec(ts(0), "RX", "dev", "x", "y", "allow")[..40],
        evil
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(glued.as_bytes())
        .unwrap();
    assert_eq!(ids(&["--request-id", "R4"]), ["R4"]);
    let (ok, out, err) = audit_cli(&path, &["--request-id", "R4"]);
    assert!(ok, "{err}");
    assert!(err.contains("skipped 2 unreadable fragments"), "{err}");
    let hazard = |c: char| c.is_control() && c != '\n' || ('\u{202a}'..='\u{202e}').contains(&c);
    assert!(!out.chars().any(hazard), "{out:?}");
    assert!(
        out.contains("\\x1b]0;owned\\x07\\x1b[2Jssh_exec\\x0d"),
        "{out}"
    );
    let (ok, out, _) = audit_cli(&path, &["--request-id", "R4", "--json"]);
    assert!(ok);
    assert!(!out.chars().any(hazard), "{out:?}");
    let back: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(back["tool"], evil["tool"]);

    let (ok, _, err) = audit_cli(&path, &["--decision", "maybe"]);
    assert!(!ok && err.contains("allow or deny"), "{err}");
    let (ok, _, err) = audit_cli(&path, &["--since", "yesterday"]);
    assert!(!ok && err.contains("--since"), "{err}");
}

// ---------------------------------------------------------------------------
// The advisor (task 020)
// ---------------------------------------------------------------------------

/// A simple `cat` through `ssh_exec` gets one short `file_read` hint, once
/// per session per hour. The call's audit record names the pattern, and
/// `prompto_gain` counts the hint and its bytes.
#[tokio::test]
async fn advisor_hints_once_and_is_recorded_and_counted() {
    let s = spawn(AuthMode::Required).await;
    let args = json!({ "host": "run", "cmd": "cat /etc/hosts" });
    let first = call(&s, "ssh_exec", args.clone()).await;
    assert_ok(&first);
    let blocks = first["result"]["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 2, "{first}");
    let hint = blocks[1]["text"].as_str().unwrap();
    assert!(hint.starts_with("[advisor] file_read "), "{hint}");
    assert!(hint.len() <= 120 && !hint.contains('\n'), "{hint}");
    assert_eq!(s.record(&rid(&first))["advisor"], "cat");

    let second = call(&s, "ssh_exec", args).await;
    assert_eq!(second["result"]["content"].as_array().unwrap().len(), 1);
    assert!(s.record(&rid(&second)).get("advisor").is_none());

    // Compound shell: never a hint.
    let piped = call(
        &s,
        "ssh_exec",
        json!({ "host": "run", "cmd": "ls -la /etc | head -3" }),
    )
    .await;
    assert_eq!(piped["result"]["content"].as_array().unwrap().len(), 1);

    let gain = result(&call(&s, "prompto_gain", json!({})).await);
    let adv = &gain["advisor"];
    assert_eq!(adv["hints"], 1, "{gain}");
    assert_eq!(adv["bytes"], hint.len(), "{gain}");
    assert_eq!(adv["by_pattern"]["cat"]["hints"], 1, "{gain}");
}

/// A call to a removed tool (a client with a stale tool list) is
/// refused with what replaces it, and recorded like any invalid call.
#[tokio::test]
async fn a_removed_tool_says_what_replaces_it() {
    let s = spawn(AuthMode::Required).await;
    let resp = call(
        &s,
        "python_exec",
        json!({ "host": "run", "script": "print(1)" }),
    )
    .await;
    let msg = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("python_exec was removed in v0.12.2")
            && msg.contains("ssh_exec with a heredoc"),
        "{resp}"
    );
    let r = s
        .records()
        .into_iter()
        .find(|r| r["tool"] == "python_exec")
        .unwrap();
    assert_eq!(r["error_class"], "invalid_args", "{r}");
    assert_eq!(r["decision"], Value::Null, "{r}");
    // v0.12.3's merges name the tool that took them over.
    for (tool, release, instead) in [
        ("vm_state", "v0.12.3", "vm_list with vm="),
        ("file_stat", "v0.12.3", "file_list with stat_only=true"),
        ("host_diagnose", "v0.12.3", "host_status"),
    ] {
        let resp = call(&s, tool, json!({ "host": "run", "vm": "v", "path": "/x" })).await;
        let msg = resp["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains(&format!("{tool} was removed in {release}")) && msg.contains(instead),
            "{resp}"
        );
    }
    assert!(s.argv_log().is_empty(), "{}", s.argv_log());
}
