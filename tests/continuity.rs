//! Continuity of service (E11), against the real binary: SIGTERM drains
//! the calls in flight; the drain deadline aborts what is left, audits it
//! `aborted` and kills its remote side; SIGUSR2 hands the socket to a
//! successor with no failed request; every config file applies without a
//! restart (S11.3).
//!
//! The fake `ssh` runs the remote command locally, in a session of its
//! own (perl's `setsid`) under a parent named like OpenSSH's
//! `sshd-session`: like a real remote command, it survives when prompto
//! kills its `ssh` process group, so only the reaper can stop it.

use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

mod common;

const BIN: &str = env!("CARGO_BIN_EXE_prompto");

const FAKE_SSH: &str = r#"#!/bin/sh
for a; do
  case $a in SetEnv=*) export "${a#SetEnv=}" ;; esac
  last=$a
done
case $last in *pgtest*) exec /bin/sh -c "$last" ;; esac
exec perl -e '$0 = "sshd-session: fake"; use POSIX; my $p = fork;
if (!$p) { POSIX::setsid(); exec "/bin/sh", "-c", $ARGV[0] }
waitpid($p, 0); exit($? >> 8)' "$last"
"#;

const INVENTORY: &str = r#"
[host.t1]
ip = "192.0.2.41"
ssh_user = "ops"
ssh_key = "/dev/null"
capabilities = ["exec"]

[host.t3]
ip = "192.0.2.43"
ssh_user = "ops"
ssh_key = "/dev/null"
capabilities = ["exec"]
request_id_env = "off"

[host.t4]
ip = "192.0.2.44"
ssh_user = "ops"
ssh_key = "/dev/null"
capabilities = ["exec"]
request_id_env = "setenv"
"#;

fn write_exe(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Proc {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Proc {
    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }
    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.log")).unwrap_or_default()
    }
    fn signal(&self, sig: libc::c_int) {
        // SAFETY: kill has no memory-safety preconditions.
        assert_eq!(unsafe { libc::kill(self.child.id() as i32, sig) }, 0);
    }
    /// Wait for the process to exit; its status code.
    fn exited_within(&mut self, d: Duration) -> Option<i32> {
        let t = Instant::now();
        while t.elapsed() < d {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s.code().unwrap_or(-1));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // A successor started by a handover in this dir.
        for pid in successors(&self.stderr()) {
            // SAFETY: as above.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
    }
}

/// PIDs of successors the log says were started.
fn successors(log: &str) -> Vec<u32> {
    log.lines()
        .filter(|l| l.contains("handover done"))
        .filter_map(|l| {
            let (_, rest) = l.split_once("successor PID ")?;
            rest.split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
        .collect()
}

/// The server, auth off unless `env` says otherwise, on a free port.
fn spawn(dir: &Path, env: &[(&str, String)]) -> Proc {
    spawn_exe(dir, Path::new(BIN), env)
}

/// [`spawn`], started as `exe` — the path a handover starts the
/// successor from.
fn spawn_exe(dir: &Path, exe: &Path, env: &[(&str, String)]) -> Proc {
    if !dir.join("prompto.toml").exists() {
        std::fs::write(dir.join("prompto.toml"), INVENTORY).unwrap();
    }
    write_exe(&dir.join("ssh"), FAKE_SSH);
    let mut cmd = Command::new(exe);
    cmd.env("PROMPTO_INVENTORY", dir.join("prompto.toml"))
        .env("PROMPTO_AUTH", "off")
        .env("PROMPTO_SSH_BIN", dir.join("ssh"))
        .env("PROMPTO_BIND", "127.0.0.1:0")
        .env("PROMPTO_ALLOWED_HOSTS", "127.0.0.1")
        .env("PROMPTO_GAIN_ENABLED", "false")
        .env("PROMPTO_USAGE_LOG", dir.join("usage.jsonl"))
        .env("PROMPTO_AUDIT_LOG", dir.join("audit.jsonl"))
        .env("PROMPTO_KILL_FILE", dir.join("kill"))
        .env("PROMPTO_AGENTS", dir.join("agents.toml"))
        .env("PROMPTO_POLICY", dir.join("policy.toml"))
        .env("PROMPTO_APPROVAL_STATE", dir.join("approval-state"))
        .env("RUST_LOG", "prompto=info")
        // Whatever runs the tests: not a systemd unit here.
        .env_remove("INVOCATION_ID")
        .env_remove("NOTIFY_SOCKET")
        .env_remove("PROMPTO_ENV_FILE")
        .env_remove("PROMPTO_DRAIN_SECS")
        .env_remove("PROMPTO_AUDIT_GROUP");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .spawn()
        .unwrap();
    let mut p = Proc {
        child,
        port: 0,
        dir: dir.to_path_buf(),
    };
    p.port = common::bound_port(&mut p.child, &dir.join("stderr.log"));
    p
}

/// One `tools/call` on a fresh connection: (HTTP status, JSON-RPC body).
async fn call_at(
    addr: SocketAddr,
    token: Option<&str>,
    tool: &str,
    args: Value,
) -> reqwest::Result<(u16, Value)> {
    let mut req = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", tool);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
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
    let text = resp.text().await?;
    let raw = text
        .lines()
        .find_map(|l| l.strip_prefix("data: ").filter(|d| d.starts_with('{')))
        .unwrap_or(&text);
    let v = serde_json::from_str(raw).unwrap_or_else(|_| json!({ "raw": text }));
    Ok((status, v))
}

async fn exec(addr: SocketAddr, cmd: &str, timeout: u64) -> Value {
    call_at(
        addr,
        None,
        "ssh_exec",
        json!({ "host": "t1", "cmd": cmd, "timeout_secs": timeout }),
    )
    .await
    .unwrap()
    .1
}

/// A successful call's stdout.
fn stdout(v: &Value) -> Option<String> {
    let text = v["result"]["content"][0]["text"].as_str()?;
    let inner: Value = serde_json::from_str(text).ok()?;
    if v["result"]["isError"] == true {
        return None;
    }
    inner["stdout"].as_str().map(str::to_string)
}

fn class(v: &Value) -> Option<&str> {
    v["error"]["data"]["error_class"].as_str()
}

fn audit(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim_start_matches('\n')).ok())
        .collect()
}

/// A sleep duration no other test or earlier run uses, to find the
/// process by.
fn unique_secs() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    20_000 + (nanos ^ u64::from(std::process::id())) % 70_000
}

fn pgrep(pattern: &str) -> String {
    let out = Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// SIGTERM: the call in flight finishes and answers normally, nothing is
/// accepted any more, and the process exits 0 once it is done — well
/// before the drain deadline.
#[tokio::test]
async fn sigterm_lets_the_calls_in_flight_finish() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = spawn(dir.path(), &[]);
    let addr = p.addr();
    let long = tokio::spawn(async move { exec(addr, "sleep 2; echo finished", 30).await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    p.signal(libc::SIGTERM);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        call_at(addr, None, "inventory_list", json!({}))
            .await
            .is_err(),
        "a new connection was accepted while draining"
    );
    let v = long.await.unwrap();
    assert_eq!(stdout(&v).as_deref(), Some("finished\n"), "{v}");
    assert_eq!(
        p.exited_within(Duration::from_secs(10)),
        Some(0),
        "{}",
        p.stderr()
    );
    let log = p.stderr();
    assert!(log.contains("draining"), "{log}");
    assert!(log.contains("drained: every call finished"), "{log}");
    let recs = audit(dir.path());
    let r = recs.iter().find(|r| r["tool"] == "ssh_exec").unwrap();
    assert_eq!(r["decision"], "allow", "{r}");
    assert!(r["error_class"].is_null(), "{r}");
}

/// The drain deadline: a call longer than `PROMPTO_DRAIN_SECS` is cut
/// off — the client gets `aborted`, the audit log says `aborted`, and
/// its remote session is gone: the reaper killed the foreground command
/// and a `nohup` job (still in the call's session), and spared a job
/// that left the session (`setsid`). The reap is audited under the
/// call's request ID. Then the process exits. On `t1` (`export`) the
/// session is recorded in `PROMPTO_CALL_SID`; on `t4` (`setenv`, as for a
/// csh host) only the login shell's sshd parent tells it — so the reap
/// must run before the call's ssh is cut.
#[tokio::test]
async fn the_drain_deadline_aborts_audits_and_reaps() {
    for host in ["t1", "t4"] {
        deadline_reaps(host).await;
    }
}

async fn deadline_reaps(host: &'static str) {
    let dir = tempfile::tempdir().unwrap();
    let mut p = spawn(dir.path(), &[("PROMPTO_DRAIN_SECS", "1".into())]);
    let addr = p.addr();
    let n = unique_secs();
    let (fg, nohup, gone) = (
        format!("^sleep {n}$"),
        format!("^sleep {}$", n + 1),
        format!("^sleep {}$", n + 2),
    );
    let cmd = format!(
        "perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' sleep {} >/dev/null 2>&1 & \
         nohup sleep {} >/dev/null 2>&1 & sleep {n}; echo never",
        n + 2,
        n + 1
    );
    let long = tokio::spawn(async move {
        call_at(
            addr,
            None,
            "ssh_exec",
            json!({ "host": host, "cmd": cmd, "timeout_secs": 600 }),
        )
        .await
        .unwrap()
        .1
    });
    let t = Instant::now();
    while [&fg, &nohup, &gone].iter().any(|p| pgrep(p).is_empty()) {
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "remote command never started"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    p.signal(libc::SIGTERM);
    let v = tokio::time::timeout(Duration::from_secs(20), long)
        .await
        .expect("no answer after the deadline")
        .unwrap();
    assert_eq!(class(&v), Some("aborted"), "{v}");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("PROMPTO_DRAIN_SECS"), "{msg}");
    assert_eq!(
        p.exited_within(Duration::from_secs(30)),
        Some(0),
        "{}",
        p.stderr()
    );
    let detached = pgrep(&gone);
    for pid in detached.split_whitespace() {
        let _ = Command::new("kill").arg(pid).status();
    }
    assert!(
        pgrep(&fg).is_empty(),
        "the remote process survived the abort: {}",
        p.stderr()
    );
    assert!(pgrep(&nohup).is_empty(), "the nohup job survived");
    assert!(!detached.is_empty(), "the setsid job was reaped");
    let recs = audit(dir.path());
    let r = recs
        .iter()
        .find(|r| r["tool"] == "ssh_exec" && r["type"] == "tool")
        .expect("no record");
    assert_eq!(r["error_class"], "aborted", "{r}");
    assert_eq!(r["request_id"], v["error"]["data"]["request_id"], "{r}");
    let reap = recs
        .iter()
        .find(|r| r["type"] == "reap")
        .unwrap_or_else(|| panic!("no reap record: {recs:?}"));
    assert_eq!(reap["request_id"], r["request_id"], "{reap}");
    assert_eq!(reap["host"], host, "{reap}");
    assert_eq!(reap["tool"], "ssh_exec", "{reap}");
    assert_eq!(reap["as_root"], false, "{reap}");
    assert_eq!(reap["ok"], true, "{reap}");
    assert_eq!(reap["sessions"].as_array().map(Vec::len), Some(1), "{reap}");
    assert!(
        reap["terminated"].as_array().is_some_and(|a| a.len() >= 3),
        "shell, nohup job and sleep: {reap}"
    );
    assert!(
        p.stderr().contains("reaped the remote side"),
        "{}",
        p.stderr()
    );
}

/// A call dropped before its ssh exits (here: its timeout) kills ssh's
/// whole process group, not just ssh — a `ProxyCommand`, or here the
/// fake ssh's child, goes with it. (`t3` has `request_id_env = "off"`
/// and runs the command in ssh's own group, so neither the reaper nor a
/// session of its own is involved.)
#[tokio::test]
async fn a_dropped_call_kills_the_ssh_process_group() {
    let dir = tempfile::tempdir().unwrap();
    let p = spawn(dir.path(), &[]);
    let n = unique_secs();
    let (_, v) = call_at(
        p.addr(),
        None,
        "ssh_exec",
        json!({"host": "t3", "cmd": format!("sleep {n}; true # pgtest"), "timeout_secs": 1}),
    )
    .await
    .unwrap();
    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains(r#""timed_out":true"#), "{v}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        pgrep(&format!("^sleep {n}$")).is_empty(),
        "ssh's child survived"
    );
}

/// SIGUSR2: a successor takes the socket while a long call finishes on
/// the old process; a client calling in a tight loop throughout sees no
/// failed request, and the old process exits once drained. The successor
/// picks up an edited `PROMPTO_ENV_FILE`.
#[tokio::test]
async fn sigusr2_hands_over_with_no_failed_request() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("env");
    std::fs::write(&env_file, "PROMPTO_STOP_VM_STEP_SECS=31\n").unwrap();
    let mut p = spawn(
        dir.path(),
        &[
            ("PROMPTO_ENV_FILE", env_file.display().to_string()),
            ("PROMPTO_STOP_VM_STEP_SECS", "31".into()),
        ],
    );
    let addr = p.addr();
    let long = tokio::spawn(async move { exec(addr, "sleep 2; echo long-done", 30).await });
    let looping = tokio::spawn(async move {
        let mut n = 0;
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            let r = call_at(addr, None, "inventory_list", json!({})).await;
            match r {
                Ok((200, v)) if v["result"].is_object() => n += 1,
                other => panic!("request {n} failed across the handover: {other:?}"),
            }
        }
        n
    });
    // The same over one pooled client, reusing keep-alive connections as
    // real clients do.
    let pooled = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut n = 0;
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            let r = client
                .post(format!("http://{addr}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", "2025-03-26")
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inventory_list","arguments":{}}}"#)
                .send()
                .await;
            match r {
                Ok(r) if r.status() == 200 => {
                    let text = r.text().await.unwrap_or_default();
                    assert!(text.contains("\"result\""), "request {n}: {text}");
                    n += 1;
                }
                other => panic!("pooled request {n} failed across the handover: {other:?}"),
            }
        }
        n
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(&env_file, "PROMPTO_STOP_VM_STEP_SECS=77\n").unwrap();
    p.signal(libc::SIGUSR2);

    let v = long.await.unwrap();
    assert_eq!(stdout(&v).as_deref(), Some("long-done\n"), "{v}");
    let n = looping.await.unwrap();
    assert!(n > 20, "only {n} requests");
    let n = pooled.await.unwrap();
    assert!(n > 20, "only {n} pooled requests");
    assert_eq!(
        p.exited_within(Duration::from_secs(10)),
        Some(0),
        "{}",
        p.stderr()
    );
    let log = p.stderr();
    let succ = successors(&log);
    assert_eq!(succ.len(), 1, "{log}");
    assert_ne!(succ[0], p.child.id());
    // Still serving, from the successor, with the edited env file.
    let v = exec(addr, "echo after", 30).await;
    assert_eq!(stdout(&v).as_deref(), Some("after\n"), "{v}");
    let log = p.stderr();
    assert!(log.contains("stop_vm_step: 77s"), "{log}");
    assert!(log.contains("listening socket inherited"), "{log}");
}

/// A successor that says it is ready and dies right after (a broken
/// deploy) never becomes the main process: the old one keeps accepting
/// through the successor's probation, so a client calling throughout sees
/// no failure, systemd is never told `MAINPID=`, and the old process
/// serves on. A good binary then hands over, `MAINPID` only after the
/// probation. And a stop during a probation abandons the successor
/// (SIGTERM) and drains here.
#[tokio::test]
async fn a_successor_that_dies_after_ready_never_takes_over() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let exe = d.join("prompto");
    std::os::unix::fs::symlink(BIN, &exe).unwrap();
    let notify = std::os::unix::net::UnixDatagram::bind(d.join("notify")).unwrap();
    notify.set_nonblocking(true).unwrap();
    let mut p = spawn_exe(
        d,
        &exe,
        &[("NOTIFY_SOCKET", d.join("notify").display().to_string())],
    );
    let addr = p.addr();
    let messages = || {
        let mut out = String::new();
        let mut buf = [0u8; 512];
        while let Ok(n) = notify.recv(&mut buf) {
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
            out.push('\n');
        }
        out
    };
    assert!(messages().contains("READY=1"));
    let looping = |addr: SocketAddr, secs: u64| {
        tokio::spawn(async move {
            let mut n = 0;
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(secs) {
                match call_at(addr, None, "inventory_list", json!({})).await {
                    Ok((200, v)) if v["result"].is_object() => n += 1,
                    other => panic!("request {n} failed: {other:?}"),
                }
            }
            n
        })
    };

    // A deploy that says ready, then crashes.
    std::fs::remove_file(&exe).unwrap();
    write_exe(&exe, "#!/bin/sh\nprintf R >&4\nsleep 1\nexit 3\n");
    let calls = looping(addr, 4);
    p.signal(libc::SIGUSR2);
    let t = Instant::now();
    while !p.stderr().contains("handover failed") {
        assert!(t.elapsed() < Duration::from_secs(15), "{}", p.stderr());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(calls.await.unwrap() > 10);
    let log = p.stderr();
    assert!(log.contains("exited during its probation"), "{log}");
    assert!(!log.contains("handover done"), "{log}");
    assert!(
        !messages().contains("MAINPID"),
        "systemd told to follow a dead successor"
    );
    let v = exec(addr, "echo still", 30).await;
    assert_eq!(stdout(&v).as_deref(), Some("still\n"), "{v}");
    assert_eq!(p.exited_within(Duration::from_millis(100)), None);

    // A stop during the probation of one that serves: it is told to
    // stop too, and this process drains and exits.
    let n = unique_secs();
    std::fs::remove_file(&exe).unwrap();
    write_exe(&exe, &format!("#!/bin/sh\nprintf R >&4\nexec sleep {n}\n"));
    p.signal(libc::SIGUSR2);
    let t = Instant::now();
    // The second probation: the crashed successor's is in the log too.
    while p
        .stderr()
        .matches("both accept until its probation ends")
        .count()
        < 2
    {
        assert!(t.elapsed() < Duration::from_secs(15), "{}", p.stderr());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    p.signal(libc::SIGTERM);
    assert_eq!(
        p.exited_within(Duration::from_secs(10)),
        Some(0),
        "{}",
        p.stderr()
    );
    assert!(
        p.stderr().contains("abandoning the successor"),
        "{}",
        p.stderr()
    );
    assert!(!messages().contains("MAINPID"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        pgrep(&format!("^sleep {n}$")).is_empty(),
        "abandoned successor still runs"
    );

    // The real binary again: handed over, MAINPID once proven.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let exe = d.join("prompto");
    std::os::unix::fs::symlink(BIN, &exe).unwrap();
    let notify = std::os::unix::net::UnixDatagram::bind(d.join("notify")).unwrap();
    let mut p = spawn_exe(
        d,
        &exe,
        &[("NOTIFY_SOCKET", d.join("notify").display().to_string())],
    );
    let mut buf = [0u8; 512];
    let n = notify.recv(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("READY=1"));
    let calls = looping(p.addr(), 3);
    p.signal(libc::SIGUSR2);
    let t = Instant::now();
    notify
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let n = notify.recv(&mut buf).unwrap();
    let msg = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(msg.starts_with("MAINPID="), "{msg}");
    assert!(
        t.elapsed() >= prompto::handover::PROBATION,
        "MAINPID before the probation ended: {:?}",
        t.elapsed()
    );
    assert!(calls.await.unwrap() > 10);
    assert_eq!(
        p.exited_within(Duration::from_secs(10)),
        Some(0),
        "{}",
        p.stderr()
    );
    assert_eq!(successors(&p.stderr()).len(), 1);
}

/// A stop during a probation means "abandon the handover and drain",
/// even when it comes as more than one signal at once (a SIGTERM with a
/// SIGINT): the drain runs in full and the call in flight finishes. Only
/// a stop sent during the drain cuts it short.
#[tokio::test]
async fn stops_during_a_probation_do_not_cut_the_drain_short() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let exe = d.join("prompto");
    std::os::unix::fs::symlink(BIN, &exe).unwrap();
    let mut p = spawn_exe(d, &exe, &[]);
    let addr = p.addr();
    let n = unique_secs();
    std::fs::remove_file(&exe).unwrap();
    write_exe(&exe, &format!("#!/bin/sh\nprintf R >&4\nexec sleep {n}\n"));
    let long = tokio::spawn(async move { exec(addr, "sleep 3; echo finished", 30).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    p.signal(libc::SIGUSR2);
    let t = Instant::now();
    while !p.stderr().contains("both accept until its probation ends") {
        assert!(t.elapsed() < Duration::from_secs(15), "{}", p.stderr());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Both pending when the process next runs, whatever the scheduling.
    p.signal(libc::SIGSTOP);
    p.signal(libc::SIGTERM);
    p.signal(libc::SIGINT);
    p.signal(libc::SIGCONT);
    let v = long.await.unwrap();
    assert_eq!(stdout(&v).as_deref(), Some("finished\n"), "{v}");
    assert_eq!(
        p.exited_within(Duration::from_secs(10)),
        Some(0),
        "{}",
        p.stderr()
    );
    let log = p.stderr();
    assert!(log.contains("abandoning the successor"), "{log}");
    assert!(log.contains("drained: every call finished"), "{log}");
    assert!(!log.contains("cutting the drain short"), "{log}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(pgrep(&format!("^sleep {n}$")).is_empty());
}

/// A successor that can't start (here: an invalid setting in the env
/// file) leaves the old process serving; under a systemd unit that is not
/// `Type=notify` a handover is refused outright, since systemd would kill
/// the successor with the old process.
#[tokio::test]
async fn a_failed_or_unsafe_handover_keeps_the_old_process_serving() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("env");
    std::fs::write(&env_file, "PROMPTO_AUTH=sometimes\n").unwrap();
    let mut p = spawn(
        dir.path(),
        &[("PROMPTO_ENV_FILE", env_file.display().to_string())],
    );
    p.signal(libc::SIGUSR2);
    let t = Instant::now();
    while !p.stderr().contains("handover failed") {
        assert!(t.elapsed() < Duration::from_secs(10), "{}", p.stderr());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let v = exec(p.addr(), "echo still", 30).await;
    assert_eq!(stdout(&v).as_deref(), Some("still\n"), "{v}");
    assert_eq!(p.exited_within(Duration::from_millis(200)), None);

    let dir = tempfile::tempdir().unwrap();
    let mut p = spawn(dir.path(), &[("INVOCATION_ID", "0123abcd".into())]);
    p.signal(libc::SIGUSR2);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = p.stderr();
    assert!(log.contains("handover refused"), "{log}");
    assert!(successors(&log).is_empty(), "{log}");
    let v = exec(p.addr(), "echo still", 30).await;
    assert_eq!(stdout(&v).as_deref(), Some("still\n"), "{v}");
    assert_eq!(p.exited_within(Duration::from_millis(200)), None);
}

/// S11.3: inventory, agents, policy and kill files all apply to a running
/// server — the same process throughout, no restart. Agents, policy and
/// kill files are re-read on the next request; the inventory on SIGHUP
/// (`systemctl reload`).
#[tokio::test]
async fn every_config_file_applies_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("agents.toml"), "").unwrap();
    let rule = |hosts: &str| {
        format!("[[rule]]\nid = \"r\"\nagents = [\"alpha\"]\nhosts = [{hosts}]\ntools = [\"*\"]\n")
    };
    std::fs::write(d.join("policy.toml"), rule("\"t1\"")).unwrap();
    let mut p = spawn(d, &[("PROMPTO_AUTH", "required".into())]);
    let pid = p.child.id();
    let addr = p.addr();
    let call = |tok: Option<String>, host: &'static str| async move {
        call_at(
            addr,
            tok.as_deref(),
            "ssh_exec",
            json!({ "host": host, "cmd": "echo hi", "timeout_secs": 30 }),
        )
        .await
        .unwrap()
    };

    // Agents: a token minted now works on the next request.
    let (status, _) = call(None, "t1").await;
    assert_eq!(status, 401);
    let out = Command::new(BIN)
        .args(["agent", "add", "alpha"])
        .env("PROMPTO_AGENTS", d.join("agents.toml"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let token = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let (status, v) = call(Some(token.clone()), "t1").await;
    assert_eq!((status, stdout(&v).as_deref()), (200, Some("hi\n")), "{v}");

    // Inventory: a new host, on SIGHUP.
    let mut inv = std::fs::read_to_string(d.join("prompto.toml")).unwrap();
    inv.push_str(
        "\n[host.t2]\nip = \"192.0.2.42\"\nssh_user = \"ops\"\nssh_key = \"/dev/null\"\n\
         capabilities = [\"exec\"]\n",
    );
    std::fs::write(d.join("prompto.toml"), inv).unwrap();
    let (_, v) = call(Some(token.clone()), "t2").await;
    assert_eq!(class(&v), Some("unknown_host"), "before SIGHUP: {v}");
    p.signal(libc::SIGHUP);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_, v) = call(Some(token.clone()), "t2").await;
    assert_eq!(
        class(&v),
        Some("refused_policy"),
        "known now, not granted: {v}"
    );

    // Policy: the grant applies on the next request.
    std::fs::write(d.join("policy.toml"), rule("\"t1\", \"t2\"")).unwrap();
    let (_, v) = call(Some(token.clone()), "t2").await;
    assert_eq!(stdout(&v).as_deref(), Some("hi\n"), "{v}");

    // Kill file: on, then off.
    std::fs::write(d.join("kill"), "maintenance\n").unwrap();
    let (_, v) = call(Some(token.clone()), "t1").await;
    assert_eq!(class(&v), Some("killed"), "{v}");
    std::fs::remove_file(d.join("kill")).unwrap();
    let (_, v) = call(Some(token.clone()), "t1").await;
    assert_eq!(stdout(&v).as_deref(), Some("hi\n"), "{v}");

    assert_eq!(p.child.id(), pid);
    assert_eq!(
        p.exited_within(Duration::from_millis(100)),
        None,
        "restarted"
    );
    assert_eq!(
        p.stderr().matches("prompto starting").count(),
        1,
        "{}",
        p.stderr()
    );
}

/// While draining with no successor, a request that still arrives on an
/// open connection is turned away before anything runs: `503`,
/// `Retry-After`, `Connection: close`, and nothing in the audit log.
/// After a handover the old process serves what still reaches it.
#[tokio::test]
async fn a_draining_server_answers_503_until_handed_over() {
    use prompto::drain::Drain;
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    write_exe(&dir.path().join("ssh"), FAKE_SSH);
    let drain = Drain::default();
    let serve = |drain: Drain| {
        let dir = dir.path().to_path_buf();
        async move {
            let audit = prompto::audit::Audit::new(
                prompto::audit::AuditLog::open(dir.join("audit.jsonl"), None, false).unwrap(),
            );
            let app = prompto::server::build_router(prompto::server::HttpParams {
                store: prompto::inventory::InventoryStore::new(
                    prompto::inventory::Inventory::from_toml_str(INVENTORY).unwrap(),
                    None,
                ),
                ssh: Arc::new(
                    prompto::ssh::SshClient::new(dir.join("ssh"), Duration::from_secs(5))
                        .with_drain(drain),
                ),
                tracker: Arc::new(mcp_gain::Tracker::disabled()),
                stop_vm_step: Duration::from_secs(1),
                trusted_proxies: Arc::new(prompto::caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
                allowed_hosts: prompto::server::AllowedHosts::List(vec!["127.0.0.1".into()]),
                legacy_session_mode: false,
                auth: Default::default(),
                audit,
                kill: prompto::kill::KillSwitch::in_dir(&dir),
                cancel: Default::default(),
            });
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .unwrap()
            });
            addr
        }
    };
    let addr = serve(drain.clone()).await;
    let v = exec(addr, "echo up", 10).await;
    assert_eq!(stdout(&v).as_deref(), Some("up\n"), "{v}");

    drain.begin(false);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    assert_eq!(
        resp.headers()["retry-after"],
        prompto::server::DRAIN_RETRY_AFTER
    );
    assert_eq!(resp.headers()["connection"], "close");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["data"]["retryable"], true, "{body}");
    let (status, _) = call_at(
        addr,
        None,
        "ssh_exec",
        json!({"host": "t1", "cmd": "echo x"}),
    )
    .await
    .unwrap();
    assert_eq!(status, 503);
    assert_eq!(
        audit(dir.path()).len(),
        1,
        "a refused request reached the audit log"
    );

    let drain = Drain::default();
    let addr = serve(drain.clone()).await;
    drain.begin(true);
    let v = exec(addr, "echo still", 10).await;
    assert_eq!(stdout(&v).as_deref(), Some("still\n"), "{v}");
}
