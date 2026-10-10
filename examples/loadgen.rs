//! Load generator for the continuity proof (roadmap E11, S12.2): N fake
//! agents, each with its own role token, call a live prompto at once and
//! every call's outcome is checked against the outcome expected for it.
//! Pass = zero unexpected outcomes.
//!
//! ```text
//! cargo run --release --example loadgen -- \
//!     --url http://sbx-core:6337 --tokens ~/.config/prompto/loadgen \
//!     --secs 1800 --out calls.jsonl [--events events.txt] \
//!     [--long-min 60 --long-max 180] [--host sbx-t1 --vault-host sbx-t2 \
//!      --refused-host sbx-bsd] [--retry-secs 0]
//! ```
//!
//! `--tokens` is a directory of token files, one per agent, mode 0600,
//! named after the agent; tokens are read from there and sent only in the
//! `Authorization` header, never printed. Every agent runs two lanes for
//! `--secs`:
//!
//! - **long**: `ssh_exec` of `sleep 60..180; echo …` back to back, so
//!   there are always long calls in flight when something restarts;
//! - **short**, a random mix with a short pause between calls: `ssh_exec`
//!   (`short`), `file_write` then `file_read` of the same content
//!   (`file_write`, `file_read`), `ssh_sudo_exec id -u` with passwordless
//!   sudo (`sudo`) and with the vault-held password (`sudo_vault`), a
//!   ticketed `bash_exec` — `POST /v1/precheck`, the call with the ticket,
//!   then its replay (`ticket_precheck`, `ticket`, `ticket_replay`, which
//!   must be refused) — and deliberately refused calls: root where policy
//!   grants none (`refused_policy`) and a host that doesn't exist
//!   (`unknown_host`).
//!
//! Half the agents speak the 2026-07-28 stateless protocol, half do an
//! `initialize` first like older clients. Connections are pooled and
//! reused like a real client's. Nothing is retried unless `--retry-secs`
//! is given: then, as a client should across a plain restart, a request
//! that provably did not run — the connection was refused, or prompto
//! answered `503` with `Retry-After` while draining — is sent again,
//! once a second, for up to that long. A request that may have run (a
//! reset or a timeout after it was sent) is never retried. Retries are
//! counted per call and in the summary.
//!
//! Each call is one JSON line in `--out`. At the end a summary (counts and
//! latencies per call type, every unexpected outcome) goes to stdout.
//! With `--events` (lines of `<unix ms> <label>`, written by whatever
//! restarts the server), the summary also gives, per event, the slowest
//! short call started in the 20 s after it and how much that adds to the
//! median short call.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Cfg {
    url: String,
    secs: u64,
    out: PathBuf,
    events: Option<PathBuf>,
    long_min: u64,
    long_max: u64,
    host: String,
    vault_host: String,
    refused_host: String,
    retry_secs: u64,
}

#[derive(Clone)]
struct Agent {
    name: String,
    token: String,
    session: String,
    modern: bool,
    /// Legacy clients: the session ID `initialize` returned, if any.
    mcp_session: Arc<Mutex<Option<String>>>,
}

/// What a call came back with.
#[derive(Debug)]
enum Outcome {
    /// A tool result: its JSON payload.
    Ok(Value),
    /// A JSON-RPC error: class and message.
    Refused(Option<String>, String),
    /// Not a JSON-RPC answer.
    Http(u16, String),
    Transport(String),
}

impl Outcome {
    fn label(&self) -> String {
        match self {
            Self::Ok(_) => "ok".into(),
            Self::Refused(c, _) => format!("error:{}", c.as_deref().unwrap_or("?")),
            Self::Http(s, _) => format!("http:{s}"),
            Self::Transport(_) => "transport".into(),
        }
    }
    fn detail(&self) -> String {
        let s = match self {
            Self::Ok(v) => v.to_string(),
            Self::Refused(_, m) => m.clone(),
            Self::Http(_, b) => b.clone(),
            Self::Transport(e) => e.clone(),
        };
        s.chars().take(400).collect()
    }
    fn stdout(&self) -> Option<&str> {
        match self {
            Self::Ok(v) => v["stdout"].as_str(),
            _ => None,
        }
    }
    fn class(&self) -> Option<&str> {
        match self {
            Self::Refused(c, _) => c.as_deref(),
            _ => None,
        }
    }
}

struct Run {
    cfg: Cfg,
    http: reqwest::Client,
    seq: AtomicU64,
    out: Mutex<std::fs::File>,
    records: Mutex<Vec<Rec>>,
    start: Instant,
}

#[derive(Clone)]
struct Rec {
    t: u64,
    kind: &'static str,
    ms: u64,
    ok: bool,
    agent: String,
    outcome: String,
    detail: String,
    retries: u32,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// xorshift64*, seeded per lane.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        Self(u64::from_le_bytes(b) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

impl Run {
    fn running(&self) -> bool {
        self.start.elapsed() < Duration::from_secs(self.cfg.secs)
    }

    fn id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        agent: &Agent,
        kind: &'static str,
        t: u64,
        ms: u64,
        ok: bool,
        o: &Outcome,
        retries: u32,
    ) {
        let rec = Rec {
            t,
            kind,
            ms,
            ok,
            agent: agent.name.clone(),
            outcome: o.label(),
            detail: if ok { String::new() } else { o.detail() },
            retries,
        };
        let line = json!({
            "t": rec.t, "agent": rec.agent, "kind": kind, "ms": ms, "ok": ok,
            "outcome": rec.outcome, "detail": rec.detail, "retries": retries,
        });
        if let Ok(mut f) = self.out.lock() {
            let _ = writeln!(f, "{line}");
        }
        if !ok {
            eprintln!(
                "UNEXPECTED {kind} {} {}: {}",
                agent.name, rec.outcome, rec.detail
            );
        }
        self.records.lock().unwrap().push(rec);
    }

    fn post(&self, agent: &Agent, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{path}", self.cfg.url))
            .header("authorization", format!("Bearer {}", agent.token))
            .header("x-prompto-session", &agent.session)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
    }

    /// Send the request `mk` builds; with `--retry-secs`, again while it
    /// provably did not run (see the module docs). The response, and how
    /// many times it was retried.
    async fn send(
        &self,
        mk: impl Fn() -> reqwest::RequestBuilder,
    ) -> (reqwest::Result<reqwest::Response>, u32) {
        let until = Instant::now() + Duration::from_secs(self.cfg.retry_secs);
        let mut retries = 0;
        loop {
            let r = mk().send().await;
            let not_run = match &r {
                Err(e) => e.is_connect(),
                Ok(resp) => {
                    resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        && resp.headers().contains_key("retry-after")
                }
            };
            if !not_run || Instant::now() >= until {
                return (r, retries);
            }
            retries += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn initialize(&self, agent: &Agent) -> Result<(), String> {
        let body = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},
            "clientInfo":{"name":"loadgen","version":"0"}}});
        let r = self
            .post(agent, "/mcp")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{e:#}"))?;
        let sid = r
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let _ = r.text().await;
        *agent.mcp_session.lock().unwrap() = sid;
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let _ = self.post(agent, "/mcp").json(&note).send().await;
        Ok(())
    }

    async fn call(&self, agent: &Agent, tool: &str, args: Value) -> (Outcome, u32) {
        let id = self.id();
        let mut headers: Vec<(&str, String)> = Vec::new();
        let body = if agent.modern {
            headers.push(("mcp-protocol-version", "2026-07-28".into()));
            headers.push(("mcp-method", "tools/call".into()));
            headers.push(("mcp-name", tool.into()));
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":tool,"arguments":args,"_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientInfo":{"name":"loadgen","version":"0"},
                    "io.modelcontextprotocol/clientCapabilities":{}}}})
        } else {
            headers.push(("mcp-protocol-version", "2025-03-26".into()));
            if let Some(s) = agent.mcp_session.lock().unwrap().clone() {
                headers.push(("mcp-session-id", s));
            }
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":tool,"arguments":args}})
        };
        let (resp, retries) = self
            .send(|| {
                let mut req = self.post(agent, "/mcp");
                for (k, v) in &headers {
                    req = req.header(*k, v);
                }
                req.json(&body)
            })
            .await;
        (self.outcome(resp).await, retries)
    }

    async fn outcome(&self, resp: reqwest::Result<reqwest::Response>) -> Outcome {
        let resp = match resp {
            Ok(r) => r,
            Err(e) => return Outcome::Transport(format!("{e:#}")),
        };
        let status = resp.status().as_u16();
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return Outcome::Transport(format!("body: {e:#}")),
        };
        let raw = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:").map(str::trim))
            .find(|d| d.starts_with('{'))
            .unwrap_or(&text);
        let Ok(v) = serde_json::from_str::<Value>(raw) else {
            return Outcome::Http(status, text);
        };
        if let Some(e) = v.get("error") {
            return Outcome::Refused(
                e["data"]["error_class"].as_str().map(str::to_string),
                e["message"].as_str().unwrap_or_default().to_string(),
            );
        }
        let Some(t) = v["result"]["content"][0]["text"].as_str() else {
            return Outcome::Http(status, text);
        };
        let inner = serde_json::from_str(t).unwrap_or(Value::String(t.to_string()));
        if v["result"]["isError"] == true {
            return Outcome::Refused(None, t.to_string());
        }
        Outcome::Ok(inner)
    }

    /// One call, timed and recorded; `check` says whether it is what was
    /// expected. The outcome is returned for follow-up calls.
    async fn timed(
        &self,
        agent: &Agent,
        kind: &'static str,
        tool: &str,
        args: Value,
        check: impl Fn(&Outcome) -> bool,
    ) -> Outcome {
        let t = now_ms();
        let i = Instant::now();
        let (o, retries) = self.call(agent, tool, args).await;
        let ok = check(&o);
        self.record(
            agent,
            kind,
            t,
            i.elapsed().as_millis() as u64,
            ok,
            &o,
            retries,
        );
        o
    }

    async fn long_lane(self: Arc<Self>, agent: Agent) {
        let mut rng = Rng::new();
        // Staggered, so the long calls don't all end together.
        tokio::time::sleep(Duration::from_millis(rng.range(0, 20_000))).await;
        while self.running() {
            let n = self.id();
            let secs = rng.range(self.cfg.long_min, self.cfg.long_max);
            let want = format!("long-{n}\n");
            self.timed(
                &agent,
                "long",
                "ssh_exec",
                json!({"host": self.cfg.host, "cmd": format!("sleep {secs}; echo long-{n}"),
                       "timeout_secs": secs + 120}),
                |o| o.stdout() == Some(want.as_str()),
            )
            .await;
        }
    }

    async fn short_lane(self: Arc<Self>, agent: Agent) {
        let mut rng = Rng::new();
        let c = &self.cfg;
        while self.running() {
            let n = self.id();
            match rng.range(0, 99) {
                0..=29 => {
                    let host = if n.is_multiple_of(2) {
                        &c.host
                    } else {
                        &c.vault_host
                    };
                    let want = format!("short-{n}\n");
                    self.timed(
                        &agent,
                        "short",
                        "ssh_exec",
                        json!({"host": host, "cmd": format!("echo short-{n}")}),
                        |o| o.stdout() == Some(want.as_str()),
                    )
                    .await;
                }
                30..=49 => {
                    let path = format!("/tmp/loadgen-{}-{}", agent.name, n % 4);
                    let content = format!("{} {n} {}\n", agent.name, rng.next());
                    let w = self
                        .timed(
                            &agent,
                            "file_write",
                            "file_write",
                            json!({"host": c.host, "path": path, "content": content}),
                            |o| matches!(o, Outcome::Ok(_)),
                        )
                        .await;
                    if matches!(w, Outcome::Ok(_)) {
                        self.timed(
                            &agent,
                            "file_read",
                            "file_read",
                            json!({"host": c.host, "path": path}),
                            |o| matches!(o, Outcome::Ok(v) if v["content"] == content.as_str()),
                        )
                        .await;
                    }
                }
                50..=61 => {
                    self.timed(
                        &agent,
                        "sudo",
                        "ssh_sudo_exec",
                        json!({"host": c.host, "cmd": "id -u"}),
                        |o| o.stdout() == Some("0\n"),
                    )
                    .await;
                }
                62..=69 => {
                    self.timed(
                        &agent,
                        "sudo_vault",
                        "ssh_sudo_exec",
                        json!({"host": c.vault_host, "cmd": "id -u"}),
                        |o| o.stdout() == Some("0\n"),
                    )
                    .await;
                }
                70..=81 => self.ticketed(&agent, n).await,
                82..=90 => {
                    self.timed(
                        &agent,
                        "refused_policy",
                        "ssh_sudo_exec",
                        json!({"host": c.refused_host, "cmd": "id -u"}),
                        |o| o.class() == Some("refused_policy"),
                    )
                    .await;
                }
                _ => {
                    self.timed(
                        &agent,
                        "unknown_host",
                        "ssh_exec",
                        json!({"host": "no-such-host", "cmd": "true"}),
                        |o| o.class() == Some("unknown_host"),
                    )
                    .await;
                }
            }
            tokio::time::sleep(Duration::from_millis(rng.range(100, 800))).await;
        }
    }

    /// precheck → ticket → the call → its replay (refused).
    async fn ticketed(&self, agent: &Agent, n: u64) {
        let args = json!({"host": self.cfg.host, "script": format!("echo ticket-{n}")});
        let t = now_ms();
        let i = Instant::now();
        let mut retries = 0;
        let pre = async {
            let (r, n) = self
                .send(|| {
                    self.post(agent, "/v1/precheck")
                        .json(&json!({"tool": "bash_exec", "arguments": args}))
                })
                .await;
            retries = n;
            let r = r.map_err(|e| Outcome::Transport(format!("{e:#}")))?;
            let status = r.status().as_u16();
            let text = r
                .text()
                .await
                .map_err(|e| Outcome::Transport(format!("{e:#}")))?;
            let v: Value =
                serde_json::from_str(&text).map_err(|_| Outcome::Http(status, text.clone()))?;
            match (status, v["decision"].as_str(), v["ticket"].as_str()) {
                (200, Some("allow"), Some(tk)) => Ok(tk.to_string()),
                _ => Err(Outcome::Http(status, text)),
            }
        };
        let pre = pre.await;
        let ticket = match pre {
            Ok(tk) => {
                self.record(
                    agent,
                    "ticket_precheck",
                    t,
                    i.elapsed().as_millis() as u64,
                    true,
                    &Outcome::Ok(Value::Null),
                    retries,
                );
                tk
            }
            Err(o) => {
                self.record(
                    agent,
                    "ticket_precheck",
                    t,
                    i.elapsed().as_millis() as u64,
                    false,
                    &o,
                    retries,
                );
                return;
            }
        };
        let mut with = args.clone();
        with["ticket"] = ticket.into();
        let want = format!("ticket-{n}\n");
        self.timed(agent, "ticket", "bash_exec", with.clone(), |o| {
            o.stdout() == Some(want.as_str())
        })
        .await;
        self.timed(
            agent,
            "ticket_replay",
            "bash_exec",
            with,
            |o| matches!(o, Outcome::Refused(_, m) if m.contains("already used")),
        )
        .await;
    }
}

fn parse_args() -> Result<(Cfg, PathBuf), String> {
    let mut a = std::env::args().skip(1);
    let mut m = BTreeMap::new();
    while let Some(k) = a.next() {
        let v = a.next().ok_or(format!("{k} needs a value"))?;
        m.insert(k.trim_start_matches('-').to_string(), v);
    }
    let get = |k: &str, d: &str| m.get(k).cloned().unwrap_or_else(|| d.to_string());
    let num = |k: &str, d: u64| -> Result<u64, String> {
        get(k, &d.to_string())
            .parse()
            .map_err(|_| format!("--{k}: not a number"))
    };
    let tokens = PathBuf::from(m.get("tokens").ok_or("--tokens <dir> is required")?);
    let cfg = Cfg {
        url: get("url", "http://127.0.0.1:6337")
            .trim_end_matches('/')
            .to_string(),
        secs: num("secs", 300)?,
        out: get("out", "loadgen-calls.jsonl").into(),
        events: m.get("events").map(PathBuf::from),
        long_min: num("long-min", 60)?,
        long_max: num("long-max", 180)?,
        host: get("host", "sbx-t1"),
        vault_host: get("vault-host", "sbx-t2"),
        refused_host: get("refused-host", "sbx-bsd"),
        retry_secs: num("retry-secs", 0)?,
    };
    Ok((cfg, tokens))
}

fn read_tokens(dir: &PathBuf) -> Result<Vec<(String, String)>, String> {
    use std::os::unix::fs::PermissionsExt;
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        let meta = std::fs::metadata(&p).map_err(|e| e.to_string())?;
        if !meta.is_file() {
            continue;
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!("{}: must be mode 0600", p.display()));
        }
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let token = std::fs::read_to_string(&p)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        out.push((name, token));
    }
    out.sort();
    Ok(out)
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Short call types, for the latency-at-restart measure.
const SHORT: &[&str] = &[
    "short",
    "file_write",
    "file_read",
    "sudo",
    "sudo_vault",
    "ticket_precheck",
    "ticket",
    "ticket_replay",
    "refused_policy",
    "unknown_host",
];

fn summary(run: &Run) -> bool {
    let recs = run.records.lock().unwrap().clone();
    let mut kinds: BTreeMap<&str, Vec<&Rec>> = BTreeMap::new();
    for r in &recs {
        kinds.entry(r.kind).or_default().push(r);
    }
    let bad: Vec<&Rec> = recs.iter().filter(|r| !r.ok).collect();
    println!("## loadgen summary\n");
    println!(
        "{} agents, {} s, {} calls, {} unexpected\n",
        run.records
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.agent.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        run.cfg.secs,
        recs.len(),
        bad.len()
    );
    let retried: Vec<&Rec> = recs.iter().filter(|r| r.retries > 0).collect();
    println!(
        "retried (refused or 503 while nothing served, nothing ran): {} calls, {} retries, \
         at most {} for one call; retry budget {} s\n",
        retried.len(),
        retried.iter().map(|r| u64::from(r.retries)).sum::<u64>(),
        retried.iter().map(|r| r.retries).max().unwrap_or(0),
        run.cfg.retry_secs
    );
    println!("| call type | calls | as expected | unexpected | p50 ms | p99 ms | max ms |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for (k, v) in &kinds {
        let mut ms: Vec<u64> = v.iter().map(|r| r.ms).collect();
        ms.sort_unstable();
        let ok = v.iter().filter(|r| r.ok).count();
        println!(
            "| {k} | {} | {ok} | {} | {} | {} | {} |",
            v.len(),
            v.len() - ok,
            pct(&ms, 0.5),
            pct(&ms, 0.99),
            ms.last().copied().unwrap_or(0)
        );
    }
    if let Some(path) = &run.cfg.events {
        let events: Vec<(u64, String)> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (t, label) = l.split_once(' ')?;
                Some((t.parse().ok()?, label.to_string()))
            })
            .collect();
        let window = |t: u64, e: u64| t + 1000 >= e && t <= e + 20_000;
        let mut base: Vec<u64> = recs
            .iter()
            .filter(|r| SHORT.contains(&r.kind) && !events.iter().any(|(e, _)| window(r.t, *e)))
            .map(|r| r.ms)
            .collect();
        base.sort_unstable();
        let p50 = pct(&base, 0.5);
        println!(
            "\n### latency around each event (short calls started from 1 s before to 20 s after)\n"
        );
        println!(
            "baseline (short calls outside every window): p50 {p50} ms, p99 {} ms, max {} ms\n",
            pct(&base, 0.99),
            base.last().copied().unwrap_or(0)
        );
        println!("| event | short calls | unexpected | max ms | added vs p50 ms |");
        println!("|---|---:|---:|---:|---:|");
        let mut worst = 0;
        for (e, label) in &events {
            let w: Vec<&Rec> = recs
                .iter()
                .filter(|r| SHORT.contains(&r.kind) && window(r.t, *e))
                .collect();
            let max = w.iter().map(|r| r.ms).max().unwrap_or(0);
            let added = max.saturating_sub(p50);
            worst = worst.max(added);
            println!(
                "| {label} | {} | {} | {max} | {added} |",
                w.len(),
                w.iter().filter(|r| !r.ok).count()
            );
        }
        println!("\nmax added latency at an event: {worst} ms");
    }
    if !bad.is_empty() {
        println!("\n### unexpected outcomes\n");
        for r in &bad {
            println!(
                "- t={} {} {} {} ({} ms): {}",
                r.t, r.agent, r.kind, r.outcome, r.ms, r.detail
            );
        }
    }
    println!(
        "\n{}",
        if bad.is_empty() {
            "PASS: zero unexpected outcomes"
        } else {
            "FAIL"
        }
    );
    bad.is_empty()
}

#[tokio::main]
async fn main() {
    let (cfg, tokens) = match parse_args() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("loadgen: {e}");
            std::process::exit(2);
        }
    };
    let tokens = match read_tokens(&tokens) {
        Ok(t) if !t.is_empty() => t,
        Ok(_) => {
            eprintln!("loadgen: no token files");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("loadgen: {e}");
            std::process::exit(2);
        }
    };
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.out)
        .expect("--out");
    eprintln!(
        "loadgen: {} agents against {} for {} s",
        tokens.len(),
        cfg.url,
        cfg.secs
    );
    let run = Arc::new(Run {
        cfg,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(600))
            .build()
            .unwrap(),
        seq: AtomicU64::new(1),
        out: Mutex::new(out),
        records: Mutex::new(Vec::new()),
        start: Instant::now(),
    });
    let pid = std::process::id();
    let mut lanes = tokio::task::JoinSet::new();
    for (i, (name, token)) in tokens.into_iter().enumerate() {
        let agent = Agent {
            session: format!("loadgen-{name}-{pid}"),
            name,
            token,
            modern: i % 2 == 0,
            mcp_session: Default::default(),
        };
        if !agent.modern
            && let Err(e) = run.initialize(&agent).await
        {
            eprintln!("loadgen: initialize {}: {e}", agent.name);
        }
        lanes.spawn(run.clone().long_lane(agent.clone()));
        lanes.spawn(run.clone().short_lane(agent));
    }
    while lanes.join_next().await.is_some() {}
    let pass = summary(&run);
    std::process::exit(if pass { 0 } else { 1 });
}
