//! Audit log (E4): one JSON record per tool call, appended to
//! `audit.jsonl` and emitted as a `tracing` event with the same fields at
//! target [`TARGET`], so journald gets them as structured fields.
//!
//! Separate from the gain usage log (`mcp_gain::Tracker`), which counts
//! tokens and knows nothing of who called or why a call was refused.
//!
//! # What is recorded
//!
//! Every tool call gets exactly one `"type": "tool"` record, written by
//! `Prompto::finish_tool` — refusals included (`unknown_host`,
//! `refused_capability`, `refused_self_target`, `refused_policy`,
//! `approval_required`), and calls whose arguments failed to parse or
//! that named no known tool (written by `Prompto::call_tool`, which
//! notices that no handler recorded anything). `GET /log` is recorded as
//! `service_logs`. See [`Record`] for the fields.
//!
//! An HTTP request refused with 401 has no tool call (the MCP body is
//! never read), but it is a security event — a revoked token still in
//! use, a guessed token, a client hijacking another agent's legacy
//! session — so it gets a `"type": "auth"` record with the reason. Those
//! come from unauthenticated peers, who must not be able to grow the
//! audit file without bound, so they are rate-limited ([`AUTH_BURST`]
//! records, refilled at one per second); the next record written after a
//! suppression says how many were dropped (`suppressed`). The journal
//! keeps its own warning line for each.
//!
//! # Arguments
//!
//! [`redact`]: shell commands are kept whole (owner decision: the audit
//! records the full command), file contents and interpreter code bodies
//! become `{sha256, len}`, and any field named like a password, token,
//! secret or key becomes `"[redacted]"`. The vault sudo password is never
//! an argument: it is fetched inside the SSH layer, after the record's
//! arguments were taken from the request.
//!
//! # Failure policy
//!
//! With `PROMPTO_AUTH` `optional` or `required` the log is *strict*: a
//! call is refused before it runs unless the log is open and the last
//! write succeeded ([`Audit::preflight`]), so no action goes unaudited;
//! the refusal is `internal` and the server logs an error. A write that
//! fails after the call ran (the disk filled mid-call) cannot undo it:
//! the journal still has the record (the `tracing` event is emitted
//! first), and every later call is refused until a write succeeds again —
//! the refusal's own record is the probe. With auth `off` the record is
//! still written (agent `-`), but a failure only warns: production must
//! not stop because its audit disk did.
//!
//! # Rotation
//!
//! The file is opened `O_APPEND` and each record is one `write(2)` of a
//! whole line, so concurrent writers (threads, or several processes on
//! one file) never interleave. Before each write the path is `stat`ed and
//! compared with the open file (device + inode); a renamed or deleted
//! file is reopened. So logrotate's default rename + `create` works with
//! no signal and no `postrotate`. `copytruncate` must not be used: lines
//! written between its copy and its truncate are lost, which an audit log
//! cannot afford. See `deploy/logrotate.d/prompto-audit`.

use crate::ctx::CallCtx;
use crate::error_class::{self, ClassifiedError, ErrorClass};
use crate::ssh::ExecOutput;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

/// `PROMPTO_AUDIT_LOG` default.
pub const DEFAULT_PATH: &str = "/var/lib/prompto/audit.jsonl";
/// `tracing` target of the audit event.
pub const TARGET: &str = "prompto::audit";
/// Mode of a file prompto creates.
pub const FILE_MODE: u32 = 0o640;
/// What a secret-named argument becomes.
pub const REDACTED: &str = "[redacted]";
/// Auth records allowed in a burst; refilled at one per second.
pub const AUTH_BURST: f64 = 60.0;

// ---------------------------------------------------------------------------
// Per-call state
// ---------------------------------------------------------------------------

/// What authorization learned about a call, kept on its `CallCtx` for the
/// record.
#[derive(Clone, Debug, Default)]
pub struct Notes {
    /// Some `authorize` call let it through.
    pub authorized: bool,
    /// The policy rule that allowed it (the first, for `rsync_sync`).
    pub rule: Option<String>,
    /// The deciding rule's `approval`, when policy decided.
    pub approval: Option<&'static str>,
    /// Refused because the audit log could not be written (strict mode).
    pub audit_refused: bool,
}

/// The raw call as the client sent it. Installed by `Prompto::call_tool`
/// around the tool handler and copied into its `CallCtx`.
#[derive(Clone, Debug)]
pub struct CallScope {
    pub tool: String,
    pub args: Arc<Value>,
    recorded: Arc<AtomicBool>,
}

impl CallScope {
    pub fn new(tool: &str, args: Option<Map<String, Value>>) -> Self {
        Self {
            tool: tool.to_string(),
            args: Arc::new(args.map(Value::Object).unwrap_or(Value::Null)),
            recorded: Default::default(),
        }
    }

    /// The handler has written this call's record.
    pub fn mark_recorded(&self) {
        self.recorded.store(true, Ordering::SeqCst);
    }

    pub fn recorded(&self) -> bool {
        self.recorded.load(Ordering::SeqCst)
    }
}

tokio::task_local! {
    static CALL: CallScope;
}

/// Run `f` with `call` as the current tool call.
pub async fn scoped<F: std::future::Future>(call: CallScope, f: F) -> F::Output {
    CALL.scope(call, f).await
}

/// The current tool call, if inside [`scoped`].
pub fn current_call() -> Option<CallScope> {
    CALL.try_with(Clone::clone).ok()
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Substrings that mark a field as secret, matched case-insensitively
/// against its name at any depth.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "key",
    "credential",
];

/// Tools whose `script` is shell, kept whole like `cmd` and `commands`.
const SHELL_SCRIPT_TOOLS: &[&str] = &["bash_exec"];

/// `args` as they go into the record:
///
/// - a field whose name contains a [`SECRET_WORDS`] entry → `"[redacted]"`;
/// - `content` (`file_write`), `script` of the code interpreters
///   (`python_exec`, `node_exec`, …) and `ticket` (E6) → `{sha256, len}`;
/// - everything else as sent: `cmd`, `commands`, `bash_exec`'s `script`
///   and `claude_exec`'s `task` are the command, and are kept whole.
pub fn redact(tool: &str, args: &Value) -> Value {
    redact_value(tool, args)
}

fn redact_value(tool: &str, v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), redact_field(tool, k, v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|v| redact_value(tool, v)).collect()),
        other => other.clone(),
    }
}

fn redact_field(tool: &str, key: &str, v: &Value) -> Value {
    let k = key.to_ascii_lowercase();
    if SECRET_WORDS.iter().any(|w| k.contains(w)) {
        return REDACTED.into();
    }
    let hashed = match k.as_str() {
        "content" | "ticket" => true,
        "script" => !SHELL_SCRIPT_TOOLS.contains(&tool),
        _ => false,
    };
    if hashed {
        digest(v)
    } else {
        redact_value(tool, v)
    }
}

/// `{sha256, len}` of a value: of a string's bytes, of anything else's
/// JSON text.
pub fn digest(v: &Value) -> Value {
    let text;
    let bytes = match v {
        Value::String(s) => s.as_bytes(),
        other => {
            text = other.to_string();
            text.as_bytes()
        }
    };
    json!({ "sha256": crate::agent::hex(&crate::agent::sha256(bytes)), "len": bytes.len() })
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One audit record. Field order is the JSON key order. Fields that only
/// some records have (`dest_*` for `rsync_sync`, `reason`/`path` for auth
/// records, `suppressed`) are left out when empty; the rest are always
/// present, `null` when unknown.
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    /// RFC 3339, UTC, milliseconds.
    pub ts: String,
    /// `tool` or `auth`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Same ULID the caller got back.
    pub request_id: String,
    /// The agent, `anonymous`, `local`, or `-` with auth off.
    pub agent: String,
    /// The agent's groups as of authentication.
    pub agent_groups: Vec<String>,
    pub session_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub tool: Option<String>,
    /// Inventory name the call resolved to, aliases resolved; `null` for
    /// hostless tools and unknown hosts.
    pub host: Option<String>,
    /// What the caller typed, when it is not `host` (an alias, or an
    /// unknown name).
    pub queried_as: Option<String>,
    /// `rsync_sync`'s second host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_queried_as: Option<String>,
    /// The arguments, through [`redact`].
    pub args: Value,
    /// `allow` (authorization passed), `deny` (refused before anything
    /// ran), or `null` (failed before authorization: bad arguments).
    pub decision: Option<&'static str>,
    /// The policy rule that decided, when policy did.
    pub rule: Option<String>,
    /// The deciding rule's `approval` (`none` | `ticket` | `human`).
    pub approval: Option<&'static str>,
    /// Who approved (E6). Always `null` for now.
    pub approved_by: Option<String>,
    pub exit_code: Option<i32>,
    /// The call did what was asked: no error, and a remote command that
    /// ran exited 0 and did not time out. Stricter than the gain log's
    /// `ok`, which only means the tool returned a result.
    pub ok: bool,
    /// Why not, when `ok` is false.
    pub error_class: Option<ErrorClass>,
    pub duration_ms: u64,
    /// Size of the response the caller got.
    pub bytes: u64,
    /// Auth records: why the request was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Auth records: the HTTP path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Auth records dropped by the rate limit since the last one written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<u64>,
}

/// Current time as the record's `ts`.
pub fn now_ts() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// How a tool call ended, as `finish_tool` sees it.
pub enum Outcome<'a> {
    /// The tool returned this payload.
    Success(&'a Value),
    Failure(&'a anyhow::Error),
}

/// Where a call went: `(canonical, queried_as)` from what the caller
/// typed and the live inventory.
pub fn resolve_host(
    inv: &crate::inventory::Inventory,
    typed: Option<&str>,
) -> (Option<String>, Option<String>) {
    let Some(typed) = typed else {
        return (None, None);
    };
    match inv.canonical(typed) {
        Some(c) if c == typed => (Some(c.to_string()), None),
        Some(c) => (Some(c.to_string()), Some(typed.to_string())),
        None => (None, Some(typed.to_string())),
    }
}

/// The parts of a record that depend on the outcome.
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub error_class: Option<ErrorClass>,
    pub decision: Option<&'static str>,
    pub rule: Option<String>,
}

/// Judge an outcome. `sudo` says whether the call ran through prompto's
/// sudo path (for `sudo_guard`). An error with no class is a bug: it is
/// judged `internal`, logged and counted
/// (`error_class::unclassified_count`).
pub fn judge(tool: &str, outcome: &Outcome, notes: &Notes, sudo: bool) -> Verdict {
    let allowed = || notes.authorized.then_some("allow");
    match outcome {
        Outcome::Success(p) => {
            let (exit_code, error_class) = success_status(p, sudo);
            Verdict {
                ok: error_class.is_none(),
                exit_code,
                error_class,
                decision: allowed(),
                rule: notes.rule.clone(),
            }
        }
        Outcome::Failure(e) => {
            let Some(c) = e.downcast_ref::<ClassifiedError>() else {
                error_class::note_unclassified();
                tracing::error!(
                    tool,
                    error = %format!("{e:#}"),
                    "BUG: tool error without an error_class — recorded as internal"
                );
                return Verdict {
                    ok: false,
                    exit_code: None,
                    error_class: Some(ErrorClass::Internal),
                    decision: if notes.audit_refused {
                        Some("deny")
                    } else {
                        allowed()
                    },
                    rule: notes.rule.clone(),
                };
            };
            let deny = c.class.is_refusal() || notes.audit_refused;
            Verdict {
                ok: false,
                exit_code: c.exit_code,
                error_class: Some(c.class),
                decision: if deny { Some("deny") } else { allowed() },
                rule: if deny {
                    c.rule.clone()
                } else {
                    notes.rule.clone()
                },
            }
        }
    }
}

/// Exit code and failure class of a successful tool result. Tools that
/// run a command return its `exit_code` (and `timed_out`, `stderr`) in
/// the payload rather than failing; `ssh_batch` returns `all_ok` and
/// per-command `items`.
fn success_status(p: &Value, sudo: bool) -> (Option<i32>, Option<ErrorClass>) {
    let exit = |v: &Value| v.get("exit_code").and_then(Value::as_i64).map(|c| c as i32);
    if p.get("all_ok") == Some(&Value::Bool(false)) {
        let first_bad = p
            .get("items")
            .and_then(Value::as_array)
            .and_then(|items| items.iter().filter_map(exit).find(|c| *c != 0));
        return (first_bad, Some(ErrorClass::RemoteNonzero));
    }
    let timed_out = p.get("timed_out") == Some(&Value::Bool(true));
    let exit_code = exit(p);
    if timed_out {
        return (exit_code, Some(ErrorClass::Timeout));
    }
    let class = match exit_code {
        None | Some(0) => None,
        Some(_) => error_class::classify_exec(
            &ExecOutput {
                stdout: String::new(),
                stderr: p
                    .get("stderr")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                exit_code,
                timed_out: false,
            },
            sudo,
        ),
    };
    (exit_code, class)
}

/// A tool record for `ctx`, without the outcome fields.
pub fn tool_record(ctx: &CallCtx, tool: &str, args: Value) -> Record {
    let (agent, agent_groups) = match &ctx.agent {
        Some(a) => (a.name.clone(), a.groups.clone()),
        None => ("-".to_string(), vec![]),
    };
    Record {
        ts: now_ts(),
        kind: "tool",
        request_id: ctx.request_id(),
        agent,
        agent_groups,
        session_id: ctx.session_id.clone(),
        client_ip: ctx.caller_ip.map(|ip| ip.to_canonical().to_string()),
        user_agent: ctx.user_agent.clone(),
        tool: Some(tool.to_string()),
        host: None,
        queried_as: None,
        dest_host: None,
        dest_queried_as: None,
        args: redact(tool, &args),
        decision: None,
        rule: None,
        approval: ctx.notes().approval,
        approved_by: None,
        exit_code: None,
        ok: false,
        error_class: None,
        duration_ms: ctx.started.elapsed().as_millis() as u64,
        bytes: 0,
        reason: None,
        path: None,
        suppressed: None,
    }
}

impl Record {
    /// Fill in the outcome fields.
    pub fn with_verdict(mut self, v: Verdict) -> Self {
        self.ok = v.ok;
        self.exit_code = v.exit_code;
        self.error_class = v.error_class;
        self.decision = v.decision;
        self.rule = v.rule;
        self
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

struct State {
    file: Option<File>,
    /// (device, inode) of `file`, to notice a rename.
    id: Option<(u64, u64)>,
    /// The last write succeeded (or none has been tried).
    healthy: bool,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    suppressed: u64,
}

/// The audit file. Shared by every call through [`Audit`].
pub struct AuditLog {
    path: PathBuf,
    gid: Option<u32>,
    strict: bool,
    state: Mutex<State>,
    auth_bucket: Mutex<Bucket>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AuditLog {
    /// The log at `path`, opened (and created if missing) now. `gid`:
    /// group to give a file prompto creates (`PROMPTO_AUDIT_GROUP`).
    /// `strict`: refuse calls the log can't record (auth on).
    pub fn open(path: PathBuf, gid: Option<u32>, strict: bool) -> io::Result<Self> {
        let log = Self::unopened(path, gid, strict);
        {
            let mut st = lock(&log.state);
            log.ensure_open(&mut st)?;
        }
        Ok(log)
    }

    /// The log at `path`, opened on first use.
    pub fn unopened(path: PathBuf, gid: Option<u32>, strict: bool) -> Self {
        Self {
            path,
            gid,
            strict,
            state: Mutex::new(State {
                file: None,
                id: None,
                healthy: true,
            }),
            auth_bucket: Mutex::new(Bucket {
                tokens: AUTH_BURST,
                last: Instant::now(),
                suppressed: 0,
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Have the file at `path` open, reopening after a rename or delete.
    fn ensure_open(&self, st: &mut State) -> io::Result<()> {
        match std::fs::metadata(&self.path) {
            Ok(m) if st.file.is_some() && st.id == Some((m.dev(), m.ino())) => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        st.file = None;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&self.path)?;
        let m = file.metadata()?;
        // A file we just created: make the mode exact whatever the umask
        // was, and hand it to the audit group.
        if m.len() == 0 {
            if m.permissions().mode() & 0o777 != FILE_MODE {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE));
            }
            if let Some(gid) = self.gid
                && m.gid() != gid
                && let Err(e) = std::os::unix::fs::fchown(&file, None, Some(gid))
            {
                tracing::warn!(
                    path = %self.path.display(),
                    gid,
                    error = %e,
                    "cannot give the audit log to PROMPTO_AUDIT_GROUP (prompto must be a \
                     member of that group); leaving its group as is"
                );
            }
        } else if m.permissions().mode() & 0o007 != 0 {
            tracing::warn!(
                path = %self.path.display(),
                mode = format!("{:o}", m.permissions().mode() & 0o777),
                "the audit log is world-accessible; it should be 0640"
            );
        }
        st.id = Some((m.dev(), m.ino()));
        st.file = Some(file);
        Ok(())
    }

    /// Append one line (which must end in `\n`) with a single write.
    fn append(&self, line: &[u8]) -> io::Result<()> {
        let mut st = lock(&self.state);
        let res = self.ensure_open(&mut st).and_then(|()| {
            let f = st.file.as_mut().expect("opened above");
            match f.write(line)? {
                n if n == line.len() => Ok(()),
                n => Err(io::Error::other(format!(
                    "short write ({n} of {} bytes)",
                    line.len()
                ))),
            }
        });
        let was_healthy = st.healthy;
        st.healthy = res.is_ok();
        if res.is_err() {
            // Reopen on the next attempt rather than keep a bad handle.
            st.file = None;
        } else if !was_healthy {
            tracing::warn!(path = %self.path.display(), "audit log writable again");
        }
        drop(st);
        if let Err(e) = &res {
            if self.strict {
                tracing::error!(
                    path = %self.path.display(),
                    error = %e,
                    "AUDIT WRITE FAILED — tool calls are refused until the audit log can be \
                     written (the record above is in the journal)"
                );
            } else if was_healthy {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "audit write failed — with PROMPTO_AUTH=off calls continue; records go \
                     to the journal only until the file can be written again"
                );
            }
        }
        res
    }

    /// Strict mode: the log is open and the last write succeeded.
    fn preflight(&self) -> Result<(), String> {
        if !self.strict {
            return Ok(());
        }
        let mut st = lock(&self.state);
        if let Err(e) = self.ensure_open(&mut st) {
            st.healthy = false;
            return Err(format!("cannot open {}: {e}", self.path.display()));
        }
        if !st.healthy {
            return Err(format!("the last write to {} failed", self.path.display()));
        }
        Ok(())
    }

    /// Take a token for an auth record: `Some(suppressed since the last
    /// one)`, or `None` when over the limit.
    fn auth_token(&self) -> Option<u64> {
        let mut b = lock(&self.auth_bucket);
        let now = Instant::now();
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64()).min(AUTH_BURST);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Some(std::mem::take(&mut b.suppressed))
        } else {
            b.suppressed += 1;
            None
        }
    }
}

/// Handle on the audit log, cloned into every `Prompto` and the `/log`
/// endpoint. [`Audit::null`] (the default) has no file: records reach
/// only the journal. It is for tests and embedders; the server always
/// opens a file.
#[derive(Clone, Default)]
pub struct Audit(Option<Arc<AuditLog>>);

/// Why a call was refused by [`Audit::preflight`], as the agent sees it.
/// The path and the OS error go to the journal only.
pub const PREFLIGHT_REFUSAL: &str = "refused: prompto cannot write its audit log, and it never \
    runs an unaudited action. Nothing was run. The operator has been alerted (journal).";

impl Audit {
    pub fn new(log: AuditLog) -> Self {
        Self(Some(Arc::new(log)))
    }

    pub fn null() -> Self {
        Self(None)
    }

    pub fn log(&self) -> Option<&AuditLog> {
        self.0.as_deref()
    }

    /// Strict mode: may a call run? `Err` is the refusal, classed
    /// `internal`; the reason is logged.
    pub fn preflight(&self, ctx: &CallCtx, tool: &str) -> Result<(), ClassifiedError> {
        let Some(log) = &self.0 else { return Ok(()) };
        log.preflight().map_err(|why| {
            tracing::error!(
                request_id = %ctx.request_id,
                agent = ctx.agent_name(),
                tool,
                reason = %why,
                "AUDIT LOG UNAVAILABLE — refusing the call before it runs"
            );
            ctx.note(|n| n.audit_refused = true);
            ClassifiedError::refused(ErrorClass::Internal, PREFLIGHT_REFUSAL)
        })
    }

    /// Emit `rec`: the `tracing` event first (so the journal has it even
    /// if the file write fails), then the file. Errors are logged here
    /// per the failure policy; the result says whether the file got it.
    pub fn write(&self, rec: &Record) -> bool {
        emit_event(rec);
        let Some(log) = &self.0 else { return true };
        let mut line = match serde_json::to_vec(rec) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "BUG: audit record failed to serialize");
                return false;
            }
        };
        line.push(b'\n');
        log.append(&line).is_ok()
    }

    /// Record a 401, subject to the rate limit (see the module docs).
    pub fn write_auth(
        &self,
        caller: Option<std::net::IpAddr>,
        user_agent: Option<String>,
        session_id: Option<String>,
        path: &str,
        reason: &str,
    ) {
        let suppressed = match &self.0 {
            Some(log) => match log.auth_token() {
                Some(n) => n,
                None => return,
            },
            None => 0,
        };
        let rec = Record {
            ts: now_ts(),
            kind: "auth",
            request_id: ulid::Ulid::generate().to_string(),
            agent: "-".into(),
            agent_groups: vec![],
            session_id,
            client_ip: caller.map(|ip| ip.to_canonical().to_string()),
            user_agent,
            tool: None,
            host: None,
            queried_as: None,
            dest_host: None,
            dest_queried_as: None,
            args: Value::Null,
            decision: Some("deny"),
            rule: None,
            approval: None,
            approved_by: None,
            exit_code: None,
            ok: false,
            error_class: None,
            duration_ms: 0,
            bytes: 0,
            reason: Some(reason.to_string()),
            path: Some(path.to_string()),
            suppressed: (suppressed > 0).then_some(suppressed),
        };
        self.write(&rec);
    }
}

/// The record as a `tracing` event at [`TARGET`]. Field names are the
/// record's keys, except `type`, which is `record_type` (a keyword).
fn emit_event(r: &Record) {
    let groups = r.agent_groups.join(",");
    let args = r.args.to_string();
    tracing::info!(
        target: TARGET,
        record_type = r.kind,
        request_id = %r.request_id,
        agent = %r.agent,
        agent_groups = %groups,
        session_id = r.session_id.as_deref(),
        client_ip = r.client_ip.as_deref(),
        user_agent = r.user_agent.as_deref(),
        tool = r.tool.as_deref(),
        host = r.host.as_deref(),
        queried_as = r.queried_as.as_deref(),
        dest_host = r.dest_host.as_deref(),
        dest_queried_as = r.dest_queried_as.as_deref(),
        args = %args,
        decision = r.decision,
        rule = r.rule.as_deref(),
        approval = r.approval,
        approved_by = r.approved_by.as_deref(),
        exit_code = r.exit_code,
        ok = r.ok,
        error_class = r.error_class.map(ErrorClass::as_str),
        duration_ms = r.duration_ms,
        bytes = r.bytes,
        reason = r.reason.as_deref(),
        path = r.path.as_deref(),
        suppressed = r.suppressed,
        "audit"
    );
}

/// `PROMPTO_AUDIT_GROUP`: a group name (looked up in `/etc/group`) or a
/// numeric gid.
pub fn resolve_group(spec: &str) -> io::Result<u32> {
    if let Ok(gid) = spec.parse() {
        return Ok(gid);
    }
    let groups = std::fs::read_to_string("/etc/group")?;
    groups
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            Some((f.next()?, f.nth(1)?))
        })
        .find(|(name, _)| *name == spec)
        .and_then(|(_, gid)| gid.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("group {spec:?} not found in /etc/group"),
            )
        })
}

// ---------------------------------------------------------------------------
// Reading (`prompto audit`)
// ---------------------------------------------------------------------------

/// `prompto audit` filters. Every set field must match.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub agent: Option<String>,
    /// Matches `host`, `queried_as` or rsync's `dest_*`.
    pub host: Option<String>,
    pub tool: Option<String>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub request_id: Option<String>,
    pub decision: Option<String>,
}

impl Filter {
    pub fn matches(&self, r: &Value) -> bool {
        let s = |k: &str| r.get(k).and_then(Value::as_str);
        let eq = |want: &Option<String>, k: &str| want.as_deref().is_none_or(|w| s(k) == Some(w));
        let host_ok = self.host.as_deref().is_none_or(|h| {
            ["host", "queried_as", "dest_host", "dest_queried_as"]
                .iter()
                .any(|k| s(k) == Some(h))
        });
        let since_ok = self.since.is_none_or(|since| {
            s("ts")
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .is_some_and(|t| t >= since)
        });
        eq(&self.agent, "agent")
            && eq(&self.tool, "tool")
            && eq(&self.request_id, "request_id")
            && eq(&self.decision, "decision")
            && host_ok
            && since_ok
    }
}

/// `--since`: a duration back from `now` (`30s`, `10m`, `2h`, `7d`, `1w`)
/// or a time (RFC 3339, `YYYY-MM-DDTHH:MM[:SS]` or `YYYY-MM-DD`, UTC
/// unless an offset is given).
pub fn parse_since(
    s: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
    let s = s.trim();
    if let Some(unit) = s.chars().last().filter(char::is_ascii_alphabetic)
        && let Ok(n) = s[..s.len() - 1].parse::<i64>()
    {
        let secs = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => anyhow::bail!("--since {s:?}: unit must be s, m, h, d or w"),
        };
        return Ok(now - chrono::Duration::seconds(n * secs));
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(t.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(Utc.from_utc_datetime(&t));
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).expect("midnight")));
    }
    anyhow::bail!("--since {s:?}: use a duration (10m, 2h, 7d) or a time (2026-10-09T12:00:00Z)")
}

/// The audit files to read, oldest first: rotated siblings
/// (`audit.jsonl.N` and `audit.jsonl.N.gz`, highest N first) whose last
/// write is not before `since`, then the live file.
pub fn files_to_read(path: &Path, since: Option<chrono::DateTime<chrono::Utc>>) -> Vec<PathBuf> {
    let mut rotated: Vec<(u32, PathBuf)> = vec![];
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return vec![path.to_path_buf()];
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let fname = e.file_name();
            let Some(f) = fname.to_str() else { continue };
            let Some(rest) = f.strip_prefix(name).and_then(|r| r.strip_prefix('.')) else {
                continue;
            };
            let Ok(n) = rest.strip_suffix(".gz").unwrap_or(rest).parse::<u32>() else {
                continue;
            };
            let recent = since.is_none_or(|since| {
                e.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| chrono::DateTime::<chrono::Utc>::from(t) >= since)
            });
            if recent {
                rotated.push((n, e.path()));
            }
        }
    }
    rotated.sort_by_key(|r| std::cmp::Reverse(r.0));
    let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    out.push(path.to_path_buf());
    out
}

/// The text of one audit file; `.gz` through `gzip -dc`. A missing file
/// is empty.
pub fn read_file(path: &Path) -> anyhow::Result<String> {
    use anyhow::Context;
    if path.extension().is_some_and(|e| e == "gz") {
        let out = std::process::Command::new("gzip")
            .arg("-dc")
            .arg(path)
            .output()
            .with_context(|| format!("gzip -dc {}", path.display()))?;
        if !out.status.success() {
            anyhow::bail!(
                "gzip -dc {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// One table row per record, columns: time, agent, tool, host, decision,
/// result, duration, detail (the command, or the arguments; the rule on a
/// refusal; the reason on an auth record).
pub fn table_row(r: &Value) -> [String; 8] {
    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("");
    let ts = s("ts");
    // 2026-10-09T12:34:56.789Z → 2026-10-09 12:34:56
    let time = ts.get(..19).unwrap_or(ts).replacen('T', " ", 1);
    let host = match (s("host"), s("queried_as")) {
        ("", "") => "-".to_string(),
        ("", q) => format!("{q}?"),
        (h, _) => h.to_string(),
    };
    let host = match r.get("dest_host").and_then(Value::as_str) {
        Some(d) => format!("{host}→{d}"),
        None => host,
    };
    let result = if r.get("ok") == Some(&Value::Bool(true)) {
        "ok".to_string()
    } else {
        let class = s("error_class");
        match r.get("exit_code").and_then(Value::as_i64) {
            Some(c) => format!(
                "{} exit={c}",
                if class.is_empty() { "failed" } else { class }
            ),
            None if class.is_empty() => "failed".into(),
            None => class.to_string(),
        }
    };
    let detail = if s("type") == "auth" {
        format!("{} {}", s("path"), s("reason"))
    } else {
        let args = r.get("args").cloned().unwrap_or(Value::Null);
        let cmd = ["cmd", "commands", "script", "task"]
            .iter()
            .find_map(|k| args.get(k))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        let mut d = cmd.unwrap_or_else(|| match &args {
            Value::Object(m) if m.is_empty() => String::new(),
            Value::Null => String::new(),
            other => other.to_string(),
        });
        if s("decision") == "deny" && !s("rule").is_empty() {
            d = format!("rule={} {d}", s("rule"));
        }
        d
    };
    [
        time,
        s("agent").to_string(),
        if s("type") == "auth" {
            "(auth)".into()
        } else {
            s("tool").to_string()
        },
        host,
        r.get("decision")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        result,
        format!(
            "{}ms",
            r.get("duration_ms").and_then(Value::as_u64).unwrap_or(0)
        ),
        one_line(&detail, 80),
    ]
}

/// `s` on one line, cut to `max` chars with `…`.
fn one_line(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= max {
        flat
    } else {
        let mut t: String = flat.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_stay_whole() {
        let a = json!({ "host": "h", "cmd": "rm -rf /tmp/x && echo done" });
        assert_eq!(redact("ssh_exec", &a), a);
        let b = json!({ "host": "h", "commands": ["a", "b c"], "fail_fast": true });
        assert_eq!(redact("ssh_batch", &b), b);
        let c = json!({ "host": "h", "script": "echo hi\nuname -a" });
        assert_eq!(redact("bash_exec", &c), c);
        let t = json!({ "host": "h", "task": "why is nginx down" });
        assert_eq!(redact("claude_exec", &t), t);
    }

    #[test]
    fn file_contents_and_code_bodies_become_digests() {
        let body = "line one\nPASSWORD=hunter2\n";
        let r = redact(
            "file_write",
            &json!({ "host": "h", "path": "/etc/x", "content": body, "mode": "0600" }),
        );
        assert_eq!(r["path"], "/etc/x");
        assert_eq!(r["mode"], "0600");
        assert_eq!(r["content"]["len"], body.len());
        assert_eq!(
            r["content"]["sha256"],
            crate::agent::hex(&crate::agent::sha256(body.as_bytes()))
        );
        assert!(!r.to_string().contains("hunter2"));
        for tool in [
            "python_exec",
            "node_exec",
            "ruby_exec",
            "perl_exec",
            "deno_exec",
        ] {
            let r = redact(
                tool,
                &json!({ "host": "h", "script": "print(1)", "args": ["-v"] }),
            );
            assert_eq!(r["script"]["len"], 8, "{tool}");
            assert_eq!(r["args"], json!(["-v"]), "{tool}");
        }
    }

    #[test]
    fn secret_named_fields_are_redacted_at_any_depth() {
        let r = redact(
            "mcp_add",
            &json!({
                "client": "c",
                "Password": "p1",
                "api_token": "t1",
                "nested": { "client_secret": "s1", "list": [{ "ssh_key": "k1" }] },
                "dest_key": "/home/u/.ssh/id",
                "ticket": "tk",
            }),
        );
        let text = r.to_string();
        for leaked in ["p1", "t1", "s1", "k1", "/home/u/.ssh/id", "\"tk\""] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert_eq!(r["Password"], REDACTED);
        assert_eq!(r["nested"]["list"][0]["ssh_key"], REDACTED);
        assert_eq!(r["ticket"]["len"], 2);
        assert_eq!(r["client"], "c");
    }

    fn notes(authorized: bool) -> Notes {
        Notes {
            authorized,
            rule: authorized.then(|| "policy.toml:3".into()),
            ..Default::default()
        }
    }

    #[test]
    fn success_with_a_failed_command_is_not_ok() {
        let n = notes(true);
        let ok = judge(
            "ssh_exec",
            &Outcome::Success(&json!({"exit_code": 0})),
            &n,
            false,
        );
        assert!(ok.ok);
        assert_eq!(ok.decision, Some("allow"));
        assert_eq!(ok.rule.as_deref(), Some("policy.toml:3"));
        let v = judge(
            "ssh_exec",
            &Outcome::Success(&json!({"exit_code": 2, "stderr": "x"})),
            &n,
            false,
        );
        assert_eq!((v.ok, v.exit_code), (false, Some(2)));
        assert_eq!(v.error_class, Some(ErrorClass::RemoteNonzero));
        let t = judge(
            "ssh_exec",
            &Outcome::Success(&json!({"exit_code": null, "timed_out": true})),
            &n,
            false,
        );
        assert_eq!(t.error_class, Some(ErrorClass::Timeout));
        let g = judge(
            "ssh_sudo_exec",
            &Outcome::Success(&json!({"exit_code": 97, "stderr": error_class::SUDO_GUARD_MESSAGE})),
            &n,
            true,
        );
        assert_eq!(g.error_class, Some(ErrorClass::SudoGuard));
        let b = judge(
            "ssh_batch",
            &Outcome::Success(
                &json!({"all_ok": false, "items": [{"exit_code": 0}, {"exit_code": 3}]}),
            ),
            &n,
            false,
        );
        assert_eq!(
            (b.exit_code, b.error_class),
            (Some(3), Some(ErrorClass::RemoteNonzero))
        );
        let plain = judge(
            "inventory_list",
            &Outcome::Success(&json!({"count": 1})),
            &n,
            false,
        );
        assert!(plain.ok);
    }

    #[test]
    fn refusals_are_denials_naming_their_rule() {
        let e: anyhow::Error = ClassifiedError::refused(ErrorClass::RefusedPolicy, "no")
            .with_rule("default-deny")
            .into();
        let v = judge("ssh_exec", &Outcome::Failure(&e), &notes(false), false);
        assert_eq!(v.decision, Some("deny"));
        assert_eq!(v.rule.as_deref(), Some("default-deny"));
        assert_eq!(v.error_class, Some(ErrorClass::RefusedPolicy));
        // Bad arguments before authorization: no decision.
        let e: anyhow::Error = ClassifiedError::refused(ErrorClass::InvalidArgs, "bad").into();
        let v = judge("ssh_batch", &Outcome::Failure(&e), &notes(false), false);
        assert_eq!(v.decision, None);
        // A failure after authorization: allowed, failed.
        let e: anyhow::Error = ClassifiedError::refused(ErrorClass::Vault, "down").into();
        let v = judge("ssh_sudo_exec", &Outcome::Failure(&e), &notes(true), true);
        assert_eq!((v.decision, v.ok), (Some("allow"), false));
    }

    #[test]
    fn unclassified_errors_are_counted_as_bugs() {
        let before = error_class::unclassified_count();
        let e = anyhow::anyhow!("plain");
        let v = judge("x", &Outcome::Failure(&e), &notes(true), false);
        assert_eq!(v.error_class, Some(ErrorClass::Internal));
        assert!(error_class::unclassified_count() > before);
    }

    #[test]
    fn since_parses_durations_and_times() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 10, 9, 12, 0, 0).unwrap();
        let at = |s| parse_since(s, now).unwrap().to_rfc3339();
        assert_eq!(at("10m"), "2026-10-09T11:50:00+00:00");
        assert_eq!(at("2h"), "2026-10-09T10:00:00+00:00");
        assert_eq!(at("1d"), "2026-10-08T12:00:00+00:00");
        assert_eq!(at("2026-10-09T08:00:00Z"), "2026-10-09T08:00:00+00:00");
        assert_eq!(at("2026-10-09T10:00:00+02:00"), "2026-10-09T08:00:00+00:00");
        assert_eq!(at("2026-10-09T08:30"), "2026-10-09T08:30:00+00:00");
        assert_eq!(at("2026-10-01"), "2026-10-01T00:00:00+00:00");
        assert!(parse_since("10y", now).is_err());
        assert!(parse_since("yesterday", now).is_err());
    }

    #[test]
    fn filter_matches_every_set_field() {
        let r = json!({
            "ts": "2026-10-09T12:00:00.000Z", "type": "tool", "request_id": "R1",
            "agent": "dev", "tool": "rsync_sync", "host": "alpha", "queried_as": "a",
            "dest_host": "bravo", "decision": "deny",
        });
        let f = |f: Filter| f.matches(&r);
        assert!(f(Filter::default()));
        assert!(f(Filter {
            host: Some("a".into()),
            ..Default::default()
        }));
        assert!(f(Filter {
            host: Some("bravo".into()),
            ..Default::default()
        }));
        assert!(!f(Filter {
            host: Some("charlie".into()),
            ..Default::default()
        }));
        assert!(f(Filter {
            agent: Some("dev".into()),
            tool: Some("rsync_sync".into()),
            decision: Some("deny".into()),
            request_id: Some("R1".into()),
            ..Default::default()
        }));
        assert!(!f(Filter {
            agent: Some("ops".into()),
            ..Default::default()
        }));
        assert!(!f(Filter {
            decision: Some("allow".into()),
            ..Default::default()
        }));
        let at = |s: &str| chrono::DateTime::parse_from_rfc3339(s).unwrap().into();
        assert!(f(Filter {
            since: Some(at("2026-10-09T11:59:00Z")),
            ..Default::default()
        }));
        assert!(!f(Filter {
            since: Some(at("2026-10-09T12:00:01Z")),
            ..Default::default()
        }));
    }

    #[test]
    fn rotated_siblings_are_read_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        for f in [
            "audit.jsonl",
            "audit.jsonl.1",
            "audit.jsonl.2.gz",
            "audit.jsonl.bak",
            "other.1",
        ] {
            std::fs::write(dir.path().join(f), "").unwrap();
        }
        let names: Vec<String> = files_to_read(&p, None)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["audit.jsonl.2.gz", "audit.jsonl.1", "audit.jsonl"]);
        // Files last written before --since hold nothing newer.
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        assert_eq!(files_to_read(&p, Some(future)), vec![p.clone()]);
    }

    #[test]
    fn creates_the_file_0640_and_reopens_after_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(p.clone(), None, true).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );
        log.append(b"one\n").unwrap();
        std::fs::rename(&p, dir.path().join("audit.jsonl.1")).unwrap();
        log.append(b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("audit.jsonl.1")).unwrap(),
            "one\n"
        );
        // Deleted outright: recreated.
        std::fs::remove_file(&p).unwrap();
        log.append(b"three\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "three\n");
    }

    #[test]
    fn auth_records_are_rate_limited_and_count_what_they_drop() {
        let log = AuditLog::unopened("/nonexistent/x".into(), None, false);
        for _ in 0..AUTH_BURST as usize {
            assert_eq!(log.auth_token(), Some(0));
        }
        assert_eq!(log.auth_token(), None);
        assert_eq!(log.auth_token(), None);
        log.auth_bucket.lock().unwrap().tokens = 1.0;
        assert_eq!(log.auth_token(), Some(2));
    }

    #[test]
    fn group_resolves_numbers_and_names() {
        assert_eq!(resolve_group("1234").unwrap(), 1234);
        assert_eq!(resolve_group("root").unwrap(), 0);
        assert!(resolve_group("no-such-group-xyz").is_err());
    }
}
