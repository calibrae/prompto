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
//! audit file without bound or drown each other out, so they are
//! rate-limited per client IP under a global ceiling (see
//! [`AUTH_IP_BURST`], [`AUTH_BURST`]); the next record written after a
//! suppression says how many were dropped (`suppressed`). The journal
//! keeps its own warning line for each.
//!
//! A call cut off before it recorded anything (prompto shutting down, a
//! handler panic) is recorded as `aborted` by a drop guard in
//! `Prompto::call_tool`.
//!
//! # Arguments and strings
//!
//! [`redact`]: commands and every interpreter's script are kept whole
//! (owner decision: the audit records the full command) up to
//! [`MAX_ARG_STRING`], file contents become `{sha256, len}`, any field
//! named like a secret ([`is_secret_name`]) becomes `"[redacted]"`, and
//! every kept string goes through [`scrub`], which hides secret *values*
//! (URL userinfo, `--password x`, `TOKEN=x`, `Authorization: …`). The
//! record's other client-chosen strings are scrubbed and capped too
//! ([`Record::clamp_strings`]), in the file and the journal alike. The
//! vault sudo password is never an argument: it is fetched inside the
//! SSH layer, after the record's arguments were taken from the request.
//!
//! # Failure policy
//!
//! With `PROMPTO_AUTH` `optional` or `required` the log is *strict*: a
//! call is refused before it runs unless the log is open and the last
//! write succeeded ([`Audit::preflight`]), so no action goes unaudited;
//! the refusal is `internal`, names the cause (`the audit disk is full`)
//! and the server logs an error. A write that
//! fails after the call ran (the disk filled mid-call) cannot undo it:
//! the journal still has the record (the `tracing` event is emitted
//! first), and every later call is refused until a write succeeds again —
//! the refusal's own record is the probe. With auth `off` the record is
//! still written (agent `-`), but a failure only warns: production must
//! not stop because its audit disk did. In every mode the journal gets
//! an error while the audit filesystem is below [`FREE_SPACE_FLOOR`];
//! a write cut short leaves a fragment, which the next record steps over
//! (it starts with `\n`), as does the reader ([`parse_line`]).
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
    /// Refused by this kill switch (`crate::kill`).
    pub kill: Option<crate::kill::Kill>,
}

/// The raw call as the client sent it. Installed by `Prompto::call_tool`
/// around the tool handler and copied into its `CallCtx`.
#[derive(Clone, Debug)]
pub struct CallScope {
    pub tool: String,
    pub args: Arc<Value>,
    recorded: Arc<AtomicBool>,
    /// The handler's `CallCtx` once it made one (without its `call`, so
    /// no reference cycle): an `aborted` record then carries the request
    /// ID, notes and start time the handler had.
    handler_ctx: Arc<std::sync::OnceLock<CallCtx>>,
}

impl CallScope {
    pub fn new(tool: &str, args: Option<Map<String, Value>>) -> Self {
        Self {
            tool: tool.to_string(),
            args: Arc::new(args.map(Value::Object).unwrap_or(Value::Null)),
            recorded: Default::default(),
            handler_ctx: Default::default(),
        }
    }

    /// Remember the handler's context (the first one made in this call).
    pub fn set_ctx(&self, ctx: &CallCtx) {
        let mut c = ctx.clone();
        c.call = None;
        let _ = self.handler_ctx.set(c);
    }

    /// The handler's context, if it got that far.
    pub fn handler_ctx(&self) -> Option<CallCtx> {
        self.handler_ctx.get().cloned()
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

/// Longest string kept in a record's `args`. A longer one (a big script,
/// a long command list entry) becomes `{sha256, len, truncated: true}`.
pub const MAX_ARG_STRING: usize = 16 * 1024;
/// Largest `args` kept, as JSON text after redaction; larger arguments
/// (an unknown tool's arbitrary JSON, thousands of keys) become one
/// `{sha256, len, truncated: true}`.
pub const MAX_ARGS_JSON: usize = 64 * 1024;

/// Is `name` (a field, flag, header, query parameter or environment
/// variable name) one that holds a secret? Case-insensitive, `-` and `_`
/// alike; the name must *be* or *end with* one of `SECRET_SUFFIXES`, or
/// be one of `SECRET_EXACT`.
///
/// Exact-or-suffix rather than substring: a secret's name ends with what
/// it is (`GITHUB_TOKEN`, `client_secret`, `X-Api-Key`, `PGPASSWORD`,
/// `aws_secret_access_key`), while a substring match also hits names
/// that only *mention* one (`dest_key` — a path, `max_tokens`,
/// `token_file`, `keyboard`) and redacts what the audit needs. There is
/// no bare `key` entry for the same reason: the `*_key` names that hold
/// key material are listed one by one.
pub fn is_secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase().replace('-', "_");
    SECRET_EXACT.contains(&n.as_str()) || SECRET_SUFFIXES.iter().any(|s| n.ends_with(s))
}

const SECRET_SUFFIXES: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "credential",
    "credentials",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "secret_key",
    "signing_key",
    "auth_key",
    "authorization",
    "cookie",
    // Short forms only after a separator: `MYSQL_PWD`, `DB_PASS`, not
    // `PWD` (the working directory) or `bypass`.
    "_pwd",
    "_pass",
    "_pw",
];

const SECRET_EXACT: &[&str] = &["pass", "pw"];

/// What a scrubbed value becomes.
pub const SCRUBBED: &str = "***";

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static pattern")
}

/// Secret *values* inside strings that are otherwise kept verbatim (a
/// command, a URL, a script): the owner wants commands whole, so the
/// command stays and only the secret in it becomes [`SCRUBBED`]:
///
/// - URL userinfo: `https://user:pw@host` → `https://***@host`;
/// - query parameters named like a secret: `?token=abc` → `?token=***`;
/// - `Authorization:` (or any secret-named header / YAML key) →
///   `Authorization: ***`; `Bearer <x>` → `Bearer ***`;
/// - long flags named like a secret: `--password x`, `--api-key=x`;
/// - assignments: `export TOKEN=x`, `X_API_KEY=x`, and quoted literals in
///   code or JSON (`password = "x"`, `"token": "x"`).
///
/// What a scrubber cannot see (a password as a positional argument,
/// `-p x`, a secret under an innocent name) stays; see the design note.
pub fn scrub(s: &str) -> std::borrow::Cow<'_, str> {
    use regex::{Captures, Regex};
    use std::borrow::Cow;
    use std::sync::LazyLock;

    // URL userinfo, any scheme.
    static USERINFO: LazyLock<Regex> =
        LazyLock::new(|| re(r#"(?i)\b([a-z][a-z0-9+.\-]*://)[^/?#\s@'"]+@"#));
    // `Name: value` (HTTP header, YAML) up to the end of the line or a
    // quote.
    static HEADER: LazyLock<Regex> =
        LazyLock::new(|| re(r#"(?m)\b([A-Za-z][A-Za-z0-9_\-]*)([ \t]*:[ \t]*)([^'"\r\n]+)"#));
    static BEARER: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{8,}"));
    // `"name": "value"` (JSON) and `name = "value"` / `name: 'value'`
    // (code), with a quoted value.
    static QUOTED_KEY: LazyLock<Regex> =
        LazyLock::new(|| re(r#""([A-Za-z_][A-Za-z0-9_.\-]*)"(\s*[:=]\s*)"(?:[^"\\]|\\.)*""#));
    static CODE_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"\b([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*)("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"#)
    });
    static QUERY: LazyLock<Regex> =
        LazyLock::new(|| re(r#"([?&;])([A-Za-z0-9_.\-]+)=([^&#\s'"]*)"#));
    static FLAG: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"(^|\s)--([A-Za-z][A-Za-z0-9_\-]*)(=|\s+)('[^']*'|"(?:[^"\\]|\\.)*"|[^\s'"]+)"#)
    });
    // `NAME=value` at a word start (after whitespace, `;`, `&`, `|`, `(`,
    // a quote or a backtick), `export` or not.
    static ENV: LazyLock<Regex> = LazyLock::new(|| {
        re(r#"(^|[\s;&|(`'"])([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"(?:[^"\\]|\\.)*"|[^\s;&|)'"`]*)"#)
    });

    let mut out = Cow::Borrowed(s);
    let mut apply = |re: &Regex, f: &dyn Fn(&Captures) -> Option<String>| {
        if !re.is_match(&out) {
            return;
        }
        let next = re.replace_all(&out, |c: &Captures| {
            f(c).unwrap_or_else(|| c[0].to_string())
        });
        if let Cow::Owned(n) = next {
            out = Cow::Owned(n);
        }
    };
    let secret = |c: &Captures, i: usize| is_secret_name(&c[i]);
    apply(&USERINFO, &|c| Some(format!("{}{SCRUBBED}@", &c[1])));
    apply(&HEADER, &|c| {
        secret(c, 1).then(|| format!("{}{}{SCRUBBED}", &c[1], &c[2]))
    });
    apply(&BEARER, &|c| Some(format!("{}{SCRUBBED}", &c[1])));
    apply(&QUOTED_KEY, &|c| {
        secret(c, 1).then(|| format!("\"{}\"{}\"{SCRUBBED}\"", &c[1], &c[2]))
    });
    apply(&CODE_ASSIGN, &|c| {
        secret(c, 1).then(|| format!("{}{}\"{SCRUBBED}\"", &c[1], &c[2]))
    });
    apply(&QUERY, &|c| {
        secret(c, 2).then(|| format!("{}{}={SCRUBBED}", &c[1], &c[2]))
    });
    apply(&FLAG, &|c| {
        secret_flag(&c[2]).then(|| format!("{}--{}{}{SCRUBBED}", &c[1], &c[2], &c[3]))
    });
    apply(&ENV, &|c| {
        secret(c, 2).then(|| format!("{}{}={SCRUBBED}", &c[1], &c[2]))
    });
    out
}

/// A `--name` flag whose value is a secret. `--no-password` is a switch.
fn secret_flag(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !n.starts_with("no-") && !n.starts_with("no_") && is_secret_name(&n)
}

/// `"--password"` alone in an argv list: the next element is its value.
fn is_bare_secret_flag(s: &str) -> bool {
    s.strip_prefix("--")
        .is_some_and(|f| !f.contains('=') && secret_flag(f))
}

/// `args` as they go into the record:
///
/// - a field named like a secret ([`is_secret_name`]) → `"[redacted]"`;
/// - `content` (`file_write`) and `ticket` (E6) → `{sha256, len}`;
/// - every other string is kept — `cmd`, `commands`, every interpreter's
///   `script`, `claude_exec`'s `task` are the command (owner decision) —
///   through [`scrub`], or as `{sha256, len, truncated: true}` above
///   [`MAX_ARG_STRING`]; in a list, the element after a bare secret flag
///   (`["--password", "x"]`) is scrubbed;
/// - the whole thing as one `{sha256, len, truncated: true}` above
///   [`MAX_ARGS_JSON`].
pub fn redact(args: &Value) -> Value {
    let r = redact_value(args);
    let text = r.to_string();
    if text.len() > MAX_ARGS_JSON {
        let mut d = digest(&Value::String(args.to_string()));
        d["truncated"] = true.into();
        return d;
    }
    r
}

fn redact_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), redact_field(k, v)))
                .collect(),
        ),
        Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            let mut after_flag = false;
            for v in a {
                out.push(if after_flag && v.is_string() {
                    Value::String(SCRUBBED.into())
                } else {
                    redact_value(v)
                });
                after_flag = v.as_str().is_some_and(is_bare_secret_flag);
            }
            Value::Array(out)
        }
        Value::String(s) if s.len() > MAX_ARG_STRING => {
            let mut d = digest(v);
            d["truncated"] = true.into();
            d
        }
        Value::String(s) => Value::String(scrub(s).into_owned()),
        other => other.clone(),
    }
}

fn redact_field(key: &str, v: &Value) -> Value {
    if is_secret_name(key) {
        return REDACTED.into();
    }
    match key.to_ascii_lowercase().as_str() {
        "content" | "ticket" => digest(v),
        _ => redact_value(v),
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

/// `s` scrubbed and cut to `max` chars (with `…`): every caller-controlled
/// string that goes into a record, so a client can neither plant a secret
/// in it verbatim nor grow the file with it.
pub fn clamp(s: &str, max: usize) -> String {
    let s = scrub(s);
    match s.char_indices().nth(max) {
        None => s.into_owned(),
        Some((i, _)) => format!("{}…", &s[..i]),
    }
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
    /// `optional` mode: the caller presented a credential that did not
    /// identify it (`revoked token for <agent>`, `invalid token`), so it
    /// ran as `anonymous`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_note: Option<String>,
    /// Auth records for a hijack attempt: the legacy `Mcp-Session-Id`
    /// that belongs to another agent, shortened like the journal's
    /// (`sessions::redact`) — the full ID is a handle to that session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_session: Option<String>,
    /// `error_class = killed`: the kill switch that refused the call —
    /// its `scope` (`global` | `agent` | `host` | `session`), `target`,
    /// `since` and `reason` (see `crate::kill`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill: Option<crate::kill::Kill>,
}

/// Caps, in chars, on the caller-controlled strings of a record (see
/// [`Record::clamp_strings`]). `args` has its own ([`redact`]).
pub const MAX_FIELD: usize = 256;
/// `path` is a URL path: a little more room.
pub const MAX_PATH: usize = 512;

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
        args: redact(&args),
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
        auth_note: ctx.auth_note.clone(),
        mcp_session: None,
        kill: ctx.notes().kill,
    }
}

impl Record {
    /// Scrub ([`scrub`]) and cap every string a client can choose — the
    /// name it typed for a host, an unknown tool's name, its User-Agent
    /// and session header, the HTTP path — so a record stays small and
    /// carries no secret verbatim, in the file and the journal alike.
    /// Operator-chosen strings (agent, rule) are capped too, for the
    /// table's sake.
    pub fn clamp_strings(&mut self) {
        let opt = |v: &mut Option<String>, max| {
            if let Some(s) = v.as_mut() {
                *s = clamp(s, max);
            }
        };
        self.agent = clamp(&self.agent, MAX_FIELD);
        for g in &mut self.agent_groups {
            *g = clamp(g, MAX_FIELD);
        }
        opt(&mut self.session_id, MAX_FIELD);
        opt(&mut self.client_ip, MAX_FIELD);
        opt(&mut self.user_agent, MAX_FIELD);
        opt(&mut self.tool, MAX_FIELD);
        opt(&mut self.host, MAX_FIELD);
        opt(&mut self.queried_as, MAX_FIELD);
        opt(&mut self.dest_host, MAX_FIELD);
        opt(&mut self.dest_queried_as, MAX_FIELD);
        opt(&mut self.rule, MAX_FIELD);
        opt(&mut self.approved_by, MAX_FIELD);
        opt(&mut self.reason, MAX_FIELD);
        opt(&mut self.path, MAX_PATH);
        opt(&mut self.auth_note, MAX_FIELD);
        opt(&mut self.mcp_session, MAX_FIELD);
        if let Some(k) = self.kill.as_mut() {
            opt(&mut k.target, MAX_FIELD);
            opt(&mut k.reason, MAX_FIELD);
        }
    }

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

/// Why the last write failed, for the refusal and the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// ENOSPC / EDQUOT / a short write: the audit filesystem is full.
    DiskFull,
    /// The file could not be opened (permissions, a missing directory).
    Open,
    /// Any other write error.
    Write,
}

impl Failure {
    fn of(e: &io::Error) -> Self {
        if e.kind() == io::ErrorKind::StorageFull
            || e.kind() == io::ErrorKind::QuotaExceeded
            || e.raw_os_error() == Some(libc::ENOSPC)
        {
            Self::DiskFull
        } else {
            Self::Write
        }
    }

    /// The reason as the agent sees it: no path, no OS detail.
    fn agent_text(self) -> &'static str {
        match self {
            Self::DiskFull => "the audit disk is full",
            Self::Open => "the audit log cannot be opened",
            Self::Write => "the last audit write failed",
        }
    }
}

struct State {
    file: Option<File>,
    /// (device, inode) of `file`, to notice a rename.
    id: Option<(u64, u64)>,
    /// Why the last write failed; `None` when it succeeded (or none was
    /// tried).
    failed: Option<Failure>,
    /// A short write left a fragment with no `\n`: the next record starts
    /// with one, so it lands on a line of its own.
    partial: bool,
    /// Last free-space check ([`FREE_SPACE_FLOOR`]), and whether it was
    /// below the floor.
    space_checked: Option<Instant>,
    space_nagged: Option<Instant>,
    /// Test hook ([`AuditLog::inject_fault`]).
    fault: Option<Fault>,
}

/// A write failure to simulate, for tests ([`AuditLog::inject_fault`]).
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// Every write fails with ENOSPC, writing nothing.
    DiskFull,
    /// Every write stops after this many bytes, like a filesystem that
    /// fills mid-write.
    Short(usize),
}

/// Below this much free space on the audit filesystem the journal gets
/// an error (at most every `FREE_SPACE_NAG`): with auth on, calls are
/// refused as soon as a write fails, and this is the warning before.
pub const FREE_SPACE_FLOOR: u64 = 64 * 1024 * 1024;
const FREE_SPACE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
const FREE_SPACE_NAG: std::time::Duration = std::time::Duration::from_secs(300);

/// 401 records: every client IP (an IPv6 /64 counts as one) gets
/// [`AUTH_IP_BURST`] records, refilled at one per [`AUTH_IP_REFILL_SECS`];
/// all of them together get [`AUTH_BURST`], refilled at one per second.
/// One flooder spends only its own allowance, so another client's
/// revoked-token 401 is still recorded; many flooders hit the global
/// ceiling, which bounds the file's growth.
pub const AUTH_BURST: f64 = 60.0;
pub const AUTH_IP_BURST: f64 = 10.0;
pub const AUTH_IP_REFILL_SECS: f64 = 10.0;
/// Client IPs tracked at once; the least recently seen is forgotten
/// first.
pub const AUTH_IPS_TRACKED: usize = 4096;

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant, burst: f64, per_sec: f64) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * per_sec).min(burst);
        self.last = now;
    }
}

struct AuthLimiter {
    global: Bucket,
    per_ip: std::collections::HashMap<std::net::IpAddr, Bucket>,
    /// Records dropped since the last one written.
    suppressed: u64,
}

/// The rate-limit key of a client: its address, an IPv6 address's /64.
fn limit_key(ip: Option<std::net::IpAddr>) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match ip.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V6(v6)) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
        Some(v4) => v4,
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

impl AuthLimiter {
    fn new(now: Instant) -> Self {
        Self {
            global: Bucket::full(AUTH_BURST, now),
            per_ip: Default::default(),
            suppressed: 0,
        }
    }

    fn take(&mut self, ip: Option<std::net::IpAddr>, now: Instant) -> Option<u64> {
        let ip_rate = 1.0 / AUTH_IP_REFILL_SECS;
        let key = limit_key(ip);
        if !self.per_ip.contains_key(&key) && self.per_ip.len() >= AUTH_IPS_TRACKED {
            // Forget the clients whose allowance is full again; failing
            // that, the one seen longest ago.
            self.per_ip.retain(|_, b| {
                let mut b = *b;
                b.refill(now, AUTH_IP_BURST, ip_rate);
                b.tokens < AUTH_IP_BURST
            });
            if self.per_ip.len() >= AUTH_IPS_TRACKED
                && let Some(oldest) = self
                    .per_ip
                    .iter()
                    .min_by_key(|(_, b)| b.last)
                    .map(|(k, _)| *k)
            {
                self.per_ip.remove(&oldest);
            }
        }
        let b = self
            .per_ip
            .entry(key)
            .or_insert_with(|| Bucket::full(AUTH_IP_BURST, now));
        b.refill(now, AUTH_IP_BURST, ip_rate);
        self.global.refill(now, AUTH_BURST, 1.0);
        if b.tokens >= 1.0 && self.global.tokens >= 1.0 {
            b.tokens -= 1.0;
            self.global.tokens -= 1.0;
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        }
    }
}

/// The audit file. Shared by every call through [`Audit`].
pub struct AuditLog {
    path: PathBuf,
    gid: Option<u32>,
    strict: bool,
    state: Mutex<State>,
    auth_limit: Mutex<AuthLimiter>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Free bytes (for unprivileged users) on the filesystem holding `path`.
// `statvfs`'s counts are u64 on Linux, u32/c_ulong on macOS.
#[allow(clippy::useless_conversion)]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` a valid
    // out-pointer for the duration of the call.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some(u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize)))
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
                failed: None,
                partial: false,
                space_checked: None,
                space_nagged: None,
                fault: None,
            }),
            auth_limit: Mutex::new(AuthLimiter::new(Instant::now())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Tests only: make every write fail like `fault` (`None` heals).
    /// Portable where `/dev/full` is not (macOS).
    #[doc(hidden)]
    pub fn inject_fault(&self, fault: Option<Fault>) {
        lock(&self.state).fault = fault;
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
        let res = match self.ensure_open(&mut st) {
            Err(e) => Err((e, Failure::Open)),
            Ok(()) => {
                // A short write left a fragment: start on a fresh line,
                // still in one write.
                let data: std::borrow::Cow<[u8]> = if st.partial {
                    [b"\n".as_slice(), line].concat().into()
                } else {
                    line.into()
                };
                match write_once(&mut st, &data) {
                    Ok(n) if n == data.len() => {
                        st.partial = false;
                        Ok(())
                    }
                    Ok(n) => {
                        if n > 0 {
                            st.partial = data[n - 1] != b'\n';
                        }
                        Err((
                            io::Error::other(format!("short write ({n} of {} bytes)", data.len())),
                            Failure::DiskFull,
                        ))
                    }
                    Err(e) => {
                        let f = Failure::of(&e);
                        Err((e, f))
                    }
                }
            }
        };
        let was_healthy = st.failed.is_none();
        st.failed = res.as_ref().err().map(|(_, f)| *f);
        if res.is_err() {
            // Reopen on the next attempt rather than keep a bad handle.
            st.file = None;
        } else if !was_healthy {
            tracing::warn!(path = %self.path.display(), "audit log writable again");
        }
        self.check_space(&mut st);
        drop(st);
        if let Err((e, f)) = &res {
            if self.strict {
                tracing::error!(
                    path = %self.path.display(),
                    error = %e,
                    cause = f.agent_text(),
                    "AUDIT WRITE FAILED ({}) — tool calls are refused until the audit log can be \
                     written (the record above is in the journal)",
                    f.agent_text()
                );
            } else if was_healthy {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    cause = f.agent_text(),
                    "audit write failed — with PROMPTO_AUTH=off calls continue; records go \
                     to the journal only until the file can be written again"
                );
            }
        }
        res.map_err(|(e, _)| e)
    }

    /// Warn (error level) while the audit filesystem is below
    /// [`FREE_SPACE_FLOOR`]: checked every `FREE_SPACE_EVERY`, logged
    /// on the way down and then every `FREE_SPACE_NAG`.
    fn check_space(&self, st: &mut State) {
        let now = Instant::now();
        if st
            .space_checked
            .is_some_and(|t| now.duration_since(t) < FREE_SPACE_EVERY)
        {
            return;
        }
        st.space_checked = Some(now);
        let Some(free) = free_bytes(&self.path) else {
            return;
        };
        if free >= FREE_SPACE_FLOOR {
            if st.space_nagged.take().is_some() {
                tracing::warn!(
                    path = %self.path.display(),
                    free_mb = free / (1024 * 1024),
                    "audit filesystem has room again"
                );
            }
            return;
        }
        if st
            .space_nagged
            .is_none_or(|t| now.duration_since(t) >= FREE_SPACE_NAG)
        {
            st.space_nagged = Some(now);
            tracing::error!(
                path = %self.path.display(),
                free_mb = free / (1024 * 1024),
                floor_mb = FREE_SPACE_FLOOR / (1024 * 1024),
                strict = self.strict,
                "AUDIT FILESYSTEM NEARLY FULL — free space on the audit log's filesystem is \
                 below the floor; when a write fails, {}",
                if self.strict {
                    "every tool call will be refused (PROMPTO_AUTH is on)"
                } else {
                    "records go to the journal only"
                }
            );
        }
    }

    /// Strict mode: the log is open and the last write succeeded. `Err`
    /// is the cause and the journal's detail.
    fn preflight(&self) -> Result<(), (Failure, String)> {
        if !self.strict {
            return Ok(());
        }
        let mut st = lock(&self.state);
        if let Err(e) = self.ensure_open(&mut st) {
            st.failed = Some(Failure::Open);
            return Err((
                Failure::Open,
                format!("cannot open {}: {e}", self.path.display()),
            ));
        }
        match st.failed {
            Some(f) => Err((
                f,
                format!(
                    "the last write to {} failed ({})",
                    self.path.display(),
                    f.agent_text()
                ),
            )),
            None => Ok(()),
        }
    }

    /// Take a token for a 401 record from `ip`: `Some(records suppressed
    /// since the last one)`, or `None` when over the limit.
    fn auth_token(&self, ip: Option<std::net::IpAddr>) -> Option<u64> {
        lock(&self.auth_limit).take(ip, Instant::now())
    }
}

/// One `write(2)` of `data` to the open file (or the injected fault).
fn write_once(st: &mut State, data: &[u8]) -> io::Result<usize> {
    let f = st.file.as_mut().expect("opened before writing");
    match st.fault {
        None => f.write(data),
        Some(Fault::DiskFull) => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
        Some(Fault::Short(n)) => f.write(&data[..n.min(data.len())]),
    }
}

/// Handle on the audit log, cloned into every `Prompto` and the `/log`
/// endpoint. [`Audit::null`] (the default) has no file: records reach
/// only the journal. It is for tests and embedders; the server always
/// opens a file.
#[derive(Clone, Default)]
pub struct Audit(Option<Arc<AuditLog>>);

/// Why a call was refused by [`Audit::preflight`], as the agent sees it:
/// the cause in a few words (`the audit disk is full`); the path and the
/// OS error go to the journal only.
pub fn preflight_refusal(cause: &str) -> String {
    format!(
        "refused: prompto cannot write its audit log ({cause}), and it never runs an unaudited \
         action. Nothing was run. The operator has been alerted (journal)."
    )
}

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
        log.preflight().map_err(|(cause, why)| {
            tracing::error!(
                request_id = %ctx.request_id,
                agent = ctx.agent_name(),
                tool,
                reason = %why,
                "AUDIT LOG UNAVAILABLE ({}) — refusing the call before it runs",
                cause.agent_text()
            );
            ctx.note(|n| n.audit_refused = true);
            ClassifiedError::refused(ErrorClass::Internal, preflight_refusal(cause.agent_text()))
        })
    }

    /// Emit `rec`, its strings clamped ([`Record::clamp_strings`]): the
    /// `tracing` event first (so the journal has it even if the file
    /// write fails), then the file. Errors are logged here per the
    /// failure policy; the result says whether the file got it.
    pub fn write(&self, mut rec: Record) -> bool {
        rec.clamp_strings();
        emit_event(&rec);
        let Some(log) = &self.0 else { return true };
        let mut line = match serde_json::to_vec(&rec) {
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
    /// `mcp_session`: the hijacked legacy session, already shortened.
    pub fn write_auth(
        &self,
        caller: Option<std::net::IpAddr>,
        user_agent: Option<String>,
        session_id: Option<String>,
        mcp_session: Option<String>,
        path: &str,
        reason: &str,
    ) {
        let suppressed = match &self.0 {
            Some(log) => match log.auth_token(caller) {
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
            auth_note: None,
            mcp_session,
            kill: None,
        };
        self.write(rec);
    }
}

// ---------------------------------------------------------------------------
// Operator records (`prompto kill`)
// ---------------------------------------------------------------------------

/// Who ran an operator command: the real uid and its name, and
/// `SUDO_USER` when it came through sudo (the uid is then 0).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Operator {
    pub uid: u32,
    pub user: Option<String>,
    pub sudo_user: Option<String>,
}

impl Operator {
    pub fn current() -> Self {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let clean = |s: &str| {
            let s: String = s.chars().filter(|&c| !is_terminal_hazard(c)).collect();
            clamp(s.trim(), MAX_FIELD)
        };
        Operator {
            uid,
            user: user_name(uid).map(|u| clean(&u)),
            sudo_user: std::env::var("SUDO_USER")
                .ok()
                .map(|u| clean(&u))
                .filter(|u| !u.is_empty()),
        }
    }

    /// `root (sudo: ops)`, `ops`, `uid 1234`.
    pub fn display(r: &Value) -> String {
        let s = |k: &str| r.get(k).and_then(Value::as_str);
        let user = match (s("user"), r.get("uid").and_then(Value::as_u64)) {
            (Some(u), _) => u.to_string(),
            (None, Some(uid)) => format!("uid {uid}"),
            (None, None) => "?".into(),
        };
        match s("sudo_user") {
            Some(su) => format!("{user} (sudo: {su})"),
            None => user,
        }
    }
}

/// The name of `uid` in the password database.
fn user_name(uid: u32) -> Option<String> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: every pointer is valid for the call; `buf` outlives the
    // use of `pw`'s strings, which point into it.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pw.pw_name.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name is a NUL-terminated string
    // in `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

/// `"type": "kill"`: an operator set (`on`) or lifted (`off`) a kill
/// switch with `prompto kill` / `unkill`. Written by the CLI, not the
/// server, so a switch set while the server is down is recorded too. A
/// switch made by hand (`touch /etc/prompto/kill`) has no such record;
/// the calls it refuses are recorded either way.
#[derive(Clone, Debug, Serialize)]
pub struct KillRecord {
    pub ts: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub request_id: String,
    /// `on` or `off`.
    pub action: &'static str,
    pub scope: crate::kill::Scope,
    /// The agent, host or session; `null` for the global switch.
    pub target: Option<String>,
    /// As the server will show it (`kill::sanitize_reason`); `null` for
    /// `off` and for a switch set without one.
    pub reason: Option<String>,
    /// The kill file.
    pub file: String,
    pub by: Operator,
}

impl KillRecord {
    pub fn new(
        on: bool,
        scope: crate::kill::Scope,
        target: Option<&str>,
        reason: &str,
        file: &Path,
        by: Operator,
    ) -> Self {
        KillRecord {
            ts: now_ts(),
            kind: "kill",
            request_id: ulid::Ulid::generate().to_string(),
            action: if on { "on" } else { "off" },
            scope,
            target: target.map(|t| clamp(t, MAX_FIELD)),
            reason: on
                .then(|| crate::kill::sanitize_reason(reason))
                .flatten()
                .map(|r| clamp(&r, MAX_FIELD)),
            file: clamp(&file.display().to_string(), MAX_PATH),
            by,
        }
    }
}

/// Append one record to the audit file from an operator command (not
/// the server), in one `write(2)` like the server's (`O_APPEND`, so the
/// two never interleave). An existing file keeps its owner and mode — a
/// root CLI appending must not take it from the server. A missing one
/// is created the way the server would create it: mode [`FILE_MODE`],
/// owned by the owner of its directory (the server's state directory),
/// group `gid` (`PROMPTO_AUDIT_GROUP`) or the directory's. If it can't
/// be handed over, it is removed again rather than left for a server
/// that couldn't write it.
pub fn append_operator_record(
    path: &Path,
    gid: Option<u32>,
    rec: &impl Serialize,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(rec).map_err(io::Error::other)?;
    line.push(b'\n');
    let file = match OpenOptions::new().append(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => create_like_the_server(path, gid)?,
        Err(e) => return Err(e),
    };
    let n = (&file).write(&line)?;
    if n != line.len() {
        return Err(io::Error::other(format!(
            "short write ({n} of {} bytes)",
            line.len()
        )));
    }
    Ok(())
}

fn create_like_the_server(path: &Path, gid: Option<u32>) -> io::Result<File> {
    let file = match OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
    {
        Ok(f) => f,
        // The server created it meanwhile: append to its file.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return OpenOptions::new().append(true).open(path);
        }
        Err(e) => return Err(e),
    };
    let hand_over = || -> io::Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let d = std::fs::metadata(dir)?;
        let m = file.metadata()?;
        let (uid, gid) = (d.uid(), gid.unwrap_or(d.gid()));
        if (m.uid(), m.gid()) != (uid, gid) {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        Ok(())
    };
    if let Err(e) = hand_over() {
        let _ = std::fs::remove_file(path);
        return Err(io::Error::new(
            e.kind(),
            format!("created it but could not give it to its directory's owner ({e}); removed it"),
        ));
    }
    Ok(file)
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
        auth_note = r.auth_note.as_deref(),
        mcp_session = r.mcp_session.as_deref(),
        kill_scope = r.kill.as_ref().map(|k| k.scope.as_str()),
        kill_target = r.kill.as_ref().and_then(|k| k.target.as_deref()),
        kill_reason = r.kill.as_ref().and_then(|k| k.reason.as_deref()),
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
    /// Matches `host`, `queried_as` or rsync's `dest_*`, or the target
    /// of a host kill record.
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
                || (s("type") == Some("kill")
                    && s("scope") == Some("host")
                    && s("target") == Some(h))
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

/// The record in one line of an audit file, and how many unreadable
/// fragments the line held (0 or 1). A line is normally one record. One
/// that doesn't parse may be the fragment of a write cut short (the disk
/// filled) with the next record glued after it — prompto now starts that
/// record on a fresh line, older builds did not. Every record starts
/// with `{"ts":"`, so the parse is retried from each later occurrence
/// and only the fragment is lost, not the record after it.
pub fn parse_line(line: &str) -> (Option<(Value, &str)>, usize) {
    if let Ok(v) = serde_json::from_str::<Value>(line) {
        return (Some((v, line)), 0);
    }
    const START: &str = "{\"ts\":\"";
    let found = line
        .match_indices(START)
        .filter(|(i, _)| *i > 0)
        .find_map(|(i, _)| {
            let rest = &line[i..];
            serde_json::from_str::<Value>(rest).ok().map(|v| (v, rest))
        });
    (found, 1)
}

/// `line` with what serde_json leaves unescaped but a terminal acts on
/// (DEL, C1 controls, bidi and zero-width formatting) written as `\uXXXX`:
/// still the same JSON, safe to print. Such characters only occur inside
/// strings in valid JSON, where `\uXXXX` means the same character.
pub fn json_for_terminal(line: &str) -> std::borrow::Cow<'_, str> {
    if !line.chars().any(is_terminal_hazard) {
        return line.into();
    }
    let mut out = String::with_capacity(line.len() + 16);
    for c in line.chars() {
        if is_terminal_hazard(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out.into()
}

/// A character that changes what a terminal shows rather than showing
/// itself: C0/C1 controls and DEL, and Unicode formatting that reorders
/// or hides text (bidi overrides and isolates, zero-width characters).
pub(crate) fn is_terminal_hazard(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}')
}

/// `s` for one table cell: newlines and tabs as spaces, every other
/// terminal hazard (`is_terminal_hazard`) — ESC, CR, BEL, bidi overrides —
/// escaped visibly (`\x1b`, `\u{202e}`), cut to `max` chars with `…`.
pub fn cell(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' | '\t' => out.push(' '),
            c if is_terminal_hazard(c) && (c as u32) < 0x100 => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if is_terminal_hazard(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    if out.chars().count() <= max {
        return out;
    }
    let mut t: String = out.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Widest a table cell other than the detail gets.
const CELL_MAX: usize = 40;

/// One table row per record, columns: time, agent, tool, host, decision,
/// result, duration, detail (the command, or the arguments; the rule on a
/// refusal; the reason on an auth record). Every cell goes through
/// [`cell`]: a record's strings come from clients, and must not drive
/// the terminal that shows them.
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
    if s("type") == "kill" {
        return kill_row(r, &time);
    }
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
        if let Some(k) = r.get("kill") {
            let ks = |f: &str| k.get(f).and_then(Value::as_str).unwrap_or("");
            let target = match ks("target") {
                "" => String::new(),
                t => format!(" {t}"),
            };
            d = format!("kill={}{target} {d}", ks("scope"));
        }
        if !s("auth_note").is_empty() {
            d = format!("[{}] {d}", s("auth_note"));
        }
        d
    };
    [
        cell(&time, CELL_MAX),
        cell(s("agent"), CELL_MAX),
        if s("type") == "auth" {
            "(auth)".into()
        } else {
            cell(s("tool"), CELL_MAX)
        },
        cell(&host, CELL_MAX),
        cell(
            r.get("decision").and_then(Value::as_str).unwrap_or("-"),
            CELL_MAX,
        ),
        cell(&result, CELL_MAX),
        format!(
            "{}ms",
            r.get("duration_ms").and_then(Value::as_u64).unwrap_or(0)
        ),
        cell(&detail, 80),
    ]
}

/// A `"type": "kill"` record as a table row: the operator in the agent
/// column, `(kill)` as the tool, the host for a host kill, `on`/`off` as
/// the result, scope, target and reason as the detail.
fn kill_row(r: &Value, time: &str) -> [String; 8] {
    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("");
    let by = r.get("by").map(Operator::display).unwrap_or_default();
    let host = if s("scope") == "host" {
        s("target")
    } else {
        "-"
    };
    let mut detail = format!("kill={}", s("scope"));
    if !s("target").is_empty() {
        detail = format!("{detail} {}", s("target"));
    }
    if !s("reason").is_empty() {
        detail = format!("{detail} reason: {}", s("reason"));
    }
    [
        cell(time, CELL_MAX),
        cell(&by, CELL_MAX),
        "(kill)".into(),
        cell(host, CELL_MAX),
        "-".into(),
        cell(&format!("kill {}", s("action")), CELL_MAX),
        "-".into(),
        cell(&detail, 80),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_and_scripts_stay_whole() {
        let a = json!({ "host": "h", "cmd": "rm -rf /tmp/x && echo done" });
        assert_eq!(redact(&a), a);
        let b = json!({ "host": "h", "commands": ["a", "b c"], "fail_fast": true });
        assert_eq!(redact(&b), b);
        let c = json!({ "host": "h", "script": "echo hi\nuname -a" });
        assert_eq!(redact(&c), c);
        let t = json!({ "host": "h", "task": "why is nginx down" });
        assert_eq!(redact(&t), t);
        // Every interpreter's script too (owner decision, task 010).
        let p = json!({ "host": "h", "script": "print(1)", "args": ["-v"] });
        assert_eq!(redact(&p), p);
    }

    #[test]
    fn strings_above_the_cap_become_digests() {
        let big = "x".repeat(MAX_ARG_STRING + 1);
        let r = redact(&json!({ "host": "h", "script": big, "commands": ["ok", big] }));
        assert_eq!(r["host"], "h");
        assert_eq!(r["script"]["len"], MAX_ARG_STRING + 1);
        assert_eq!(r["script"]["truncated"], true);
        assert_eq!(
            r["script"]["sha256"],
            crate::agent::hex(&crate::agent::sha256(big.as_bytes()))
        );
        assert_eq!(r["commands"][0], "ok");
        assert_eq!(r["commands"][1]["truncated"], true);
        let at_cap = "y".repeat(MAX_ARG_STRING);
        assert_eq!(redact(&json!({ "cmd": at_cap }))["cmd"], at_cap);
        // Many small strings: the whole args are one digest.
        let many: Map<String, Value> = (0..MAX_ARGS_JSON / 8)
            .map(|i| (format!("k{i}"), Value::from("vvvvvvvv")))
            .collect();
        let r = redact(&Value::Object(many));
        assert_eq!(r["truncated"], true);
        assert!(r.to_string().len() < 200);
    }

    #[test]
    fn file_contents_are_digests() {
        let body = "line one\nPASSWORD=hunter2\n";
        let r = redact(&json!({ "host": "h", "path": "/etc/x", "content": body, "mode": "0600" }));
        assert_eq!(r["path"], "/etc/x");
        assert_eq!(r["mode"], "0600");
        assert_eq!(r["content"]["len"], body.len());
        assert_eq!(
            r["content"]["sha256"],
            crate::agent::hex(&crate::agent::sha256(body.as_bytes()))
        );
        assert!(r["content"].get("truncated").is_none());
        assert!(!r.to_string().contains("hunter2"));
    }

    #[test]
    fn secret_named_fields_are_redacted_at_any_depth() {
        let r = redact(&json!({
            "client": "c",
            "Password": "p1",
            "api_token": "t1",
            "nested": { "client_secret": "s1", "list": [{ "X-Api-Key": "k1" }] },
            "dest_key": "/home/u/.ssh/id",
            "ticket": "tk",
        }));
        let text = r.to_string();
        for leaked in ["p1", "t1", "s1", "k1", "\"tk\""] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert_eq!(r["Password"], REDACTED);
        assert_eq!(r["nested"]["list"][0]["X-Api-Key"], REDACTED);
        assert_eq!(r["ticket"]["len"], 2);
        assert_eq!(r["client"], "c");
        // A path, not a key: kept (owner decision, task 010).
        assert_eq!(r["dest_key"], "/home/u/.ssh/id");
    }

    #[test]
    fn secret_names_match_exactly_or_by_suffix() {
        for n in [
            "password",
            "PGPASSWORD",
            "db_password",
            "passwd",
            "ssh_passphrase",
            "token",
            "GITHUB_TOKEN",
            "api-token",
            "clientSecret",
            "credentials",
            "aws_secret_access_key",
            "X-Api-Key",
            "apiKey",
            "private_key",
            "SECRET_KEY",
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "MYSQL_PWD",
            "DB_PASS",
            "pass",
            "pw",
        ] {
            assert!(is_secret_name(n), "{n}");
        }
        for n in [
            "dest_key",
            "key",
            "keyboard",
            "max_tokens",
            "token_file",
            "PWD",
            "bypass",
            "path",
            "host",
            "secrets_dir",
            "passenger",
        ] {
            assert!(!is_secret_name(n), "{n}");
        }
    }

    /// Each scrubber pattern, and that the command around it survives.
    #[test]
    fn scrub_hides_secret_values_in_kept_strings() {
        let cases = [
            (
                "git clone https://user:hunter2@git.example/x.git",
                "git clone https://***@git.example/x.git",
            ),
            (
                "curl https://ghp_abcdef123@api.example/r",
                "curl https://***@api.example/r",
            ),
            (
                "curl 'https://api.example/v1?q=1&token=abc123&x=2'",
                "curl 'https://api.example/v1?q=1&token=***&x=2'",
            ),
            (
                "https://h/cb?access_token=zz#frag",
                "https://h/cb?access_token=***#frag",
            ),
            (
                r#"curl -H "Authorization: Bearer eyJhbGciOi.xyz" https://h"#,
                r#"curl -H "Authorization: ***" https://h"#,
            ),
            (
                "curl -H 'Authorization: Basic dXNlcjpwdw==' https://h",
                "curl -H 'Authorization: ***' https://h",
            ),
            (
                r#"curl -H "X-Api-Key: k-123456" https://h"#,
                r#"curl -H "X-Api-Key: ***" https://h"#,
            ),
            ("echo Bearer abcdefgh12345 | x", "echo Bearer *** | x"),
            (
                "mysql --password=hunter2 -u root db",
                "mysql --password=*** -u root db",
            ),
            (
                "tool --api-key sk_live_123 --verbose",
                "tool --api-key *** --verbose",
            ),
            (
                r#"tool --client-secret "a b c" run"#,
                "tool --client-secret *** run",
            ),
            (
                "export TOKEN=abc123 && ./deploy",
                "export TOKEN=*** && ./deploy",
            ),
            (
                "X_API_KEY=xyz PGPASSWORD='p w' psql -h db",
                "X_API_KEY=*** PGPASSWORD=*** psql -h db",
            ),
            (
                "env GITHUB_TOKEN=\"ghp_1\" gh pr list",
                "env GITHUB_TOKEN=*** gh pr list",
            ),
            (
                "password = \"hunter2\"\nprint(1)",
                "password = \"***\"\nprint(1)",
            ),
            (
                "curl -d '{\"user\":\"u\",\"password\":\"hunter2\"}' https://h",
                "curl -d '{\"user\":\"u\",\"password\":\"***\"}' https://h",
            ),
            ("token: abc123", "token: ***"),
        ];
        for (input, want) in cases {
            assert_eq!(scrub(input), want, "{input}");
        }
    }

    #[test]
    fn scrub_leaves_ordinary_commands_alone() {
        for cmd in [
            "ls -la /tmp",
            "systemctl restart nginx",
            "grep -rn token src/",
            "echo $TOKEN",
            "ssh admin@host uptime",
            "rsync -a src/ backup@nas:/srv/x",
            "git clone https://github.example/x/y.git",
            "curl 'https://h/api?page=2&limit=10'",
            "FOO=bar make -j4",
            "PWD=/tmp ls",
            "cat ~/.ssh/id_ed25519.pub",
            "pg_dump --no-password db > x.sql",
            "tool --token-file /etc/x --key-dir /k",
            "docker run -e MODE=prod img",
            "echo basic test",
            "journalctl -u nginx --since '1 hour ago'",
            "awk -F: '{print $1}' /etc/passwd",
            "key=value; echo $key",
            "for i in 1 2; do echo $i; done",
            "python3 -c 'print(\"hello\")'",
            "",
        ] {
            assert_eq!(scrub(cmd), cmd);
        }
    }

    #[test]
    fn scrub_reaches_every_kept_string_and_argv_pairs() {
        let r = redact(&json!({
            "client": "c",
            "url_or_cmd": "https://u:pw@mcp.example/sse?token=t0",
            "commands": ["echo ok", "export SECRET=s1"],
            "args": ["--verbose", "--password", "p1", "--token=t1", "plain"],
        }));
        let text = r.to_string();
        for leaked in ["pw@", "t0", "s1", "p1", "t1"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert_eq!(
            r["args"],
            json!(["--verbose", "--password", "***", "--token=***", "plain"])
        );
        assert_eq!(r["commands"][0], "echo ok");
    }

    #[test]
    fn record_strings_are_scrubbed_and_capped() {
        let ctx = CallCtx::new(None);
        let mut rec = tool_record(&ctx, "ssh_exec", json!({}));
        rec.tool = Some("t".repeat(10_000));
        rec.queried_as = Some("q".repeat(10_000));
        rec.path = Some(format!("/mcp/{}", "p".repeat(100_000)));
        rec.reason = Some("r".repeat(10_000));
        rec.user_agent = Some("curl https://u:pw@x/".into());
        rec.clamp_strings();
        assert_eq!(rec.tool.as_ref().unwrap().chars().count(), MAX_FIELD + 1);
        assert_eq!(
            rec.queried_as.as_ref().unwrap().chars().count(),
            MAX_FIELD + 1
        );
        assert_eq!(rec.reason.as_ref().unwrap().chars().count(), MAX_FIELD + 1);
        assert_eq!(rec.path.as_ref().unwrap().chars().count(), MAX_PATH + 1);
        assert!(rec.path.as_ref().unwrap().ends_with('…'));
        assert_eq!(rec.user_agent.as_deref(), Some("curl https://***@x/"));
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

    fn ip(s: &str) -> Option<std::net::IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn auth_records_are_rate_limited_per_ip_and_count_what_they_drop() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new(t0);
        for _ in 0..AUTH_IP_BURST as usize {
            assert_eq!(l.take(ip("192.0.2.1"), t0), Some(0));
        }
        assert_eq!(l.take(ip("192.0.2.1"), t0), None);
        assert_eq!(l.take(ip("192.0.2.1"), t0), None);
        // One flooder does not hide another client's 401.
        assert_eq!(l.take(ip("192.0.2.2"), t0), Some(2));
        // The flooder gets one more after the refill period.
        let later = t0 + std::time::Duration::from_secs_f64(AUTH_IP_REFILL_SECS);
        assert_eq!(l.take(ip("192.0.2.1"), later), Some(0));
    }

    #[test]
    fn a_flood_from_one_ip_leaves_room_for_others() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new(t0);
        for _ in 0..10_000 {
            l.take(ip("192.0.2.1"), t0);
        }
        assert!(l.take(ip("198.51.100.7"), t0).is_some());
        // An IPv6 /64 is one client.
        for i in 0..1000u32 {
            l.take(ip(&format!("2001:db8:1:2::{i:x}")), t0);
        }
        assert!(l.take(ip("2001:db8:9:9::1"), t0).is_some());
    }

    #[test]
    fn many_ips_hit_the_global_ceiling_and_the_map_stays_bounded() {
        let t0 = Instant::now();
        let mut l = AuthLimiter::new(t0);
        let written = (0..(AUTH_IPS_TRACKED as u32 * 2))
            .filter(|i| {
                let a = std::net::Ipv4Addr::from(0x0a00_0000 + i);
                l.take(Some(a.into()), t0).is_some()
            })
            .count();
        assert_eq!(written, AUTH_BURST as usize);
        assert!(l.per_ip.len() <= AUTH_IPS_TRACKED);
    }

    #[test]
    fn a_short_write_never_glues_the_next_record_to_a_fragment() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(p.clone(), None, true).unwrap();
        log.append(b"{\"ts\":\"1\"}\n").unwrap();
        log.inject_fault(Some(Fault::Short(5)));
        assert!(log.append(b"{\"ts\":\"2\",\"x\":1}\n").is_err());
        assert_eq!(
            log.preflight().unwrap_err().0,
            Failure::DiskFull,
            "a short write is a full disk"
        );
        log.inject_fault(None);
        log.append(b"{\"ts\":\"3\"}\n").unwrap();
        log.append(b"{\"ts\":\"4\"}\n").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            text,
            "{\"ts\":\"1\"}\n{\"ts\"\n{\"ts\":\"3\"}\n{\"ts\":\"4\"}\n"
        );
        assert!(log.preflight().is_ok());
    }

    #[test]
    fn the_reader_skips_only_the_fragment() {
        let (r, bad) = parse_line(r#"{"ts":"2026-10-09T12:00:00.000Z","tool":"a"}"#);
        assert_eq!((r.unwrap().0["tool"].clone(), bad), (json!("a"), 0));
        // An older build glued the next record to the fragment.
        let glued = r#"{"ts":"2026-10-09T12:00:00.000Z","type":"to{"ts":"2026-10-09T12:00:01.000Z","tool":"b","args":{"x":{"ts":"n"}}}"#;
        let (r, bad) = parse_line(glued);
        let (v, text) = r.unwrap();
        assert_eq!((v["tool"].clone(), bad), (json!("b"), 1));
        assert!(text.starts_with(r#"{"ts":"2026-10-09T12:00:01"#));
        let (r, bad) = parse_line(r#"{"ts":"2026-10"#);
        assert!(r.is_none());
        assert_eq!(bad, 1);
    }

    #[test]
    fn disk_full_is_named_in_the_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join("a.jsonl"), None, true).unwrap();
        log.inject_fault(Some(Fault::DiskFull));
        assert!(log.append(b"x\n").is_err());
        let audit = Audit::new(log);
        let e = audit
            .preflight(&CallCtx::new(None), "ssh_exec")
            .unwrap_err();
        assert_eq!(e.class, ErrorClass::Internal);
        let msg = e.to_string();
        assert!(msg.contains("the audit disk is full"), "{msg}");
        assert!(!msg.contains("a.jsonl"), "no path for the agent: {msg}");
    }

    #[test]
    fn table_cells_cannot_drive_the_terminal() {
        let r = json!({
            "ts": "2026-10-09T12:00:00.000Z\u{1b}[2J",
            "type": "tool",
            "agent": "a\u{7}\rb",
            "tool": "\u{1b}]0;pwned\u{7}\u{1b}[31mssh_exec",
            "host": "h\u{202e}x",
            "queried_as": null,
            "decision": "allow\u{9b}1m",
            "error_class": "internal\u{1b}[0m",
            "ok": false,
            "args": { "cmd": "echo \u{1b}[2Jhi\nthere" },
        });
        let row = table_row(&r);
        for c in &row {
            assert!(!c.chars().any(is_terminal_hazard), "{c:?}");
        }
        assert_eq!(row[2], "\\x1b]0;pwned\\x07\\x1b[31mssh_exec");
        assert_eq!(row[1], "a\\x07\\x0db");
        assert_eq!(row[3], "h\\u{202e}x");
        assert_eq!(row[7], "echo \\x1b[2Jhi there");
        // Long cells are cut.
        let long = json!({ "type": "tool", "tool": "t".repeat(500) });
        assert_eq!(table_row(&long)[2].chars().count(), CELL_MAX);
    }

    /// A kill record carries the reason as the server shows it, clamped,
    /// none for `off`; the table puts the operator in the agent column
    /// and `--host` finds host kills.
    #[test]
    fn kill_records_read_like_the_switch() {
        let by = Operator {
            uid: 0,
            user: Some("root".into()),
            sudo_user: Some("ops".into()),
        };
        let r = KillRecord::new(
            true,
            crate::kill::Scope::Host,
            Some("web1"),
            "disk\x1b[2J full token=hunter2",
            Path::new("/etc/prompto/kill.d/host-web1"),
            by.clone(),
        );
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["type"], "kill");
        assert_eq!(v["action"], "on");
        assert_eq!(v["scope"], "host");
        let reason = v["reason"].as_str().unwrap();
        assert!(
            !reason.contains('\x1b') && !reason.contains("hunter2"),
            "{reason}"
        );
        assert_eq!(v["by"]["sudo_user"], "ops");
        let row = table_row(&v);
        assert_eq!(row[1], "root (sudo: ops)");
        assert_eq!(row[2], "(kill)");
        assert_eq!(row[3], "web1");
        assert_eq!(row[5], "kill on");
        assert!(
            row[7].starts_with("kill=host web1 reason: disk"),
            "{}",
            row[7]
        );
        let f = |h: &str| Filter {
            host: Some(h.into()),
            ..Default::default()
        };
        assert!(f("web1").matches(&v) && !f("web2").matches(&v));

        let off = KillRecord::new(
            false,
            crate::kill::Scope::Global,
            None,
            "x",
            Path::new("/k"),
            by,
        );
        let v = serde_json::to_value(&off).unwrap();
        assert_eq!(
            (v["action"].as_str(), &v["reason"]),
            (Some("off"), &Value::Null)
        );
        assert_eq!(table_row(&v)[3], "-");
        assert_eq!(table_row(&v)[7], "kill=global");
        assert!(!f("web1").matches(&v));
    }

    /// A file the CLI creates but can't hand to its directory's owner
    /// and group is removed, not left for a server that couldn't write
    /// it. Root can always chown, so this runs unprivileged only.
    #[test]
    fn an_operator_created_audit_file_is_handed_over_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append_operator_record(&path, None, &json!({"type": "kill"})).unwrap();
        let m = std::fs::metadata(&path).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, FILE_MODE);
        let d = std::fs::metadata(dir.path()).unwrap();
        assert_eq!((m.uid(), m.gid()), (d.uid(), d.gid()));
        std::fs::remove_file(&path).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // A group this process is not in: chown to it is EPERM.
        let mut groups = vec![0 as libc::gid_t; 256];
        let n = unsafe { libc::getgroups(256, groups.as_mut_ptr()) };
        groups.truncate(n.max(0) as usize);
        groups.push(unsafe { libc::getegid() });
        let foreign = (1..60000).find(|g| !groups.contains(g)).unwrap();
        let err = append_operator_record(&path, Some(foreign), &json!({})).unwrap_err();
        assert!(err.to_string().contains("removed it"), "{err}");
        assert!(!path.exists(), "left a file the server may not write");
    }

    #[test]
    fn table_names_the_kill_switch() {
        let r = json!({
            "type": "tool", "tool": "ssh_exec", "decision": "deny", "ok": false,
            "error_class": "killed", "args": { "cmd": "id" },
            "kill": { "scope": "host", "target": "web1", "reason": "disk" },
        });
        assert_eq!(table_row(&r)[5], "killed");
        assert_eq!(table_row(&r)[7], "kill=host web1 id");
        let g = json!({ "type": "tool", "args": {}, "kill": { "scope": "global" } });
        assert_eq!(table_row(&g)[7], "kill=global ");
    }

    #[test]
    fn json_output_escapes_what_serde_leaves_raw() {
        let line =
            serde_json::to_string(&json!({ "t": "a\u{7f}b\u{9b}c\u{202e}d\u{1b}" })).unwrap();
        let safe = json_for_terminal(&line);
        assert!(!safe.chars().any(is_terminal_hazard), "{safe}");
        let back: Value = serde_json::from_str(&safe).unwrap();
        assert_eq!(back["t"], "a\u{7f}b\u{9b}c\u{202e}d\u{1b}");
    }

    #[test]
    fn group_resolves_numbers_and_names() {
        assert_eq!(resolve_group("1234").unwrap(), 1234);
        // gid 0 is `root` on Linux and `wheel` on macOS.
        let groups = std::fs::read_to_string("/etc/group").unwrap();
        let gid0 = groups
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.get(2) == Some(&"0")).then(|| f[0].to_string())
            })
            .expect("a group with gid 0");
        assert_eq!(resolve_group(&gid0).unwrap(), 0);
        assert!(resolve_group("no-such-group-xyz").is_err());
    }
}
