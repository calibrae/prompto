//! Kill switches (roadmap E5): stop calls at any scope, from the next
//! call on, without a restart or a signal.
//!
//! | Scope | File | Refuses |
//! |---|---|---|
//! | global | `/etc/prompto/kill` (`PROMPTO_KILL_FILE`) | every tool call and `GET /log` |
//! | agent | `kill.d/agent-<name>` | every call by that agent |
//! | host | `kill.d/host-<name>` | every call that targets that host, by any agent |
//! | session | `kill.d/session-<id>` | every call carrying that `X-Prompto-Session` |
//!
//! `kill.d` sits next to the global file (`<PROMPTO_KILL_FILE>.d`, or
//! `PROMPTO_KILL_DIR`). A file's existence is the switch: its first line,
//! if any, is the reason, and its mtime the time it was set. The server
//! only reads them — `prompto kill …` writes them as root, and so does a
//! hand-made `touch` or `echo reason >`.
//!
//! Every call stats the files that could apply to it (one `stat` for the
//! global file, one per agent, session and host named): cheap, and with
//! nothing cached there is nothing to reload. The check runs **before
//! anything else** a call does — argument parsing, host lookup, the
//! self-target guard, policy and the audit preflight — so a kill works
//! whatever state those are in, a broken audit log included. Its refusal
//! (class `killed`) is still written to the audit log when the log can
//! take it, and always to the journal.
//!
//! A switch that can't be checked fails **closed**. At startup the
//! server refuses to start if it can't check the global file or look
//! inside `kill.d` ([`KillSwitch::probe`]): any `stat` error other than
//! "absent" (permission denied on the directory, a symlink loop) stops
//! it with an error naming the path, so an upgrade shows the problem at
//! once instead of shipping a panic button that doesn't work. If a path
//! that was checkable becomes uncheckable while running, every call that
//! needs it is refused as `killed`, reason `kill switch unreadable: …`,
//! and the server logs `KILL SWITCH UNREADABLE` (at most once a minute;
//! each refusal is logged and audited anyway).
//!
//! Names are validated before they become file names ([`validate`]): no
//! `/`, no leading `.`, so `kill host ../x` can't reach outside `kill.d`.
//! A call naming a host that isn't a valid file name can't match a file
//! and is not looked up.
//!
//! **Switches set over HTTP** (`POST /v1/kill`, `crate::agent_api`) live
//! in a second directory the server itself may write
//! (`PROMPTO_KILL_API_DIR`, default `/var/lib/prompto/kill.d`: under
//! systemd `/etc` is read-only to it). Two kinds only: `global` (an
//! approver's TOTP code is required to set it) and
//! `session-<agent>.<session>` (an agent stopping its own session: it
//! stops that agent's calls carrying that session, nobody else's). The
//! server never removes them: an operator does, with `prompto kill off`
//! and `prompto unkill session <id>`. They are checked, listed and probed
//! like the others.
//!
//! That directory is the service's own: created mode 0700, its files
//! 0600, owned by the user prompto runs as. Anything running as that
//! user can therefore remove an HTTP kill — it is the service itself,
//! which could stop enforcing anyway. The operator's switches (`kill`
//! and `kill.d` under `/etc`) stay root-owned and out of its reach.
//! Agents can't fill the disk through it: at most
//! [`MAX_SESSION_KILLS_PER_AGENT`] live session kills per agent and
//! [`MAX_API_KILLS`] files in all; beyond that `set_agent_session`
//! refuses ([`Full`]) until an operator lifts some.

use crate::error_class::{ClassifiedError, ErrorClass};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Default global kill file.
pub const DEFAULT_FILE: &str = "/etc/prompto/kill";
/// Default directory of the switches set over HTTP (see the module docs).
pub const DEFAULT_API_DIR: &str = "/var/lib/prompto/kill.d";
/// File name of the global switch in the API directory.
const API_GLOBAL: &str = "global";
/// Longest reason shown, in chars.
pub const MAX_REASON: usize = 200;
/// Bytes read from a kill file to find its first line.
const READ_LIMIT: u64 = 4096;
/// Live session kills set over HTTP, per agent.
pub const MAX_SESSION_KILLS_PER_AGENT: usize = 100;
/// Files in the API directory, in all.
pub const MAX_API_KILLS: usize = 1000;

/// The API directory holds as many session kills as it may: the error
/// `set_agent_session` returns (downcast it to tell it apart).
#[derive(Debug)]
pub struct Full(pub String);

impl std::fmt::Display for Full {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Full {}

/// Serialises the API directory's count-then-write.
static API_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What a kill switch applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Global,
    Agent,
    Host,
    Session,
    /// One agent's calls in one session, set over HTTP by the agent
    /// itself. `target` is the session, `agent` the agent.
    #[serde(rename = "agent_session")]
    AgentSession,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Agent => "agent",
            Scope::Host => "host",
            Scope::Session => "session",
            Scope::AgentSession => "agent_session",
        }
    }

    /// Parse a scoped kill's kind (`agent`, `host`, `session`).
    pub fn parse_named(s: &str) -> Option<Self> {
        match s {
            "agent" => Some(Scope::Agent),
            "host" => Some(Scope::Host),
            "session" => Some(Scope::Session),
            _ => None,
        }
    }

    /// File name prefix in `kill.d`.
    fn prefix(self) -> &'static str {
        match self {
            Scope::Global => "",
            Scope::Agent => "agent-",
            Scope::Host => "host-",
            Scope::Session | Scope::AgentSession => "session-",
        }
    }

    const NAMED: [Scope; 3] = [Scope::Agent, Scope::Host, Scope::Session];
}

/// Is `name` usable as the target of a scoped kill? Agents follow
/// `agent::validate_name`; hosts and sessions `[A-Za-z0-9][A-Za-z0-9._:-]`,
/// at most 128 chars (the `X-Prompto-Session` charset). Either way the
/// name can't contain `/` or start with `.`, so the file stays in
/// `kill.d`.
pub fn validate(scope: Scope, name: &str) -> Result<()> {
    match scope {
        Scope::Global => bail!("the global kill takes no name"),
        Scope::Agent => crate::agent::validate_name("agent", name),
        Scope::Host | Scope::Session | Scope::AgentSession => {
            let ok = !name.is_empty()
                && name.len() <= crate::agent::MAX_SESSION_LEN
                && name.as_bytes()[0].is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
            if !ok {
                bail!(
                    "{} {name:?}: use 1-128 of A-Z a-z 0-9 . _ : - (starting with a letter or \
                     digit)",
                    scope.as_str()
                );
            }
            Ok(())
        }
    }
}

/// An active kill switch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Kill {
    pub scope: Scope,
    /// The agent, host or session; `None` for the global kill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `agent_session`: whose calls in that session are stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// When it was set (the file's mtime), RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// The file's first line: bounded, control characters removed. For
    /// an unreadable switch, `kill switch unreadable: <path>: <error>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The switch could not be checked, so the call is refused anyway
    /// (fail closed). It may not be set at all.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unreadable: bool,
}

impl Kill {
    /// The fixed, actionable refusal the caller gets.
    pub fn message(&self) -> String {
        let t = self.target.as_deref().unwrap_or("");
        let (what, lift) = match self.scope {
            Scope::Global => (
                "every prompto tool call".to_string(),
                "prompto kill off".to_string(),
            ),
            Scope::Agent => (
                format!("every call by agent {t}"),
                format!("prompto unkill agent {t}"),
            ),
            Scope::Host => (
                format!("every call to host {t}"),
                format!("prompto unkill host {t}"),
            ),
            Scope::Session => (
                format!("every call from session {t}"),
                format!("prompto unkill session {t}"),
            ),
            Scope::AgentSession => (
                format!(
                    "every call by agent {} in session {t}",
                    self.agent.as_deref().unwrap_or("?")
                ),
                format!("prompto unkill session {t}"),
            ),
        };
        if self.unreadable {
            return format!(
                "refused: prompto cannot check its {} kill switch ({}), so it fails closed and \
                 refuses {what}. Nothing was run. Do not retry or work around it; stop and tell \
                 the user. An operator fixes it by making the kill switch path checkable by \
                 prompto again.",
                self.scope.as_str(),
                self.reason.as_deref().unwrap_or("kill switch unreadable"),
            );
        }
        let mut detail = format!("{} kill switch", self.scope.as_str());
        if let Some(s) = &self.since {
            detail.push_str(&format!(", set {s}"));
        }
        if let Some(r) = &self.reason {
            detail.push_str(&format!(", reason: {r}"));
        }
        let who = match self.scope {
            Scope::AgentSession => "this session was stopped on request, so prompto refuses",
            _ => "the operator has stopped",
        };
        format!(
            "refused: {who} {what} ({detail}). Nothing was run. This is deliberate, not a \
             fault: do not retry or work around it; stop and tell the user. An operator lifts \
             it with `{lift}`."
        )
    }

    /// The refusal as a classified error (`killed`).
    pub fn refusal(&self) -> ClassifiedError {
        ClassifiedError::refused(ErrorClass::Killed, self.message())
    }
}

/// Who and what a call is about, for [`KillSwitch::check`].
#[derive(Debug, Default)]
pub struct Subject<'a> {
    /// `None` with auth off: agent kills don't apply.
    pub agent: Option<&'a str>,
    /// `X-Prompto-Session`.
    pub session: Option<&'a str>,
    /// Every name the call targets: as typed and, if it resolves, the
    /// inventory name.
    pub hosts: Vec<String>,
}

/// Argument fields that name a target host, across every tool.
pub const HOST_ARGS: &[&str] = &["host", "source_host", "dest_host"];

/// The host names a call's raw arguments target ([`HOST_ARGS`]): each as
/// typed and, when it resolves, its inventory name and every alias — so
/// a host kill set under any of a host's names catches a call that uses
/// another.
pub fn hosts_in(args: &serde_json::Value, inv: &crate::inventory::Inventory) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    };
    for typed in HOST_ARGS.iter().filter_map(|k| args.get(*k)?.as_str()) {
        add(typed);
        if let Some(c) = inv.canonical(typed) {
            add(c);
            if let Ok(h) = inv.get(c) {
                h.aliases.iter().for_each(|a| add(a));
            }
        }
    }
    out
}

/// Where the kill files are.
#[derive(Clone, Debug)]
pub struct KillSwitch {
    file: PathBuf,
    dir: PathBuf,
    /// The switches set over HTTP; `None`: that endpoint can't set any.
    api: Option<PathBuf>,
}

impl Default for KillSwitch {
    /// `/etc/prompto/kill`, `/etc/prompto/kill.d` and
    /// `/var/lib/prompto/kill.d`.
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_FILE), None).with_api_dir(Some(DEFAULT_API_DIR.into()))
    }
}

impl KillSwitch {
    /// The global file and the directory of scoped ones (default:
    /// `<file>.d`).
    pub fn new(file: PathBuf, dir: Option<PathBuf>) -> Self {
        let dir = dir.unwrap_or_else(|| {
            let mut d = file.clone().into_os_string();
            d.push(".d");
            d.into()
        });
        Self {
            file,
            dir,
            api: None,
        }
    }

    /// The directory of the switches set over HTTP.
    pub fn with_api_dir(mut self, api: Option<PathBuf>) -> Self {
        self.api = api;
        self
    }

    /// `<dir>/kill`, `<dir>/kill.d` and `<dir>/api-kill.d` (tests).
    pub fn in_dir(dir: &Path) -> Self {
        Self::new(dir.join("kill"), None).with_api_dir(Some(dir.join("api-kill.d")))
    }

    /// `PROMPTO_KILL_FILE`, `PROMPTO_KILL_DIR` and `PROMPTO_KILL_API_DIR`.
    pub fn from_env() -> Self {
        let get = |k| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self::new(
            get("PROMPTO_KILL_FILE").unwrap_or_else(|| PathBuf::from(DEFAULT_FILE)),
            get("PROMPTO_KILL_DIR"),
        )
        .with_api_dir(Some(
            get("PROMPTO_KILL_API_DIR").unwrap_or_else(|| PathBuf::from(DEFAULT_API_DIR)),
        ))
    }

    pub fn api_dir(&self) -> Option<&Path> {
        self.api.as_deref()
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file for a kill switch. Validates the name.
    pub fn path(&self, scope: Scope, name: Option<&str>) -> Result<PathBuf> {
        match (scope, name) {
            (Scope::Global, None) => Ok(self.file.clone()),
            (Scope::Global, Some(_)) => bail!("the global kill takes no name"),
            (Scope::AgentSession, _) => {
                bail!("an agent's session kill is set over HTTP (set_agent_session)")
            }
            (_, None) => bail!("a {} kill needs a name", scope.as_str()),
            (_, Some(n)) => {
                validate(scope, n)?;
                Ok(self.dir.join(format!("{}{n}", scope.prefix())))
            }
        }
    }

    /// The global kill, if set.
    pub fn global(&self) -> Option<Kill> {
        read(&self.file, Scope::Global, None)
    }

    /// The kill switch for one agent, host or session, if set. An invalid
    /// name has no file, so it is never killed.
    pub fn named(&self, scope: Scope, name: &str) -> Option<Kill> {
        let path = self.path(scope, Some(name)).ok()?;
        read(&path, scope, Some(name))
    }

    /// The global kill set over HTTP, if set.
    pub fn api_global(&self) -> Option<Kill> {
        read(&self.api.as_ref()?.join(API_GLOBAL), Scope::Global, None)
    }

    /// The file of agent `agent`'s kill of session `session`. Validates
    /// both: agent names have no `.`, so the name is unambiguous.
    fn agent_session_path(&self, agent: &str, session: &str) -> Result<PathBuf> {
        let api = self
            .api
            .as_ref()
            .context("no directory for kill switches set over HTTP")?;
        crate::agent::validate_name("agent", agent)?;
        validate(Scope::Session, session)?;
        Ok(api.join(format!("session-{agent}.{session}")))
    }

    /// The file of a switch set over HTTP: `Global`, or `AgentSession`
    /// with the agent and the session.
    pub fn api_path(
        &self,
        scope: Scope,
        agent: Option<&str>,
        session: Option<&str>,
    ) -> Result<PathBuf> {
        match (scope, agent, session) {
            (Scope::Global, None, None) => Ok(self
                .api
                .as_ref()
                .context("no directory for kill switches set over HTTP")?
                .join(API_GLOBAL)),
            (Scope::AgentSession, Some(a), Some(s)) => self.agent_session_path(a, s),
            _ => bail!("only a global or an agent's session kill is set over HTTP"),
        }
    }

    /// Agent `agent`'s kill of its session `session`, if set.
    pub fn agent_session(&self, agent: &str, session: &str) -> Option<Kill> {
        let path = self.agent_session_path(agent, session).ok()?;
        read(&path, Scope::AgentSession, Some(session)).map(|k| Kill {
            agent: Some(agent.to_string()),
            ..k
        })
    }

    /// The kill switch that stops this call, if any: global first (the
    /// file, then the one set over HTTP), then the agent, the session,
    /// the agent's own kill of that session and each host.
    pub fn check(&self, s: &Subject) -> Option<Kill> {
        self.global()
            .or_else(|| self.api_global())
            .or_else(|| s.agent.and_then(|a| self.named(Scope::Agent, a)))
            .or_else(|| s.session.and_then(|id| self.named(Scope::Session, id)))
            .or_else(|| {
                s.agent
                    .zip(s.session)
                    .and_then(|(a, id)| self.agent_session(a, id))
            })
            .or_else(|| s.hosts.iter().find_map(|h| self.named(Scope::Host, h)))
    }

    /// Set the global kill over HTTP (the caller checked the approver).
    pub fn set_api_global(&self, reason: &str) -> Result<PathBuf> {
        let api = self
            .api
            .as_ref()
            .context("no directory for kill switches set over HTTP")?;
        create_private_dir(api)?;
        let path = api.join(API_GLOBAL);
        write_switch(&path, reason, 0o600)?;
        Ok(path)
    }

    /// Agent `agent` stops its own session `session`. Refuses with
    /// [`Full`] when the agent already has [`MAX_SESSION_KILLS_PER_AGENT`]
    /// live ones, or the directory [`MAX_API_KILLS`] files (setting one
    /// that is already set is always fine: it only rewrites the reason).
    pub fn set_agent_session(&self, agent: &str, session: &str, reason: &str) -> Result<PathBuf> {
        let path = self.agent_session_path(agent, session)?;
        create_private_dir(path.parent().context("kill file has no directory")?)?;
        let _one = API_WRITE.lock().unwrap_or_else(|e| e.into_inner());
        if std::fs::symlink_metadata(&path).is_err() {
            let (global, pairs, other) = self.api_entries()?;
            let mine = pairs.iter().filter(|(a, _)| a == agent).count();
            if mine >= MAX_SESSION_KILLS_PER_AGENT {
                return Err(Full(format!(
                    "agent {agent} already has {mine} session kills in place (at most \
                     {MAX_SESSION_KILLS_PER_AGENT}); an operator lifts them with `prompto unkill \
                     session <id>`"
                ))
                .into());
            }
            let all = usize::from(global) + pairs.len() + other.len();
            if all >= MAX_API_KILLS {
                return Err(Full(format!(
                    "the HTTP kill directory holds {all} switches (at most {MAX_API_KILLS}); an \
                     operator lifts some with `prompto unkill session <id>`"
                ))
                .into());
            }
        }
        write_switch(&path, reason, 0o600)?;
        Ok(path)
    }

    /// `prompto kill off`'s second half: lift the global kill set over
    /// HTTP. `Ok(false)`: it wasn't set.
    pub fn clear_api_global(&self) -> Result<bool> {
        match &self.api {
            Some(api) => remove(&api.join(API_GLOBAL)),
            None => Ok(false),
        }
    }

    /// `prompto unkill session <id>`'s second half: lift every agent's
    /// kill of that session. Returns the agents whose kill was lifted.
    pub fn clear_agent_sessions(&self, session: &str) -> Result<Vec<String>> {
        validate(Scope::Session, session)?;
        let mut lifted = vec![];
        for (agent, sess) in self.api_entries()?.1 {
            if sess == session && remove(&self.agent_session_path(&agent, &sess)?)? {
                lifted.push(agent);
            }
        }
        Ok(lifted)
    }

    /// The API directory's switches: whether `global` is there, and each
    /// valid `session-<agent>.<session>`, sorted. Other files are ignored
    /// (and returned as the third element).
    #[allow(clippy::type_complexity)]
    fn api_entries(&self) -> Result<(bool, Vec<(String, String)>, Vec<String>)> {
        let Some(api) = &self.api else {
            return Ok((false, vec![], vec![]));
        };
        let entries = match std::fs::read_dir(api) {
            Ok(e) => e,
            Err(e) if absent(&e) => return Ok((false, vec![], vec![])),
            Err(e) => return Err(e).with_context(|| format!("reading {}", api.display())),
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let (mut global, mut pairs, mut ignored) = (false, vec![], vec![]);
        for f in names {
            if f == API_GLOBAL {
                global = true;
                continue;
            }
            let pair = f
                .strip_prefix("session-")
                .and_then(|r| r.split_once('.'))
                .filter(|(a, s)| {
                    crate::agent::validate_name("agent", a).is_ok()
                        && validate(Scope::Session, s).is_ok()
                });
            match pair {
                Some((a, s)) => pairs.push((a.to_string(), s.to_string())),
                None => ignored.push(f),
            }
        }
        Ok((global, pairs, ignored))
    }

    /// Every active kill switch, global first, and the files in `kill.d`
    /// that are not kill switches (bad prefix or name), which are ignored.
    pub fn list(&self) -> Result<(Vec<Kill>, Vec<String>)> {
        let mut kills: Vec<Kill> = self.global().into_iter().collect();
        let mut ignored = Vec::new();
        let mut names: Vec<String> = match std::fs::read_dir(&self.dir) {
            Ok(e) => e
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        names.sort();
        for file in names {
            let found = Scope::NAMED.iter().find_map(|&scope| {
                let name = file.strip_prefix(scope.prefix())?;
                validate(scope, name).ok()?;
                self.named(scope, name)
            });
            match found {
                Some(k) => kills.push(k),
                None => ignored.push(file),
            }
        }
        let (global, pairs, other) = self.api_entries()?;
        if global && let Some(k) = self.api_global() {
            kills.insert(
                usize::from(!kills.is_empty() && kills[0].scope == Scope::Global),
                k,
            );
        }
        for (a, s) in pairs {
            kills.extend(self.agent_session(&a, &s));
        }
        if let Some(api) = &self.api {
            ignored.extend(other.into_iter().map(|f| api.join(f).display().to_string()));
        }
        Ok((kills, ignored))
    }

    /// Set a kill switch (`reason` may be empty). Creates `kill.d` if
    /// needed. The file is written whole, then renamed into place, mode
    /// 0644: the reason is not a secret and the server must read it.
    pub fn set(&self, scope: Scope, name: Option<&str>, reason: &str) -> Result<PathBuf> {
        let path = self.path(scope, name)?;
        let parent = path.parent().context("kill file has no directory")?;
        if scope != Scope::Global {
            create_dir(parent)?;
        }
        write_switch(&path, reason, 0o644)?;
        Ok(path)
    }

    /// Lift a kill switch. `Ok(false)`: it wasn't set.
    pub fn clear(&self, scope: Scope, name: Option<&str>) -> Result<bool> {
        remove(&self.path(scope, name)?)
    }

    /// Can this process check every kill switch? The global file, the
    /// directory and a name inside it (which needs search permission on
    /// `kill.d`) are `stat`ed exactly as a call would. `Err` names the
    /// path and the error; the server refuses to start on it (see the
    /// module docs).
    pub fn probe(&self) -> std::result::Result<(), String> {
        // `.probe` is never a valid switch name, so it is normally absent.
        let mut paths = vec![self.file.clone(), self.dir.clone(), self.dir.join(".probe")];
        if let Some(api) = &self.api {
            paths.extend([api.clone(), api.join(".probe")]);
        }
        for p in &paths {
            if let Err(e) = std::fs::metadata(p)
                && !absent(&e)
            {
                return Err(format!("{}: {e}", p.display()));
            }
        }
        Ok(())
    }
}

/// Write a switch whole, then rename it into place, mode `mode`: 0644
/// for the operator's (the reason is not a secret and the server must
/// read it), 0600 for the server's own. Newlines in the reason become
/// spaces.
fn write_switch(path: &Path, reason: &str, mode: u32) -> Result<()> {
    let parent = path.parent().context("kill file has no directory")?;
    let reason: String = reason
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let body = if reason.trim().is_empty() {
        String::new()
    } else {
        format!("{}\n", reason.trim())
    };
    let tmp = parent.join(format!(
        ".{}.tmp{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let write = || -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        // Whatever the umask said.
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        std::fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

/// Remove a switch. `Ok(false)`: it wasn't there.
fn remove(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

fn create_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o755).create(dir) {
        // Whatever the umask said: a server not running as root must be
        // able to look inside, or scoped kills silently stop working.
        Ok(()) => {
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .with_context(|| format!("chmod {}", dir.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("creating {}", dir.display())),
    }
}

/// The API directory: the service's own, mode 0700. One made by an
/// older prompto (0755) is tightened when this process owns it.
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", dir.display())),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
            // SAFETY: geteuid has no preconditions and cannot fail.
            if meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod {}", dir.display()))?;
            }
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", dir.display())),
    }
}

/// The file isn't there (or a path component isn't a directory).
fn absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// The kill switch at `path`, if the file exists — or if it can't be
/// told whether it exists (fail closed).
fn read(path: &Path, scope: Scope, target: Option<&str>) -> Option<Kill> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if absent(&e) => return None,
        Err(e) => {
            unreadable(path, &e);
            return Some(Kill {
                scope,
                target: target.map(str::to_string),
                agent: None,
                since: None,
                reason: sanitize_reason(&format!(
                    "kill switch unreadable: {}: {e}",
                    path.display()
                )),
                unreadable: true,
            });
        }
    };
    let since = meta.modified().ok().map(rfc3339);
    // The reason is best effort: a file the server can stat but not read
    // (mode 0600 root) still kills, without a reason.
    let reason = std::fs::File::open(path).ok().and_then(|f| {
        let mut buf = Vec::new();
        f.take(READ_LIMIT).read_to_end(&mut buf).ok()?;
        sanitize_reason(&String::from_utf8_lossy(&buf))
    });
    Some(Kill {
        scope,
        target: target.map(str::to_string),
        agent: None,
        since,
        reason,
        unreadable: false,
    })
}

/// `raw`'s first line with tabs as spaces and control and formatting
/// characters dropped, trimmed; `None` when nothing is left.
pub fn sanitize_line(raw: &str) -> Option<String> {
    let line = raw.lines().next().unwrap_or("");
    let clean: String = line
        .chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|&c| !crate::audit::is_terminal_hazard(c))
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_string())
}

/// A kill file's first line, fit to show an agent and a terminal:
/// control and formatting characters dropped, at most [`MAX_REASON`]
/// chars. `None` when nothing is left.
pub fn sanitize_reason(raw: &str) -> Option<String> {
    let clean = sanitize_line(raw)?;
    if clean.chars().count() <= MAX_REASON {
        return Some(clean);
    }
    let mut t: String = clean.chars().take(MAX_REASON - 1).collect();
    t.push('…');
    Some(t)
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Log, at most once a minute, that a kill file can't be checked (each
/// call it refuses is logged and audited on its own).
fn unreadable(path: &Path, e: &io::Error) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 60
        && LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::error!(
            path = %path.display(),
            error = %e,
            "KILL SWITCH UNREADABLE — every call it applies to is REFUSED (killed, fail closed) \
             until prompto can stat this path again (fix the permissions)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> (tempfile::TempDir, KillSwitch) {
        let d = tempfile::tempdir().unwrap();
        let k = KillSwitch::in_dir(d.path());
        (d, k)
    }

    #[test]
    fn default_paths() {
        let k = KillSwitch::default();
        assert_eq!(k.file(), Path::new("/etc/prompto/kill"));
        assert_eq!(k.dir(), Path::new("/etc/prompto/kill.d"));
        let k = KillSwitch::new("/x/stop".into(), Some("/y".into()));
        assert_eq!(k.dir(), Path::new("/y"));
    }

    #[test]
    fn global_on_and_off_with_reason_and_time() {
        let (_d, k) = ks();
        assert_eq!(k.global(), None);
        k.set(Scope::Global, None, "incident 42\nsecond line")
            .unwrap();
        let g = k.global().expect("set");
        assert_eq!(g.scope, Scope::Global);
        assert_eq!(g.reason.as_deref(), Some("incident 42 second line"));
        assert!(g.since.as_deref().unwrap().ends_with('Z'), "{g:?}");
        let msg = g.message();
        assert!(msg.contains("every prompto tool call"), "{msg}");
        assert!(msg.contains("reason: incident 42"), "{msg}");
        assert!(msg.contains("prompto kill off"), "{msg}");
        assert!(k.clear(Scope::Global, None).unwrap());
        assert!(!k.clear(Scope::Global, None).unwrap());
        assert_eq!(k.global(), None);
    }

    #[test]
    fn a_hand_made_empty_file_kills_without_a_reason() {
        let (_d, k) = ks();
        std::fs::write(k.file(), "").unwrap();
        let g = k.global().unwrap();
        assert_eq!(g.reason, None);
        assert!(!g.message().contains("reason"));
        // Written by hand into kill.d: same effect as the CLI.
        std::fs::create_dir(k.dir()).unwrap();
        std::fs::write(k.dir().join("host-web1"), "disk\n").unwrap();
        let h = k.named(Scope::Host, "web1").unwrap();
        assert_eq!(h.reason.as_deref(), Some("disk"));
    }

    #[test]
    fn reasons_are_bounded_and_cleaned() {
        assert_eq!(sanitize_reason("  \n"), None);
        assert_eq!(
            sanitize_reason("a\x1b]0;x\x07b\u{202e}c\td\r\nnext").as_deref(),
            Some("a]0;xbc d")
        );
        let long = "é".repeat(1000);
        let r = sanitize_reason(&long).unwrap();
        assert_eq!(r.chars().count(), MAX_REASON);
        assert!(r.ends_with('…'));
        // Only the first READ_LIMIT bytes are read.
        let (_d, k) = ks();
        std::fs::write(k.file(), "x".repeat(1 << 20)).unwrap();
        assert_eq!(
            k.global().unwrap().reason.unwrap().chars().count(),
            MAX_REASON
        );
    }

    #[test]
    fn each_scope_matches_only_its_target() {
        let (_d, k) = ks();
        k.set(Scope::Agent, Some("dev"), "").unwrap();
        k.set(Scope::Host, Some("web1"), "").unwrap();
        k.set(Scope::Session, Some("s-1"), "").unwrap();
        let check = |agent, session, hosts: &[&str]| {
            k.check(&Subject {
                agent,
                session,
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
            })
            .map(|k| (k.scope, k.target.unwrap_or_default()))
        };
        assert_eq!(check(Some("ops"), Some("s-2"), &["web2"]), None);
        assert_eq!(check(None, None, &[]), None);
        assert_eq!(
            check(Some("dev"), None, &[]),
            Some((Scope::Agent, "dev".into()))
        );
        assert_eq!(
            check(Some("ops"), Some("s-1"), &[]),
            Some((Scope::Session, "s-1".into()))
        );
        assert_eq!(
            check(Some("ops"), None, &["web2", "web1"]),
            Some((Scope::Host, "web1".into()))
        );
        // An agent kill doesn't touch a host or session of the same name.
        assert_eq!(check(None, Some("dev"), &["dev"]), None);
        // Global wins over everything.
        k.set(Scope::Global, None, "").unwrap();
        assert_eq!(
            check(Some("dev"), None, &["web1"]).map(|k| k.0),
            Some(Scope::Global)
        );
        let (kills, ignored) = k.list().unwrap();
        let scopes: Vec<_> = kills.iter().map(|k| k.scope).collect();
        assert_eq!(
            scopes,
            [Scope::Global, Scope::Agent, Scope::Host, Scope::Session]
        );
        assert!(ignored.is_empty(), "{ignored:?}");
        for (s, n) in [
            (Scope::Agent, "dev"),
            (Scope::Host, "web1"),
            (Scope::Session, "s-1"),
        ] {
            assert!(k.clear(s, Some(n)).unwrap());
        }
        assert!(k.clear(Scope::Global, None).unwrap());
        assert_eq!(check(Some("dev"), Some("s-1"), &["web1"]), None);
    }

    /// No name can reach outside `kill.d`, from the CLI or from a call.
    #[test]
    fn names_cannot_escape_the_directory() {
        let (d, k) = ks();
        for bad in [
            "../kill",
            "..",
            ".",
            "a/b",
            "/etc/passwd",
            ".hidden",
            "",
            "a b",
            "a\0b",
            "-x",
        ] {
            for s in Scope::NAMED {
                assert!(k.set(s, Some(bad), "").is_err(), "{s:?} {bad:?} accepted");
                assert!(k.clear(s, Some(bad)).is_err(), "{s:?} {bad:?} accepted");
            }
        }
        assert!(k.set(Scope::Global, Some("x"), "").is_err());
        assert!(k.set(Scope::Host, None, "").is_err());
        // Nothing was created anywhere.
        let left: Vec<_> = std::fs::read_dir(d.path()).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
        // A call naming `../kill` as its host must not hit the global
        // file through `kill.d/host-../kill`.
        std::fs::create_dir_all(k.dir().join("host-..")).unwrap();
        std::fs::write(d.path().join("kill.d").join("host-..").join("x"), "").unwrap();
        assert_eq!(k.named(Scope::Host, "../x"), None);
        assert_eq!(k.named(Scope::Host, "host-../x"), None);
        // Valid odd names are fine.
        k.set(Scope::Session, Some("a1:b.c_d-e"), "").unwrap();
        assert!(k.named(Scope::Session, "a1:b.c_d-e").is_some());
        // Unknown files in kill.d are listed as ignored, not as kills.
        std::fs::write(k.dir().join("hots-web1"), "").unwrap();
        let (kills, ignored) = k.list().unwrap();
        assert_eq!(kills.len(), 1);
        assert_eq!(ignored, ["host-..", "hots-web1"]);
    }

    #[test]
    fn files_are_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, k) = ks();
        let p = k.set(Scope::Host, Some("web1"), "r").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let dmode = std::fs::metadata(k.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o755);
    }

    /// A switch that can't be checked refuses (fail closed), at every
    /// scope, and `probe` reports it. A symlink loop gives `ELOOP` even
    /// as root, on Linux and macOS alike.
    #[test]
    fn an_uncheckable_switch_kills() {
        let (d, k) = ks();
        std::os::unix::fs::symlink("kill", k.file()).unwrap();
        let g = k.global().expect("unreadable global must kill");
        assert!(g.unreadable, "{g:?}");
        assert_eq!(g.since, None);
        let r = g.reason.as_deref().unwrap();
        assert!(r.starts_with("kill switch unreadable: "), "{r}");
        assert!(r.contains(&*k.file().to_string_lossy()), "{r}");
        let msg = g.message();
        assert!(msg.contains("fails closed"), "{msg}");
        assert!(msg.contains("kill switch unreadable"), "{msg}");
        assert!(k.probe().unwrap_err().contains("kill"), "probe");
        assert_eq!(serde_json::to_value(&g).unwrap()["unreadable"], true);
        std::fs::remove_file(k.file()).unwrap();
        assert_eq!(k.global(), None);
        assert_eq!(k.probe(), Ok(()));

        // kill.d itself: every scoped check that needs it refuses.
        std::os::unix::fs::symlink("kill.d", k.dir()).unwrap();
        assert!(k.probe().is_err());
        let s = Subject {
            agent: Some("dev"),
            ..Default::default()
        };
        let got = k.check(&s).expect("unreadable kill.d must kill");
        assert_eq!((got.scope, got.unreadable), (Scope::Agent, true));
        // A call that needs no file in kill.d is not affected.
        assert_eq!(k.check(&Subject::default()), None);
        drop(d);
    }

    /// Permission denied on `kill.d` (search bit off): `probe` sees it
    /// although `kill.d` itself can be stat'ed, and calls are refused.
    /// Root ignores modes, so this one only runs unprivileged.
    #[test]
    fn a_kill_dir_without_search_permission_is_uncheckable() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_d, k) = ks();
        std::fs::create_dir(k.dir()).unwrap();
        std::fs::set_permissions(k.dir(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let probe = k.probe();
        let got = k.named(Scope::Host, "web1");
        std::fs::set_permissions(k.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(probe.unwrap_err().contains(".probe"), "probe");
        assert!(got.expect("must kill").unreadable);
        assert_eq!(k.probe(), Ok(()));
    }

    #[test]
    fn probe_reports_only_real_errors() {
        let (d, k) = ks();
        assert_eq!(k.probe(), Ok(()));
        // A path whose parent is a file: absent, not an error.
        std::fs::write(d.path().join("f"), "").unwrap();
        let k = KillSwitch::new(d.path().join("f").join("kill"), None);
        assert_eq!(k.probe(), Ok(()));
        assert_eq!(k.global(), None);
    }

    fn subject<'a>(agent: &'a str, session: &'a str) -> Subject<'a> {
        Subject {
            agent: Some(agent),
            session: Some(session),
            hosts: vec![],
        }
    }

    #[test]
    fn an_agents_session_kill_stops_that_agent_in_that_session_only() {
        let (_d, k) = ks();
        assert_eq!(k.check(&subject("alpha", "s1")), None);
        k.set_agent_session("alpha", "s1", "runaway").unwrap();
        let hit = k.check(&subject("alpha", "s1")).expect("killed");
        assert_eq!(hit.scope, Scope::AgentSession);
        assert_eq!(hit.agent.as_deref(), Some("alpha"));
        assert_eq!(hit.target.as_deref(), Some("s1"));
        assert!(hit.message().contains("agent alpha in session s1"));
        assert_eq!(k.check(&subject("alpha", "s2")), None);
        assert_eq!(k.check(&subject("beta", "s1")), None);
        // Listed, and lifted by `unkill session`.
        let (kills, ignored) = k.list().unwrap();
        assert_eq!(kills, vec![hit]);
        assert!(ignored.is_empty());
        assert_eq!(k.clear_agent_sessions("s2").unwrap(), Vec::<String>::new());
        assert_eq!(k.clear_agent_sessions("s1").unwrap(), vec!["alpha"]);
        assert_eq!(k.check(&subject("alpha", "s1")), None);
        // Names that could escape the directory are refused.
        assert!(k.set_agent_session("al.pha", "s1", "").is_err());
        assert!(k.set_agent_session("alpha", "../s1", "").is_err());
        assert!(k.set_agent_session("alpha", ".s1", "").is_err());
    }

    #[test]
    fn a_global_kill_set_over_http_stops_everything() {
        let (_d, k) = ks();
        k.set_api_global("panic").unwrap();
        let hit = k.check(&Subject::default()).expect("killed");
        assert_eq!(hit.scope, Scope::Global);
        assert_eq!(hit.reason.as_deref(), Some("panic"));
        // Listed next to the file's own global kill.
        k.set(Scope::Global, None, "file").unwrap();
        let reasons: Vec<_> = k.list().unwrap().0.into_iter().map(|k| k.reason).collect();
        assert_eq!(reasons, vec![Some("file".into()), Some("panic".into())]);
        k.clear(Scope::Global, None).unwrap();
        assert!(
            k.check(&Subject::default()).is_some(),
            "the HTTP one is still on"
        );
        assert!(k.clear_api_global().unwrap());
        assert!(!k.clear_api_global().unwrap());
        assert_eq!(k.check(&Subject::default()), None);
    }

    #[test]
    fn without_an_api_directory_nothing_is_set_over_http() {
        let d = tempfile::tempdir().unwrap();
        let k = KillSwitch::new(d.path().join("kill"), None);
        assert!(k.set_api_global("x").is_err());
        assert!(k.set_agent_session("alpha", "s1", "x").is_err());
        assert!(!k.clear_api_global().unwrap());
        assert_eq!(k.check(&subject("alpha", "s1")), None);
    }

    #[test]
    fn an_api_directory_that_cant_be_checked_fails_closed() {
        let (d, k) = ks();
        // A symlink loop: stat fails with ELOOP, as root too.
        std::os::unix::fs::symlink("api-kill.d", d.path().join("api-kill.d")).unwrap();
        assert!(k.probe().unwrap_err().contains("api-kill.d"));
        let hit = k.check(&Subject::default()).expect("fails closed");
        assert!(hit.unreadable);
    }

    #[test]
    fn the_api_directory_is_private_to_the_service() {
        use std::os::unix::fs::PermissionsExt;
        let (d, k) = ks();
        let api = d.path().join("api-kill.d");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let p = k.set_agent_session("alpha", "s1", "r").unwrap();
        assert_eq!(mode(&api), 0o700, "as created");
        let g = k.set_api_global("r").unwrap();
        assert_eq!((mode(&p), mode(&g), mode(&api)), (0o600, 0o600, 0o700));
        // One an older prompto made world-readable is tightened.
        std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o755)).unwrap();
        k.set_agent_session("alpha", "s2", "r").unwrap();
        assert_eq!(mode(&api), 0o700);
        // The server still reads its own switches.
        assert!(k.check(&subject("alpha", "s1")).is_some());
    }

    #[test]
    fn session_kills_over_http_are_capped() {
        let (d, k) = ks();
        for i in 0..MAX_SESSION_KILLS_PER_AGENT {
            k.set_agent_session("alpha", &format!("s{i}"), "r").unwrap();
        }
        let e = k.set_agent_session("alpha", "one-more", "r").unwrap_err();
        assert!(e.downcast_ref::<Full>().is_some(), "{e:#}");
        assert!(format!("{e}").contains("alpha already has 100"), "{e}");
        assert!(k.agent_session("alpha", "one-more").is_none());
        // Setting one already set only rewrites it.
        k.set_agent_session("alpha", "s0", "again").unwrap();
        // Another agent has its own allowance...
        k.set_agent_session("beta", "s0", "r").unwrap();
        // ...within the directory's.
        let api = d.path().join("api-kill.d");
        for i in 0..MAX_API_KILLS {
            std::fs::write(api.join(format!("junk{i}")), "").unwrap();
        }
        let e = k.set_agent_session("gamma", "s0", "r").unwrap_err();
        assert!(e.downcast_ref::<Full>().is_some(), "{e:#}");
        assert!(format!("{e}").contains("holds"), "{e}");
    }

    #[test]
    fn junk_in_the_api_directory_is_ignored() {
        let (d, k) = ks();
        let api = d.path().join("api-kill.d");
        std::fs::create_dir(&api).unwrap();
        for f in ["session-noagent", "session-a.b/c", "other"] {
            let _ = std::fs::write(api.join(f), "");
        }
        let (kills, ignored) = k.list().unwrap();
        assert!(kills.is_empty(), "{kills:?}");
        assert_eq!(ignored.len(), 2, "{ignored:?}");
    }
}
