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
//! A file that can't be checked (permission denied on the directory) does
//! **not** stop calls: making the box that controls every other box fall
//! over because of a directory mode would be a new failure mode for
//! deployments that never use kill switches. It is logged as an error
//! instead, at startup and then at most once a minute, and `prompto kill
//! status` reports it.
//!
//! Names are validated before they become file names ([`validate`]): no
//! `/`, no leading `.`, so `kill host ../x` can't reach outside `kill.d`.
//! A call naming a host that isn't a valid file name can't match a file
//! and is not looked up.

use crate::error_class::{ClassifiedError, ErrorClass};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Default global kill file.
pub const DEFAULT_FILE: &str = "/etc/prompto/kill";
/// Longest reason shown, in chars.
pub const MAX_REASON: usize = 200;
/// Bytes read from a kill file to find its first line.
const READ_LIMIT: u64 = 4096;

/// What a kill switch applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Global,
    Agent,
    Host,
    Session,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Agent => "agent",
            Scope::Host => "host",
            Scope::Session => "session",
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
            Scope::Session => "session-",
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
        Scope::Host | Scope::Session => {
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
    /// When it was set (the file's mtime), RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// The file's first line: bounded, control characters removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
        };
        let mut detail = format!("{} kill switch", self.scope.as_str());
        if let Some(s) = &self.since {
            detail.push_str(&format!(", set {s}"));
        }
        if let Some(r) = &self.reason {
            detail.push_str(&format!(", reason: {r}"));
        }
        format!(
            "refused: the operator has stopped {what} ({detail}). Nothing was run. This is \
             deliberate, not a fault: do not retry or work around it; stop and tell the user. \
             An operator lifts it with `{lift}`."
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
pub const HOST_ARGS: &[&str] = &["host", "client", "source_host", "dest_host"];

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
}

impl Default for KillSwitch {
    /// `/etc/prompto/kill` and `/etc/prompto/kill.d`.
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_FILE), None)
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
        Self { file, dir }
    }

    /// `<dir>/kill` and `<dir>/kill.d` (tests).
    pub fn in_dir(dir: &Path) -> Self {
        Self::new(dir.join("kill"), None)
    }

    /// `PROMPTO_KILL_FILE` and `PROMPTO_KILL_DIR`.
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

    /// The kill switch that stops this call, if any: global first, then
    /// the agent, the session and each host.
    pub fn check(&self, s: &Subject) -> Option<Kill> {
        self.global()
            .or_else(|| s.agent.and_then(|a| self.named(Scope::Agent, a)))
            .or_else(|| s.session.and_then(|id| self.named(Scope::Session, id)))
            .or_else(|| s.hosts.iter().find_map(|h| self.named(Scope::Host, h)))
    }

    /// Every active kill switch, global first, and the files in `kill.d`
    /// that are not kill switches (bad prefix or name), which are ignored.
    pub fn list(&self) -> Result<(Vec<Kill>, Vec<String>)> {
        let mut kills: Vec<Kill> = self.global().into_iter().collect();
        let mut ignored = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((kills, ignored)),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
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
                .mode(0o644)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            // Whatever the umask said.
            std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
            std::fs::rename(&tmp, &path)
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("writing {}", path.display()));
        }
        Ok(path)
    }

    /// Lift a kill switch. `Ok(false)`: it wasn't set.
    pub fn clear(&self, scope: Scope, name: Option<&str>) -> Result<bool> {
        let path = self.path(scope, name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// Can the server see the kill files? `Err` describes what it can't
    /// check (logged at startup; see the module docs).
    pub fn probe(&self) -> std::result::Result<(), String> {
        for p in [&self.file, &self.dir] {
            if let Err(e) = std::fs::symlink_metadata(p)
                && !absent(&e)
            {
                return Err(format!("{}: {e}", p.display()));
            }
        }
        Ok(())
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

/// The file isn't there (or a path component isn't a directory).
fn absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// The kill switch at `path`, if the file exists.
fn read(path: &Path, scope: Scope, target: Option<&str>) -> Option<Kill> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if absent(&e) => return None,
        Err(e) => {
            unreadable(path, &e);
            return None;
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
        since,
        reason,
    })
}

/// A kill file's first line, fit to show an agent and a terminal:
/// control and formatting characters dropped, at most [`MAX_REASON`]
/// chars. `None` when nothing is left.
pub fn sanitize_reason(raw: &str) -> Option<String> {
    let line = raw.lines().next().unwrap_or("");
    let clean: String = line
        .chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|&c| !crate::audit::is_terminal_hazard(c))
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        return None;
    }
    if clean.chars().count() <= MAX_REASON {
        return Some(clean.to_string());
    }
    let mut t: String = clean.chars().take(MAX_REASON - 1).collect();
    t.push('…');
    Some(t)
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Log, at most once a minute, that a kill file can't be checked.
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
            "CANNOT CHECK KILL SWITCH — calls are NOT stopped by it until prompto can stat this \
             path (fix the directory's permissions)"
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
}
