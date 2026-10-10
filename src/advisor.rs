//! Per-tool usage advisor — appends a one-line hint to a result when a
//! known anti-pattern fires.
//!
//! This is the active-feedback alternative to teaching via tool descriptions.
//! Tool descriptions get paid every turn (system prompt overhead, even when
//! the tool isn't used). Hints get paid only when the bad pattern actually
//! occurs — but each one still costs context, so they are kept short (one
//! line, at most [`MAX_HINT_BYTES`]) and rare.
//!
//! Rules (deliberately conservative), at most one hint per call:
//!   - an `ssh_exec` / `ssh_sudo_exec` whose command is a *simple* instance
//!     of a typed tool ([`typed_tool`]: `cat <path>` → `file_read`,
//!     `systemctl restart <unit>` → `service_control`, …). Compound shell
//!     never matches.
//!   - 4+ ssh_exec calls to the same host within 90s → suggest ssh_batch.
//!   - 3+ file_write calls to the same host within 60s → suggest rsync_sync.
//!
//! Each distinct hint fires at most once per caller per [`COOLDOWN`]. The
//! caller is the session (`X-Prompto-Session`), or the agent and client IP
//! when there is none ([`Advisor::who`]); calls are counted per caller too.
//!
//! In-memory only: state and counters are per prompto process and reset on
//! restart. The audit record of a call that got a hint names its pattern
//! (`advisor`), which is what survives. Counters are in `prompto_gain`.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW_SSH_EXEC: Duration = Duration::from_secs(90);
const THRESHOLD_SSH_EXEC: usize = 4;

const WINDOW_FILE_WRITE: Duration = Duration::from_secs(60);
const THRESHOLD_FILE_WRITE: usize = 3;

/// One hint per caller per this long.
pub const COOLDOWN: Duration = Duration::from_secs(3600);

/// The longest a hint block (`[advisor] …`) may be.
pub const MAX_HINT_BYTES: usize = 120;

const RING_CAP: usize = 256;

/// Past this many (caller, hint) entries, expired ones are dropped.
const LAST_HINT_PRUNE: usize = 4096;

/// A hint: the pattern that fired (for the counters and the audit
/// record) and the block appended to the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    /// What the call did: `cat`, `head_tail`, `ls`, `stat`, `systemctl`,
    /// `journalctl`, `write`, `repeated_ssh_exec`, `repeated_file_write`.
    pub pattern: &'static str,
    /// The typed tool suggested. One hint per tool: `cat` and `head_tail`
    /// share `file_read`'s, and its cooldown.
    pub tool: &'static str,
    /// The whole block, `[advisor] …`.
    pub text: &'static str,
}

const fn hint(pattern: &'static str, tool: &'static str, text: &'static str) -> Hint {
    Hint {
        pattern,
        tool,
        text,
    }
}

const FILE_READ: &str =
    "[advisor] file_read does this: typed, size-capped (max_bytes), policy-scoped.";
const FILE_LIST: &str = "[advisor] file_list does this: typed entries (mode, size, owner, mtime).";
const FILE_STAT: &str = "[advisor] file_stat does this: typed mode, size, owner, mtime, kind.";
const SERVICE_CONTROL: &str = "[advisor] service_control does this (start/stop/restart/status/…).";
const SERVICE_LOGS: &str = "[advisor] service_logs does this: journalctl -u <unit>, lines=N.";
const FILE_WRITE: &str =
    "[advisor] file_write does this: content over stdin, no quoting; mode, sudo=true for root.";
const SSH_BATCH: &str =
    "[advisor] Several ssh_exec calls to this host: ssh_batch runs them in one round-trip.";
const RSYNC_SYNC: &str =
    "[advisor] Several file_write calls: rsync_sync copies a tree in one round-trip.";

/// Every hint the advisor can give, for the tests and the counters.
pub const HINTS: &[Hint] = &[
    hint("cat", "file_read", FILE_READ),
    hint("head_tail", "file_read", FILE_READ),
    hint("ls", "file_list", FILE_LIST),
    hint("stat", "file_stat", FILE_STAT),
    hint("systemctl", "service_control", SERVICE_CONTROL),
    hint("journalctl", "service_logs", SERVICE_LOGS),
    hint("write", "file_write", FILE_WRITE),
    hint("repeated_ssh_exec", "ssh_batch", SSH_BATCH),
    hint("repeated_file_write", "rsync_sync", RSYNC_SYNC),
];

fn by_pattern(pattern: &str) -> Hint {
    *HINTS
        .iter()
        .find(|h| h.pattern == pattern)
        .expect("a pattern in HINTS")
}

/// What the advisor needs to know about one finished call.
pub struct Call<'a> {
    pub tool: &'a str,
    pub host: Option<&'a str>,
    /// `cmd` for the exec tools.
    pub cmd: Option<&'a str>,
    /// [`Advisor::who`].
    pub who: String,
    /// Only a successful result carries a hint.
    pub ok: bool,
}

#[derive(Clone)]
struct CallRecord {
    at: Instant,
    tool: String,
    host: String,
    who: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PatternStats {
    pub hints: u64,
    pub bytes: u64,
}

/// What `prompto_gain` reports under `advisor`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    /// Hints given since this process started.
    pub hints: u64,
    /// Bytes they added to results.
    pub bytes: u64,
    pub by_pattern: BTreeMap<&'static str, PatternStats>,
}

#[derive(Default)]
pub struct Advisor {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    recent: VecDeque<CallRecord>,
    /// (caller, suggested tool) → when that hint was last given.
    last_hint: HashMap<(String, &'static str), Instant>,
    stats: Stats,
}

impl Advisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whose cooldown a call counts against: its session, else its agent
    /// and client IP.
    pub fn who(session: Option<&str>, agent: &str, ip: Option<std::net::IpAddr>) -> String {
        match session {
            Some(s) => format!("session:{s}"),
            None => format!(
                "agent:{agent}@{}",
                ip.map(|i| i.to_canonical().to_string()).unwrap_or_default()
            ),
        }
    }

    /// Record a call and, if a known anti-pattern just fired and its hint
    /// is out of cooldown for this caller, return it (counted as given).
    pub fn record(&self, call: &Call) -> Option<Hint> {
        self.record_at(call, Instant::now())
    }

    fn record_at(&self, call: &Call, now: Instant) -> Option<Hint> {
        let host = call.host?;
        let mut g = self.inner.lock().ok()?;
        g.recent.push_back(CallRecord {
            at: now,
            tool: call.tool.to_owned(),
            host: host.to_owned(),
            who: call.who.clone(),
        });
        if g.recent.len() > RING_CAP {
            g.recent.pop_front();
        }
        if !call.ok {
            return None;
        }
        // First match wins: one crisp hint, never a wall of text.
        let fired = [
            call.cmd.and_then(|c| typed_tool(call.tool, c)),
            repeated(
                &g.recent,
                call,
                now,
                "ssh_exec",
                WINDOW_SSH_EXEC,
                THRESHOLD_SSH_EXEC,
            )
            .then(|| by_pattern("repeated_ssh_exec")),
            repeated(
                &g.recent,
                call,
                now,
                "file_write",
                WINDOW_FILE_WRITE,
                THRESHOLD_FILE_WRITE,
            )
            .then(|| by_pattern("repeated_file_write")),
        ];
        for h in fired.into_iter().flatten() {
            if cooldown_passed(&mut g.last_hint, &call.who, h.tool, now) {
                let s = &mut g.stats;
                s.hints += 1;
                s.bytes += h.text.len() as u64;
                let p = s.by_pattern.entry(h.pattern).or_default();
                p.hints += 1;
                p.bytes += h.text.len() as u64;
                return Some(h);
            }
        }
        None
    }

    /// The counters, since this process started.
    pub fn stats(&self) -> Stats {
        self.inner
            .lock()
            .map(|g| g.stats.clone())
            .unwrap_or_default()
    }
}

/// `call` is a `tool` call and, with it, there have been `threshold`
/// such calls by the same caller to the same host within `window`.
fn repeated(
    recent: &VecDeque<CallRecord>,
    call: &Call,
    now: Instant,
    tool: &str,
    window: Duration,
    threshold: usize,
) -> bool {
    call.tool == tool
        && recent
            .iter()
            .filter(|r| {
                r.tool == tool
                    && Some(r.host.as_str()) == call.host
                    && r.who == call.who
                    && now.duration_since(r.at) <= window
            })
            .count()
            >= threshold
}

fn cooldown_passed(
    last: &mut HashMap<(String, &'static str), Instant>,
    who: &str,
    tool: &'static str,
    now: Instant,
) -> bool {
    if last.len() > LAST_HINT_PRUNE {
        last.retain(|_, at| now.duration_since(*at) < COOLDOWN);
    }
    let key = (who.to_owned(), tool);
    match last.get(&key) {
        Some(prev) if now.duration_since(*prev) < COOLDOWN => false,
        _ => {
            last.insert(key, now);
            true
        }
    }
}

/// The typed tool an exec call's command is a simple instance of.
///
/// Simple means one command of plain words — no pipe, `&&`, `;`,
/// redirection, substitution, glob or quote — in one of the shapes below,
/// with a path the typed tool would accept (`files::validate_path`) or a
/// valid unit name. Anything else is legitimate shell and gets no hint.
/// The one multi-line shape is a write: `cat > P <<EOF` / `tee P <<EOF`,
/// a heredoc body, and its terminator as the last line.
///
/// Reads (`cat`, `head`, `tail`, `ls`, `stat`) match `ssh_exec` only:
/// `file_read` and friends can't read as root, so under `ssh_sudo_exec`
/// they are no substitute. `systemctl`, `journalctl` and writes (which
/// `file_write` does with `sudo = true`) match both, with or without a
/// leading `sudo` / `sudo -n`.
pub fn typed_tool(tool: &str, cmd: &str) -> Option<Hint> {
    if tool != "ssh_exec" && tool != "ssh_sudo_exec" {
        return None;
    }
    let cmd = cmd.trim();
    if let Some(h) = heredoc_write(cmd) {
        return Some(h);
    }
    if !cmd
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " /._-+=:,@%~".contains(c))
    {
        return None;
    }
    let words: Vec<&str> = cmd.split(' ').filter(|w| !w.is_empty()).collect();
    let (sudo, words) = strip_sudo(&words);
    let reads = tool == "ssh_exec" && !sudo;
    let path = |p: &str| !p.starts_with('-') && crate::files::validate_path(p).is_ok();
    let unit = |u: &str| !u.starts_with('-') && crate::systemd::validate_unit_name(u).is_ok();
    let pattern = match words {
        ["cat", p] if reads && path(p) => "cat",
        ["head" | "tail", p] if reads && path(p) => "head_tail",
        ["head" | "tail", n, p] if reads && path(p) && line_count(n) => "head_tail",
        ["head" | "tail", "-n", n, p] if reads && path(p) && is_number(n) => "head_tail",
        ["ls", p] if reads && path(p) => "ls",
        ["ls", f, p] if reads && path(p) && ls_flags(f) => "ls",
        ["stat", p] if reads && path(p) => "stat",
        ["systemctl", action, u] if SYSTEMCTL_ACTIONS.contains(action) && unit(u) => "systemctl",
        ["systemctl", action, "--no-pager", u] | ["systemctl", "--no-pager", action, u]
            if SYSTEMCTL_ACTIONS.contains(action) && unit(u) =>
        {
            "systemctl"
        }
        ["journalctl", rest @ ..] if journalctl_unit(rest) => "journalctl",
        _ => return None,
    };
    Some(by_pattern(pattern))
}

/// What `service_control` accepts.
const SYSTEMCTL_ACTIONS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "status",
    "is-active",
    "is-enabled",
];

fn strip_sudo<'a, 'b>(words: &'a [&'b str]) -> (bool, &'a [&'b str]) {
    match words {
        ["sudo", "-n", rest @ ..] | ["sudo", rest @ ..] => (true, rest),
        _ => (false, words),
    }
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 7 && s.chars().all(|c| c.is_ascii_digit())
}

/// `-20` or `-n20`.
fn line_count(s: &str) -> bool {
    s.strip_prefix("-n")
        .or_else(|| s.strip_prefix('-'))
        .is_some_and(is_number)
}

/// One flag group of `l`, `a`, `A`, `h`, `1`: `ls -la`.
fn ls_flags(s: &str) -> bool {
    s.strip_prefix('-')
        .is_some_and(|f| !f.is_empty() && f.chars().all(|c| "laAh1".contains(c)))
}

/// `-u <unit>` exactly once, plus only what `service_logs` also does
/// (`-n N`, `--no-pager`): `--since`, `-f`, `-b` and the rest are other
/// questions, not a simpler spelling of this one.
fn journalctl_unit(args: &[&str]) -> bool {
    let mut units = 0;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "-u" | "--unit" => match it.next() {
                Some(u) if crate::systemd::validate_unit_name(u).is_ok() && !u.starts_with('-') => {
                    units += 1
                }
                _ => return false,
            },
            "-n" | "--lines" => match it.next() {
                Some(n) if is_number(n) => {}
                _ => return false,
            },
            "--no-pager" | "-q" | "--quiet" => {}
            a if line_count(a) => {}
            a if a.strip_prefix("--lines=").is_some_and(is_number) => {}
            _ => return false,
        }
    }
    units == 1
}

/// `[sudo] cat > P <<EOF` or `[sudo] tee P [> /dev/null] <<EOF`, a body,
/// and the terminator alone on the last line.
fn heredoc_write(cmd: &str) -> Option<Hint> {
    let (first, rest) = cmd.split_once('\n')?;
    let (head, marker) = first.split_once("<<")?;
    let marker = marker.trim().trim_start_matches('-').trim();
    let word = marker
        .strip_prefix('\'')
        .and_then(|m| m.strip_suffix('\''))
        .or_else(|| marker.strip_prefix('"').and_then(|m| m.strip_suffix('"')))
        .unwrap_or(marker);
    if word.is_empty() || !word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let last = rest.trim_end_matches('\n').rsplit('\n').next()?;
    if last.trim() != word {
        return None;
    }
    // The body ends at the first terminator line: anything after it is
    // more shell.
    let body_lines = rest.trim_end_matches('\n').split('\n');
    if body_lines.clone().filter(|l| l.trim() == word).count() != 1 {
        return None;
    }
    let words: Vec<&str> = head.split_whitespace().collect();
    let (_, words) = strip_sudo(&words);
    let path = |p: &str| crate::files::validate_path(p).is_ok() && !p.starts_with('-');
    let ok = match words {
        ["cat", ">", p] | ["tee", p] | ["tee", p, ">", "/dev/null"] => path(p),
        ["cat", p] => p.strip_prefix('>').is_some_and(path),
        ["tee", p, null] => *null == ">/dev/null" && path(p),
        _ => false,
    };
    ok.then(|| by_pattern("write"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call<'a>(tool: &'a str, host: Option<&'a str>, cmd: Option<&'a str>, who: &str) -> Call<'a> {
        Call {
            tool,
            host,
            cmd,
            who: who.into(),
            ok: true,
        }
    }

    fn rec(a: &Advisor, tool: &str, host: &str) -> Option<Hint> {
        a.record(&call(tool, Some(host), None, "s1"))
    }

    #[test]
    fn hints_are_one_short_line() {
        for h in HINTS {
            assert!(
                h.text.len() <= MAX_HINT_BYTES,
                "{} bytes: {}",
                h.text.len(),
                h.text
            );
            assert!(
                h.text.starts_with("[advisor] ") && !h.text.contains('\n'),
                "{}",
                h.text
            );
            assert!(h.text.contains(h.tool), "{}", h.text);
        }
    }

    #[test]
    fn no_hint_below_threshold() {
        let a = Advisor::new();
        for _ in 0..3 {
            assert!(rec(&a, "ssh_exec", "alpha").is_none());
        }
    }

    #[test]
    fn fires_at_threshold() {
        let a = Advisor::new();
        let mut last = None;
        for _ in 0..4 {
            last = rec(&a, "ssh_exec", "alpha");
        }
        assert_eq!(last.unwrap().tool, "ssh_batch");
    }

    #[test]
    fn cooldown_suppresses_repeated_hints_for_an_hour() {
        let a = Advisor::new();
        let t0 = Instant::now();
        let c = call("ssh_exec", Some("alpha"), None, "s1");
        for i in 0..4 {
            a.record_at(&c, t0 + Duration::from_secs(i));
        }
        // Still a burst, later in the hour: nothing.
        let later = t0 + Duration::from_secs(1800);
        for i in 0..5 {
            assert!(a.record_at(&c, later + Duration::from_secs(i)).is_none());
        }
        // An hour after the hint, the same burst gets it again.
        let next = t0 + COOLDOWN + Duration::from_secs(10);
        let got: Vec<_> = (0..4)
            .filter_map(|i| a.record_at(&c, next + Duration::from_secs(i)))
            .collect();
        assert_eq!(got.len(), 1);
    }

    /// The cooldown is per caller: another session still gets its hint,
    /// and calls of another session don't count towards a burst.
    #[test]
    fn callers_are_separate() {
        let a = Advisor::new();
        for _ in 0..4 {
            a.record(&call("ssh_exec", Some("alpha"), None, "s1"));
        }
        for _ in 0..3 {
            assert!(
                a.record(&call("ssh_exec", Some("alpha"), None, "s2"))
                    .is_none()
            );
        }
        assert!(
            a.record(&call("ssh_exec", Some("alpha"), None, "s2"))
                .is_some()
        );
        let mixed = Advisor::new();
        for who in ["s1", "s2", "s3", "s4"] {
            assert!(
                mixed
                    .record(&call("ssh_exec", Some("alpha"), None, who))
                    .is_none()
            );
        }
    }

    #[test]
    fn different_hosts_dont_count_together() {
        let a = Advisor::new();
        for _ in 0..3 {
            rec(&a, "ssh_exec", "alpha");
        }
        for _ in 0..3 {
            rec(&a, "ssh_exec", "beta");
        }
        assert!(rec(&a, "ssh_exec", "gamma").is_none());
    }

    #[test]
    fn file_write_rule_fires() {
        let a = Advisor::new();
        let mut last = None;
        for _ in 0..3 {
            last = rec(&a, "file_write", "alpha");
        }
        assert_eq!(last.unwrap().tool, "rsync_sync");
    }

    #[test]
    fn host_required() {
        let a = Advisor::new();
        for _ in 0..10 {
            assert!(
                a.record(&call("ssh_exec", None, Some("cat /etc/x"), "s1"))
                    .is_none()
            );
        }
    }

    /// A failed call gets no hint and doesn't spend the cooldown.
    #[test]
    fn a_failed_call_gets_nothing_and_spends_nothing() {
        let a = Advisor::new();
        let mut c = call("ssh_exec", Some("alpha"), Some("cat /etc/hosts"), "s1");
        c.ok = false;
        assert!(a.record(&c).is_none());
        c.ok = true;
        assert_eq!(a.record(&c).unwrap().tool, "file_read");
        assert_eq!(a.stats().hints, 1);
    }

    /// One hint per call, and once per caller per hour for each typed
    /// tool: `head` after `cat` (both file_read) gets nothing, `ls` does.
    #[test]
    fn typed_tool_hints_once_per_tool_and_count_per_pattern() {
        let a = Advisor::new();
        let go = |cmd| a.record(&call("ssh_exec", Some("alpha"), Some(cmd), "s1"));
        assert_eq!(go("cat /etc/hosts").unwrap().pattern, "cat");
        assert!(go("cat /etc/hosts").is_none());
        assert!(go("head -n 5 /etc/hosts").is_none());
        assert_eq!(go("ls -la /etc").unwrap().pattern, "ls");
        // The 4th ssh_exec in a row: ssh_batch's hint, a different one.
        assert_eq!(go("uptime").unwrap().pattern, "repeated_ssh_exec");
        let s = a.stats();
        assert_eq!(s.hints, 3);
        assert_eq!(s.by_pattern["cat"].hints, 1);
        assert_eq!(s.by_pattern["ls"].hints, 1);
        assert!(!s.by_pattern.contains_key("head_tail"));
        assert_eq!(
            s.bytes as usize,
            FILE_READ.len() + FILE_LIST.len() + SSH_BATCH.len()
        );
    }

    #[test]
    fn simple_commands_match_their_typed_tool() {
        for (tool, cmd, want) in [
            ("ssh_exec", "cat /etc/hosts", "cat"),
            ("ssh_exec", "  cat  /var/log/syslog ", "cat"),
            ("ssh_exec", "cat ~/.bashrc", "cat"),
            ("ssh_exec", "head /etc/passwd", "head_tail"),
            ("ssh_exec", "head -n 20 /etc/passwd", "head_tail"),
            (
                "ssh_exec",
                "tail -n 100 /var/log/nginx/error.log",
                "head_tail",
            ),
            ("ssh_exec", "tail -50 /var/log/x.log", "head_tail"),
            ("ssh_exec", "tail -n50 /var/log/x.log", "head_tail"),
            ("ssh_exec", "ls /etc", "ls"),
            ("ssh_exec", "ls -la /etc/nginx/", "ls"),
            ("ssh_exec", "ls -lah /srv", "ls"),
            ("ssh_exec", "stat /etc/hosts", "stat"),
            ("ssh_exec", "systemctl status nginx", "systemctl"),
            ("ssh_exec", "systemctl restart nginx.service", "systemctl"),
            (
                "ssh_exec",
                "sudo systemctl restart getty@tty1.service",
                "systemctl",
            ),
            ("ssh_sudo_exec", "systemctl stop prometheus", "systemctl"),
            (
                "ssh_exec",
                "systemctl is-active --no-pager sshd",
                "systemctl",
            ),
            ("ssh_exec", "journalctl -u nginx", "journalctl"),
            (
                "ssh_sudo_exec",
                "journalctl -u nginx -n 100 --no-pager",
                "journalctl",
            ),
            (
                "ssh_exec",
                "sudo -n journalctl --no-pager -n50 -u prompto",
                "journalctl",
            ),
            ("ssh_exec", "journalctl -u x --lines=20", "journalctl"),
            (
                "ssh_exec",
                "cat > /etc/motd <<EOF\nhello\nworld\nEOF",
                "write",
            ),
            (
                "ssh_exec",
                "cat >/tmp/a.conf << 'EOF'\nk = \"$v\" | x; y\nEOF\n",
                "write",
            ),
            (
                "ssh_sudo_exec",
                "tee /etc/x.conf <<-END\n\ta=1\nEND",
                "write",
            ),
            (
                "ssh_exec",
                "sudo tee /etc/x.conf > /dev/null <<\"EOF\"\na\nEOF",
                "write",
            ),
            ("ssh_exec", "tee /tmp/x >/dev/null <<EOF\nEOF", "write"),
        ] {
            let got = typed_tool(tool, cmd).map(|h| h.pattern);
            assert_eq!(got, Some(want), "{tool} {cmd:?}");
        }
    }

    /// Legitimate shell — compound, piped, redirected, with options a
    /// typed tool doesn't have, or reads under sudo — never gets a hint.
    #[test]
    fn everything_else_gets_no_hint() {
        for (tool, cmd) in [
            ("ssh_exec", "cat /etc/hosts | grep x"),
            ("ssh_exec", "cat /etc/hosts && echo ok"),
            ("ssh_exec", "cat /etc/hosts; ls"),
            ("ssh_exec", "cat /etc/a /etc/b"),
            ("ssh_exec", "cat -n /etc/hosts"),
            ("ssh_exec", "cat"),
            ("ssh_exec", "cat $HOME/x"),
            ("ssh_exec", "cat /var/log/*.log"),
            ("ssh_exec", "cat '/etc/my file'"),
            ("ssh_exec", "cat /etc/hosts > /tmp/x"),
            ("ssh_exec", "cat /etc/hosts 2>/dev/null"),
            ("ssh_exec", "cat $(ls)"),
            ("ssh_exec", "tail -f /var/log/syslog"),
            ("ssh_exec", "tail -n +5 /var/log/syslog"),
            ("ssh_exec", "head -c 100 /dev/urandom"),
            ("ssh_exec", "ls"),
            ("ssh_exec", "ls -R /etc"),
            ("ssh_exec", "ls -la /etc /var"),
            ("ssh_exec", "stat -c %s /etc/hosts"),
            ("ssh_sudo_exec", "cat /etc/shadow"),
            ("ssh_exec", "sudo cat /etc/shadow"),
            ("ssh_sudo_exec", "ls -la /root"),
            ("ssh_exec", "systemctl list-units --failed"),
            ("ssh_exec", "systemctl daemon-reload"),
            ("ssh_exec", "systemctl restart a b"),
            (
                "ssh_exec",
                "systemctl restart nginx && systemctl status nginx",
            ),
            ("ssh_exec", "systemctl --user restart foo"),
            ("ssh_exec", "journalctl -u nginx --since today"),
            ("ssh_exec", "journalctl -f -u nginx"),
            ("ssh_exec", "journalctl -u nginx | tail"),
            ("ssh_exec", "journalctl -u a -u b"),
            ("ssh_exec", "journalctl -n 50"),
            ("ssh_exec", "journalctl -b"),
            (
                "ssh_exec",
                "cat > /etc/motd <<EOF\nhi\nEOF\nsystemctl restart x",
            ),
            ("ssh_exec", "cat > /etc/motd <<EOF\nhi\nEOF\nEOF"),
            ("ssh_exec", "cat > /etc/motd <<EOF\nhi\n"),
            ("ssh_exec", "cat >> /etc/motd <<EOF\nhi\nEOF"),
            ("ssh_exec", "tee -a /etc/motd <<EOF\nhi\nEOF"),
            ("ssh_exec", "cat <<EOF | sudo tee /etc/x\nhi\nEOF"),
            ("ssh_exec", "cd /x && cat > y <<EOF\nhi\nEOF"),
            ("ssh_exec", "python3 - <<'EOF'\nprint(1)\nEOF"),
            ("ssh_exec", "tee /etc/a /etc/b <<EOF\nx\nEOF"),
            ("bash_exec", "cat /etc/hosts"),
            ("bash_exec", "systemctl restart nginx"),
            ("ssh_batch", "journalctl -u nginx"),
            // `#` starts a comment: this is a bare `cat`.
            ("ssh_exec", "cat #notes"),
            ("ssh_exec", "ls -la #x"),
            ("file_read", "cat /etc/hosts"),
            ("ssh_exec", "uptime"),
            ("ssh_exec", ""),
        ] {
            assert_eq!(typed_tool(tool, cmd), None, "{tool} {cmd:?}");
        }
    }

    #[test]
    fn who_is_the_session_else_agent_and_ip() {
        let ip: std::net::IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(Advisor::who(Some("S"), "ops", Some(ip)), "session:S");
        assert_eq!(Advisor::who(None, "ops", Some(ip)), "agent:ops@192.0.2.7");
        assert_eq!(Advisor::who(None, "local", None), "agent:local@");
    }
}
