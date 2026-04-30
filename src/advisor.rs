//! Per-tool usage advisor — emits a hint when a known anti-pattern fires.
//!
//! This is the active-feedback alternative to teaching via tool descriptions.
//! Tool descriptions get paid every turn (system prompt overhead, even when
//! the tool isn't used). Hints get paid only when the bad pattern actually
//! occurs, and only once per cooldown window.
//!
//! Current rules (deliberately conservative):
//!   - 4+ ssh_exec calls to the same host within 90s → suggest ssh_batch.
//!   - 3+ file_write calls to the same host within 60s → suggest rsync_sync.
//!
//! The advisor is in-memory only. State is per prompto-process and resets
//! on restart. No disk I/O — this stays cheap.
//!
//! Cooldown: once a hint fires for a (host, rule) pair, it's suppressed for
//! `COOLDOWN`. We don't want to nag the agent every call — one nudge per
//! pattern episode is enough.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW_SSH_EXEC: Duration = Duration::from_secs(90);
const THRESHOLD_SSH_EXEC: usize = 4;

const WINDOW_FILE_WRITE: Duration = Duration::from_secs(60);
const THRESHOLD_FILE_WRITE: usize = 3;

const COOLDOWN: Duration = Duration::from_secs(300);

const RING_CAP: usize = 64;

#[derive(Clone)]
struct CallRecord {
    at: Instant,
    tool: &'static str,
    host: String,
}

#[derive(Default)]
pub struct Advisor {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    recent: VecDeque<CallRecord>,
    last_hint: HashMap<(String, &'static str), Instant>,
}

impl Advisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call and, if a known anti-pattern just fired, return a
    /// short hint string. Hints are gated by the per-(host, rule)
    /// cooldown so the agent doesn't get nagged on every call.
    pub fn record(&self, tool: &'static str, host: Option<&str>) -> Option<String> {
        let host = host?.to_owned();
        let mut g = self.inner.lock().ok()?;
        let now = Instant::now();
        g.recent.push_back(CallRecord {
            at: now,
            tool,
            host: host.clone(),
        });
        if g.recent.len() > RING_CAP {
            g.recent.pop_front();
        }

        // Try each rule in order. First match wins so the agent sees one
        // crisp hint rather than a wall of text.
        if let Some(hint) = check_rule(
            &g.recent,
            now,
            "ssh_exec",
            &host,
            WINDOW_SSH_EXEC,
            THRESHOLD_SSH_EXEC,
            "ssh_batch",
            "Multiple ssh_exec calls to this host in quick succession — consider ssh_batch to collapse them into one round-trip.",
        ) && cooldown_passed(&mut g.last_hint, &host, "ssh_batch", now)
        {
            return Some(hint);
        }
        if let Some(hint) = check_rule(
            &g.recent,
            now,
            "file_write",
            &host,
            WINDOW_FILE_WRITE,
            THRESHOLD_FILE_WRITE,
            "rsync_sync",
            "Several file_write calls in a row — if you're copying a tree, rsync_sync is one round-trip instead of N.",
        ) && cooldown_passed(&mut g.last_hint, &host, "rsync_sync", now)
        {
            return Some(hint);
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn check_rule(
    recent: &VecDeque<CallRecord>,
    now: Instant,
    target_tool: &str,
    host: &str,
    window: Duration,
    threshold: usize,
    _rule_id: &'static str,
    msg: &'static str,
) -> Option<String> {
    let count = recent
        .iter()
        .filter(|r| r.tool == target_tool && r.host == host && now.duration_since(r.at) <= window)
        .count();
    if count >= threshold {
        Some(msg.to_string())
    } else {
        None
    }
}

fn cooldown_passed(
    last: &mut HashMap<(String, &'static str), Instant>,
    host: &str,
    rule_id: &'static str,
    now: Instant,
) -> bool {
    let key = (host.to_owned(), rule_id);
    match last.get(&key) {
        Some(prev) if now.duration_since(*prev) < COOLDOWN => false,
        _ => {
            last.insert(key, now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hint_below_threshold() {
        let a = Advisor::new();
        for _ in 0..3 {
            let h = a.record("ssh_exec", Some("alpha"));
            assert!(h.is_none());
        }
    }

    #[test]
    fn fires_at_threshold() {
        let a = Advisor::new();
        let mut last = None;
        for _ in 0..4 {
            last = a.record("ssh_exec", Some("alpha"));
        }
        assert!(last.unwrap().contains("ssh_batch"));
    }

    #[test]
    fn cooldown_suppresses_repeated_hints() {
        let a = Advisor::new();
        for _ in 0..4 {
            a.record("ssh_exec", Some("alpha"));
        }
        // 5th call still in window, but cooldown should suppress.
        let h = a.record("ssh_exec", Some("alpha"));
        assert!(h.is_none());
    }

    #[test]
    fn different_hosts_dont_count_together() {
        let a = Advisor::new();
        for _ in 0..3 {
            a.record("ssh_exec", Some("alpha"));
        }
        for _ in 0..3 {
            a.record("ssh_exec", Some("beta"));
        }
        // 3 + 3 calls; neither host hit threshold of 4.
        let h = a.record("ssh_exec", Some("gamma"));
        assert!(h.is_none());
    }

    #[test]
    fn file_write_rule_fires() {
        let a = Advisor::new();
        let mut last = None;
        for _ in 0..3 {
            last = a.record("file_write", Some("alpha"));
        }
        assert!(last.unwrap().contains("rsync_sync"));
    }

    #[test]
    fn host_required() {
        let a = Advisor::new();
        for _ in 0..10 {
            assert!(a.record("ssh_exec", None).is_none());
        }
    }
}
