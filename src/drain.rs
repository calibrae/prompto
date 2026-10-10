//! Continuity of service (E11): graceful drain, the drain deadline, and
//! the remote cleanup of calls cut off by it.
//!
//! # Drain
//!
//! On SIGTERM, and in the predecessor after a binary handover (SIGUSR2,
//! see `main.rs`), the server stops accepting connections and lets the
//! tool calls in flight finish. [`Drain`] counts those calls (every
//! `call_tool` holds a [`CallGuard`]) and remembers each remote command
//! they have running ([`Drain::track`]). A request that still reaches a
//! draining server on an open connection is refused with a retryable
//! `503` when no successor is serving (`server::drain_gate`); after a
//! handover it is served, since the state it touches is shared safely
//! (see below).
//!
//! # Deadline
//!
//! `PROMPTO_DRAIN_SECS` (default [`DEFAULT_DRAIN_SECS`]) bounds the wait.
//! At the deadline, first [`Drain::deadline`]: no remote command starts
//! any more, and each one still running is reaped on its host
//! ([`reap_script`]) while its `ssh` connection is still up. Then
//! [`Drain::abort`]: every call still running returns an `aborted` error
//! to its client and is audited `aborted` (a call whose remote side the
//! reaper ended answers `aborted` too, see `SshClient::run`); dropping
//! it kills its local `ssh` process group.
//!
//! Killing `ssh` alone would not stop the remote command — sshd leaves a
//! command without a terminal running when the connection drops — hence
//! the reaper. It kills the call's **session** on the host, and nothing
//! else (see [`reap_script`] for how it finds it): what the command
//! started and left there — plain background jobs, `nohup` ones — goes
//! with it; what left the session — `setsid`, `daemon(3)`, a service
//! started through the init system — survives. Each reap is audited
//! (`"type": "reap"`, [`reap_record`]) under the aborted call's identity.
//!
//! # Two processes at once
//!
//! During a handover the predecessor (draining) and the successor
//! (serving) both run. What they share on disk is safe for that: audit
//! and usage records are single `O_APPEND` writes, the approval state
//! (used nonces and TOTP steps) is locked and re-read on every check
//! (`approval::State::sync`), and the kill API directory's
//! count-then-write is locked across processes (`kill::DirLock`). What is
//! only in memory — the approver lockout counters, the `/v1/audit` read
//! limit — starts fresh in the successor, as it does after any restart.

use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::{HostConfig, RequestIdEnv};
use crate::ssh::{CALL_SID_ENV, SshClient};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// `PROMPTO_DRAIN_SECS` default: ten minutes, longer than any default
/// tool timeout (`vm_ensure_up`'s 180 s is the longest).
pub const DEFAULT_DRAIN_SECS: u64 = 600;

/// How long one remote reap may take.
pub const REAP_TIMEOUT: Duration = Duration::from_secs(20);

const SERVING: u8 = 0;
const DRAINING: u8 = 1;
const HANDED_OVER: u8 = 2;

/// Where a server is in its life, as far as new requests are concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Serving,
    /// Stopping with no successor: new requests get a retryable 503.
    Draining,
    /// A successor serves the listening socket: requests that still
    /// arrive here are served.
    HandedOver,
}

/// One remote command in flight, for [`reap`].
#[derive(Clone, Debug)]
pub struct Remote {
    pub request_id: String,
    pub host: HostConfig,
    pub sudo: bool,
    /// The call's context: whose call it was, for the reap's audit record.
    pub ctx: CallCtx,
}

#[derive(Default)]
struct Inner {
    phase: AtomicU8,
    calls: AtomicUsize,
    idle: Notify,
    past_deadline: AtomicBool,
    abort: CancellationToken,
    next: AtomicU64,
    remote: Mutex<HashMap<u64, Remote>>,
}

/// In-flight calls and remote commands of one server; `Default` is a
/// server that never drains (tests, stdio).
#[derive(Clone, Default)]
pub struct Drain(Arc<Inner>);

impl Drain {
    pub fn phase(&self) -> Phase {
        match self.0.phase.load(Ordering::SeqCst) {
            SERVING => Phase::Serving,
            DRAINING => Phase::Draining,
            _ => Phase::HandedOver,
        }
    }

    /// Start draining; `handed_over` when a successor now serves the
    /// socket. Draining never goes back to serving.
    pub fn begin(&self, handed_over: bool) {
        let to = if handed_over { HANDED_OVER } else { DRAINING };
        let _ = self
            .0
            .phase
            .compare_exchange(SERVING, to, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// A tool call starts; it counts until the guard drops.
    pub fn enter(&self) -> CallGuard {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        CallGuard(self.clone())
    }

    /// Tool calls in flight.
    pub fn calls(&self) -> usize {
        self.0.calls.load(Ordering::SeqCst)
    }

    /// Resolves once no tool call is in flight.
    pub async fn idle(&self) {
        loop {
            let notified = self.0.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.calls() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Resolves when the drain deadline fired.
    pub async fn aborted(&self) {
        self.0.abort.cancelled().await
    }

    pub fn is_aborted(&self) -> bool {
        self.0.abort.is_cancelled()
    }

    /// The deadline, first step: no remote command starts after this
    /// ([`Drain::track`] refuses), and a remote command that ends from now
    /// on is reported `aborted` ([`Drain::past_deadline`]). Returns the
    /// remote commands still running, to [`reap`] — while their `ssh`
    /// connections are still up, before [`Drain::abort`].
    pub fn deadline(&self) -> Vec<Remote> {
        let map = self.0.remote.lock().unwrap_or_else(|e| e.into_inner());
        self.0.past_deadline.store(true, Ordering::SeqCst);
        map.values().cloned().collect()
    }

    pub fn past_deadline(&self) -> bool {
        self.0.past_deadline.load(Ordering::SeqCst)
    }

    /// The deadline, last step: cut off every call still running.
    pub fn abort(&self) {
        self.0.past_deadline.store(true, Ordering::SeqCst);
        self.0.abort.cancel();
    }

    /// A remote command for `ctx` starts on `host`; registered until the
    /// guard drops. Refused (`aborted`) once the deadline passed.
    pub fn track(
        &self,
        ctx: &CallCtx,
        host: &HostConfig,
        sudo: bool,
    ) -> Result<RemoteGuard, ClassifiedError> {
        let mut map = self.0.remote.lock().unwrap_or_else(|e| e.into_inner());
        if self.past_deadline() {
            return Err(aborted_error());
        }
        let id = self.0.next.fetch_add(1, Ordering::SeqCst);
        map.insert(
            id,
            Remote {
                request_id: ctx.request_id(),
                host: host.clone(),
                sudo,
                ctx: ctx.clone(),
            },
        );
        Ok(RemoteGuard {
            drain: self.clone(),
            id,
        })
    }

    /// Remote commands in flight (tests).
    pub fn remote_count(&self) -> usize {
        self.0.remote.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for Drain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Drain")
            .field("phase", &self.phase())
            .field("calls", &self.calls())
            .field("aborted", &self.is_aborted())
            .finish()
    }
}

/// Counts one tool call in flight.
pub struct CallGuard(Drain);

impl Drop for CallGuard {
    fn drop(&mut self) {
        if self.0.0.calls.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.0.idle.notify_waiters();
        }
    }
}

/// Keeps one remote command registered (see [`Drain::track`]).
pub struct RemoteGuard {
    drain: Drain,
    id: u64,
}

impl Drop for RemoteGuard {
    fn drop(&mut self) {
        let mut map = self
            .drain
            .0
            .remote
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&self.id);
    }
}

/// What a call cut off by the drain deadline fails with.
pub fn aborted_error() -> ClassifiedError {
    ClassifiedError::refused(ErrorClass::Aborted, ABORTED_MESSAGE)
}

/// The client-facing reason of a call cut off by the deadline.
pub const ABORTED_MESSAGE: &str = "prompto shut down before the call finished \
(drain deadline, PROMPTO_DRAIN_SECS): it was cancelled and its remote processes killed. \
Whether it took effect is unknown; check before retrying.";

/// `PROMPTO_DRAIN_SECS`.
pub fn drain_secs_from_env() -> Duration {
    Duration::from_secs(
        std::env::var("PROMPTO_DRAIN_SECS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_DRAIN_SECS),
    )
}

/// POSIX `sh` that kills, on the host it runs on, the remote side of
/// one call: every process in the call's **session**, and nothing else.
///
/// sshd runs a command without a terminal in a session of its own (it
/// calls `setsid` before it starts the login shell), so that session is
/// the call: the login shell, what it runs, and what those start and
/// leave behind. A process that left it (`setsid`, `daemon(3)`, an init
/// script or `systemctl start`, whose service the init system runs) is
/// not the call any more and is spared. `nohup` does not change the
/// session (it only ignores SIGHUP, and the reaper sends TERM and KILL),
/// so a `nohup cmd &` started by a call cut off at the deadline is
/// reaped like any background job: it is indistinguishable from the
/// call's own work, and a process meant to outlive the call should leave
/// its session. (A call that only starts `nohup cmd > log 2>&1 &` returns
/// at once and is never in flight at a deadline.)
///
/// Finding the call's session: a process carries the call's marker,
/// `PROMPTO_REQUEST_ID=<request_id>`, in its environment (inherited) or
/// command line (the login shell's, with the export prefix), and
///
/// - a marked session leader whose parent is sshd (`sshd`,
///   `sshd-session`) is the call's login shell — the connection is still
///   up when the reaper runs (see [`Drain::deadline`]); this works for
///   every `request_id_env` mode and login shell, csh included;
/// - `PROMPTO_CALL_SID=<sid>` in a marked process's environment names the
///   session the export prefix and the vault sudo path recorded at start
///   (the login shell's `$$`): that finds the session even after its
///   login shell exited, and a `setsid` child that inherited it still
///   points at the call, not at itself.
///
/// A session is reaped only if one of its members carries the marker,
/// so a recycled session ID, or a value set by hand, can't point the
/// reaper anywhere else. macOS `ps` has no session ID: the process group
/// stands in there (the login shell leads both; a job a non-interactive
/// shell starts stays in its group), so there a command that makes a
/// process group of its own (`timeout`, `setpgid`) also escapes.
///
/// TERM first, KILL a second later for what is left; prints
/// `prompto-reap key=<sid|pgid> sessions=<ids>`, then
/// `prompto-reap-term <pids>` and `prompto-reap-kill <pids>`.
/// Linux reads `/proc`; elsewhere `ps axeww` (BSD `ps` shows the
/// environment with `e`). The marker is assembled at run time so the
/// script's own command line never contains it; the reaper's own
/// session is skipped. `request_id` must be a ULID: it is spliced in
/// unquoted.
pub fn reap_script(request_id: &str) -> String {
    assert!(
        request_id.chars().all(|c| c.is_ascii_alphanumeric()),
        "request ID must be a ULID"
    );
    format!(
        r#"r={request_id}
m="PROMPTO_REQUEST_ID""=$r"
if ps -o sid= -p $$ >/dev/null 2>&1; then k=sid; else k=pgid; fi
me=$(ps -o $k= -p $$ | tr -d ' ')
marked() {{
  if [ -r /proc/self/environ ]; then
    for d in /proc/[0-9]*; do
      if grep -qsF -- "$m" "$d/environ" "$d/cmdline" 2>/dev/null; then
        echo "M ${{d#/proc/}}" $(tr '\0' '\n' < "$d/environ" 2>/dev/null | sed -n 's/^{CALL_SID_ENV}=\([0-9][0-9]*\)$/\1/p')
      fi
    done
  else
    ps axeww -o pid= -o command= 2>/dev/null | grep -F -- "$m" |
      awk '{{ v = ""; for (i = 2; i <= NF; i++) if ($i ~ /^{CALL_SID_ENV}=[0-9]+$/) v = v " " substr($i, {sid_at}); print "M " $1 v }}'
  fi
}}
sessions() {{
  {{ marked; ps -A -ww -o pid= -o ppid= -o $k= -o args= 2>/dev/null | sed 's/^/T /'; }} |
    awk -v me="$me" '
      $1 == "M" {{ mk[$2] = 1; for (i = 3; i <= NF; i++) rec[$i] = 1; next }}
      $1 == "T" {{ s[$2] = $4; pp[$2] = $3; a = $5; sub(/.*\//, "", a); arg[$2] = a }}
      END {{
        for (p in mk) {{
          if (!(p in s)) continue
          own[s[p]] = 1
          if (s[p] == p && (pp[p] in arg) && arg[pp[p]] ~ /^sshd/) call[p] = 1
        }}
        for (c in rec) if (c in own) call[c] = 1
        for (c in call) if (c != me && c > 1) print c
      }}' | sort -n | tr '\n' ' '
}}
members() {{
  ps -A -o pid= -o $k= 2>/dev/null | awk -v S=" $1 " 'index(S, " " $2 " ") {{ print $1 }}' | tr '\n' ' '
}}
S=$(sessions)
echo "prompto-reap key=$k sessions=$S"
t=$(members "$S")
for p in $t; do kill -s TERM "$p" 2>/dev/null; done
echo "prompto-reap-term $t"
[ -n "$t" ] && sleep 1
l=$(members "$S")
for p in $l; do kill -s KILL "$p" 2>/dev/null; done
echo "prompto-reap-kill $l"
"#,
        sid_at = CALL_SID_ENV.len() + 2,
    )
}

/// What one reap did, from [`reap_script`]'s output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reaped {
    /// `sid` or `pgid` (macOS): what `sessions` are.
    pub key: String,
    pub sessions: Vec<u64>,
    /// Sent TERM.
    pub terminated: Vec<u64>,
    /// Still there a second later: sent KILL.
    pub killed: Vec<u64>,
}

impl Reaped {
    pub fn parse(stdout: &str) -> Option<Self> {
        let nums = |s: &str| -> Vec<u64> {
            s.split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect()
        };
        let mut r = Reaped::default();
        let mut seen = false;
        for l in stdout.lines() {
            if let Some(rest) = l.strip_prefix("prompto-reap key=") {
                let (k, s) = rest.split_once(" sessions=")?;
                r.key = k.to_string();
                r.sessions = nums(s);
                seen = true;
            } else if let Some(rest) = l.strip_prefix("prompto-reap-term") {
                r.terminated = nums(rest);
            } else if let Some(rest) = l.strip_prefix("prompto-reap-kill") {
                r.killed = nums(rest);
            }
        }
        seen.then_some(r)
    }
}

/// The `"type": "reap"` audit record of one reap: the aborted call's
/// request ID and identity (agent, session, client), the host, whether
/// it ran as root, and what was killed — or why not (`error`).
pub fn reap_record(
    r: &Remote,
    host: Option<&str>,
    reaped: Result<&Reaped, &str>,
    duration: Duration,
) -> serde_json::Value {
    use crate::audit;
    let ctx = &r.ctx;
    let (agent, groups) = match &ctx.agent {
        Some(a) => (a.name.clone(), a.groups.clone()),
        None => ("-".to_string(), vec![]),
    };
    let mut rec = serde_json::json!({
        "ts": audit::now_ts(),
        "type": "reap",
        "request_id": r.request_id,
        "agent": audit::clamp(&agent, audit::MAX_FIELD),
        "agent_groups": groups,
        "session_id": ctx.session_id.as_deref().map(|s| audit::clamp(s, audit::MAX_FIELD)),
        "client_ip": ctx.caller_ip.map(|ip| ip.to_canonical().to_string()),
        "user_agent": ctx.user_agent.as_deref().map(|u| audit::clamp(u, audit::MAX_FIELD)),
        "tool": ctx.call.as_ref().map(|c| audit::clamp(&c.tool, audit::MAX_FIELD)),
        "host": host,
        "ip": r.host.ip.to_string(),
        "as_root": r.sudo,
        "duration_ms": duration.as_millis() as u64,
    });
    match reaped {
        Ok(x) => {
            rec["ok"] = true.into();
            rec["key"] = x.key.clone().into();
            rec["sessions"] = x.sessions.clone().into();
            rec["terminated"] = x.terminated.clone().into();
            rec["killed"] = x.killed.clone().into();
        }
        Err(why) => {
            rec["ok"] = false.into();
            rec["error"] = audit::clamp(why, audit::MAX_FIELD).into();
        }
    }
    rec
}

/// Reap one remote command left at the deadline (see [`reap_script`]),
/// as root when it ran as root, and audit it ([`reap_record`]; `host` is
/// its inventory name). Best effort: logged, never fatal. A host with
/// `request_id_env = "off"` carries no marker to find it by.
pub async fn reap(ssh: &SshClient, audit: &crate::audit::Audit, r: &Remote, host: Option<&str>) {
    let started = std::time::Instant::now();
    let outcome = reap_remote(ssh, r).await;
    let rec = reap_record(
        r,
        host,
        outcome.as_ref().map_err(String::as_str),
        started.elapsed(),
    );
    tracing::info!(target: crate::audit::TARGET, record = %rec, "reap");
    if let Some(log) = audit.log() {
        let mut line = rec.to_string().into_bytes();
        line.push(b'\n');
        // The journal line above has it either way.
        let _ = log.append(&line);
    }
    match outcome {
        Ok(x) => tracing::warn!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            sudo = r.sudo,
            sessions = ?x.sessions,
            terminated = ?x.terminated,
            killed = ?x.killed,
            "reaped the remote side of a call aborted at the drain deadline"
        ),
        Err(e) => tracing::error!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            sudo = r.sudo,
            error = %e,
            "reaping an aborted call's remote side failed"
        ),
    }
}

async fn reap_remote(ssh: &SshClient, r: &Remote) -> Result<Reaped, String> {
    if r.host.request_id_env() == RequestIdEnv::Off {
        return Err("request_id_env = \"off\" on this host: no marker to find the call by".into());
    }
    // A fresh context: the reaper must not carry the marker it looks for.
    let ctx = CallCtx::new(None);
    // Not tracked: the drain refuses new remote commands after the deadline.
    let ssh = ssh.clone().with_drain(Drain::default());
    let script = reap_script(&r.request_id);
    let run = async {
        if r.sudo {
            ssh.exec(&ctx, &r.host, &script, Some(REAP_TIMEOUT), true)
                .await
        } else {
            ssh.exec_stdin(
                &ctx,
                &r.host,
                "sh -s",
                script.as_bytes(),
                Some(REAP_TIMEOUT),
                false,
            )
            .await
        }
    };
    match tokio::time::timeout(REAP_TIMEOUT + Duration::from_secs(5), run).await {
        Ok(Ok(out)) if out.ok() => Reaped::parse(&out.stdout).ok_or_else(|| {
            format!(
                "unexpected reaper output: {}",
                out.stdout.chars().take(200).collect::<String>()
            )
        }),
        Ok(Ok(out)) => Err(format!(
            "exit {:?}{}: {}",
            out.exit_code,
            if out.timed_out { " (timed out)" } else { "" },
            out.stderr.chars().take(200).collect::<String>()
        )),
        Ok(Err(e)) => Err(format!("{e:#}")),
        Err(_) => Err("timed out".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn host() -> HostConfig {
        crate::inventory::Inventory::from_toml_str(
            "[host.h]\nip = \"192.0.2.5\"\nssh_user = \"u\"\nssh_key = \"/dev/null\"\n",
        )
        .unwrap()
        .get("h")
        .unwrap()
        .clone()
    }

    #[tokio::test]
    async fn idle_waits_for_every_call() {
        let d = Drain::default();
        let a = d.enter();
        let b = d.enter();
        assert_eq!(d.calls(), 2);
        let w = tokio::spawn({
            let d = d.clone();
            async move { d.idle().await }
        });
        drop(a);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!w.is_finished(), "one call still in flight");
        drop(b);
        tokio::time::timeout(Duration::from_secs(2), w)
            .await
            .unwrap()
            .unwrap();
    }

    /// After the deadline nothing new may start on a host: a command
    /// started then would outlive the reap. A command that ends from then
    /// on is reported `aborted` (`SshClient::run`).
    #[test]
    fn deadline_returns_the_remote_commands_and_refuses_new_ones() {
        let d = Drain::default();
        let ctx = CallCtx::new(None);
        let g = d.track(&ctx, &host(), true).unwrap();
        assert!(!d.past_deadline());
        let live = d.deadline();
        assert!(d.past_deadline() && !d.is_aborted());
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].request_id, ctx.request_id());
        assert_eq!(live[0].ctx.request_id, ctx.request_id);
        assert!(live[0].sudo);
        let e = d.track(&CallCtx::new(None), &host(), false).err().unwrap();
        assert_eq!(e.class, ErrorClass::Aborted);
        d.abort();
        assert!(d.is_aborted());
        drop(g);
        assert_eq!(d.remote_count(), 0);
    }

    #[test]
    fn begin_is_one_way() {
        let d = Drain::default();
        assert_eq!(d.phase(), Phase::Serving);
        d.begin(true);
        assert_eq!(d.phase(), Phase::HandedOver);
        d.begin(false);
        assert_eq!(d.phase(), Phase::HandedOver);
    }

    fn alive(pid: u32) -> bool {
        // Zombies count as gone: `ps -o stat=` starts with Z.
        let out = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        !s.trim().is_empty() && !s.trim().starts_with('Z')
    }

    /// The reaper kills the call's session and spares what left it. A
    /// fake sshd (perl, named `sshd-session` as OpenSSH's is) starts the
    /// "login shell" in a session of its own, as sshd does, with
    /// `setsid sleep A &`, `nohup sleep B &` and `sleep C` — a background
    /// job, a nohup'd one, the foreground command. A and an unrelated
    /// process survive; B, C and the shell go. Both ways of finding the
    /// session are covered:
    ///
    /// - `export` mode: the shell exports the marker and
    ///   `PROMPTO_CALL_SID=$$`, and its parent is not sshd (the
    ///   connection already dropped);
    /// - `setenv` mode: the marker is in the shell's environment only (as
    ///   `SetEnv` puts it, csh-style), and its parent is sshd.
    ///
    /// Each through `/proc` and through `ps`, the script's fallback.
    #[test]
    fn reap_script_kills_the_call_session_only() {
        for (export, via_ps) in [(true, false), (true, true), (false, false), (false, true)] {
            reap_session(export, via_ps);
        }
    }

    /// Neither a recorded session nor an sshd parent: the shell can't be
    /// told from a daemon, so nothing is killed. And a `PROMPTO_CALL_SID`
    /// naming a session none of whose members carries the marker (set by
    /// hand, or a recycled ID) is ignored: here it names an unrelated
    /// session leader, which survives.
    #[test]
    fn reap_script_without_a_session_to_trust_kills_nothing() {
        let rid = ulid::Ulid::generate().to_string();
        let n = 3190 + std::process::id() % 7;
        let mut unrelated = Command::new("perl")
            .args(["-e", "use POSIX; POSIX::setsid(); exec @ARGV", "sleep"])
            .arg((n + 7).to_string())
            .spawn()
            .unwrap();
        let mut marked = Command::new("perl")
            .args([
                "-e",
                "use POSIX; my $p = fork; if (!$p) { POSIX::setsid(); exec @ARGV } waitpid($p, 0)",
                "/bin/sh",
                "-c",
                &format!("sleep {n}"),
            ])
            .env(crate::ssh::REQUEST_ID_ENV, &rid)
            .env(CALL_SID_ENV, unrelated.id().to_string())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(reap_script(&rid))
            .output()
            .unwrap();
        let r = Reaped::parse(&String::from_utf8_lossy(&out.stdout)).unwrap();
        assert!(r.sessions.is_empty() && r.terminated.is_empty(), "{r:?}");
        assert!(!pids(&format!("^sleep {n}$")).is_empty());
        assert!(alive(unrelated.id()), "a session named by hand was reaped");
        let _ = marked.kill();
        let _ = Command::new("pkill")
            .args(["-f", &format!("^sleep {n}$")])
            .status();
        let _ = marked.wait();
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }

    fn pids(pattern: &str) -> String {
        let out = Command::new("pgrep")
            .args(["-f", pattern])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn reap_session(export: bool, via_ps: bool) {
        let rid = ulid::Ulid::generate().to_string();
        let base = 3100 + 10 * (2 * u32::from(export) + u32::from(via_ps)) + std::process::id() % 7;
        let (a, b, c, other) = (base, base + 1, base + 2, base + 3);
        let body = format!(
            "perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' sleep {a} & \
             nohup sleep {b} >/dev/null 2>&1 & sleep {c}"
        );
        let (script, sshd_name) = if export {
            (
                format!("export PROMPTO_REQUEST_ID={rid} PROMPTO_CALL_SID=$$; {body}"),
                "perl",
            )
        } else {
            (body, "sshd-session: ops@notty")
        };
        // The fake sshd: forks the session leader, waits for it.
        let mut sshd = Command::new("perl")
            .args([
                "-e",
                "$0 = shift; use POSIX; my $p = fork; \
                 if (!$p) { POSIX::setsid(); exec '/bin/sh', '-c', $ARGV[0] } waitpid($p, 0)",
                sshd_name,
                &script,
            ])
            .env(crate::ssh::REQUEST_ID_ENV, if export { "" } else { &rid })
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut unrelated = Command::new("sleep")
            .arg(other.to_string())
            .spawn()
            .unwrap();
        let t = std::time::Instant::now();
        while [a, b, c]
            .iter()
            .any(|n| pids(&format!("^sleep {n}$")).is_empty())
        {
            assert!(t.elapsed() < Duration::from_secs(5), "jobs not started");
            std::thread::sleep(Duration::from_millis(50));
        }

        let mut script = reap_script(&rid);
        if via_ps {
            script = script.replace("[ -r /proc/self/environ ]", "false");
        }
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let ctx = format!(
            "export={export} via_ps={via_ps}: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{ctx}");
        let r = Reaped::parse(&stdout).expect(&ctx);
        assert_eq!(r.sessions.len(), 1, "{ctx}");
        assert_eq!(
            r.terminated.len(),
            3,
            "shell, nohup'd job, foreground: {ctx}"
        );
        let _ = sshd.wait();
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            pids(&format!("^sleep {b}$")).is_empty(),
            "nohup job survived: {ctx}"
        );
        assert!(
            pids(&format!("^sleep {c}$")).is_empty(),
            "foreground survived: {ctx}"
        );
        let left = pids(&format!("^sleep {a}$"));
        assert!(!left.is_empty(), "the setsid'd job was killed: {ctx}");
        assert!(alive(unrelated.id()), "unrelated process killed: {ctx}");
        for p in left.split_whitespace() {
            let _ = Command::new("kill").arg(p).status();
        }
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }

    #[test]
    fn reaped_output_parses() {
        let r = Reaped::parse(
            "prompto-reap key=sid sessions=12 \nprompto-reap-term 12 13 \nprompto-reap-kill 13\n",
        )
        .unwrap();
        assert_eq!(r.key, "sid");
        assert_eq!(r.sessions, vec![12]);
        assert_eq!(r.terminated, vec![12, 13]);
        assert_eq!(r.killed, vec![13]);
        assert_eq!(Reaped::parse("garbage"), None);
    }

    /// No marked process: nothing is killed, and the script says so.
    #[test]
    fn reap_script_with_nothing_to_reap() {
        let rid = ulid::Ulid::generate().to_string();
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(reap_script(&rid))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let r = Reaped::parse(&String::from_utf8_lossy(&out.stdout)).unwrap();
        assert!(
            r.sessions.is_empty() && r.terminated.is_empty() && r.killed.is_empty(),
            "{r:?}"
        );
    }
}
