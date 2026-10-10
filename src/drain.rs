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
//! At the deadline [`Drain::abort`] fires: every call still running
//! returns an `aborted` error to its client and is audited `aborted`;
//! dropping it kills its local `ssh` process group (`SshClient::run`).
//! Killing `ssh` does not stop the remote command — sshd leaves a
//! command without a terminal running when the connection drops — so
//! each remote command still registered is then reaped on its host
//! ([`reap_script`]): a second connection kills every process group
//! carrying the call's `PROMPTO_REQUEST_ID`, as root when the call ran
//! as root.
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
use crate::ssh::SshClient;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
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
}

#[derive(Default)]
struct Inner {
    phase: AtomicU8,
    calls: AtomicUsize,
    idle: Notify,
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

    /// The deadline: cut off every call still running. Returns the
    /// remote commands they had running, to [`reap`]. No remote command
    /// starts after this ([`Drain::track`] refuses).
    pub fn abort(&self) -> Vec<Remote> {
        let map = self.0.remote.lock().unwrap_or_else(|e| e.into_inner());
        self.0.abort.cancel();
        map.values().cloned().collect()
    }

    /// A remote command for `ctx` starts on `host`; registered until the
    /// guard drops. Refused (`aborted`) once the deadline fired.
    pub fn track(
        &self,
        ctx: &CallCtx,
        host: &HostConfig,
        sudo: bool,
    ) -> Result<RemoteGuard, ClassifiedError> {
        let mut map = self.0.remote.lock().unwrap_or_else(|e| e.into_inner());
        if self.0.abort.is_cancelled() {
            return Err(aborted_error());
        }
        let id = self.0.next.fetch_add(1, Ordering::SeqCst);
        map.insert(
            id,
            Remote {
                request_id: ctx.request_id(),
                host: host.clone(),
                sudo,
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

/// POSIX `sh` that kills, on the host it runs on, every process group
/// holding a process whose environment or command line carries
/// `PROMPTO_REQUEST_ID=<request_id>` — the remote side of one call (the
/// export prefix puts it on the login shell's command line, and every
/// process the command starts inherits it). TERM first, KILL a second
/// later for what is left; prints `prompto-reaped <groups>`.
///
/// Linux reads `/proc`; elsewhere `ps axeww` (BSD `ps` shows the
/// environment with `e`). The marker is assembled at run time so the
/// script's own command line never contains it, and the script's own
/// process group is skipped. `request_id` must be a ULID: it is spliced
/// in unquoted.
pub fn reap_script(request_id: &str) -> String {
    assert!(
        request_id.chars().all(|c| c.is_ascii_alphanumeric()),
        "request ID must be a ULID"
    );
    format!(
        r#"r={request_id}
m="PROMPTO_REQUEST_ID""=$r"
me=$(ps -o pgid= -p $$ | tr -d ' ')
groups() {{
  if [ -r /proc/self/environ ]; then
    for d in /proc/[0-9]*; do
      p=${{d#/proc/}}
      if grep -qsF -- "$m" "$d/environ" "$d/cmdline" 2>/dev/null; then
        ps -o pgid= -p "$p" 2>/dev/null
      fi
    done
  else
    ps axeww -o pgid= -o command= 2>/dev/null | grep -F -- "$m" | awk '{{print $1}}'
  fi | tr -d ' ' | grep -v -x -e "$me" -e 0 -e 1 -e '' | sort -u
}}
g=$(groups)
for x in $g; do kill -s TERM -- "-$x" 2>/dev/null; done
[ -n "$g" ] && sleep 1
for x in $(groups); do kill -s KILL -- "-$x" 2>/dev/null; done
echo prompto-reaped $g
"#
    )
}

/// Reap one remote command cut off by the deadline (see [`reap_script`]),
/// as root when it ran as root. Best effort: logged, never fatal. A host
/// with `request_id_env = "off"` carries no marker to find it by.
pub async fn reap(ssh: &SshClient, r: &Remote) {
    if r.host.request_id_env() == RequestIdEnv::Off {
        tracing::warn!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            "cannot reap the remote side of an aborted call: request_id_env = \"off\" on this host"
        );
        return;
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
        Ok(Ok(out)) if out.ok() => {
            let groups = out
                .stdout
                .lines()
                .find_map(|l| l.strip_prefix("prompto-reaped"))
                .unwrap_or("")
                .trim()
                .to_string();
            tracing::warn!(
                request_id = %r.request_id,
                ip = %r.host.ip,
                sudo = r.sudo,
                process_groups = %groups,
                "reaped the remote side of a call aborted at the drain deadline"
            );
        }
        Ok(Ok(out)) => tracing::error!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            exit_code = ?out.exit_code,
            stderr = %out.stderr.chars().take(300).collect::<String>(),
            "reaping an aborted call's remote side failed"
        ),
        Ok(Err(e)) => tracing::error!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            error = %format!("{e:#}"),
            "reaping an aborted call's remote side failed"
        ),
        Err(_) => tracing::error!(
            request_id = %r.request_id,
            ip = %r.host.ip,
            "reaping an aborted call's remote side timed out"
        ),
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
    /// started then would outlive the reap.
    #[test]
    fn abort_returns_the_remote_commands_and_refuses_new_ones() {
        let d = Drain::default();
        let ctx = CallCtx::new(None);
        let g = d.track(&ctx, &host(), true).unwrap();
        let live = d.abort();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].request_id, ctx.request_id());
        assert!(live[0].sudo);
        let e = d.track(&CallCtx::new(None), &host(), false).err().unwrap();
        assert_eq!(e.class, ErrorClass::Aborted);
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

    /// The reaper finds a call's processes by the marker alone — here a
    /// shell that exported it (marker on its command line only) and a
    /// background job in a session of its own (perl's `setsid`; marker in
    /// its environment only), as a remote command can leave them — kills
    /// both groups, and spares an unrelated process and itself. `ps` is
    /// the script's fallback where there is no `/proc`.
    #[test]
    fn reap_script_kills_the_marked_process_groups_only() {
        for via_ps in [false, true] {
            reap_marked(via_ps);
        }
    }

    fn reap_marked(via_ps: bool) {
        use std::os::unix::process::CommandExt;
        let rid = ulid::Ulid::generate().to_string();
        let (a, b, c) = if via_ps {
            (3171, 3172, 3173)
        } else {
            (3174, 3175, 3176)
        };
        let mut marked = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "export PROMPTO_REQUEST_ID={rid}; \
                 perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' sleep {a} & sleep {b}; wait"
            ))
            .process_group(0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut other = Command::new("sleep")
            .arg(c.to_string())
            .process_group(0)
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let pids = |n: i32| {
            let out = Command::new("pgrep")
                .args(["-f", &format!("^sleep {n}$")])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert!(!pids(a).is_empty(), "background job not started");

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
        assert!(out.status.success(), "{out:?}");
        let groups: Vec<&str> = stdout
            .trim()
            .strip_prefix("prompto-reaped")
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(groups.len(), 2, "via_ps={via_ps}: {stdout}");
        assert!(
            groups.contains(&marked.id().to_string().as_str()),
            "{stdout}"
        );
        let _ = marked.wait();
        std::thread::sleep(Duration::from_millis(200));
        assert!(pids(a).is_empty() && pids(b).is_empty(), "survivors");
        assert!(alive(other.id()), "unrelated process killed");
        let _ = other.kill();
        let _ = other.wait();
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
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "prompto-reaped"
        );
    }
}
