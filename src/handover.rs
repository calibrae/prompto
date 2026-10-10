//! Restart without a gap (E11, S11.2): binary handover.
//!
//! `SIGUSR2` asks a running server to hand its listening socket to a new
//! process of the binary now at its path (a deploy has replaced it):
//!
//! 1. the server starts the successor with the socket as fd 3
//!    ([`LISTEN_FD_ENV`]) and the write end of a pipe as fd 4
//!    ([`READY_FD_ENV`]);
//! 2. the successor loads its configuration as at any start — a bad one
//!    makes it exit, and the old server, which never stopped serving,
//!    logs why and carries on;
//! 3. once serving on the inherited socket it writes one byte on the
//!    pipe ([`signal_ready`]);
//! 4. the old server tells systemd the successor is the service's main
//!    process now (`MAINPID=`, [`notify`]), stops accepting, and drains
//!    its calls in flight (`crate::drain`) before it exits.
//!
//! The socket is the same one throughout — one accept queue, never
//! closed — so a client connecting at any moment is accepted by one
//! process or the other: no refused connection and no wait for a
//! restart, and no `SO_REUSEPORT` (whose per-socket queues drop the
//! connections still queued on the socket that closes). What the two
//! processes share is made safe for it (see `crate::drain`).
//!
//! The successor gets the old process's environment, with
//! `PROMPTO_ENV_FILE` (the unit's `EnvironmentFile`) re-read on top
//! ([`successor_env`]), so an edit to it applies on a handover as on a
//! restart.
//!
//! Under systemd this needs `Type=notify` (`deploy/prompto.service`):
//! with `Type=simple` systemd would take the old process's exit for the
//! service's and kill the successor, so a handover is then refused
//! ([`refusal`]).
//!
//! The same fd-3 path takes a socket from systemd socket activation
//! (`LISTEN_FDS`, `deploy/prompto.socket`), which keeps the socket — and
//! the connections queued on it — across a plain `systemctl restart`.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The inherited listening socket's descriptor, set by the predecessor.
pub const LISTEN_FD_ENV: &str = "PROMPTO_LISTEN_FD";
/// The pipe to signal readiness on.
pub const READY_FD_ENV: &str = "PROMPTO_READY_FD";
/// The predecessor's PID: a successor stopped while it still drains
/// waits for it, so systemd's final kill doesn't cut its calls off.
pub const PREDECESSOR_ENV: &str = "PROMPTO_PREDECESSOR_PID";
/// The unit's environment file, re-read for a successor.
pub const ENV_FILE_ENV: &str = "PROMPTO_ENV_FILE";
/// How long a successor may take to start serving.
pub const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// Where the listening socket came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A predecessor's handover.
    Handover,
    /// systemd socket activation.
    Systemd,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handover => "handover",
            Self::Systemd => "systemd socket activation",
        }
    }
}

/// What a predecessor or systemd handed this process.
#[derive(Default)]
pub struct Inherited {
    /// The listening socket, or why the one named can't be used.
    pub listener: Option<Result<(std::net::TcpListener, Source), String>>,
    /// The readiness pipe ([`signal_ready`]), if this is a successor.
    pub ready: Option<std::fs::File>,
    /// The predecessor's PID, if this is a successor.
    pub predecessor: Option<u32>,
}

impl Inherited {
    /// Take it from the environment. Must run before any other thread
    /// exists: the variables that named it are removed, so nothing this
    /// process starts sees them. The descriptors are made close-on-exec
    /// (ssh children must not hold the socket open).
    pub fn take() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        let (fd, ready, pred, fds, pid) = (
            var(LISTEN_FD_ENV),
            var(READY_FD_ENV),
            var(PREDECESSOR_ENV),
            var("LISTEN_FDS"),
            var("LISTEN_PID"),
        );
        for k in [
            LISTEN_FD_ENV,
            READY_FD_ENV,
            PREDECESSOR_ENV,
            "LISTEN_FDS",
            "LISTEN_PID",
            "LISTEN_FDNAMES",
        ] {
            // SAFETY: called first thing in `main`, before any thread.
            unsafe { std::env::remove_var(k) };
        }
        let ready = ready
            .and_then(|v| v.trim().parse::<RawFd>().ok())
            .filter(|fd| set_cloexec(*fd).is_ok())
            // SAFETY: the predecessor opened it for us at this number.
            .map(|fd| unsafe { std::fs::File::from_raw_fd(fd) });
        let listener = match (fd, fds) {
            (Some(v), _) => Some(
                v.trim()
                    .parse::<RawFd>()
                    .map_err(|_| format!("{LISTEN_FD_ENV}={v:?} is not a descriptor"))
                    .and_then(|fd| adopt(fd, Source::Handover)),
            ),
            (None, Some(n))
                if pid.and_then(|p| p.trim().parse::<u32>().ok()) == Some(std::process::id()) =>
            {
                if n.trim() == "1" {
                    Some(adopt(3, Source::Systemd))
                } else {
                    Some(Err(format!(
                        "LISTEN_FDS={n}: prompto takes exactly one socket (one ListenStream=)"
                    )))
                }
            }
            _ => None,
        };
        Self {
            listener,
            ready,
            predecessor: pred.and_then(|v| v.trim().parse().ok()),
        }
    }
}

fn adopt(fd: RawFd, source: Source) -> Result<(std::net::TcpListener, Source), String> {
    check_listening_socket(fd).map_err(|e| e.to_string())?;
    set_cloexec(fd).map_err(|e| e.to_string())?;
    // SAFETY: checked above to be an open listening socket nothing else
    // in this process owns.
    let l = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    l.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok((l, source))
}

fn check_listening_socket(fd: RawFd) -> Result<()> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid out-pointers of the right size.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if r != 0 {
        bail!(
            "inherited descriptor {fd} is not a socket: {}",
            std::io::Error::last_os_error()
        );
    }
    if v == 0 {
        bail!("inherited descriptor {fd} is a socket that is not listening");
    }
    Ok(())
}

fn set_cloexec(fd: RawFd) -> Result<()> {
    // SAFETY: fcntl on a descriptor checked to be open.
    let r = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if r != 0 {
        bail!("FD_CLOEXEC on {fd}: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Tell the predecessor this process serves now.
pub fn signal_ready(pipe: std::fs::File) {
    use std::io::Write;
    let mut pipe = pipe;
    if let Err(e) = pipe.write_all(b"R") {
        tracing::error!(error = %e, "cannot tell the predecessor this process is ready");
    }
}

/// Resolves once `pid`, this process's parent at handover, has exited
/// (this process is then re-parented).
pub async fn predecessor_gone(pid: u32) {
    // SAFETY: getppid has no preconditions.
    while unsafe { libc::getppid() } as u32 == pid {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Send `msg` to systemd's notify socket, if there is one.
pub fn notify(msg: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Err(e) = send_notify(Path::new(&path), msg) {
        tracing::warn!(error = %e, "sd_notify failed");
    }
}

fn send_notify(path: &Path, msg: &str) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    let sock = UnixDatagram::unbound()?;
    let bytes = path.as_os_str().as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(msg.as_bytes(), &addr)?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(std::io::Error::other("abstract notify socket off Linux"));
        }
    }
    sock.send_to(msg.as_bytes(), path)?;
    Ok(())
}

/// Why a handover can't be done here, if it can't: under systemd
/// (`INVOCATION_ID`) without a notify socket the unit is `Type=simple`,
/// and systemd would kill the successor when this process exits.
pub fn refusal(invocation_id: Option<&str>, notify_socket: Option<&str>) -> Option<&'static str> {
    match (invocation_id, notify_socket) {
        (Some(_), None) => Some(
            "the systemd unit is not Type=notify, so systemd would stop the successor when this \
             process exits — install deploy/prompto.service (Type=notify) and restart once",
        ),
        _ => None,
    }
}

/// The binary to start as successor: the path this process was started
/// as (a deploy replaced the file there), else the running executable.
pub fn successor_exe() -> Result<PathBuf> {
    if let Some(a0) = std::env::args_os().next().map(PathBuf::from)
        && a0.is_absolute()
    {
        return Ok(a0);
    }
    let exe = std::env::current_exe().context("current_exe")?;
    // Linux names a replaced binary "<path> (deleted)".
    let s = exe.to_string_lossy();
    Ok(s.strip_suffix(" (deleted)")
        .map_or(exe.clone(), PathBuf::from))
}

/// `KEY=VALUE` lines as systemd's `EnvironmentFile=` reads them (the
/// common subset): blank lines and `#`/`;` comments skipped, the key and
/// an unquoted value trimmed, one pair of surrounding `"…"` or `'…'`
/// removed, `\` escapes inside double quotes. Lines without `=` or with
/// an invalid name are skipped, as systemd does.
pub fn parse_env_file(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim_start();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let valid = !k.is_empty()
            && !k.starts_with(|c: char| c.is_ascii_digit())
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            continue;
        }
        let v = v.trim();
        let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            let mut s = String::new();
            let mut it = v[1..v.len() - 1].chars();
            while let Some(c) = it.next() {
                if c == '\\' {
                    if let Some(n) = it.next() {
                        s.push(n);
                    }
                } else {
                    s.push(c);
                }
            }
            s
        } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
            v[1..v.len() - 1].to_string()
        } else {
            v.to_string()
        };
        out.insert(k.to_string(), v);
    }
    out
}

/// What to change in this process's environment for a successor: the
/// env file as it is now on top, and the keys that were in it at this
/// process's start (`at_start`) but no longer are removed. `Err` if the
/// file can't be read: the handover is then refused rather than started
/// with a configuration that may be stale.
pub fn successor_env(
    file: &Path,
    at_start: &BTreeMap<String, String>,
) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("re-reading {} ({ENV_FILE_ENV})", file.display()))?;
    let now = parse_env_file(&text);
    let removed = at_start
        .keys()
        .filter(|k| !now.contains_key(*k))
        .cloned()
        .collect();
    Ok((now, removed))
}

/// A successor started and not yet ready.
pub struct Successor {
    pub child: tokio::process::Child,
    ready: std::fs::File,
}

/// Start `exe` with `listener` as fd 3 and a readiness pipe as fd 4.
pub fn spawn_successor(
    exe: &Path,
    args: &[String],
    listener: RawFd,
    set: &BTreeMap<String, String>,
    remove: &[String],
) -> Result<Successor> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: a valid out-array of two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    let (rd, wr) = (fds[0], fds[1]);
    // SAFETY: both just opened and owned here.
    let (ready, wr_file) = unsafe {
        (
            std::fs::File::from_raw_fd(rd),
            std::fs::File::from_raw_fd(wr),
        )
    };
    set_cloexec(rd)?;
    set_cloexec(wr)?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args);
    for k in remove {
        cmd.env_remove(k);
    }
    cmd.envs(set)
        .env(LISTEN_FD_ENV, "3")
        .env(READY_FD_ENV, "4")
        .env(PREDECESSOR_ENV, std::process::id().to_string());
    let wr_fd = wr_file.as_raw_fd();
    // SAFETY: only async-signal-safe calls (fcntl, dup2, close) between
    // fork and exec. Each source is first copied above 10 so neither can
    // be overwritten by the other's dup2, and dup2 clears close-on-exec
    // on 3 and 4.
    unsafe {
        cmd.pre_exec(move || {
            let a = libc::fcntl(listener, libc::F_DUPFD, 10);
            let b = libc::fcntl(wr_fd, libc::F_DUPFD, 10);
            if a < 0 || b < 0 || libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(a);
            libc::close(b);
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    // Ours closed: the pipe reads EOF if the successor exits unready.
    drop(wr_file);
    Ok(Successor { child, ready })
}

impl Successor {
    /// Wait until the successor serves; `Err` (and the successor killed)
    /// if it exits or stays silent past [`READY_TIMEOUT`].
    pub async fn ready(mut self) -> Result<u32> {
        let pid = self.child.id().context("successor already reaped")?;
        let mut pipe = self.ready;
        let read = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut b = [0u8; 1];
            pipe.read(&mut b).map(|n| n == 1 && b[0] == b'R')
        });
        match tokio::time::timeout(READY_TIMEOUT, read).await {
            Ok(Ok(Ok(true))) => {
                // Reaped in the background if it exits while we still run.
                tokio::spawn(async move {
                    let _ = self.child.wait().await;
                });
                Ok(pid)
            }
            Ok(_) => {
                let status = self.child.wait().await;
                bail!("the successor exited before it was ready ({status:?}); see its log above")
            }
            Err(_) => {
                let _ = self.child.kill().await;
                bail!(
                    "the successor was not ready within {}s; killed it",
                    READY_TIMEOUT.as_secs()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_subset() {
        let m = parse_env_file(
            "# c\n; c\n\nA=1\n B = two words \nC=\"q \\\"x\\\" y\"\nD='s q'\nbad line\n9X=1\nE=\nF=a=b\n",
        );
        assert_eq!(m["A"], "1");
        assert_eq!(m["B"], "two words");
        assert_eq!(m["C"], "q \"x\" y");
        assert_eq!(m["D"], "s q");
        assert_eq!(m["E"], "");
        assert_eq!(m["F"], "a=b");
        assert!(!m.contains_key("9X"));
        assert_eq!(m.len(), 6);
    }

    #[test]
    fn successor_env_drops_keys_removed_from_the_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("env");
        std::fs::write(&f, "A=1\nB=2\n").unwrap();
        let start = parse_env_file(&std::fs::read_to_string(&f).unwrap());
        std::fs::write(&f, "A=3\nC=4\n").unwrap();
        let (set, removed) = successor_env(&f, &start).unwrap();
        assert_eq!(set["A"], "3");
        assert_eq!(set["C"], "4");
        assert_eq!(removed, vec!["B".to_string()]);
        assert!(successor_env(&d.path().join("none"), &start).is_err());
    }

    /// A `Type=simple` unit would kill the successor with the old
    /// process: refused. Outside systemd, or with a notify socket, fine.
    #[test]
    fn handover_refused_under_systemd_without_notify() {
        assert!(refusal(Some("abc"), None).is_some());
        assert!(refusal(Some("abc"), Some("/run/systemd/notify")).is_none());
        assert!(refusal(None, None).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notify_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("prompto-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = std::os::unix::net::UnixDatagram::bind_addr(&addr).unwrap();
        send_notify(Path::new(&format!("@{name}")), "READY=1").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn notify_reaches_a_path_socket() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("n.sock");
        let rx = std::os::unix::net::UnixDatagram::bind(&p).unwrap();
        send_notify(&p, "MAINPID=1\nREADY=1").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"MAINPID=1\nREADY=1");
    }
}
