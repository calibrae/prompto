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
//! 4. probation ([`PROBATION`]): both processes accept, and the
//!    successor must stay up — if it dies, the old server, which never
//!    stopped accepting, carries on alone ([`Successor::proven`]);
//! 5. the old server tells systemd the successor is the service's main
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
/// How long a successor that serves must stay up, both processes
/// accepting, before it becomes the main process ([`Successor::proven`]).
pub const PROBATION: Duration = Duration::from_secs(5);

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

/// Is `fd` a listening TCP socket? Portable: `fstat` says socket,
/// `SO_TYPE` stream, `getsockname` an IPv4/IPv6 address, and
/// `getpeername` finds no peer (a connected socket has one).
/// `SO_ACCEPTCONN` then confirms it listens where the kernel answers it:
/// Linux and FreeBSD do, macOS fails it with `ENOPROTOOPT`, so there a
/// stream socket with no peer is taken as listening.
fn check_listening_socket(fd: RawFd) -> Result<()> {
    check_socket(fd, ACCEPTCONN_SUPPORTED)
}

fn check_socket(fd: RawFd, acceptconn: bool) -> Result<()> {
    let err = std::io::Error::last_os_error;
    // SAFETY: a zeroed stat is a valid out-buffer for fstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        bail!("inherited descriptor {fd} is not open: {}", err());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        bail!("inherited descriptor {fd} is not a socket");
    }
    if sockopt(fd, libc::SO_TYPE).map_err(|e| anyhow::anyhow!("SO_TYPE on {fd}: {e}"))?
        != libc::SOCK_STREAM
    {
        bail!("inherited descriptor {fd} is not a stream socket");
    }
    // SAFETY: a zeroed sockaddr_storage is a valid out-buffer.
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: valid out-pointers of the right size.
    if unsafe {
        libc::getsockname(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } != 0
    {
        bail!("getsockname on inherited descriptor {fd}: {}", err());
    }
    let family = libc::c_int::from(addr.ss_family);
    if family != libc::AF_INET && family != libc::AF_INET6 {
        bail!("inherited descriptor {fd} is not a TCP/IP socket (family {family})");
    }
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: as above.
    if unsafe {
        libc::getpeername(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } == 0
    {
        bail!("inherited descriptor {fd} is a connected socket, not a listening one");
    }
    if acceptconn {
        match sockopt(fd, libc::SO_ACCEPTCONN) {
            Ok(0) => bail!("inherited descriptor {fd} is a socket that is not listening"),
            Ok(_) => {}
            // Not answered here after all: the checks above stand.
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
            Err(e) => bail!("SO_ACCEPTCONN on inherited descriptor {fd}: {e}"),
        }
    }
    Ok(())
}

/// Whether the kernel answers `SO_ACCEPTCONN` (see
/// [`check_listening_socket`]).
const ACCEPTCONN_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd"
));

fn sockopt(fd: RawFd, opt: libc::c_int) -> std::io::Result<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid out-pointers of the right size.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(v)
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

/// A successor started and not yet proven (see [`Successor::proven`]).
pub struct Successor {
    child: tokio::process::Child,
    ready: Option<std::io::PipeReader>,
    /// It said it serves: it accepts on the socket too.
    serving: bool,
}

/// Start `exe` with `listener` as fd 3 and a readiness pipe as fd 4.
pub fn spawn_successor(
    exe: &Path,
    args: &[String],
    listener: RawFd,
    set: &BTreeMap<String, String>,
    remove: &[String],
) -> Result<Successor> {
    // Both ends close-on-exec from the start (`pipe2(O_CLOEXEC)` where
    // there is one; macOS has none, std sets the flag right after), so
    // no other child — an ssh started meanwhile — inherits the write end
    // and keeps the pipe from reading EOF when the successor dies.
    let (ready, wr) = std::io::pipe().context("readiness pipe")?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args);
    for k in remove {
        cmd.env_remove(k);
    }
    cmd.envs(set)
        .env(LISTEN_FD_ENV, "3")
        .env(READY_FD_ENV, "4")
        .env(PREDECESSOR_ENV, std::process::id().to_string());
    let wr_fd = wr.as_raw_fd();
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
    drop(wr);
    Ok(Successor {
        child,
        ready: Some(ready),
        serving: false,
    })
}

impl Successor {
    /// The two phases of a handover; the caller keeps serving — accepting
    /// on the socket — throughout, and its PID when the successor is
    /// proven:
    ///
    /// 1. the successor loads its configuration and starts serving, then
    ///    says so on the pipe — `Err` (and the successor killed) if it
    ///    exits first or stays silent past [`READY_TIMEOUT`];
    /// 2. probation: both processes accept for `probation`, and the
    ///    successor must still be running at its end — `Err` if it exits
    ///    meanwhile.
    ///
    /// Only then may the caller move `MAINPID` and stop accepting. A
    /// successor that crashes right after "ready" thus never becomes the
    /// service's main process: the old one, which never stopped
    /// accepting, carries on alone, instead of systemd restarting the
    /// service and killing the calls it was draining. (A connection the
    /// successor accepted before dying is lost with it.)
    pub async fn proven(&mut self, probation: Duration) -> Result<u32> {
        let pid = self.child.id().context("successor already reaped")?;
        let mut pipe = self.ready.take().context("successor already waited for")?;
        let read = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut b = [0u8; 1];
            pipe.read(&mut b).map(|n| n == 1 && b[0] == b'R')
        });
        match tokio::time::timeout(READY_TIMEOUT, read).await {
            Ok(Ok(Ok(true))) => {}
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
        self.serving = true;
        tracing::info!(
            successor = pid,
            probation_secs = probation.as_secs(),
            "handover: the successor serves; both accept until its probation ends"
        );
        tokio::select! {
            status = self.child.wait() => bail!(
                "the successor exited during its probation ({status:?}), after it said it was \
                 ready; see its log above"
            ),
            () = tokio::time::sleep(probation) => Ok(pid),
        }
    }

    /// The successor runs on; reaped in the background if it exits while
    /// this process still runs.
    pub fn detach(mut self) {
        tokio::spawn(async move {
            let _ = self.child.wait().await;
        });
    }

    /// This process stops before the successor was proven: one that
    /// already serves is asked to drain (SIGTERM), one that doesn't yet
    /// is killed.
    pub fn abandon(mut self) {
        match (self.serving, self.child.id()) {
            (true, Some(pid)) => {
                // SAFETY: kill has no memory-safety preconditions; the
                // child is unreaped, so the PID is still its own.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            }
            _ => {
                let _ = self.child.start_kill();
            }
        }
        self.detach();
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

    /// The inherited-socket check, both ways: with `SO_ACCEPTCONN` (Linux,
    /// FreeBSD) and without (macOS, where the kernel refuses it — a
    /// check that relied on it failed every handover there).
    #[test]
    fn only_a_listening_tcp_socket_is_adopted() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let d = tempfile::tempdir().unwrap();
        let unix = std::os::unix::net::UnixListener::bind(d.path().join("s")).unwrap();
        let file = std::fs::File::open(d.path()).unwrap();
        for acceptconn in [false, true] {
            check_socket(listener.as_raw_fd(), acceptconn).unwrap();
            for (fd, what) in [
                (client.as_raw_fd(), "connected"),
                (udp.as_raw_fd(), "stream"),
                (unix.as_raw_fd(), "TCP/IP"),
                (file.as_raw_fd(), "not a socket"),
                (-1, "not open"),
            ] {
                let e = check_socket(fd, acceptconn).unwrap_err().to_string();
                assert!(e.contains(what), "{what}: {e}");
            }
        }
        check_listening_socket(listener.as_raw_fd()).unwrap();
    }

    /// Where the kernel answers it, a bound TCP socket that never called
    /// `listen` is refused too.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn a_bound_socket_that_does_not_listen_is_refused() {
        // SAFETY: plain socket calls on a descriptor owned here.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(fd >= 0);
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let r = libc::bind(
                fd,
                (&sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            assert_eq!(r, 0);
            let e = check_listening_socket(fd).unwrap_err().to_string();
            assert!(e.contains("not listening"), "{e}");
            libc::close(fd);
        }
    }
}
