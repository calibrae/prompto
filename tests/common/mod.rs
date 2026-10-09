//! Shared by the test binaries that run the real `prompto` server.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Child;
use std::time::Duration;

/// The port of a `prompto` started with `PROMPTO_BIND=127.0.0.1:0` and
/// its stderr in `log`, once it listens: read from its own startup line.
///
/// Not a port probed beforehand (bind `:0`, drop, pass it on): between
/// the drop and the child's bind another test can take it — macOS hands
/// out ephemeral ports at random — and the test then talks to someone
/// else's server, or to none once that one stops.
pub fn bound_port(child: &mut Child, log: &Path) -> u16 {
    const MARK: &str = "transport: streamable-http on ";
    let mut text = String::new();
    for _ in 0..200 {
        text = std::fs::read_to_string(log).unwrap_or_default();
        let addr = text.lines().find_map(|l| {
            let (_, rest) = l.split_once(MARK)?;
            let addr = rest
                .split(|c: char| c.is_whitespace() || c == '\x1b')
                .next()?;
            addr.parse::<SocketAddr>().ok()
        });
        if let Some(a) = addr {
            return a.port();
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("prompto exited before listening ({status}): {text}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("prompto did not start listening: {text}");
}
