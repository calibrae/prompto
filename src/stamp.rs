//! What a `stat` of a config file says (`agents.toml`, `policy.toml`):
//! enough to notice any change — an atomic replace changes the inode, an
//! in-place edit moves mtime, ctime or size — for one `stat` per call.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stamp {
    Missing,
    Unreadable(std::io::ErrorKind),
    File {
        dev: u64,
        ino: u64,
        size: u64,
        mtime: (i64, i64),
        ctime: (i64, i64),
    },
}

impl Stamp {
    pub fn of(path: &Path) -> Self {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path) {
            Ok(m) => Stamp::File {
                dev: m.dev(),
                ino: m.ino(),
                size: m.size(),
                mtime: (m.mtime(), m.mtime_nsec()),
                ctime: (m.ctime(), m.ctime_nsec()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stamp::Missing,
            Err(e) => Stamp::Unreadable(e.kind()),
        }
    }
}

impl Stamp {
    /// Modified so recently that a second write in the same timestamp
    /// tick could leave every field as it is (coarse kernel clocks tick
    /// every few ms; some filesystems store whole seconds).
    fn racy(&self) -> bool {
        let Stamp::File { mtime, ctime, .. } = self else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        now - mtime.0.max(ctime.0) < RACY_SECS
    }
}

impl Stamp {
    /// Time since the file's content last changed (mtime); `None` if it
    /// isn't a file or its mtime is in the future.
    fn age(&self) -> Option<Duration> {
        let Stamp::File { mtime, .. } = self else {
            return None;
        };
        let t =
            UNIX_EPOCH.checked_add(Duration::new(u64::try_from(mtime.0).ok()?, mtime.1 as u32))?;
        SystemTime::now().duration_since(t).ok()
    }
}

/// Read a config file that its writer may not replace atomically (an
/// editor or `echo >` truncates, then writes), retrying what looks like
/// half a file:
///
/// - the stamps around the read differ: the read overlapped a write;
/// - the read failed and the file was written in the last
///   [`SETTLE_FRESH`]: probably a writer between its truncate and its
///   last write, so wait [`SETTLE_PAUSE`] and read again.
///
/// Returns the stamp taken before the read whose result is returned.
/// After [`SETTLE_TRIES`] the last result stands — the store fails closed
/// on it if it is invalid; if the file is still changing its stamp no
/// longer matches, so the next check reads it again. The wait blocks the
/// calling request, at most `(SETTLE_TRIES - 1) * SETTLE_PAUSE`, and only
/// while a just-written file doesn't parse.
pub fn read_settled<T, E>(
    path: &Path,
    mut read: impl FnMut(&Path) -> Result<T, E>,
) -> (Stamp, Result<T, E>) {
    let mut tries = 0;
    loop {
        tries += 1;
        let before = Stamp::of(path);
        let out = read(path);
        let moved = Stamp::of(path) != before;
        let half_written = out.is_err() && before.age().is_some_and(|a| a < SETTLE_FRESH);
        if tries == SETTLE_TRIES || !(moved || half_written) {
            return (before, out);
        }
        if !moved {
            std::thread::sleep(SETTLE_PAUSE);
        }
    }
}

/// Reads per [`read_settled`] call.
const SETTLE_TRIES: u32 = 3;
/// A file that fails to parse is suspected to be mid-write this long
/// after its last write...
const SETTLE_FRESH: Duration = Duration::from_millis(50);
/// ...and given this long to finish before it is read again.
const SETTLE_PAUSE: Duration = Duration::from_millis(5);

/// A file modified less than this long before it was read is read again
/// on the next check, whatever its stamp says (git's "racy" rule).
const RACY_SECS: i64 = 2;

/// What a store last read: its stamp, and whether that stamp can be
/// trusted to show the next change ([`Stamp::racy`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct Seen(Option<(Stamp, bool)>);

impl Seen {
    /// Record the stamp taken just before a read.
    pub fn record(&mut self, s: Stamp) {
        self.0 = Some((s, s.racy()));
    }

    /// Should the file, which now looks like `now`, be read again?
    /// `None`: no. `Some(true)`: it changed. `Some(false)`: same stamp,
    /// but too fresh to trust (a quiet re-read).
    pub fn check(&self, now: Stamp) -> Option<bool> {
        match self.0 {
            Some((s, false)) if s == now => None,
            Some((s, true)) if s == now => Some(false),
            _ => Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file read in the same tick as its last write is read again on
    /// the next check even though its stamp hasn't moved; an old file
    /// with an unchanged stamp is not.
    #[test]
    fn fresh_stamps_are_not_trusted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "a").unwrap();
        let mut seen = Seen::default();
        assert_eq!(seen.check(Stamp::of(&p)), Some(true));
        seen.record(Stamp::of(&p));
        assert_eq!(seen.check(Stamp::of(&p)), Some(false), "fresh: re-read");
        // A stamp whose times are both a minute old is trusted.
        let mut s = Stamp::of(&p);
        if let Stamp::File { mtime, ctime, .. } = &mut s {
            *mtime = (mtime.0 - 60, 0);
            *ctime = (ctime.0 - 60, 0);
        }
        seen.record(s);
        assert_eq!(seen.check(s), None);
        assert_eq!(seen.check(Stamp::Missing), Some(true));
        let mut missing = Seen::default();
        missing.record(Stamp::Missing);
        assert_eq!(missing.check(Stamp::Missing), None);
    }

    /// A read that a writer overlapped (the file changed between the
    /// stamps around it) is retried, and the result returned is from a
    /// read the file held still for, with that read's stamp.
    #[test]
    fn a_read_overlapped_by_a_write_is_retried() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "[agent.half").unwrap();
        let mut reads = 0;
        let (stamp, got) = read_settled(&p, |p| {
            reads += 1;
            let seen = std::fs::read_to_string(p).unwrap();
            if reads == 1 {
                // The writer finishes while we parse the half file.
                std::fs::write(p, "[agent.whole]\n").unwrap();
            }
            Ok::<_, ()>(seen)
        });
        assert_eq!(got.unwrap(), "[agent.whole]\n");
        assert_eq!(reads, 2);
        assert_eq!(stamp, Stamp::of(&p));

        // A writer that never stops: bounded, and the stamp returned is
        // stale, so the next `Seen::check` reads again.
        let mut n = 0u32;
        let (stamp, _) = read_settled(&p, |p| {
            n += 1;
            std::fs::write(p, "x".repeat(n as usize)).unwrap();
            Ok::<_, ()>(())
        });
        assert_eq!(n, SETTLE_TRIES);
        let mut seen = Seen::default();
        seen.record(stamp);
        assert_eq!(seen.check(Stamp::of(&p)), Some(true));
    }

    /// A just-written file that doesn't parse is given time to finish
    /// (the writer is between its truncate and its last write) and read
    /// again; an old one that doesn't parse is broken, and read once.
    #[test]
    fn a_fresh_unparsable_file_is_read_again() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "[agent.ha").unwrap();
        // Fails once, as if the rest of the file arrived during the pause.
        let mut reads = 0;
        let (_, got) = read_settled(&p, |_| {
            reads += 1;
            if reads == 1 { Err("half") } else { Ok(()) }
        });
        assert_eq!((reads, got), (2, Ok(())));

        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(60))
            .unwrap();
        let mut reads = 0;
        let (_, got) = read_settled(&p, |_| {
            reads += 1;
            Err::<(), _>("broken")
        });
        assert_eq!((reads, got), (1, Err("broken")));
    }
}
