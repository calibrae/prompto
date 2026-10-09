//! What a `stat` of a config file says (`agents.toml`, `policy.toml`):
//! enough to notice any change — an atomic replace changes the inode, an
//! in-place edit moves mtime, ctime or size — for one `stat` per call.

use std::path::Path;

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
}
