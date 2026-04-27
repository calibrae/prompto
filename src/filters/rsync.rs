//! rsync output compaction. Keeps only the `--stats` block at the end
//! ("Number of files: X", "Total transferred file size: Y bytes", etc.).
//! Drops the per-file progress lines that aren't useful in agent
//! context.

use std::borrow::Cow;

use super::CommandFilter;

pub struct Rsync;

impl CommandFilter for Rsync {
    fn name(&self) -> &'static str {
        "rsync"
    }

    fn matches(&self, cmd: &str) -> bool {
        // Bare `rsync` invocation OR an SSH-wrapped rsync (the actual
        // command on the wire when prompto's rsync_sync runs).
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "rsync")
            .unwrap_or(false)
            || cmd.contains(" rsync ")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        // Look for the --stats block: starts with "Number of files:" and
        // the lines after it follow a `<key>: <value>` pattern. If we
        // find it, keep just the stats. Otherwise pass through.
        let mut stats_start: Option<usize> = None;
        for (i, line) in stdout.lines().enumerate() {
            if line.starts_with("Number of files:") {
                stats_start = Some(i);
                break;
            }
        }
        match stats_start {
            Some(start) => {
                let kept: String = stdout.lines().skip(start).collect::<Vec<_>>().join("\n");
                let mut out = kept;
                out.push('\n');
                Cow::Owned(out)
            }
            None => Cow::Borrowed(stdout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsync_keeps_only_stats_block() {
        let s = "sending incremental file list\n\
                 ./\n\
                 file1.txt\n\
                 file2.txt\n\
                 dir/file3.txt\n\
                 \n\
                 Number of files: 4 (reg: 3, dir: 1)\n\
                 Number of created files: 0\n\
                 Total file size: 1,234 bytes\n\
                 Total transferred file size: 1,234 bytes\n\
                 sent 1,500 bytes  received 100 bytes  3,200.00 bytes/sec\n\
                 total size is 1,234  speedup is 0.77\n";
        let out = Rsync.filter("rsync -av src host:dst", s);
        let s = out.as_ref();
        assert!(s.contains("Number of files: 4"));
        assert!(s.contains("Total transferred"));
        assert!(!s.contains("file1.txt"));
        assert!(!s.contains("sending incremental file list"));
    }

    #[test]
    fn rsync_passes_through_when_no_stats() {
        let s = "rsync warning: something\nbut no stats block\n";
        let out = Rsync.filter("rsync foo", s);
        assert_eq!(out, s);
    }

    #[test]
    fn rsync_matches_bare_and_wrapped() {
        assert!(Rsync.matches("rsync -av src dst"));
        assert!(Rsync.matches("ssh host rsync -av src dst"));
        assert!(!Rsync.matches("ls /tmp"));
    }
}
