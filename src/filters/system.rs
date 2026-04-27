//! System-tool filters: `journalctl`, `find`, `ls -l`. Conservative —
//! drop only what's clearly noise.

use std::borrow::Cow;

use super::CommandFilter;

const FIND_LINE_CAP: usize = 100;

pub struct Journalctl;

impl CommandFilter for Journalctl {
    fn name(&self) -> &'static str {
        "journalctl"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace().any(|t| t == "journalctl")
    }

    /// journalctl tails are already line-bounded by `-n`. Compaction
    /// here is just dedup of consecutive identical lines, which catches
    /// "unit restarted N times in M seconds" floods.
    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut out = String::with_capacity(stdout.len());
        let mut prev: Option<&str> = None;
        let mut repeat = 0u64;
        let mut changed = false;
        for line in stdout.lines() {
            // Compare ignoring leading timestamps so two identical events
            // 1 second apart collapse. journalctl default format starts
            // with `Mon DD HH:MM:SS host service[pid]:` — drop everything
            // up to the first `]:`.
            let body = strip_journal_prefix(line);
            if Some(body) == prev {
                repeat += 1;
                changed = true;
                continue;
            }
            if repeat > 0 {
                out.push_str(&format!("(… repeated {repeat} more times)\n"));
                repeat = 0;
            }
            out.push_str(line);
            out.push('\n');
            prev = Some(body);
        }
        if repeat > 0 {
            out.push_str(&format!("(… repeated {repeat} more times)\n"));
            changed = true;
        }
        if changed {
            Cow::Owned(out)
        } else {
            Cow::Borrowed(stdout)
        }
    }
}

fn strip_journal_prefix(line: &str) -> &str {
    if let Some(idx) = line.find("]: ") {
        &line[idx + 3..]
    } else {
        line
    }
}

pub struct FindCmd;

impl CommandFilter for FindCmd {
    fn name(&self) -> &'static str {
        "find"
    }

    fn matches(&self, cmd: &str) -> bool {
        // Bare `find` invocation — first non-env token is `find`.
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "find")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let total = stdout.lines().count();
        if total <= FIND_LINE_CAP {
            return Cow::Borrowed(stdout);
        }
        let mut out: String = stdout
            .lines()
            .take(FIND_LINE_CAP)
            .collect::<Vec<_>>()
            .join("\n");
        out.push('\n');
        out.push_str(&format!(
            "… find truncated ({FIND_LINE_CAP} kept, {total} total)\n"
        ));
        Cow::Owned(out)
    }
}

pub struct LsLong;

impl CommandFilter for LsLong {
    fn name(&self) -> &'static str {
        "ls_long"
    }

    fn matches(&self, cmd: &str) -> bool {
        // `ls -l`, `ls -la`, `ls -al`, etc. — flags after the first token.
        let mut tokens = cmd.split_whitespace();
        if tokens.next() != Some("ls") {
            return false;
        }
        tokens.any(|t| {
            if let Some(flags) = t.strip_prefix('-') {
                flags.contains('l')
            } else {
                false
            }
        })
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        // Drop "total N" header and blank lines.
        let mut out = String::with_capacity(stdout.len());
        let mut changed = false;
        for line in stdout.lines() {
            if line.starts_with("total ") || line.trim().is_empty() {
                changed = true;
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        if changed {
            Cow::Owned(out)
        } else {
            Cow::Borrowed(stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journalctl_dedupes_consecutive_repeats() {
        let s = "Apr 27 08:37:27 doppio doppio-mqtt.sh[1265]: Error: No route to host\n\
                 Apr 27 08:37:30 doppio doppio-mqtt.sh[1267]: Error: No route to host\n\
                 Apr 27 08:37:33 doppio doppio-mqtt.sh[1268]: Error: No route to host\n\
                 Apr 27 08:37:36 doppio systemd[1]: Started doppio-mqtt.service\n";
        let out = Journalctl.filter("journalctl -u doppio-mqtt", s);
        // First "No route" line stays, next two collapse, then the Started line.
        assert!(out.contains("Error: No route to host"));
        assert!(out.contains("repeated 2 more times"));
        assert!(out.contains("Started doppio-mqtt"));
    }

    #[test]
    fn journalctl_passes_through_when_no_repeats() {
        let s = "Apr 27 08:37:27 doppio app[1]: a\n\
                 Apr 27 08:37:28 doppio app[1]: b\n\
                 Apr 27 08:37:29 doppio app[1]: c\n";
        let out = Journalctl.filter("journalctl", s);
        assert_eq!(out, s);
    }

    #[test]
    fn find_caps_at_100() {
        let s: String = (0..200).map(|i| format!("/path/{i}\n")).collect();
        let out = FindCmd.filter("find / -name foo", &s);
        let kept = out.lines().filter(|l| l.starts_with("/path/")).count();
        assert_eq!(kept, 100);
        assert!(out.contains("200 total"));
    }

    #[test]
    fn ls_long_drops_total_header() {
        let s = "total 4096\n\
                 drwx------ 2 cali staff 64 Apr 27 ./\n\
                 -rw-r--r-- 1 cali staff 12 Apr 27 file\n";
        let out = LsLong.filter("ls -la", s);
        assert!(!out.contains("total 4096"));
        assert!(out.contains("drwx"));
    }

    #[test]
    fn ls_long_matches_combined_flags() {
        assert!(LsLong.matches("ls -la"));
        assert!(LsLong.matches("ls -al"));
        assert!(LsLong.matches("ls -l /tmp"));
        assert!(LsLong.matches("ls /tmp -l"));
        assert!(!LsLong.matches("ls -h"));
        assert!(!LsLong.matches("cat -l"));
    }
}
