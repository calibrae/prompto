//! git filters — `log`, `diff`, `show` are the highest-volume cases.

use std::borrow::Cow;

use super::CommandFilter;

const LOG_LINE_CAP: usize = 50;
const DIFF_LINE_CAP: usize = 200;
const SHOW_LINE_CAP: usize = 200;

/// Match `git log [...]` (and `git lg`, common alias). Caps to N commits.
pub struct GitLog;

impl CommandFilter for GitLog {
    fn name(&self) -> &'static str {
        "git_log"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_git_subcommand(cmd, "log") || is_git_subcommand(cmd, "lg")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap_lines(stdout, LOG_LINE_CAP, "commits")
    }
}

/// Match `git diff [...]`. Caps to N lines and drops pure-context lines
/// (lines that don't start with +, -, @, or "diff ").
pub struct GitDiff;

impl CommandFilter for GitDiff {
    fn name(&self) -> &'static str {
        "git_diff"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_git_subcommand(cmd, "diff")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let kept: Vec<&str> = stdout
            .lines()
            .filter(|l| {
                l.starts_with('+')
                    || l.starts_with('-')
                    || l.starts_with("@@")
                    || l.starts_with("diff ")
                    || l.starts_with("--- ")
                    || l.starts_with("+++ ")
                    || l.starts_with("index ")
            })
            .collect();
        if kept.is_empty() {
            return Cow::Borrowed(stdout);
        }
        let truncated = kept.len() > DIFF_LINE_CAP;
        let take = kept.iter().take(DIFF_LINE_CAP);
        let mut out: String = take.copied().collect::<Vec<_>>().join("\n");
        out.push('\n');
        if truncated {
            out.push_str(&format!(
                "… diff truncated ({} kept lines, {} total)\n",
                DIFF_LINE_CAP,
                kept.len()
            ));
        }
        Cow::Owned(out)
    }
}

/// Match `git show [...]`. Same shape as diff with the commit header
/// preserved (everything before the first `diff --git` line).
pub struct GitShow;

impl CommandFilter for GitShow {
    fn name(&self) -> &'static str {
        "git_show"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_git_subcommand(cmd, "show")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap_lines(stdout, SHOW_LINE_CAP, "lines")
    }
}

fn cap_lines<'a>(stdout: &'a str, cap: usize, unit: &str) -> Cow<'a, str> {
    let total = stdout.lines().count();
    if total <= cap {
        return Cow::Borrowed(stdout);
    }
    let mut out: String = stdout.lines().take(cap).collect::<Vec<_>>().join("\n");
    out.push('\n');
    out.push_str(&format!("… truncated ({cap} {unit} kept, {total} total)\n"));
    Cow::Owned(out)
}

/// Match `<prefix> git <subcommand>` allowing inline env, options, etc.
fn is_git_subcommand(cmd: &str, sub: &str) -> bool {
    let tokens = cmd.split_whitespace();
    let mut saw_git = false;
    for t in tokens {
        if !saw_git {
            if t == "git" {
                saw_git = true;
            }
            continue;
        }
        // Skip git-level flags (--no-pager, -C path, etc.) until we hit
        // the first non-flag token, which is the subcommand.
        if t.starts_with('-') {
            continue;
        }
        return t == sub;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_git_log_in_various_shapes() {
        assert!(GitLog.matches("git log"));
        assert!(GitLog.matches("git log --oneline -20"));
        assert!(GitLog.matches("git --no-pager log -5"));
        assert!(GitLog.matches("PAGER=cat git log"));
        assert!(!GitLog.matches("git status"));
        assert!(!GitLog.matches("cargo log"));
    }

    #[test]
    fn git_log_passes_through_when_under_cap() {
        let s = "abc one\nabc two\n";
        let out = GitLog.filter("git log", s);
        assert_eq!(out, s);
    }

    #[test]
    fn git_log_caps_at_50() {
        let s: String = (0..80).map(|i| format!("commit-{i}\n")).collect();
        let out = GitLog.filter("git log", &s);
        let kept = out.lines().filter(|l| l.starts_with("commit-")).count();
        assert_eq!(kept, 50);
        assert!(out.contains("80 total"));
    }

    #[test]
    fn git_diff_drops_context_lines_keeps_changes() {
        let s = "diff --git a/foo b/foo\n\
                 index abc..def 100644\n\
                 --- a/foo\n\
                 +++ b/foo\n\
                 @@ -1,3 +1,3 @@\n\
                  unchanged context line\n\
                 -old line\n\
                 +new line\n\
                  another context line\n";
        let out = GitDiff.filter("git diff", s);
        assert!(out.contains("+new line"));
        assert!(out.contains("-old line"));
        assert!(!out.contains("unchanged context line"));
    }

    #[test]
    fn git_diff_truncates_at_200_changes() {
        let mut s = String::from("diff --git a/foo b/foo\n");
        for i in 0..400 {
            s.push_str(&format!("+line {i}\n"));
        }
        let out = GitDiff.filter("git diff", &s);
        // header + 400 + lines = 401 kept (capped to 200), 401 total.
        assert!(out.contains("diff truncated"));
        assert!(out.contains("401 total"));
    }
}
