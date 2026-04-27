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

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
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

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("diff truncated") { 2 } else { 1 }
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

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
    }
}

/// Match `git status [...]`. Drops the noisy `(use "git ...")` hint lines
/// and collapses to `ok` when the working tree is clean. Pure parser —
/// lifted from RTK (Apache-2.0/MIT, Patrick Szymkowiak).
pub struct GitStatus;

impl CommandFilter for GitStatus {
    fn name(&self) -> &'static str {
        "git_status"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_git_subcommand(cmd, "status")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut kept = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("(use \"git")
                || trimmed.starts_with("(create/copy files")
                || trimmed.contains("(use \"git add")
                || trimmed.contains("(use \"git restore")
            {
                continue;
            }
            if trimmed.contains("nothing to commit") && trimmed.contains("working tree clean") {
                return Cow::Owned("ok".to_string());
            }
            kept.push(line);
        }
        if kept.is_empty() {
            Cow::Owned("ok".to_string())
        } else {
            Cow::Owned(kept.join("\n"))
        }
    }
}

/// Match `git branch [-a|-r|...]`. Highlights current branch, separates
/// local from remote-only, caps remote-only at 10. Lifted from RTK.
pub struct GitBranch;

impl CommandFilter for GitBranch {
    fn name(&self) -> &'static str {
        "git_branch"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_git_subcommand(cmd, "branch")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut current = String::new();
        let mut local: Vec<String> = Vec::new();
        let mut remote: Vec<String> = Vec::new();
        let mut seen_remote: std::collections::HashSet<String> = std::collections::HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(branch) = line.strip_prefix("* ") {
                current = branch.to_string();
            } else if let Some(rest) = line.strip_prefix("remotes/") {
                if let Some(slash) = rest.find('/') {
                    let branch = &rest[slash + 1..];
                    if branch.starts_with("HEAD ") {
                        continue;
                    }
                    if seen_remote.insert(branch.to_string()) {
                        remote.push(branch.to_string());
                    }
                }
            } else {
                local.push(line.to_string());
            }
        }

        let mut out = Vec::new();
        if !current.is_empty() {
            out.push(format!("* {current}"));
        }
        for b in &local {
            out.push(format!("  {b}"));
        }
        let remote_only: Vec<&String> = remote
            .iter()
            .filter(|r| *r != &current && !local.contains(r))
            .collect();
        if !remote_only.is_empty() {
            out.push(format!("  remote-only ({}):", remote_only.len()));
            for b in remote_only.iter().take(10) {
                out.push(format!("    {b}"));
            }
            if remote_only.len() > 10 {
                out.push(format!("    ... +{} more", remote_only.len() - 10));
            }
        }
        Cow::Owned(out.join("\n"))
    }

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("... +") { 2 } else { 1 }
    }
}

/// Match `git stash list`. Strips the "WIP on <branch>:" prefix from each
/// entry. Lifted from RTK.
pub struct GitStashList;

impl CommandFilter for GitStashList {
    fn name(&self) -> &'static str {
        "git_stash_list"
    }

    fn matches(&self, cmd: &str) -> bool {
        if !is_git_subcommand(cmd, "stash") {
            return false;
        }
        cmd.split_whitespace().any(|t| t == "list")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut out = Vec::new();
        for line in stdout.lines() {
            if let Some(colon) = line.find(": ") {
                let index = &line[..colon];
                let rest = &line[colon + 2..];
                let message = if let Some(second) = rest.find(": ") {
                    rest[second + 2..].trim()
                } else {
                    rest.trim()
                };
                out.push(format!("{index}: {message}"));
            } else {
                out.push(line.to_string());
            }
        }
        Cow::Owned(out.join("\n"))
    }
}

/// Match `git worktree list`. Joins the `path  hash  [branch]` columns
/// into a normalized one-line-per-worktree shape. Lifted from RTK
/// (without local-home-dir abbreviation, since prompto runs against
/// remote hosts).
pub struct GitWorktreeList;

impl CommandFilter for GitWorktreeList {
    fn name(&self) -> &'static str {
        "git_worktree_list"
    }

    fn matches(&self, cmd: &str) -> bool {
        if !is_git_subcommand(cmd, "worktree") {
            return false;
        }
        cmd.split_whitespace().any(|t| t == "list")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut out = Vec::new();
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let path = parts[0];
                let hash = parts[1];
                let branch = parts[2..].join(" ");
                out.push(format!("{path} {hash} {branch}"));
            } else {
                out.push(line.to_string());
            }
        }
        Cow::Owned(out.join("\n"))
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
    fn tier_full_when_under_cap() {
        let s = "abc one\nabc two\n";
        let out = GitLog.filter("git log", s);
        assert_eq!(GitLog.tier(&out), 1);
    }

    #[test]
    fn tier_degraded_when_truncated() {
        let s: String = (0..80).map(|i| format!("commit-{i}\n")).collect();
        let out = GitLog.filter("git log", &s);
        assert_eq!(GitLog.tier(&out), 2);
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

    #[test]
    fn git_status_clean_tree_collapses_to_ok() {
        let s = "On branch main\nYour branch is up to date with 'origin/main'.\n\nnothing to commit, working tree clean\n";
        let out = GitStatus.filter("git status", s);
        assert_eq!(out, "ok");
    }

    #[test]
    fn git_status_strips_hint_lines() {
        let s = "On branch main\n\
                 Changes not staged for commit:\n\
                   (use \"git add <file>...\" to update what will be committed)\n\
                   (use \"git restore <file>...\" to discard changes in working directory)\n\
                 \tmodified:   src/main.rs\n";
        let out = GitStatus.filter("git status", s);
        assert!(out.contains("modified:   src/main.rs"));
        assert!(!out.contains("(use \"git"));
        assert!(!out.contains("\n\n"));
    }

    #[test]
    fn git_branch_groups_remote_only() {
        let s = "* main\n  feature/x\n  remotes/origin/HEAD -> origin/main\n  remotes/origin/main\n  remotes/origin/feature/y\n";
        let out = GitBranch.filter("git branch -a", s);
        assert!(out.contains("* main"));
        assert!(out.contains("  feature/x"));
        assert!(out.contains("remote-only (1)"));
        assert!(out.contains("    feature/y"));
    }

    #[test]
    fn git_branch_caps_remote_only_at_10() {
        let mut s = String::from("* main\n");
        for i in 0..15 {
            s.push_str(&format!("  remotes/origin/branch-{i}\n"));
        }
        let out = GitBranch.filter("git branch -a", &s);
        assert!(out.contains("remote-only (15)"));
        assert!(out.contains("... +5 more"));
        assert_eq!(GitBranch.tier(&out), 2);
    }

    #[test]
    fn git_stash_list_strips_wip_prefix() {
        let s = "stash@{0}: WIP on main: abc1234 some change\nstash@{1}: On feature: def5678 another change\n";
        let out = GitStashList.filter("git stash list", s);
        assert!(out.contains("stash@{0}: abc1234 some change"));
        assert!(out.contains("stash@{1}: def5678 another change"));
        assert!(!out.contains("WIP on"));
    }

    #[test]
    fn git_stash_list_only_matches_list_subcommand() {
        assert!(GitStashList.matches("git stash list"));
        assert!(!GitStashList.matches("git stash"));
        assert!(!GitStashList.matches("git stash pop"));
    }

    #[test]
    fn git_worktree_list_normalizes_columns() {
        let s = "/repo/main             abc1234 [main]\n/repo/feature-x        def5678 [feature/x]\n";
        let out = GitWorktreeList.filter("git worktree list", s);
        assert_eq!(out, "/repo/main abc1234 [main]\n/repo/feature-x def5678 [feature/x]");
    }
}
