//! Output compaction for `ssh_exec` / `ssh_sudo_exec`.
//!
//! Plugin-shaped: each `CommandFilter` declares whether it handles a given
//! remote command and how to compact its stdout. The first filter to claim
//! a command wins; non-matching commands pass through unchanged.
//!
//! Filters are compiled in — there's no subprocess fork or external loader.
//! Adding one is a 30-line file plus a `Box::new` in [`FilterChain::default`].
//! When/if we want third-party filters, the trait stays — we just add an
//! external loader alongside.

use std::borrow::Cow;

/// Re-export of [`tier_parse`]'s structured-parsing primitives. Filters that
/// produce typed output (rather than compacted text) should return a
/// [`ParseResult<T>`] and surface its tier through [`CommandFilter::tier`].
pub use tier_parse::{ParseResult, OutputParser, extract_json_object, truncate_output};

pub mod cargo;
pub mod git;
pub mod k8s;
pub mod node;
pub mod ops;
pub mod pkg;
pub mod python;
pub mod rsync;
pub mod sys;
pub mod system;
pub mod zfs;

pub trait CommandFilter: Send + Sync {
    /// Stable identifier used in the response so callers can see which
    /// filter touched their output.
    fn name(&self) -> &'static str;

    /// Returns true if this filter wants to compact `cmd`'s stdout.
    fn matches(&self, cmd: &str) -> bool;

    /// Compact stdout. Best-effort — return `Cow::Borrowed(stdout)` if the
    /// output doesn't match the expected shape (don't drop data on
    /// surprises).
    fn filter<'a>(&self, cmd: &str, stdout: &'a str) -> Cow<'a, str>;

    /// Tier of the filter's output, in the `tier-parse` sense:
    ///
    /// - `1` = Full — clean structured transform, no data dropped.
    /// - `2` = Degraded — heuristic kicked in (line cap, truncation,
    ///   filter-by-pattern); some content was elided.
    /// - `3` = Passthrough — filter declined to transform; output is the
    ///   raw stdout verbatim.
    ///
    /// Default: Full. Override to expose degradation to callers.
    fn tier(&self, _filtered: &str) -> u8 {
        1
    }
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct FilterReport {
    /// Name of the filter that matched, or `None` if pass-through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<&'static str>,
    pub original_bytes: usize,
    pub filtered_bytes: usize,
    /// `tier-parse` tier: 1 = Full, 2 = Degraded, 3 = Passthrough. Defaults
    /// to 1 when no filter matched (untransformed output is "full" in the
    /// sense that nothing was elided).
    #[serde(default = "default_tier")]
    pub tier: u8,
}

fn default_tier() -> u8 {
    1
}

/// Does `cmd` run more than one command, such that stdout is a
/// concatenation of several commands' output?
///
/// Every filter's `matches()` is a substring test against the whole
/// command string — `cargo_build` fires on `cmd.contains("cargo build")`.
/// That is fine for a lone command and catastrophic for a compound one:
/// `cargo build && echo APPLY_CHECK_OK && grep …` matched `cargo_build`,
/// which then compacted the *entire concatenated* stdout as though it
/// were pure cargo output, silently discarding the echo and grep results.
/// Exit 0, no truncation marker, no log line. Two independent agents hit
/// it on the same day, and it had been live since v0.5.0.
///
/// So: if the command chains statements, no filter runs. The filters
/// only ever knew how to parse one program's output; handing them a
/// concatenation was always outside their contract.
///
/// **Pipes and redirects are deliberately NOT treated as compounding.**
/// `systemctl status foo | head -3` is still one command's output, merely
/// narrowed, and those cases are exactly what the filters handle well.
/// Only separators that let a *different* program append to stdout count:
/// `;`, `&&`, `&`, `||`, and newline.
///
/// A separator inside a quoted argument (`grep "a;b" file`) counts as
/// compound too, so such a command goes unfiltered. That is a deliberate
/// false positive: the cost is a missed compaction, whereas the cost of
/// the opposite error is silently deleting a caller's output.
pub fn is_compound(cmd: &str) -> bool {
    cmd.contains(';') || cmd.contains('&') || cmd.contains("||") || cmd.contains('\n')
}

pub struct FilterChain {
    filters: Vec<Box<dyn CommandFilter>>,
}

impl Default for FilterChain {
    fn default() -> Self {
        Self {
            filters: vec![
                Box::new(cargo::CargoTest),
                Box::new(cargo::CargoBuild),
                Box::new(git::GitLog),
                Box::new(git::GitDiff),
                Box::new(git::GitShow),
                Box::new(git::GitStashList),
                Box::new(git::GitWorktreeList),
                Box::new(git::GitStatus),
                Box::new(git::GitBranch),
                Box::new(python::Pytest),
                Box::new(node::NpmTest),
                Box::new(ops::DockerPs),
                Box::new(ops::SystemctlStatus),
                Box::new(ops::PsCmd),
                Box::new(k8s::Kubectl),
                Box::new(k8s::Helm),
                Box::new(sys::Lsof),
                Box::new(sys::Du),
                Box::new(sys::Dmesg),
                Box::new(sys::Vmstat),
                Box::new(pkg::PkgList),
                Box::new(pkg::SystemctlUnits),
                Box::new(pkg::Dnf),
                Box::new(rsync::Rsync),
                Box::new(zfs::ZfsList),
                Box::new(zfs::ZfsGet),
                Box::new(zfs::ZpoolStatus),
                Box::new(zfs::ZpoolList),
                Box::new(system::Journalctl),
                Box::new(system::FindCmd),
                Box::new(system::LsLong),
            ],
        }
    }
}

impl FilterChain {
    pub fn empty() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Run the chain. Returns the (possibly filtered) stdout plus a
    /// report describing what happened.
    ///
    /// Compound commands are never filtered — see [`is_compound`].
    pub fn apply<'a>(&self, cmd: &str, stdout: &'a str) -> (Cow<'a, str>, FilterReport) {
        let original = stdout.len();
        if is_compound(cmd) {
            return (
                Cow::Borrowed(stdout),
                FilterReport {
                    applied: None,
                    original_bytes: original,
                    filtered_bytes: original,
                    tier: 1,
                },
            );
        }
        for f in &self.filters {
            if f.matches(cmd) {
                let out = f.filter(cmd, stdout);
                let tier = f.tier(&out);
                let report = FilterReport {
                    applied: Some(f.name()),
                    original_bytes: original,
                    filtered_bytes: out.len(),
                    tier,
                };
                return (out, report);
            }
        }
        (
            Cow::Borrowed(stdout),
            FilterReport {
                applied: None,
                original_bytes: original,
                filtered_bytes: original,
                tier: 1,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Always(&'static str);
    impl CommandFilter for Always {
        fn name(&self) -> &'static str {
            self.0
        }
        fn matches(&self, _: &str) -> bool {
            true
        }
        fn filter<'a>(&self, _: &str, _: &'a str) -> Cow<'a, str> {
            Cow::Owned(format!("[{}]", self.0))
        }
    }

    #[test]
    fn empty_chain_passes_through() {
        let c = FilterChain::empty();
        let (out, rep) = c.apply("anything", "hello");
        assert_eq!(out, "hello");
        assert_eq!(rep.applied, None);
        assert_eq!(rep.original_bytes, 5);
        assert_eq!(rep.filtered_bytes, 5);
    }

    #[test]
    fn first_match_wins() {
        let c = FilterChain {
            filters: vec![Box::new(Always("a")), Box::new(Always("b"))],
        };
        let (out, rep) = c.apply("x", "hello");
        assert_eq!(out, "[a]");
        assert_eq!(rep.applied, Some("a"));
    }

    fn always_chain() -> FilterChain {
        FilterChain {
            filters: vec![Box::new(Always("a"))],
        }
    }

    /// THE regression. A filter matching on a substring of a compound
    /// command used to compact the whole concatenated stdout, silently
    /// deleting every other command's output. Nothing errored and the
    /// exit code stayed 0, so it went unnoticed from v0.5.0 until two
    /// agents independently reported it.
    #[test]
    fn compound_commands_are_never_filtered() {
        let c = always_chain();
        // Both real-world reports, verbatim in shape.
        for cmd in [
            "cargo build --release && echo APPLY_CHECK_OK && grep -n foo f && echo BUILD_EXIT=$?",
            "grep unit x ; ls bin ; ls backups ; curl -s localhost/health ; ldd --version",
            "echo BEFORE; systemctl status sshd | head -3; echo AFTER; id -un",
            "systemctl status a || systemctl status b",
            "cargo build & echo backgrounded",
            "cargo build\necho second-line",
        ] {
            let (out, rep) = c.apply(cmd, "FULL OUTPUT");
            assert_eq!(out, "FULL OUTPUT", "compound command was filtered: {cmd}");
            assert_eq!(rep.applied, None, "filter fired on compound: {cmd}");
            assert_eq!(rep.original_bytes, rep.filtered_bytes);
        }
    }

    /// The counterweight: the fix must not disable filtering wholesale.
    /// A lone command, including one narrowed by a pipe or a redirect,
    /// still gets compacted — that is the entire value of the chain.
    #[test]
    fn lone_and_piped_commands_still_filter() {
        let c = always_chain();
        for cmd in [
            "cargo build --release",
            "systemctl status sshd --no-pager | head -3",
            "journalctl -u prompto -n 50 > /dev/null",
            "rpm -qa | sort",
        ] {
            let (out, rep) = c.apply(cmd, "FULL OUTPUT");
            assert_eq!(out, "[a]", "filter did not fire on lone command: {cmd}");
            assert_eq!(rep.applied, Some("a"), "no filter on: {cmd}");
        }
    }

    #[test]
    fn is_compound_classifies_separators_not_pipes() {
        assert!(is_compound("a; b"));
        assert!(is_compound("a && b"));
        assert!(is_compound("a || b"));
        assert!(is_compound("a & b"));
        assert!(is_compound("a\nb"));
        assert!(!is_compound("a | b"));
        assert!(!is_compound("a > b"));
        assert!(!is_compound("cargo build --release"));
        // Deliberate false positive: a separator inside quotes disables
        // filtering. Missing a compaction is cheap; deleting output is not.
        assert!(is_compound(r#"grep "a;b" file"#));
    }
}
