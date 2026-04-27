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

pub mod cargo;
pub mod git;
pub mod k8s;
pub mod node;
pub mod ops;
pub mod python;
pub mod rsync;
pub mod sys;
pub mod system;

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
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct FilterReport {
    /// Name of the filter that matched, or `None` if pass-through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<&'static str>,
    pub original_bytes: usize,
    pub filtered_bytes: usize,
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
                Box::new(rsync::Rsync),
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
    pub fn apply<'a>(&self, cmd: &str, stdout: &'a str) -> (Cow<'a, str>, FilterReport) {
        let original = stdout.len();
        for f in &self.filters {
            if f.matches(cmd) {
                let out = f.filter(cmd, stdout);
                let report = FilterReport {
                    applied: Some(f.name()),
                    original_bytes: original,
                    filtered_bytes: out.len(),
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
}
