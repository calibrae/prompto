//! Python tooling filters: `pytest` summary extraction.

use std::borrow::Cow;

use super::CommandFilter;

/// `pytest` (any subcommand). Collapses the per-test progress lines and
/// keeps the final summary line ("=== N passed, M failed in Xs ===").
pub struct Pytest;

impl CommandFilter for Pytest {
    fn name(&self) -> &'static str {
        "pytest"
    }

    fn matches(&self, cmd: &str) -> bool {
        let lower = cmd.to_ascii_lowercase();
        lower.contains("pytest") || lower.contains("python -m pytest")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        // pytest's summary line is "=== <stuff> in <N>s ===" or
        // "=== short test summary info ===" followed by failures.
        // Keep only:
        //   - any line containing "FAILED " or "ERROR " (per-failure)
        //   - the final " in <N>s ===" summary
        //   - "=== short test summary info ==="-bracketed block
        let mut summary: Option<&str> = None;
        let mut failures: Vec<&str> = Vec::new();
        let mut errors: Vec<&str> = Vec::new();
        for line in stdout.lines() {
            if line.contains(" in ") && line.contains("===") {
                summary = Some(line);
            } else if line.starts_with("FAILED ") {
                failures.push(line);
            } else if line.starts_with("ERROR ") {
                errors.push(line);
            }
        }
        match summary {
            Some(s) => {
                let mut out = String::new();
                for f in &failures {
                    out.push_str(f);
                    out.push('\n');
                }
                for e in &errors {
                    out.push_str(e);
                    out.push('\n');
                }
                out.push_str(s);
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
    fn pytest_keeps_summary_and_failures() {
        let s = "============================= test session starts ==============================\n\
                 platform linux -- Python 3.11.0\n\
                 collected 47 items\n\
                 \n\
                 tests/test_foo.py::test_a PASSED                          [  2%]\n\
                 tests/test_foo.py::test_b PASSED                          [  4%]\n\
                 tests/test_bar.py::test_c FAILED                          [  6%]\n\
                 \n\
                 =================================== FAILURES ===================================\n\
                 ___________________________________ test_c _____________________________________\n\
                 ... lots of traceback ...\n\
                 \n\
                 FAILED tests/test_bar.py::test_c - AssertionError: x != y\n\
                 ========================= 1 failed, 46 passed in 2.34s =========================\n";
        let out = Pytest.filter("pytest", s);
        let s = out.as_ref();
        assert!(s.contains("FAILED tests/test_bar.py::test_c"));
        assert!(s.contains("1 failed, 46 passed in 2.34s"));
        assert!(!s.contains("test_a PASSED"));
    }

    #[test]
    fn pytest_passes_through_when_no_summary() {
        let s = "no summary line here\n";
        let out = Pytest.filter("pytest", s);
        assert_eq!(out, s);
    }

    #[test]
    fn pytest_matches_invocations() {
        assert!(Pytest.matches("pytest"));
        assert!(Pytest.matches("pytest -v tests/"));
        assert!(Pytest.matches("python -m pytest tests/"));
        assert!(!Pytest.matches("cargo test"));
    }
}
