//! Node tooling filters: vitest / jest / npm test summary extraction.

use std::borrow::Cow;

use super::CommandFilter;

/// `npm test`, `pnpm test`, `yarn test`, `vitest`, `jest`. Different
/// runners share a similar summary: "Test Files N failed | M passed",
/// "Tests N passed (M)", "Test Suites: N passed". Keep only those.
pub struct NpmTest;

impl CommandFilter for NpmTest {
    fn name(&self) -> &'static str {
        "npm_test"
    }

    fn matches(&self, cmd: &str) -> bool {
        let lower = cmd.to_ascii_lowercase();
        lower.contains("npm test")
            || lower.contains("pnpm test")
            || lower.contains("yarn test")
            || lower.contains("npm run test")
            || lower.contains("vitest")
            || lower.contains("jest")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut kept: Vec<&str> = Vec::new();
        for line in stdout.lines() {
            // vitest:  Test Files  1 passed (1)
            //          Tests       42 passed (42)
            //          Duration    1.23s (transform ...)
            // jest:    Test Suites: 1 passed, 1 total
            //          Tests:       42 passed, 42 total
            //          Time:        1.234s
            let trimmed = line.trim_start();
            if trimmed.starts_with("Test Files")
                || trimmed.starts_with("Test Suites:")
                || trimmed.starts_with("Tests")
                || trimmed.starts_with("Time:")
                || trimmed.starts_with("Duration")
                || trimmed.starts_with("Snapshots:")
                || trimmed.starts_with("FAIL ")
                || trimmed.starts_with("PASS ")
                || trimmed.starts_with("✗ ")
                || trimmed.starts_with("✓ ")
                || trimmed.starts_with("× ")
                || trimmed.contains("failing")
            {
                kept.push(line);
            }
        }
        if kept.is_empty() {
            return Cow::Borrowed(stdout);
        }
        let mut out = kept.join("\n");
        out.push('\n');
        Cow::Owned(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_test_extracts_vitest_summary() {
        let s = "RUN  v1.2.3\n\
                 \n\
                 \x20\x20✓ src/foo.test.ts (10)\n\
                 \x20\x20✓ src/bar.test.ts (5)\n\
                 \n\
                 \x20Test Files  2 passed (2)\n\
                 \x20     Tests  15 passed (15)\n\
                 \x20  Start at  10:00\n\
                 \x20  Duration  1.23s\n";
        let out = NpmTest.filter("vitest", s);
        let s = out.as_ref();
        assert!(s.contains("Test Files  2 passed"));
        assert!(s.contains("Tests  15 passed"));
        assert!(s.contains("Duration"));
    }

    #[test]
    fn npm_test_extracts_jest_summary() {
        let s = "PASS  src/foo.test.ts\n\
                 PASS  src/bar.test.ts\n\
                 Test Suites: 2 passed, 2 total\n\
                 Tests:       15 passed, 15 total\n\
                 Time:        1.234 s\n";
        let out = NpmTest.filter("jest", s);
        let s = out.as_ref();
        assert!(s.contains("Test Suites: 2 passed"));
        assert!(s.contains("Time:"));
    }

    #[test]
    fn npm_test_matches_invocations() {
        assert!(NpmTest.matches("npm test"));
        assert!(NpmTest.matches("pnpm test"));
        assert!(NpmTest.matches("yarn test"));
        assert!(NpmTest.matches("npm run test"));
        assert!(NpmTest.matches("vitest run"));
        assert!(NpmTest.matches("jest --coverage"));
        assert!(!NpmTest.matches("cargo test"));
    }
}
