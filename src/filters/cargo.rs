//! Cargo output filters.
//!
//! `cargo test` emits per-binary headers and per-test progress lines that
//! we don't need in agent context — collapse to "N passed, M failed
//! (S suites, T total)". `cargo build` is similar: keep the final
//! `Compiling`/`Finished` lines, drop the per-crate progress.

use std::borrow::Cow;

use super::CommandFilter;

pub struct CargoTest;

impl CommandFilter for CargoTest {
    fn name(&self) -> &'static str {
        "cargo_test"
    }

    fn matches(&self, cmd: &str) -> bool {
        // cargo test or cargo nextest run, with anything in between.
        let lower = cmd.to_ascii_lowercase();
        lower.contains("cargo test") || lower.contains("cargo nextest")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut total_passed = 0u64;
        let mut total_failed = 0u64;
        let mut total_ignored = 0u64;
        let mut suites = 0u64;
        let mut total_time = 0.0_f64;
        let mut any_match = false;

        for line in stdout.lines() {
            let line = line.trim_start();
            // libtest: "test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s"
            // libtest fail: "test result: FAILED. 28 passed; 2 failed; ..."
            if let Some(rest) = line.strip_prefix("test result: ") {
                any_match = true;
                suites += 1;
                total_passed += scan_count(rest, "passed");
                total_failed += scan_count(rest, "failed");
                total_ignored += scan_count(rest, "ignored");
                if let Some(t) = scan_seconds(rest) {
                    total_time += t;
                }
            }
        }

        if !any_match {
            return Cow::Borrowed(stdout);
        }

        let mut summary = format!("cargo test: {total_passed} passed");
        if total_failed > 0 {
            summary.push_str(&format!(", {total_failed} failed"));
        }
        if total_ignored > 0 {
            summary.push_str(&format!(", {total_ignored} ignored"));
        }
        summary.push_str(&format!(" ({suites} suites, {total_time:.2}s)\n"));
        Cow::Owned(summary)
    }
}

pub struct CargoBuild;

impl CommandFilter for CargoBuild {
    fn name(&self) -> &'static str {
        "cargo_build"
    }

    fn matches(&self, cmd: &str) -> bool {
        let lower = cmd.to_ascii_lowercase();
        (lower.contains("cargo build")
            || lower.contains("cargo check")
            || lower.contains("cargo clippy"))
            && !lower.contains("cargo test")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        // Keep only Errors, Warnings, and the final Finished/error line.
        // Drop "Compiling foo v1.2.3 (...)" progress chatter.
        let mut kept = Vec::new();
        let mut warning_count = 0u64;
        let mut error_count = 0u64;
        let mut saw_finished = false;
        let mut last_line: Option<&str> = None;

        for raw in stdout.lines() {
            last_line = Some(raw);
            let trimmed = raw.trim_start();
            if trimmed.starts_with("Compiling ") {
                continue;
            }
            if trimmed.starts_with("warning:")
                || trimmed.starts_with("warning[")
                || trimmed.starts_with("error:")
                || trimmed.starts_with("error[")
            {
                if trimmed.starts_with("warning") {
                    warning_count += 1;
                } else {
                    error_count += 1;
                }
                kept.push(raw);
                continue;
            }
            if trimmed.starts_with("Finished ") {
                saw_finished = true;
                kept.push(raw);
                continue;
            }
        }

        // Rust-format error blocks span multiple lines (the indented
        // " --> path:line", "  |", etc.). Collapsing aggressively risks
        // dropping critical context. v0.5 keeps it conservative: only the
        // header lines. If users want full errors they can drop --filter.
        if !saw_finished && kept.is_empty() {
            // Compile didn't reach a Finished line and we matched nothing
            // worth keeping — punt to original output.
            return Cow::Borrowed(stdout);
        }

        let mut out = String::new();
        for line in &kept {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "cargo build ({} crates compiled)\n",
            count_compiling(stdout)
        ));
        if error_count > 0 || warning_count > 0 {
            out.push_str(&format!(
                "Errors: {error_count}, Warnings: {warning_count}\n"
            ));
        }
        let _ = last_line; // silence the unused warning if branch never lit
        Cow::Owned(out)
    }
}

fn scan_count(s: &str, label: &str) -> u64 {
    // Find "<digits> <label>" in s.
    let needle = format!(" {label}");
    if let Some(idx) = s.find(&needle) {
        let prefix = &s[..idx];
        // Walk back to find the run of digits.
        let digits: String = prefix
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        let digits: String = digits.chars().rev().collect();
        return digits.parse().unwrap_or(0);
    }
    0
}

fn scan_seconds(s: &str) -> Option<f64> {
    // "finished in 0.31s"
    let idx = s.find("finished in ")?;
    let rest = &s[idx + "finished in ".len()..];
    let secs_str: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    secs_str.parse().ok()
}

fn count_compiling(stdout: &str) -> u64 {
    stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("Compiling "))
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_test_summarises_libtest_output() {
        let s = "running 12 tests\n\
                 test foo ... ok\n\
                 test bar ... ok\n\
                 \n\
                 test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s\n\
                 \n\
                 running 5 tests\n\
                 test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n";
        let out = CargoTest.filter("cargo test", s);
        assert_eq!(out.trim(), "cargo test: 17 passed (2 suites, 0.52s)");
    }

    #[test]
    fn cargo_test_reports_failures() {
        let s = "test result: FAILED. 8 passed; 2 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.23s\n";
        let out = CargoTest.filter("cargo test", s);
        assert!(out.contains("8 passed"));
        assert!(out.contains("2 failed"));
        assert!(out.contains("1 ignored"));
    }

    #[test]
    fn cargo_test_passes_through_when_no_summary() {
        let s = "no test summary here, just chatter\n";
        let out = CargoTest.filter("cargo test", s);
        assert_eq!(out, "no test summary here, just chatter\n");
    }

    #[test]
    fn cargo_test_matches_nextest() {
        assert!(CargoTest.matches("cargo nextest run --release"));
        assert!(CargoTest.matches("cargo test --workspace"));
        assert!(!CargoTest.matches("cargo build"));
    }

    #[test]
    fn cargo_build_drops_compiling_lines() {
        let s = "    Compiling serde v1.0.228\n\
                     Compiling tokio v1.52.1\n\
                 warning: unused import: `Foo`\n\
                 error[E0277]: trait bound not satisfied\n\
                     Compiling foo v0.1.0\n\
                 error: aborting due to 1 previous error; 1 warning emitted\n\
                     Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.10s\n";
        let out = CargoBuild.filter("cargo build", s);
        assert!(!out.contains("serde v1.0.228"), "stripped Compiling lines");
        assert!(out.contains("warning: unused import"));
        assert!(out.contains("error[E0277]"));
        assert!(out.contains("Finished"));
        assert!(out.contains("Errors: 2"), "counts both error: lines");
    }

    #[test]
    fn scan_count_finds_digits() {
        assert_eq!(scan_count("ok. 30 passed; 0 failed", "passed"), 30);
        assert_eq!(scan_count("ok. 30 passed; 5 failed", "failed"), 5);
        assert_eq!(scan_count("nothing", "passed"), 0);
    }

    #[test]
    fn scan_seconds_finds_time() {
        assert_eq!(
            scan_seconds("ok. 30 passed; 0 failed; finished in 0.31s"),
            Some(0.31)
        );
        assert_eq!(scan_seconds("no finished line"), None);
    }
}
