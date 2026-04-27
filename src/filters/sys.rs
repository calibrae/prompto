//! System inspection commands: lsof, du, dmesg, vmstat. Conservative
//! caps + dmesg's noisy kernel-timing prefix gets stripped.

use std::borrow::Cow;

use super::CommandFilter;

const LSOF_LINE_CAP: usize = 100;
const DU_LINE_CAP: usize = 50;
const DMESG_LINE_CAP: usize = 100;

pub struct Lsof;

impl CommandFilter for Lsof {
    fn name(&self) -> &'static str {
        "lsof"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "lsof")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, LSOF_LINE_CAP, "lsof")
    }
}

pub struct Du;

impl CommandFilter for Du {
    fn name(&self) -> &'static str {
        "du"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "du")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, DU_LINE_CAP, "du")
    }
}

/// dmesg lines are typically `[<seconds>.<micros>] <message>`. The
/// timestamp prefix is rarely useful in agent context. Strip it; the
/// chronological order of lines is preserved.
pub struct Dmesg;

impl CommandFilter for Dmesg {
    fn name(&self) -> &'static str {
        "dmesg"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "dmesg")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let mut out = String::with_capacity(stdout.len());
        let mut changed = false;
        let mut total = 0usize;
        for line in stdout.lines() {
            total += 1;
            if total > DMESG_LINE_CAP {
                changed = true;
                break;
            }
            let stripped = strip_kernel_ts(line);
            if stripped.len() != line.len() {
                changed = true;
            }
            out.push_str(stripped);
            out.push('\n');
        }
        let true_total = stdout.lines().count();
        if true_total > DMESG_LINE_CAP {
            out.push_str(&format!(
                "… dmesg truncated ({DMESG_LINE_CAP} kept, {true_total} total)\n"
            ));
            changed = true;
        }
        if changed {
            Cow::Owned(out)
        } else {
            Cow::Borrowed(stdout)
        }
    }
}

fn strip_kernel_ts(line: &str) -> &str {
    let bytes = line.as_bytes();
    if bytes.first() != Some(&b'[') {
        return line;
    }
    if let Some(end) = line.find(']') {
        // Confirm the inside is digits / dots / spaces.
        let inside = &line[1..end];
        if inside
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ' ')
        {
            // Skip "] " too if present.
            let after = &line[end + 1..];
            return after.strip_prefix(' ').unwrap_or(after);
        }
    }
    line
}

/// vmstat output is a header line + rows. Keep header, the first 3 data
/// rows (the most informative), and drop the rest. Pass-through for very
/// short output.
pub struct Vmstat;

impl CommandFilter for Vmstat {
    fn name(&self) -> &'static str {
        "vmstat"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "vmstat")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let lines: Vec<&str> = stdout.lines().collect();
        // vmstat header is 2 lines (group header + column header) + N data rows.
        if lines.len() <= 6 {
            return Cow::Borrowed(stdout);
        }
        let mut out = String::new();
        for line in lines.iter().take(5) {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!(
            "… vmstat truncated (5 kept, {} total)\n",
            lines.len()
        ));
        Cow::Owned(out)
    }
}

fn cap<'a>(stdout: &'a str, line_cap: usize, label: &str) -> Cow<'a, str> {
    let total = stdout.lines().count();
    if total <= line_cap {
        return Cow::Borrowed(stdout);
    }
    let mut out: String = stdout.lines().take(line_cap).collect::<Vec<_>>().join("\n");
    out.push('\n');
    out.push_str(&format!(
        "… {label} truncated ({line_cap} kept, {total} total)\n"
    ));
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsof_caps_at_100() {
        let s: String = (0..200).map(|i| format!("proc-{i} u TCP\n")).collect();
        let out = Lsof.filter("lsof -i", &s);
        assert!(out.contains("lsof truncated"));
        assert!(out.contains("200 total"));
    }

    #[test]
    fn du_caps_at_50() {
        let s: String = (0..80).map(|i| format!("4K\t/path/{i}\n")).collect();
        let out = Du.filter("du -h", &s);
        assert!(out.contains("du truncated"));
        assert!(out.contains("80 total"));
    }

    #[test]
    fn dmesg_strips_kernel_timestamp() {
        let s = "[    0.000000] Linux version 6.17.1\n\
                 [    0.123456] Command line: BOOT_IMAGE=/boot/vmlinuz\n\
                 [12345.678901] something happened\n";
        let out = Dmesg.filter("dmesg", s);
        let s = out.as_ref();
        assert!(s.contains("Linux version 6.17.1"));
        assert!(s.contains("Command line:"));
        assert!(s.contains("something happened"));
        assert!(!s.contains("[    0.000000]"));
        assert!(!s.contains("[12345.678901]"));
    }

    #[test]
    fn dmesg_passes_through_when_no_timestamp() {
        let s = "regular log line\n\
                 another one\n";
        let out = Dmesg.filter("dmesg", s);
        assert_eq!(out, s);
    }

    #[test]
    fn dmesg_caps_long_output() {
        let mut s = String::new();
        for i in 0..150 {
            s.push_str(&format!("[{i}.000000] event {i}\n"));
        }
        let out = Dmesg.filter("dmesg", &s);
        assert!(out.contains("dmesg truncated"));
        assert!(out.contains("150 total"));
    }

    #[test]
    fn vmstat_keeps_header_and_first_rows() {
        let s = "procs -----------memory---------- ---swap-- -----io---- ...\n\
                 \x20r  b   swpd   free   buff  cache   si   so    bi    bo  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     5    19  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     0     0  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     0     0  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     0     0  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     0     0  ...\n\
                 \x20 0  0      0  54528  0  8435    0    0     0     0  ...\n";
        let out = Vmstat.filter("vmstat 1 6", s);
        assert!(out.contains("vmstat truncated"));
        assert!(out.contains("8 total"));
    }
}
