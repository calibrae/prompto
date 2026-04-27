//! Composite host probe — one tool, one round-trip, ~6 sections of
//! status. Replaces the "let me check uptime, then mem, then disk, …"
//! agent dance.

use std::collections::HashMap;

use serde::Serialize;

/// Shell script run via `bash -s` over SSH stdin. Each section is
/// delimited by `==NAME==` markers so we can parse them out
/// deterministically. Each command is best-effort: tolerates missing
/// tools (Linux `ss` vs BSD `netstat`, etc.) by chaining fallbacks.
pub const DIAGNOSE_SCRIPT: &str = r#"
echo '==UPTIME=='
uptime 2>/dev/null
echo '==LOADAVG=='
cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg 2>/dev/null
echo '==MEM=='
free -m 2>/dev/null || vm_stat 2>/dev/null | head -5
echo '==DISK_ROOT=='
df -h / 2>/dev/null
echo '==LAST_BOOT=='
who -b 2>/dev/null || uptime -s 2>/dev/null
echo '==KERNEL=='
uname -srm 2>/dev/null
echo '==LISTENING=='
(ss -tln 2>/dev/null | tail -n +2 | head -30) || (netstat -tln 2>/dev/null | head -30)
echo '==FAILED_SERVICES=='
systemctl --failed --no-pager --no-legend 2>/dev/null | head -20
echo '==END=='
"#;

#[derive(Clone, Debug, Default, Serialize, schemars::JsonSchema)]
pub struct DiagnoseReport {
    pub uptime: Option<String>,
    /// 1m, 5m, 15m load average — extracted from `/proc/loadavg` or
    /// `vm.loadavg`. None if the parse failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_avg: Option<(f64, f64, f64)>,
    /// Memory in MB — total, used, free. From `free -m` line 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_free_mb: Option<u64>,
    /// Root disk: total / used / available / use % / device. From
    /// `df -h /` last line.
    pub disk_root: Option<String>,
    pub last_boot: Option<String>,
    pub kernel: Option<String>,
    /// One line per listening socket — already trimmed by the script
    /// to a max of 30.
    pub listening_ports: Vec<String>,
    /// Failed systemd units. Empty when everything is healthy.
    pub failed_services: Vec<String>,
}

/// Split the script output into sections and parse the interesting bits.
pub fn parse(stdout: &str) -> DiagnoseReport {
    let mut sections: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current: Option<&str> = None;
    for line in stdout.lines() {
        if let Some(name) = section_header(line) {
            if name == "END" {
                break;
            }
            current = Some(name);
            continue;
        }
        if let Some(s) = current
            && !line.is_empty()
        {
            sections.entry(s).or_default().push(line);
        }
    }

    let mut r = DiagnoseReport {
        uptime: sections
            .get("UPTIME")
            .and_then(|v| v.first().map(|s| s.trim().to_string())),
        ..Default::default()
    };

    if let Some(lines) = sections.get("LOADAVG")
        && let Some(first) = lines.first()
    {
        let parts: Vec<&str> = first.split_whitespace().collect();
        if parts.len() >= 3
            && let (Ok(a), Ok(b), Ok(c)) = (
                parts[0].parse::<f64>(),
                parts[1].parse::<f64>(),
                parts[2].parse::<f64>(),
            )
        {
            r.load_avg = Some((a, b, c));
        }
    }

    if let Some(lines) = sections.get("MEM") {
        // free -m line 2 looks like:
        //   Mem:  64144  1829  54528  1  8435  62315
        for line in lines {
            if let Some(rest) = line.trim_start().strip_prefix("Mem:") {
                let cols: Vec<&str> = rest.split_whitespace().collect();
                if cols.len() >= 3 {
                    r.mem_total_mb = cols[0].parse().ok();
                    r.mem_used_mb = cols[1].parse().ok();
                    r.mem_free_mb = cols[2].parse().ok();
                }
                break;
            }
        }
    }

    r.disk_root = sections
        .get("DISK_ROOT")
        .and_then(|v| v.last().map(|s| s.trim().to_string()))
        .filter(|s| !s.starts_with("Filesystem")); // skip header if it leaked

    r.last_boot = sections
        .get("LAST_BOOT")
        .and_then(|v| v.first().map(|s| s.trim().to_string()));

    r.kernel = sections
        .get("KERNEL")
        .and_then(|v| v.first().map(|s| s.trim().to_string()));

    if let Some(lines) = sections.get("LISTENING") {
        r.listening_ports = lines.iter().map(|l| l.trim().to_string()).collect();
    }

    if let Some(lines) = sections.get("FAILED_SERVICES") {
        r.failed_services = lines.iter().map(|l| l.trim().to_string()).collect();
    }

    r
}

fn section_header(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.starts_with("==") && line.ends_with("==") && line.len() > 4 {
        let name = &line[2..line.len() - 2];
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_linux_output() {
        let s = "==UPTIME==\n\
                 \x20  10:30:00 up 1 day,  2:30,  3 users,  load average: 0.30, 0.27, 0.27\n\
                 ==LOADAVG==\n\
                 0.30 0.27 0.27 1/200 12345\n\
                 ==MEM==\n\
                 \x20             total        used        free      shared  buff/cache   available\n\
                 Mem:          64144        1829       54528           1        8435       62315\n\
                 Swap:             0           0           0\n\
                 ==DISK_ROOT==\n\
                 Filesystem            Size  Used Avail Use% Mounted on\n\
                 /dev/mapper/root      221G   78G  144G  35% /\n\
                 ==LAST_BOOT==\n\
                 system boot  2026-04-27 08:00\n\
                 ==KERNEL==\n\
                 Linux 6.17.1-300.fc43.x86_64 x86_64\n\
                 ==LISTENING==\n\
                 LISTEN 0   128   0.0.0.0:6337   0.0.0.0:*\n\
                 LISTEN 0   128   0.0.0.0:22     0.0.0.0:*\n\
                 ==FAILED_SERVICES==\n\
                 ==END==\n";

        let r = parse(s);
        assert!(r.uptime.as_ref().unwrap().contains("load average"));
        assert_eq!(r.load_avg, Some((0.30, 0.27, 0.27)));
        assert_eq!(r.mem_total_mb, Some(64144));
        assert_eq!(r.mem_used_mb, Some(1829));
        assert_eq!(r.mem_free_mb, Some(54528));
        assert!(r.disk_root.as_ref().unwrap().contains("35%"));
        assert!(r.last_boot.as_ref().unwrap().contains("2026-04-27"));
        assert!(r.kernel.as_ref().unwrap().contains("Linux"));
        assert_eq!(r.listening_ports.len(), 2);
        assert!(r.failed_services.is_empty());
    }

    #[test]
    fn parse_handles_missing_sections() {
        let s = "==UPTIME==\n\
                 \x20  noon up 5min\n\
                 ==END==\n";
        let r = parse(s);
        assert!(r.uptime.is_some());
        assert!(r.load_avg.is_none());
        assert!(r.mem_total_mb.is_none());
        assert!(r.kernel.is_none());
        assert!(r.listening_ports.is_empty());
    }

    #[test]
    fn parse_picks_up_failed_services() {
        let s = "==FAILED_SERVICES==\n\
                 broken.service                                  loaded failed failed Some Broken Thing\n\
                 alsobroken.service                              loaded failed failed The Other Thing\n\
                 ==END==\n";
        let r = parse(s);
        assert_eq!(r.failed_services.len(), 2);
        assert!(r.failed_services[0].contains("broken.service"));
    }

    #[test]
    fn section_header_recognised() {
        assert_eq!(section_header("==UPTIME=="), Some("UPTIME"));
        assert_eq!(section_header("  ==DISK_ROOT==  "), Some("DISK_ROOT"));
        assert_eq!(section_header("regular line"), None);
        assert_eq!(section_header("=="), None);
        assert_eq!(section_header("====="), None);
    }
}
