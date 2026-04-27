//! Ops-tool filters: `docker ps`, `systemctl status`, `ps`. Keep tight
//! columns, drop progress noise.

use std::borrow::Cow;

use super::CommandFilter;

const DOCKER_PS_LINE_CAP: usize = 50;
const PS_LINE_CAP: usize = 100;

pub struct DockerPs;

impl CommandFilter for DockerPs {
    fn name(&self) -> &'static str {
        "docker_ps"
    }

    fn matches(&self, cmd: &str) -> bool {
        let mut tokens = cmd.split_whitespace();
        let bin = tokens.next();
        let sub = tokens.find(|t| !t.starts_with('-'));
        matches!(
            (bin, sub),
            (Some("docker"), Some("ps")) | (Some("podman"), Some("ps"))
        )
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let total = stdout.lines().count();
        if total <= DOCKER_PS_LINE_CAP {
            return Cow::Borrowed(stdout);
        }
        let mut out: String = stdout
            .lines()
            .take(DOCKER_PS_LINE_CAP)
            .collect::<Vec<_>>()
            .join("\n");
        out.push('\n');
        out.push_str(&format!(
            "… docker ps truncated ({DOCKER_PS_LINE_CAP} kept, {total} total)\n"
        ));
        Cow::Owned(out)
    }
}

pub struct SystemctlStatus;

impl CommandFilter for SystemctlStatus {
    fn name(&self) -> &'static str {
        "systemctl_status"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.contains("systemctl status") || cmd.contains("systemctl is-active")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        // Keep:
        //   header line ("● foo.service - …")
        //   Loaded: line
        //   Active: line
        //   Main PID: line
        //   Tasks/Memory/CPU: lines
        // Drop the journal tail at the bottom.
        let mut kept: Vec<&str> = Vec::new();
        let mut changed = false;
        for line in stdout.lines() {
            let trimmed = line.trim_start();
            if line.starts_with('●')
                || trimmed.starts_with("Loaded:")
                || trimmed.starts_with("Active:")
                || trimmed.starts_with("Main PID:")
                || trimmed.starts_with("Tasks:")
                || trimmed.starts_with("Memory:")
                || trimmed.starts_with("CPU:")
                || trimmed.starts_with("CGroup:")
                || trimmed.starts_with("TriggeredBy:")
                || trimmed.starts_with("Triggers:")
                || trimmed.starts_with("Docs:")
                || trimmed.starts_with("Process:")
                || trimmed.starts_with("Status:")
            {
                kept.push(line);
            } else {
                changed = true;
            }
        }
        if !changed || kept.is_empty() {
            return Cow::Borrowed(stdout);
        }
        let mut out = kept.join("\n");
        out.push('\n');
        Cow::Owned(out)
    }
}

pub struct PsCmd;

impl CommandFilter for PsCmd {
    fn name(&self) -> &'static str {
        "ps"
    }

    fn matches(&self, cmd: &str) -> bool {
        // Bare `ps` invocation — first non-env token is `ps`.
        cmd.split_whitespace()
            .find(|t| !t.contains('='))
            .map(|t| t == "ps")
            .unwrap_or(false)
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        let total = stdout.lines().count();
        if total <= PS_LINE_CAP {
            return Cow::Borrowed(stdout);
        }
        let mut out: String = stdout
            .lines()
            .take(PS_LINE_CAP)
            .collect::<Vec<_>>()
            .join("\n");
        out.push('\n');
        out.push_str(&format!(
            "… ps truncated ({PS_LINE_CAP} kept, {total} total)\n"
        ));
        Cow::Owned(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_ps_caps_at_50() {
        let mut s = String::from("CONTAINER ID  IMAGE  COMMAND  STATUS\n");
        for i in 0..80 {
            s.push_str(&format!("abc{i}  img  sh  Up\n"));
        }
        let out = DockerPs.filter("docker ps", &s);
        assert!(out.contains("docker ps truncated"));
        assert!(out.contains("81 total"));
    }

    #[test]
    fn docker_ps_matches_docker_and_podman() {
        assert!(DockerPs.matches("docker ps"));
        assert!(DockerPs.matches("docker ps -a"));
        assert!(DockerPs.matches("docker --tls ps"));
        assert!(DockerPs.matches("podman ps"));
        assert!(!DockerPs.matches("docker images"));
        assert!(!DockerPs.matches("docker"));
    }

    #[test]
    fn systemctl_status_drops_journal_tail() {
        let s = "● prompto.service - prompto homelab control plane\n\
                 \x20    Loaded: loaded (/etc/systemd/system/prompto.service; enabled)\n\
                 \x20    Active: active (running) since Mon 2026-04-27\n\
                 \x20  Main PID: 12345 (prompto)\n\
                 \x20     Tasks: 3 (limit: 4579)\n\
                 \x20    Memory: 2.7M (peak: 3.3M)\n\
                 \x20       CPU: 32ms\n\
                 \n\
                 Apr 27 11:00:00 mista prompto[12345]: log line 1\n\
                 Apr 27 11:00:01 mista prompto[12345]: log line 2\n\
                 Apr 27 11:00:02 mista prompto[12345]: log line 3\n";
        let out = SystemctlStatus.filter("systemctl status prompto", s);
        let s = out.as_ref();
        assert!(s.contains("● prompto.service"));
        assert!(s.contains("Active:"));
        assert!(s.contains("Memory:"));
        assert!(!s.contains("log line 1"));
    }

    #[test]
    fn ps_caps_at_100() {
        let mut s = String::from("USER PID CPU MEM CMD\n");
        for i in 0..200 {
            s.push_str(&format!("user {i} 0.0 0.0 thing\n"));
        }
        let out = PsCmd.filter("ps aux", &s);
        assert!(out.contains("ps truncated"));
        assert!(out.contains("201 total"));
    }
}
