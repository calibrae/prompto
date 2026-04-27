//! Package-listing + systemd-units + dnf filters. All naturally
//! verbose commands that benefit from a hard cap with a truncation
//! footer.

use std::borrow::Cow;

use super::CommandFilter;

const PKG_LIST_CAP: usize = 50;
const SYSTEMCTL_UNITS_CAP: usize = 60;
const DNF_LINE_CAP: usize = 80;

pub struct PkgList;

impl CommandFilter for PkgList {
    fn name(&self) -> &'static str {
        "pkg_list"
    }

    fn matches(&self, cmd: &str) -> bool {
        let lower = cmd.to_ascii_lowercase();
        // Listing commands across the major package ecosystems. Match on
        // the *combination* (e.g. "rpm -qa", not bare "rpm" since rpm
        // does many things).
        lower.contains("rpm -qa")
            || lower.contains("dpkg -l")
            || lower.contains("dpkg --list")
            || lower.contains("apt list")
            || lower.contains("apt-get list")
            || lower.contains("pip list")
            || lower.contains("pip freeze")
            || lower.contains("pip3 list")
            || lower.contains("pip3 freeze")
            || lower.contains("cargo install --list")
            || lower.contains("brew list")
            || lower.contains("brew leaves")
            || lower.contains("npm list -g")
            || lower.contains("npm ls -g")
            || lower.contains("pnpm list -g")
            || lower.contains("yarn global list")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, PKG_LIST_CAP, "pkg list")
    }
}

pub struct SystemctlUnits;

impl CommandFilter for SystemctlUnits {
    fn name(&self) -> &'static str {
        "systemctl_units"
    }

    fn matches(&self, cmd: &str) -> bool {
        cmd.contains("systemctl list-units")
            || cmd.contains("systemctl list-unit-files")
            || cmd.contains("systemctl list-sockets")
            || cmd.contains("systemctl list-timers")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, SYSTEMCTL_UNITS_CAP, "systemctl list")
    }
}

pub struct Dnf;

impl CommandFilter for Dnf {
    fn name(&self) -> &'static str {
        "dnf"
    }

    fn matches(&self, cmd: &str) -> bool {
        // Match dnf or yum (Fedora/RHEL family). Bare-token check so
        // we don't catch `--cacheonly=dnf` style flags.
        let mut tokens = cmd.split_whitespace();
        let bin = tokens.find(|t| !t.contains('='));
        let sub = tokens.find(|t| !t.starts_with('-'));
        match (bin, sub) {
            (Some("dnf"), Some(s)) | (Some("dnf5"), Some(s)) | (Some("yum"), Some(s)) => matches!(
                s,
                "list"
                    | "check-update"
                    | "history"
                    | "repoquery"
                    | "search"
                    | "info"
                    | "repolist"
                    | "group"
                    | "module"
            ),
            _ => false,
        }
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, DNF_LINE_CAP, "dnf")
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
    fn pkg_list_matches_common_commands() {
        assert!(PkgList.matches("rpm -qa"));
        assert!(PkgList.matches("rpm -qa | head"));
        assert!(PkgList.matches("dpkg -l"));
        assert!(PkgList.matches("apt list --installed"));
        assert!(PkgList.matches("pip list"));
        assert!(PkgList.matches("pip3 freeze"));
        assert!(PkgList.matches("brew list"));
        assert!(PkgList.matches("cargo install --list"));
        assert!(!PkgList.matches("rpm -V foo")); // verify, not list
        assert!(!PkgList.matches("apt show foo"));
    }

    #[test]
    fn pkg_list_caps_at_50() {
        let s: String = (0..200).map(|i| format!("pkg-{i}-1.0\n")).collect();
        let out = PkgList.filter("rpm -qa", &s);
        assert!(out.contains("pkg list truncated"));
        assert!(out.contains("200 total"));
    }

    #[test]
    fn systemctl_units_matches_list_variants() {
        assert!(SystemctlUnits.matches("systemctl list-units"));
        assert!(SystemctlUnits.matches("systemctl list-units --type=service"));
        assert!(SystemctlUnits.matches("systemctl list-unit-files"));
        assert!(SystemctlUnits.matches("systemctl list-timers"));
        assert!(!SystemctlUnits.matches("systemctl status foo"));
        assert!(!SystemctlUnits.matches("systemctl restart foo"));
    }

    #[test]
    fn systemctl_units_caps_at_60() {
        let mut s = String::from("UNIT  LOAD  ACTIVE\n");
        for i in 0..150 {
            s.push_str(&format!("svc-{i}.service  loaded  active\n"));
        }
        let out = SystemctlUnits.filter("systemctl list-units", &s);
        assert!(out.contains("systemctl list truncated"));
        assert!(out.contains("151 total"));
    }

    #[test]
    fn dnf_matches_subcommands() {
        assert!(Dnf.matches("dnf list installed"));
        assert!(Dnf.matches("dnf check-update"));
        assert!(Dnf.matches("dnf history"));
        assert!(Dnf.matches("dnf -y --refresh check-update"));
        assert!(Dnf.matches("dnf5 list"));
        assert!(Dnf.matches("yum list installed"));
        assert!(!Dnf.matches("dnf install foo")); // install isn't typically chatty in stdout the way list is
        assert!(!Dnf.matches("rpm -qa"));
    }

    #[test]
    fn dnf_caps_at_80() {
        let s: String = (0..200)
            .map(|i| format!("pkg-{i}.fc43.x86_64  installed\n"))
            .collect();
        let out = Dnf.filter("dnf list installed", &s);
        assert!(out.contains("dnf truncated"));
        assert!(out.contains("200 total"));
    }
}
