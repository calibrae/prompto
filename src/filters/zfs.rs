//! ZFS / zpool output compactors. Triggered for `zfs list`, `zfs get`,
//! `zpool status`, `zpool list`. Each is naturally chatty: `zfs list`
//! prints a header + one line per dataset/snapshot (homelab pools have
//! hundreds of snapshots), `zpool status` includes a verbose tree per
//! vdev. We cap and tighten without losing the shape.

use std::borrow::Cow;

use super::CommandFilter;

const ZFS_LINE_CAP: usize = 80;
const ZPOOL_STATUS_LINE_CAP: usize = 60;

/// `zfs list [-t snapshot|filesystem|...]`. Caps to the first
/// ZFS_LINE_CAP rows. Output already comes one-per-line so a line cap
/// is the right shape — preserves header and the first N entries.
pub struct ZfsList;

impl CommandFilter for ZfsList {
    fn name(&self) -> &'static str {
        "zfs_list"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_zfs_subcommand(cmd, "list")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, ZFS_LINE_CAP, "zfs entries")
    }

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
    }
}

/// `zfs get …`. Same shape as zfs list (one row per property), same cap.
pub struct ZfsGet;

impl CommandFilter for ZfsGet {
    fn name(&self) -> &'static str {
        "zfs_get"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_zfs_subcommand(cmd, "get")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, ZFS_LINE_CAP, "zfs entries")
    }

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
    }
}

/// `zpool status [pool]`. Verbose tree output — we cap to the first 60
/// lines, which preserves the header + the per-vdev section for a few
/// pools without flooding context for big multi-pool boxes.
pub struct ZpoolStatus;

impl CommandFilter for ZpoolStatus {
    fn name(&self) -> &'static str {
        "zpool_status"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_zpool_subcommand(cmd, "status")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, ZPOOL_STATUS_LINE_CAP, "zpool status lines")
    }

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
    }
}

/// `zpool list [pool]`. One line per pool. Tight by default — cap is
/// generous since most boxes have <10 pools.
pub struct ZpoolList;

impl CommandFilter for ZpoolList {
    fn name(&self) -> &'static str {
        "zpool_list"
    }

    fn matches(&self, cmd: &str) -> bool {
        is_zpool_subcommand(cmd, "list")
    }

    fn filter<'a>(&self, _cmd: &str, stdout: &'a str) -> Cow<'a, str> {
        cap(stdout, 30, "zpool entries")
    }

    fn tier(&self, filtered: &str) -> u8 {
        if filtered.contains("… truncated") { 2 } else { 1 }
    }
}

fn is_zfs_subcommand(cmd: &str, sub: &str) -> bool {
    is_subcommand_of(cmd, "zfs", sub) || is_subcommand_of(cmd, "/sbin/zfs", sub)
}

fn is_zpool_subcommand(cmd: &str, sub: &str) -> bool {
    is_subcommand_of(cmd, "zpool", sub) || is_subcommand_of(cmd, "/sbin/zpool", sub)
}

/// Match `<env_or_sudo>* <bin> <flags>* <sub>`. Env-prefix tokens (`X=Y`),
/// sudo, and global flags (starting with `-`) are skipped until we hit
/// the bin; then global flags again until we hit the subcommand.
fn is_subcommand_of(cmd: &str, bin: &str, sub: &str) -> bool {
    let tokens = cmd.split_whitespace();
    let mut saw_bin = false;
    for t in tokens {
        if !saw_bin {
            if t == bin {
                saw_bin = true;
            }
            continue;
        }
        if t.starts_with('-') {
            continue;
        }
        return t == sub;
    }
    false
}

fn cap<'a>(stdout: &'a str, cap_n: usize, unit: &str) -> Cow<'a, str> {
    let total = stdout.lines().count();
    if total <= cap_n {
        return Cow::Borrowed(stdout);
    }
    let mut out: String = stdout.lines().take(cap_n).collect::<Vec<_>>().join("\n");
    out.push('\n');
    out.push_str(&format!("… truncated ({cap_n} {unit} kept, {total} total)\n"));
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_zfs_list_variants() {
        assert!(ZfsList.matches("zfs list"));
        assert!(ZfsList.matches("zfs list -t snapshot"));
        assert!(ZfsList.matches("/sbin/zfs list -H -o name"));
        assert!(ZfsList.matches("sudo zfs list"));
        assert!(!ZfsList.matches("zfs get all"));
        assert!(!ZfsList.matches("zfs"));
    }

    #[test]
    fn matches_zfs_get() {
        assert!(ZfsGet.matches("zfs get all tank"));
        assert!(ZfsGet.matches("zfs get -H used,available tank"));
        assert!(!ZfsGet.matches("zfs list"));
    }

    #[test]
    fn matches_zpool_status() {
        assert!(ZpoolStatus.matches("zpool status"));
        assert!(ZpoolStatus.matches("zpool status tank"));
        assert!(ZpoolStatus.matches("/sbin/zpool status -v"));
        assert!(!ZpoolStatus.matches("zpool list"));
    }

    #[test]
    fn matches_zpool_list() {
        assert!(ZpoolList.matches("zpool list"));
        assert!(ZpoolList.matches("zpool list -H"));
        assert!(!ZpoolList.matches("zpool status"));
    }

    #[test]
    fn zfs_list_under_cap_passes_through() {
        let s = "NAME    USED  AVAIL\ntank    1G    9G\n";
        let out = ZfsList.filter("zfs list", s);
        assert_eq!(out, s);
        assert_eq!(ZfsList.tier(&out), 1);
    }

    #[test]
    fn zfs_list_caps_at_80() {
        let mut s = String::from("NAME    USED  AVAIL\n");
        for i in 0..150 {
            s.push_str(&format!("tank/snap-{i}    1G    9G\n"));
        }
        let out = ZfsList.filter("zfs list", &s);
        assert!(out.contains("151 total"));
        assert!(out.contains("… truncated"));
        assert_eq!(ZfsList.tier(&out), 2);
    }

    #[test]
    fn zpool_status_caps_at_60() {
        let mut s = String::from("  pool: tank\n state: ONLINE\n  scan: none\nconfig:\n\n");
        for i in 0..100 {
            s.push_str(&format!("\tdisk-{i:03}    ONLINE   0    0    0\n"));
        }
        let out = ZpoolStatus.filter("zpool status", &s);
        assert!(out.contains("… truncated"));
        assert_eq!(ZpoolStatus.tier(&out), 2);
    }
}
