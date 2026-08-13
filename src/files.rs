//! Typed file read/write over SSH. Replaces the ad-hoc
//! `ssh host cat /path` and `ssh host "cat > /path" < content` dance
//! with a tight, validated, capability-gated pair.

use anyhow::{Result, bail};
use std::time::Duration;

use crate::inventory::{HostConfig, Platform};
use crate::ssh::{ExecOutput, SshClient};

/// Default + max read size. Operators can ask for less via `max_bytes`;
/// can't go above 1 MB to keep MCP responses bounded.
pub const DEFAULT_READ_BYTES: u64 = 65_536;
pub const MAX_READ_BYTES: u64 = 1_048_576;

/// Validate a remote path. Permissive enough for normal absolute/relative
/// paths and `~/foo`-style home shortcuts; rejects anything that would
/// let the path escape the argument position.
pub fn validate_path(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("path is empty");
    }
    if p.len() > 4096 {
        bail!("path too long");
    }
    let bad = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '*', '?', '(', ')', '{',
        '}', '\t', ' ',
    ];
    if p.chars().any(|c| bad.contains(&c)) {
        bail!("path {p:?} contains shell metacharacter or whitespace");
    }
    Ok(())
}

/// Validate an octal mode string ("0644", "755", etc.). Only digits, max
/// 5 chars (so e.g. "01777" still fits).
pub fn validate_mode(m: &str) -> Result<()> {
    if m.is_empty() {
        bail!("mode is empty");
    }
    if m.len() > 5 {
        bail!("mode too long");
    }
    if !m.chars().all(|c| c.is_ascii_digit()) {
        bail!("mode {m:?} must be octal digits only");
    }
    Ok(())
}

/// Read up to `max_bytes` from a remote path via `head -c`. Caller gets
/// the bytes plus a `truncated` flag (true when the read hit the cap and
/// the file may be larger).
pub async fn read(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    max_bytes: u64,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("head -c {max_bytes} -- {path}");
    let res = ssh
        .exec(host, &cmd, Some(Duration::from_secs(15)), false)
        .await?;
    if !res.ok() {
        bail!(
            "head failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res)
}

/// Write bytes to a remote path. Pipes the content through SSH stdin to
/// `tee -- <path> >/dev/null`. With `sudo=true` the tee runs as root via
/// `sudo -n tee` (caller must have `sudo_exec` capability checked).
pub async fn write(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    content: &[u8],
    sudo: bool,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("tee -- {path} >/dev/null");
    let res = ssh
        .exec_stdin(host, &cmd, content, Some(Duration::from_secs(30)), sudo)
        .await?;
    if !res.ok() {
        bail!(
            "tee {path} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res)
}

#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct FileEntry {
    pub name: String,
    /// 10-char mode string from `ls -l` (e.g. `drwxr-xr-x`).
    pub mode: String,
    pub size: u64,
    pub owner: String,
    pub group: String,
    /// Modification time, raw string from `ls -la --time-style=long-iso`.
    pub mtime: String,
    pub is_dir: bool,
    pub is_link: bool,
}

/// `ls` invocation for a platform.
///
/// GNU's `--time-style=long-iso` gives `YYYY-MM-DD HH:MM` in two tokens.
/// BSD has no such flag; `-T` is the closest, yielding a four-token
/// `Mon DD HH:MM:SS YYYY`. Different token counts, hence two parsers —
/// see [`parse_ls_long`] and [`parse_ls_long_bsd`].
pub fn ls_command(platform: Platform, path: &str) -> String {
    if platform.is_gnu() {
        format!("ls -la --time-style=long-iso -- {path}")
    } else {
        format!("ls -laT -- {path}")
    }
}

/// Parse `ls` output for `platform`, normalising both dialects to the
/// same [`FileEntry`] shape — including an ISO `YYYY-MM-DD HH:MM` mtime,
/// so a caller never has to know which kind of host it asked.
pub fn parse_ls(platform: Platform, stdout: &str) -> Vec<FileEntry> {
    if platform.is_gnu() {
        parse_ls_long(stdout)
    } else {
        parse_ls_long_bsd(stdout)
    }
}

fn month_to_num(m: &str) -> Option<&'static str> {
    Some(match m {
        "Jan" => "01",
        "Feb" => "02",
        "Mar" => "03",
        "Apr" => "04",
        "May" => "05",
        "Jun" => "06",
        "Jul" => "07",
        "Aug" => "08",
        "Sep" => "09",
        "Oct" => "10",
        "Nov" => "11",
        "Dec" => "12",
        _ => return None,
    })
}

/// Parse BSD `ls -laT`:
/// `mode links owner group size Mon DD HH:MM:SS YYYY name…`
///
/// Rebuilds the date into `YYYY-MM-DD HH:MM` so the `mtime` field matches
/// what the GNU path produces. Seconds are dropped for exactly that
/// reason — GNU's `long-iso` has none.
pub fn parse_ls_long_bsd(stdout: &str) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("total ") {
            continue;
        }
        let toks: Vec<&str> = trimmed.split_whitespace().collect();
        if toks.len() < 10 {
            continue;
        }
        let mode = toks[0];
        if mode.len() != 10 {
            continue;
        }
        let size: u64 = match toks[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let (Some(month), Ok(day), Some(hhmm), year) = (
            month_to_num(toks[5]),
            toks[6].parse::<u32>(),
            toks[7].get(..5),
            toks[8],
        ) else {
            continue;
        };
        if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        out.push(FileEntry {
            name: toks[9..].join(" "),
            mode: mode.to_string(),
            size,
            owner: toks[2].to_string(),
            group: toks[3].to_string(),
            mtime: format!("{year}-{month}-{day:02} {hhmm}"),
            is_dir: mode.starts_with('d'),
            is_link: mode.starts_with('l'),
        });
    }
    out
}

/// Parse `ls -la --time-style=long-iso` output. Tolerates a `total N`
/// header and skips it; ignores lines that don't fit the expected
/// column count.
pub fn parse_ls_long(stdout: &str) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("total ") {
            continue;
        }
        // Expect: mode links owner group size YYYY-MM-DD HH:MM name…
        // split_whitespace collapses runs of spaces; the name (which can
        // include spaces) is reconstructed from tokens[7..].
        let toks: Vec<&str> = trimmed.split_whitespace().collect();
        if toks.len() < 8 {
            continue;
        }
        let mode = toks[0];
        if mode.len() != 10 {
            continue;
        }
        let owner = toks[2].to_string();
        let group = toks[3].to_string();
        let size: u64 = match toks[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mtime = format!("{} {}", toks[5], toks[6]);
        let name = toks[7..].join(" ");
        let is_dir = mode.starts_with('d');
        let is_link = mode.starts_with('l');
        out.push(FileEntry {
            name,
            mode: mode.to_string(),
            size,
            owner,
            group,
            mtime,
            is_dir,
            is_link,
        });
    }
    out
}

#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub struct FileStat {
    pub path: String,
    pub mode: String, // octal
    pub size: u64,
    pub owner: String,
    pub group: String,
    pub mtime: String,
    pub kind: String,
}

/// `stat` invocation for a platform, emitting the same pipe-delimited
/// 7-field shape either way so [`parse_stat`] stays single.
///
/// GNU and BSD `stat` share no flags at all — `-c` is "format" on GNU and
/// an illegal option on BSD. The field codes differ too, so this is a
/// genuine translation rather than a flag tweak:
///
/// | field | GNU  | BSD              |
/// |-------|------|------------------|
/// | mode  | `%a` | `%Lp`            |
/// | size  | `%s` | `%z`             |
/// | owner | `%U` | `%Su`            |
/// | group | `%G` | `%Sg`            |
/// | mtime | `%y` | `%Sm` (+ `-t`)   |
/// | kind  | `%F` | `%HT`            |
/// | name  | `%n` | `%N`             |
pub fn stat_command(platform: Platform, path: &str) -> String {
    if platform.is_gnu() {
        format!("stat -c '%a|%s|%U|%G|%y|%F|%n' -- {path}")
    } else {
        // `-t` sets the strftime used by %Sm, so mtime comes back in the
        // same ISO-ish shape GNU's %y gives instead of BSD's default
        // "Aug 13 14:23:45 2026".
        format!("stat -f '%Lp|%z|%Su|%Sg|%Sm|%HT|%N' -t '%Y-%m-%d %H:%M:%S' -- {path}")
    }
}

/// Trim a stat mtime to `YYYY-MM-DD HH:MM:SS`.
///
/// GNU `%y` is `2025-07-25 02:00:00.000000000 +0200` — nanoseconds and a
/// UTC offset. BSD `%Sm` with our `-t` is already `2026-08-03 15:12:18`.
/// Without this the two platforms return visibly different strings for
/// the same field, which defeats the point of adapting at all. Both are
/// local time, so dropping the offset loses nothing the BSD side ever
/// carried.
///
/// Anything that doesn't look like a leading ISO timestamp is passed
/// through untouched rather than mangled.
fn normalise_mtime(raw: &str) -> String {
    let b = raw.as_bytes();
    let iso_shaped = b.len() >= 19
        && b[..19].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        });
    if iso_shaped {
        raw[..19].to_string()
    } else {
        raw.to_string()
    }
}

pub fn parse_stat(stdout: &str) -> Option<FileStat> {
    // Both platforms emit '%a|%s|%U|%G|%y|%F|%n' order — see stat_command.
    let line = stdout.lines().find(|l| !l.is_empty())?;
    let parts: Vec<&str> = line.splitn(7, '|').collect();
    if parts.len() != 7 {
        return None;
    }
    Some(FileStat {
        mode: parts[0].to_string(),
        size: parts[1].parse().ok()?,
        owner: parts[2].to_string(),
        group: parts[3].to_string(),
        mtime: normalise_mtime(parts[4]),
        // GNU %F yields "regular file"; BSD %HT yields "Regular File".
        // Lowercase so callers get one vocabulary regardless of target.
        // Idempotent on GNU.
        kind: parts[5].to_lowercase(),
        path: parts[6].to_string(),
    })
}

/// Optional chmod after a write. No-op if `mode` is `None`.
pub async fn chmod(
    ssh: &SshClient,
    host: &HostConfig,
    path: &str,
    mode: &str,
    sudo: bool,
) -> Result<()> {
    validate_path(path)?;
    validate_mode(mode)?;
    let cmd = format!("chmod {mode} -- {path}");
    let res = ssh
        .exec(host, &cmd, Some(Duration::from_secs(10)), sudo)
        .await?;
    if !res.ok() {
        bail!(
            "chmod {mode} {path} failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the whole point of `Platform`: prompto used to send
    /// GNU syntax everywhere, so `file_stat` against a Mac returned
    /// `stat: illegal option -- c` and `file_list` returned a raw BSD
    /// usage string.
    #[test]
    fn commands_use_the_right_dialect_per_platform() {
        let gnu_stat = stat_command(Platform::Linux, "/etc/hosts");
        assert!(gnu_stat.contains("stat -c"), "{gnu_stat}");
        for p in [Platform::Macos, Platform::Freebsd] {
            let bsd = stat_command(p, "/etc/hosts");
            assert!(bsd.contains("stat -f"), "{p:?}: {bsd}");
            assert!(!bsd.contains("-c "), "BSD stat must not use -c: {bsd}");
        }

        let gnu_ls = ls_command(Platform::Linux, "/tmp");
        assert!(gnu_ls.contains("--time-style=long-iso"), "{gnu_ls}");
        for p in [Platform::Macos, Platform::Freebsd] {
            let bsd = ls_command(p, "/tmp");
            assert!(
                !bsd.contains("--time-style"),
                "BSD ls has no --time-style: {bsd}"
            );
            assert!(bsd.contains("-laT"), "{p:?}: {bsd}");
        }
    }

    /// Both dialects must yield the SAME `FileEntry` shape — notably an
    /// ISO `YYYY-MM-DD HH:MM` mtime — so a caller never has to know what
    /// kind of host answered.
    #[test]
    fn bsd_and_gnu_ls_normalise_to_one_shape() {
        let gnu = "total 8\n\
                   drwxr-xr-x 3 cali staff 96 2026-08-13 14:23 somedir\n\
                   -rw-r--r-- 1 cali staff 42 2026-08-13 09:05 a file.txt\n";
        let bsd = "total 8\n\
                   drwxr-xr-x 3 cali staff 96 Aug 13 14:23:07 2026 somedir\n\
                   -rw-r--r-- 1 cali staff 42 Aug 13 09:05:59 2026 a file.txt\n";

        let g = parse_ls(Platform::Linux, gnu);
        let b = parse_ls(Platform::Macos, bsd);
        assert_eq!(g.len(), 2, "gnu parse: {g:?}");
        assert_eq!(b.len(), 2, "bsd parse: {b:?}");

        for (x, y) in g.iter().zip(b.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.mode, y.mode);
            assert_eq!(x.size, y.size);
            assert_eq!(x.owner, y.owner);
            assert_eq!(x.group, y.group);
            assert_eq!(x.is_dir, y.is_dir);
            assert_eq!(
                x.mtime, y.mtime,
                "mtime must normalise identically across dialects"
            );
        }
        // Names containing spaces survive both parsers.
        assert_eq!(b[1].name, "a file.txt");
        assert_eq!(b[0].mtime, "2026-08-13 14:23");
    }

    /// BSD `%HT` yields "Regular File"; GNU `%F` yields "regular file".
    /// Callers get one vocabulary.
    #[test]
    fn stat_kind_is_lowercased_for_both() {
        let bsd = "755|4096|cali|staff|2026-08-13 14:23:07|Directory|/tmp";
        let gnu = "755|4096|cali|staff|2026-08-13 14:23:07|directory|/tmp";
        assert_eq!(parse_stat(bsd).unwrap().kind, "directory");
        assert_eq!(parse_stat(gnu).unwrap().kind, "directory");
    }

    /// Caught in production on the v0.9.0 deploy: `kind` normalised but
    /// `mtime` did not, so macOS returned `2026-08-03 15:12:18` while
    /// Linux returned `2025-07-25 02:00:00.000000000 +0200` for the same
    /// field. Adapting the command is only half the job — the *output*
    /// has to land on one shape too.
    #[test]
    fn stat_mtime_normalises_across_platforms() {
        let gnu = "644|293|root|root|2025-07-25 02:00:00.000000000 +0200|regular file|/etc/hosts";
        let bsd = "644|293|root|wheel|2025-07-25 02:00:00|Regular File|/etc/hosts";
        assert_eq!(parse_stat(gnu).unwrap().mtime, "2025-07-25 02:00:00");
        assert_eq!(parse_stat(bsd).unwrap().mtime, "2025-07-25 02:00:00");
        assert_eq!(
            parse_stat(gnu).unwrap().mtime,
            parse_stat(bsd).unwrap().mtime
        );
    }

    #[test]
    fn normalise_mtime_passes_through_unrecognised_shapes() {
        // Don't mangle something we don't understand.
        assert_eq!(normalise_mtime("not a timestamp"), "not a timestamp");
        assert_eq!(normalise_mtime(""), "");
        assert_eq!(normalise_mtime("2026-08-13"), "2026-08-13");
    }

    #[test]
    fn platform_capability_matrix() {
        assert!(Platform::Linux.is_gnu());
        assert!(!Platform::Macos.is_gnu());
        assert!(!Platform::Freebsd.is_gnu());
        // macOS ships bash 3.2 — ssh_batch works there. OPNsense does not.
        assert!(Platform::Macos.has_bash());
        assert!(!Platform::Freebsd.has_bash());
        // systemd is Linux-only; launchd/rc.d are a different model.
        assert!(Platform::Linux.has_systemd());
        assert!(!Platform::Macos.has_systemd());
        assert!(!Platform::Freebsd.has_systemd());
    }

    #[test]
    fn validate_path_accepts_normal_inputs() {
        validate_path("/etc/prompto.toml").unwrap();
        validate_path("./relative/file").unwrap();
        validate_path("~/Developer/project").unwrap();
        validate_path("/var/log/syslog.1").unwrap();
        validate_path("file-with_dashes.txt").unwrap();
    }

    #[test]
    fn validate_path_rejects_shell_metas() {
        assert!(validate_path("/etc; rm -rf /").is_err());
        assert!(validate_path("/etc/$(whoami)").is_err());
        assert!(validate_path("/etc/`id`").is_err());
        assert!(validate_path("/etc/foo bar").is_err());
        assert!(validate_path("/etc/foo|bar").is_err());
        assert!(validate_path("/etc/foo>bar").is_err());
        assert!(validate_path("").is_err());
        assert!(validate_path(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn validate_mode_accepts_octal() {
        validate_mode("644").unwrap();
        validate_mode("0644").unwrap();
        validate_mode("0755").unwrap();
        validate_mode("01777").unwrap();
    }

    #[test]
    fn parse_ls_long_extracts_entries() {
        let s = "total 12\n\
                 drwxr-xr-x 2 cali staff   64 2026-04-27 12:00 .\n\
                 drwxr-xr-x 5 cali staff  160 2026-04-27 11:00 ..\n\
                 -rw-r--r-- 1 cali staff   42 2026-04-27 11:30 file.txt\n\
                 lrwxrwxrwx 1 cali staff    7 2026-04-27 11:31 link -> target\n";
        let entries = parse_ls_long(s);
        assert_eq!(entries.len(), 4);
        assert!(entries[0].is_dir);
        assert_eq!(entries[2].name, "file.txt");
        assert_eq!(entries[2].size, 42);
        assert!(!entries[2].is_dir);
        assert!(entries[3].is_link);
    }

    #[test]
    fn parse_stat_one_line() {
        let s =
            "0644|42|cali|staff|2026-04-27 11:30:00.000000 +0000|regular file|/home/cali/x.txt\n";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.mode, "0644");
        assert_eq!(st.size, 42);
        assert_eq!(st.owner, "cali");
        assert_eq!(st.kind, "regular file");
        assert_eq!(st.path, "/home/cali/x.txt");
    }

    #[test]
    fn parse_stat_rejects_malformed() {
        assert!(parse_stat("nonsense\n").is_none());
        assert!(parse_stat("").is_none());
    }

    #[test]
    fn validate_mode_rejects_garbage() {
        assert!(validate_mode("rw-r--r--").is_err());
        assert!(validate_mode("644a").is_err());
        assert!(validate_mode("").is_err());
        assert!(validate_mode("999999").is_err());
    }
}
