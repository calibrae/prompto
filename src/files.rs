//! Typed file read/write over SSH. Replaces the ad-hoc
//! `ssh host cat /path` and `ssh host "cat > /path" < content` dance
//! with a tight, validated, capability-gated pair.

use anyhow::Result;
use std::time::Duration;

use crate::ctx::CallCtx;
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
        crate::fail!(InvalidArgs, "path is empty");
    }
    if p.len() > 4096 {
        crate::fail!(InvalidArgs, "path too long");
    }
    let bad = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '*', '?', '(', ')', '{',
        '}', '\t', ' ',
    ];
    if p.chars().any(|c| bad.contains(&c)) {
        crate::fail!(
            InvalidArgs,
            "path {p:?} contains shell metacharacter or whitespace"
        );
    }
    Ok(())
}

/// Validate an octal mode string ("0644", "755", etc.). Only digits, max
/// 5 chars (so e.g. "01777" still fits).
pub fn validate_mode(m: &str) -> Result<()> {
    if m.is_empty() {
        crate::fail!(InvalidArgs, "mode is empty");
    }
    if m.len() > 5 {
        crate::fail!(InvalidArgs, "mode too long");
    }
    if !m.chars().all(|c| c.is_ascii_digit()) {
        crate::fail!(InvalidArgs, "mode {m:?} must be octal digits only");
    }
    Ok(())
}

/// Read up to `max_bytes` from a remote path via `head -c`. Caller gets
/// the bytes plus a `truncated` flag (true when the read hit the cap and
/// the file may be larger).
pub async fn read(
    ssh: &SshClient,
    ctx: &CallCtx,
    host: &HostConfig,
    path: &str,
    max_bytes: u64,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("head -c {max_bytes} -- {path}");
    let res = ssh
        .exec(ctx, host, &cmd, Some(Duration::from_secs(15)), false)
        .await?;
    if !res.ok() {
        return Err(crate::error_class::ClassifiedError::exec_failure(
            &res,
            false,
            format!(
                "head failed (exit={:?}): {}",
                res.exit_code,
                res.stderr.trim()
            ),
        )
        .into());
    }
    Ok(res)
}

/// Write bytes to a remote path. Pipes the content through SSH stdin to
/// `tee -- <path> >/dev/null`. With `sudo=true` the tee runs as root
/// (caller must have `sudo_exec` capability checked).
pub async fn write(
    ssh: &SshClient,
    ctx: &CallCtx,
    host: &HostConfig,
    path: &str,
    content: &[u8],
    sudo: bool,
) -> Result<ExecOutput> {
    validate_path(path)?;
    let cmd = format!("tee -- {path} >/dev/null");
    let res = ssh
        .exec_stdin(
            ctx,
            host,
            &cmd,
            content,
            Some(Duration::from_secs(30)),
            sudo,
        )
        .await?;
    if !res.ok() {
        return Err(crate::error_class::ClassifiedError::exec_failure(
            &res,
            sudo,
            format!(
                "tee {path} failed (exit={:?}): {}",
                res.exit_code,
                res.stderr.trim()
            ),
        )
        .into());
    }
    Ok(res)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct FileEntry {
    /// The name as `ls` prints it; for a symlink that is
    /// `name -> target` (the target is also in `link_target`).
    pub name: String,
    /// 10-char mode string from `ls -l` (e.g. `drwxr-xr-x`), without the
    /// indicator `ls` may append (see `xattrs`, `acl`, `security_context`).
    pub mode: String,
    /// Bytes; 0 for a device file (see `device`).
    pub size: u64,
    pub owner: String,
    pub group: String,
    /// Modification time, `YYYY-MM-DD HH:MM` on every platform.
    pub mtime: String,
    pub is_dir: bool,
    pub is_link: bool,
    /// The symlink's target, for a symlink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// `major,minor` for a character or block device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// BSD/macOS `@`: the file has extended attributes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub xattrs: bool,
    /// `+` (BSD and GNU): the file has an ACL.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub acl: bool,
    /// GNU `.`: the file has an SELinux security context and no ACL.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub security_context: bool,
}

/// A parsed `ls -l`: the entries, and every line that wasn't one —
/// kept rather than dropped, so a format prompto doesn't know shows up
/// instead of silently shrinking the listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<FileEntry>,
    /// The first [`MAX_UNPARSED`] such lines, each cut to
    /// [`MAX_UNPARSED_LINE`] bytes.
    pub unparsed: Vec<String>,
    /// How many lines were unparseable in all.
    pub unparsed_count: usize,
}

/// Unparseable lines kept in [`Listing::unparsed`].
pub const MAX_UNPARSED: usize = 20;
/// Byte cap of one kept unparseable line.
pub const MAX_UNPARSED_LINE: usize = 256;

/// `ls` invocation for a platform.
///
/// GNU's `--time-style=long-iso` gives `YYYY-MM-DD HH:MM` in two tokens.
/// BSD has no such flag; `-T` is the closest, yielding a four-token
/// `Mon DD HH:MM:SS YYYY`. Both are parsed by [`parse_ls`].
///
/// A path that is a symlink to a directory lists that directory (macOS
/// `/tmp` → `private/tmp`): `ls -l` alone lists the link itself. GNU
/// has a flag for exactly that; BSD's `-H` follows every symlink named
/// on the command line, so there a symlink to a file is listed as the
/// file it points to.
pub fn ls_command(platform: Platform, path: &str) -> String {
    if platform.is_gnu() {
        format!("ls -la --time-style=long-iso --dereference-command-line-symlink-to-dir -- {path}")
    } else {
        format!("ls -laTH -- {path}")
    }
}

/// Parse `ls` output for `platform`, normalising both dialects to the
/// same [`FileEntry`] shape — including an ISO `YYYY-MM-DD HH:MM` mtime,
/// so a caller never has to know which kind of host it asked.
pub fn parse_ls(platform: Platform, stdout: &str) -> Listing {
    let mut out = Listing::default();
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || is_total(trimmed) {
            continue;
        }
        match parse_line(platform.is_gnu(), line) {
            Some(e) => out.entries.push(e),
            None => {
                out.unparsed_count += 1;
                if out.unparsed.len() < MAX_UNPARSED {
                    let mut end = line.len().min(MAX_UNPARSED_LINE);
                    while !line.is_char_boundary(end) {
                        end -= 1;
                    }
                    out.unparsed.push(line[..end].to_string());
                }
            }
        }
    }
    out
}

/// `total 12` (GNU may print `total 1.5K` with `-h`; not used here).
fn is_total(line: &str) -> bool {
    line.strip_prefix("total ")
        .is_some_and(|n| !n.is_empty() && !n.contains(' '))
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

/// Whitespace-separated tokens of `line` with their byte offsets, so the
/// name (which may hold runs of spaces) is taken verbatim from the line.
fn tokens(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices() {
        match (c.is_whitespace(), start) {
            (true, Some(s)) => {
                out.push((s, &line[s..i]));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

/// The 10-char mode and the flags of the indicator `ls` may append:
/// `@` extended attributes (BSD), `+` ACL (both), `.` SELinux context
/// (GNU).
fn parse_mode(tok: &str) -> Option<(&str, bool, bool, bool)> {
    if !tok.is_ascii() || !(10..=11).contains(&tok.len()) {
        return None;
    }
    let (mode, ind) = tok.split_at(10);
    if !"-dlcbpsDwn?".contains(&mode[..1]) {
        return None;
    }
    let perms_ok = mode[1..].chars().all(|c| "-rwxsStTlL".contains(c));
    if !perms_ok {
        return None;
    }
    match ind {
        "" => Some((mode, false, false, false)),
        "@" => Some((mode, true, false, false)),
        "+" => Some((mode, false, true, false)),
        "." => Some((mode, false, false, true)),
        _ => None,
    }
}

/// One `ls -l` line:
/// - GNU `ls -la --time-style=long-iso`:
///   `mode links owner group size YYYY-MM-DD HH:MM name…`
/// - BSD `ls -laT`:
///   `mode links owner group size Mon DD HH:MM:SS YYYY name…`
///
/// A device prints `major, minor` (two tokens) where the size goes. BSD
/// dates are rebuilt as `YYYY-MM-DD HH:MM`, seconds dropped because
/// GNU's `long-iso` has none.
fn parse_line(gnu: bool, line: &str) -> Option<FileEntry> {
    let toks = tokens(line);
    let (mode, xattrs, acl, security_context) = parse_mode(toks.first()?.1)?;
    toks.get(1)?.1.parse::<u64>().ok()?;
    let owner = toks.get(2)?.1;
    let group = toks.get(3)?.1;
    let (size, device, next) = match toks.get(4)?.1.strip_suffix(',') {
        Some(major) => {
            let minor = toks.get(5)?.1;
            (0, Some(format!("{major},{minor}")), 6)
        }
        None => (toks[4].1.parse::<u64>().ok()?, None, 5),
    };
    let (mtime, name_at) = if gnu {
        let (date, time) = (toks.get(next)?.1, toks.get(next + 1)?.1);
        let date_ok = date.len() == 10
            && date.char_indices().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            });
        if !date_ok || time.len() != 5 || time.as_bytes()[2] != b':' {
            return None;
        }
        (format!("{date} {time}"), next + 2)
    } else {
        let month = month_to_num(toks.get(next)?.1)?;
        let day: u32 = toks.get(next + 1)?.1.parse().ok()?;
        let hhmm = toks.get(next + 2)?.1.get(..5)?;
        let year = toks.get(next + 3)?.1;
        if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        (format!("{year}-{month}-{day:02} {hhmm}"), next + 4)
    };
    let name = &line[toks.get(name_at)?.0..];
    let is_link = mode.starts_with('l');
    let link_target = if is_link {
        name.split_once(" -> ").map(|(_, t)| t.to_string())
    } else {
        None
    };
    Some(FileEntry {
        name: name.to_string(),
        mode: mode.to_string(),
        size,
        owner: owner.to_string(),
        group: group.to_string(),
        mtime,
        is_dir: mode.starts_with('d'),
        is_link,
        link_target,
        device,
        xattrs,
        acl,
        security_context,
    })
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

/// `chmod` for a validated mode and path, on every platform.
///
/// `--` goes before the mode. BSD `chmod` (FreeBSD, macOS) stops option
/// parsing at the first operand, so the GNU-only `chmod 640 -- /p` takes
/// `--` as a file name there: `chmod: --: No such file or directory`,
/// exit 1, after the file was already written.
pub fn chmod_command(mode: &str, path: &str) -> String {
    format!("chmod -- {mode} {path}")
}

/// Optional chmod after a write. No-op if `mode` is `None`.
pub async fn chmod(
    ssh: &SshClient,
    ctx: &CallCtx,
    host: &HostConfig,
    path: &str,
    mode: &str,
    sudo: bool,
) -> Result<()> {
    validate_path(path)?;
    validate_mode(mode)?;
    let cmd = chmod_command(mode, path);
    let res = ssh
        .exec(ctx, host, &cmd, Some(Duration::from_secs(10)), sudo)
        .await?;
    if !res.ok() {
        return Err(crate::error_class::ClassifiedError::exec_failure(
            &res,
            sudo,
            format!(
                "chmod {mode} {path} failed (exit={:?}): {}",
                res.exit_code,
                res.stderr.trim()
            ),
        )
        .into());
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
                   drwxr-xr-x 3 user staff 96 2026-08-13 14:23 somedir\n\
                   -rw-r--r-- 1 user staff 42 2026-08-13 09:05 a file.txt\n";
        let bsd = "total 8\n\
                   drwxr-xr-x 3 user staff 96 Aug 13 14:23:07 2026 somedir\n\
                   -rw-r--r-- 1 user staff 42 Aug 13 09:05:59 2026 a file.txt\n";

        let g = parse_ls(Platform::Linux, gnu).entries;
        let b = parse_ls(Platform::Macos, bsd).entries;
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
        let bsd = "755|4096|user|staff|2026-08-13 14:23:07|Directory|/tmp";
        let gnu = "755|4096|user|staff|2026-08-13 14:23:07|directory|/tmp";
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
    fn parse_ls_gnu_extracts_entries() {
        let s = "total 12\n\
                 drwxr-xr-x 2 user staff   64 2026-04-27 12:00 .\n\
                 drwxr-xr-x 5 user staff  160 2026-04-27 11:00 ..\n\
                 -rw-r--r-- 1 user staff   42 2026-04-27 11:30 file.txt\n\
                 lrwxrwxrwx 1 user staff    7 2026-04-27 11:31 link -> target\n";
        let l = parse_ls(Platform::Linux, s);
        let entries = l.entries;
        assert_eq!(entries.len(), 4);
        assert!(l.unparsed.is_empty());
        assert!(entries[0].is_dir);
        assert_eq!(entries[2].name, "file.txt");
        assert_eq!(entries[2].size, 42);
        assert!(!entries[2].is_dir);
        assert!(entries[3].is_link);
        // `name` keeps what ls printed; the target is split out too.
        assert_eq!(entries[3].name, "link -> target");
        assert_eq!(entries[3].link_target.as_deref(), Some("target"));
    }

    /// Verbatim from the macOS 26 bench (`ls -laT`): `@` (extended
    /// attributes) after the mode made the line 11 chars and it was
    /// silently dropped, so `file_list /` came back without `/tmp`.
    #[test]
    fn bsd_mode_indicators_are_parsed_not_dropped() {
        let s = "total 0\n\
                 drwxrwxrwt@ 7 root wheel 224 Oct 10 13:02:11 2026 .\n\
                 lrwxr-xr-x@ 1 root wheel 11 Oct 10 12:58:40 2026 /tmp -> private/tmp\n\
                 drwxr-xr-x+ 4 ops  staff 128 Oct  9 08:01:02 2026 Desktop\n\
                 -rw-r--r--  1 ops  staff  42 Oct  9 08:01:02 2026 plain\n";
        let l = parse_ls(Platform::Macos, s);
        assert_eq!(l.unparsed, Vec::<String>::new());
        let e = &l.entries;
        assert_eq!(e.len(), 4, "{e:?}");
        assert_eq!(e[0].mode, "drwxrwxrwt", "the indicator is not part of mode");
        assert!(e[0].xattrs && !e[0].acl && e[0].is_dir);
        assert_eq!(e[0].mtime, "2026-10-10 13:02");
        assert!(e[1].is_link && e[1].xattrs);
        assert_eq!(e[1].name, "/tmp -> private/tmp");
        assert_eq!(e[1].link_target.as_deref(), Some("private/tmp"));
        assert!(e[2].acl && !e[2].xattrs);
        assert_eq!(e[2].mtime, "2026-10-09 08:01");
        assert!(!e[3].acl && !e[3].xattrs && !e[3].security_context);
    }

    /// GNU appends `+` (ACL) and, on SELinux hosts, `.` to nearly every
    /// mode: those lines were dropped too.
    #[test]
    fn gnu_mode_indicators_are_parsed() {
        let s = "-rw-r--r--. 1 root root 1024 2026-10-01 10:00 /etc/hosts\n\
                 drwxrwxr-x+ 2 ops  ops    40 2026-10-01 10:00 shared\n";
        let e = parse_ls(Platform::Linux, s).entries;
        assert_eq!(e.len(), 2);
        assert!(e[0].security_context && !e[0].acl);
        assert_eq!(e[0].mode, "-rw-r--r--");
        assert!(e[1].acl && e[1].is_dir);
    }

    /// The indicators and the extra fields are omitted when unset, so a
    /// plain Linux entry serialises exactly as before.
    #[test]
    fn plain_entries_serialise_as_before() {
        let e = &parse_ls(
            Platform::Linux,
            "-rw-r--r-- 1 u g 42 2026-04-27 11:30 file.txt\n",
        )
        .entries[0];
        let v = serde_json::to_value(e).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "group", "is_dir", "is_link", "mode", "mtime", "name", "owner", "size"
            ]
        );
    }

    /// Devices print `major, minor` where the size goes: two tokens, and
    /// `3,` is no size, so these lines were dropped.
    #[test]
    fn device_files_on_both_dialects() {
        // GNU, verbatim from Debian 13.
        let gnu = "crw-rw-rw- 1 root root 1, 3 2026-10-08 19:11 /dev/null\n\
                   brw-rw---- 1 root disk 254,   0 2026-10-08 19:11 vda\n";
        let g = parse_ls(Platform::Linux, gnu);
        assert!(g.unparsed.is_empty(), "{:?}", g.unparsed);
        assert_eq!(g.entries[0].device.as_deref(), Some("1,3"));
        assert_eq!(g.entries[0].size, 0);
        assert_eq!(g.entries[0].name, "/dev/null");
        assert_eq!(g.entries[1].device.as_deref(), Some("254,0"));
        // macOS: `%3d, %3d`, or a hex minor above 255.
        let bsd = "crw-rw-rw-  1 root  wheel    3,   2 Oct 10 13:02:11 2026 null\n\
                   crw-------  1 root  wheel   20, 0x00000004 Oct 10 13:02:11 2026 ttyp4\n";
        let b = parse_ls(Platform::Macos, bsd);
        assert!(b.unparsed.is_empty(), "{:?}", b.unparsed);
        assert_eq!(b.entries[0].device.as_deref(), Some("3,2"));
        assert_eq!(b.entries[0].name, "null");
        assert_eq!(b.entries[0].mtime, "2026-10-10 13:02");
        assert_eq!(b.entries[1].device.as_deref(), Some("20,0x00000004"));
    }

    /// Names are taken verbatim from the line: runs of spaces survive,
    /// and an arrow in a regular file's name is no link target.
    #[test]
    fn names_with_spaces_and_arrows() {
        // GNU, verbatim from Debian 13.
        let gnu = "-rw-rw-r--  1 ops  ops     0 2026-10-10 11:38 a  b.txt\n\
                   lrwxrwxrwx  1 ops  ops     8 2026-10-10 11:38 lnk sp -> a  b.txt\n\
                   -rw-rw-r--  1 ops  ops     0 2026-10-10 11:38 x -> y\n";
        let g = parse_ls(Platform::Linux, gnu).entries;
        assert_eq!(g[0].name, "a  b.txt");
        assert_eq!(g[1].link_target.as_deref(), Some("a  b.txt"));
        assert_eq!(g[2].name, "x -> y");
        assert_eq!(g[2].link_target, None);
        let bsd = "-rw-r--r--@ 1 ops  staff  6 Oct 10 13:05:00 2026 My  Notes.txt\n\
                   lrwxr-xr-x  1 ops  staff  9 Oct 10 13:05:00 2026 to notes -> My  Notes.txt\n";
        let b = parse_ls(Platform::Macos, bsd).entries;
        assert_eq!(b[0].name, "My  Notes.txt");
        assert_eq!(b[1].link_target.as_deref(), Some("My  Notes.txt"));
    }

    /// Nothing is dropped silently: a line that is no entry comes back in
    /// `unparsed`, bounded in count and length.
    #[test]
    fn unparseable_lines_are_returned_bounded() {
        let mut s = String::from("total 4\n-rw-r--r-- 1 u g 1 2026-04-27 11:30 ok\n");
        s.push_str("-????????? ? ? ? ? ? broken\n");
        let l = parse_ls(Platform::Linux, &s);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.unparsed, ["-????????? ? ? ? ? ? broken"]);
        assert_eq!(l.unparsed_count, 1);
        // A GNU line handed to the BSD parser is unparsed, not lost.
        let l = parse_ls(Platform::Macos, "-rw-r--r-- 1 u g 1 2026-04-27 11:30 ok\n");
        assert_eq!((l.entries.len(), l.unparsed_count), (0, 1));

        let long = format!("weird {}\n", "é".repeat(400));
        let many = long.repeat(MAX_UNPARSED + 5);
        let l = parse_ls(Platform::Macos, &many);
        assert_eq!(l.unparsed_count, MAX_UNPARSED + 5);
        assert_eq!(l.unparsed.len(), MAX_UNPARSED);
        assert!(l.unparsed.iter().all(|u| u.len() <= MAX_UNPARSED_LINE));
    }

    /// A path that is a symlink to a directory lists the directory
    /// (macOS `/tmp` → `private/tmp` returned `entries: []` before).
    #[test]
    fn ls_follows_a_symlink_to_a_directory() {
        assert!(
            ls_command(Platform::Linux, "/tmp")
                .contains(" --dereference-command-line-symlink-to-dir ")
        );
        for p in [Platform::Macos, Platform::Freebsd] {
            let c = ls_command(p, "/tmp");
            assert!(c.starts_with("ls -laTH -- "), "{p:?}: {c}");
        }
    }

    #[test]
    fn parse_stat_one_line() {
        let s =
            "0644|42|user|staff|2026-04-27 11:30:00.000000 +0000|regular file|/home/user/x.txt\n";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.mode, "0644");
        assert_eq!(st.size, 42);
        assert_eq!(st.owner, "user");
        assert_eq!(st.kind, "regular file");
        assert_eq!(st.path, "/home/user/x.txt");
    }

    #[test]
    fn parse_stat_rejects_malformed() {
        assert!(parse_stat("nonsense\n").is_none());
        assert!(parse_stat("").is_none());
    }

    /// sbx-bsd (FreeBSD 14.5) and sbx-mac (macOS 26), task 017: every
    /// `file_write` with `mode` failed with
    /// `chmod 640 /tmp/x failed (exit=Some(1)): chmod: --: No such file or directory`.
    #[test]
    fn chmod_command_puts_double_dash_before_the_mode() {
        assert_eq!(chmod_command("640", "/tmp/x"), "chmod -- 640 /tmp/x");
    }

    /// The command as built works with the local `chmod` too: GNU here,
    /// BSD when the suite runs on macOS.
    #[cfg(unix)]
    #[test]
    fn chmod_command_runs_with_the_local_chmod() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(chmod_command("640", f.to_str().unwrap()))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn validate_mode_rejects_garbage() {
        assert!(validate_mode("rw-r--r--").is_err());
        assert!(validate_mode("644a").is_err());
        assert!(validate_mode("").is_err());
        assert!(validate_mode("999999").is_err());
    }
}
