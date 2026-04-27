//! Typed file read/write over SSH. Replaces the ad-hoc
//! `ssh host cat /path` and `ssh host "cat > /path" < content` dance
//! with a tight, validated, capability-gated pair.

use anyhow::{Result, bail};
use std::time::Duration;

use crate::inventory::HostConfig;
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

pub fn parse_stat(stdout: &str) -> Option<FileStat> {
    // We invoke stat -c '%a|%s|%U|%G|%y|%F|%n'
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
        mtime: parts[4].to_string(),
        kind: parts[5].to_string(),
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
