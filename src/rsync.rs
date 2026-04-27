//! `rsync` passthrough between two inventory hosts.
//!
//! Shape: prompto SSHs to the *source* host and runs rsync there with
//! the *dest* host as the target. Both hosts must be in the inventory
//! with the `exec` capability. The source host must have an SSH key for
//! the dest host already in place — typical homelab setup where every
//! box carries `~/.ssh/<key>`.
//!
//! No support yet for local-staging-to-remote (would need
//! `ReadWritePaths` widened beyond `/var/lib/prompto`). v0.7+ once
//! the agent feedback dictates.

use anyhow::{Result, bail};
use std::time::Duration;

use crate::files::validate_path;
use crate::inventory::HostConfig;
use crate::ssh::{ExecOutput, SshClient};

/// Validate an `--exclude=PATTERN` value. rsync patterns are gloob-like;
/// we allow alphanumerics + a small set of glob/path chars and reject
/// shell metacharacters that could break out of the rsync arg.
pub fn validate_exclude(p: &str) -> Result<()> {
    if p.is_empty() {
        bail!("exclude pattern is empty");
    }
    if p.len() > 256 {
        bail!("exclude pattern too long");
    }
    let bad = [
        '`', '$', '\\', '"', '\'', '\n', '\r', ';', '&', '|', '>', '<', '(', ')', '{', '}', '\t',
        ' ',
    ];
    if p.chars().any(|c| bad.contains(&c)) {
        bail!("exclude pattern {p:?} contains shell metacharacter or whitespace");
    }
    Ok(())
}

pub struct RsyncOptions<'a> {
    pub archive: bool,
    pub delete: bool,
    pub dry_run: bool,
    pub excludes: &'a [String],
}

/// Build the rsync command that runs *on the source host* and pushes to
/// the dest host. Returns the assembled shell command string for the
/// SshClient to execute on `source_host`.
pub fn build_command(
    source_path: &str,
    dest_user: &str,
    dest_ip: &str,
    dest_port: u16,
    dest_key_path: &str,
    dest_path: &str,
    opts: &RsyncOptions<'_>,
) -> String {
    let mut cmd = String::from("rsync");
    if opts.archive {
        cmd.push_str(" -a");
    }
    if opts.delete {
        cmd.push_str(" --delete");
    }
    if opts.dry_run {
        cmd.push_str(" --dry-run");
    }
    cmd.push_str(" --stats");
    for ex in opts.excludes {
        cmd.push_str(" --exclude=");
        cmd.push_str(ex);
    }
    // Inner ssh transport — uses the source host's view of the dest
    // host's SSH key. We also pin BatchMode + accept-new so a missing
    // host key fails explicitly rather than hanging on a prompt.
    cmd.push_str(&format!(
        r#" -e 'ssh -i {dest_key_path} -p {dest_port} -o BatchMode=yes -o StrictHostKeyChecking=accept-new'"#
    ));
    cmd.push(' ');
    cmd.push_str(source_path);
    cmd.push(' ');
    cmd.push_str(&format!("{dest_user}@{dest_ip}:{dest_path}"));
    cmd
}

/// Run an rsync from `source` host to `dest` host. Both HostConfigs come
/// from the inventory after capability validation.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    ssh: &SshClient,
    source_host: &HostConfig,
    source_path: &str,
    dest_host: &HostConfig,
    dest_path: &str,
    opts: &RsyncOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExecOutput> {
    validate_path(source_path)?;
    validate_path(dest_path)?;
    for ex in opts.excludes {
        validate_exclude(ex)?;
    }
    // The source host needs to know where its own copy of the SSH key
    // lives. We assume the same key path the inventory uses for the dest
    // host, which is typically the operator's homelab convention.
    let dest_key = dest_host
        .ssh_key
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("dest ssh_key is not valid UTF-8"))?;
    let cmd = build_command(
        source_path,
        &dest_host.ssh_user,
        &dest_host.ip,
        dest_host.ssh_port,
        dest_key,
        dest_path,
        opts,
    );
    let res = ssh
        .exec(
            source_host,
            &cmd,
            timeout.or(Some(Duration::from_secs(300))),
            false,
        )
        .await?;
    if !res.ok() {
        bail!(
            "rsync failed (exit={:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_assembles_expected_shape() {
        let cmd = build_command(
            "/var/www/docs/",
            "admin",
            "192.0.2.13",
            22,
            "/home/admin/.ssh/id_rsa",
            "/var/www/docs/",
            &RsyncOptions {
                archive: true,
                delete: false,
                dry_run: false,
                excludes: &[],
            },
        );
        assert!(cmd.starts_with("rsync -a --stats"));
        assert!(cmd.contains("BatchMode=yes"));
        assert!(cmd.contains("admin@192.0.2.13:/var/www/docs/"));
    }

    #[test]
    fn build_command_emits_excludes_and_dry_run() {
        let excludes = vec![".git".to_string(), "*.log".to_string()];
        let cmd = build_command(
            "/src/",
            "admin",
            "192.0.2.13",
            22,
            "/k",
            "/dst/",
            &RsyncOptions {
                archive: true,
                delete: true,
                dry_run: true,
                excludes: &excludes,
            },
        );
        assert!(cmd.contains("--delete"));
        assert!(cmd.contains("--dry-run"));
        assert!(cmd.contains("--exclude=.git"));
        assert!(cmd.contains("--exclude=*.log"));
    }

    #[test]
    fn validate_exclude_accepts_normal_globs() {
        validate_exclude(".git").unwrap();
        validate_exclude("*.log").unwrap();
        validate_exclude("node_modules/").unwrap();
        validate_exclude("/var/cache/**").unwrap();
    }

    #[test]
    fn validate_exclude_rejects_shell_metas() {
        assert!(validate_exclude("foo;bar").is_err());
        assert!(validate_exclude("$(id)").is_err());
        assert!(validate_exclude("foo bar").is_err());
        assert!(validate_exclude("").is_err());
    }
}
