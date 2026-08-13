//! `rsync` passthrough between two inventory hosts.
//!
//! Shape: prompto SSHs to the *source* host and runs rsync there with
//! the *dest* host as the target. Both hosts must be in the inventory
//! with the `exec` capability.
//!
//! # The precondition, stated plainly
//!
//! **The source host must already be able to SSH to the dest host as
//! `dest_host.ssh_user`.** prompto does not and cannot broker that: the
//! rsync runs on the source box, so it is the source box's SSH identity
//! that authenticates, not prompto's.
//!
//! Until v0.8.0 this module violated its own premise. It passed
//! `dest_host.ssh_key` — an *inventory* path like
//! `/etc/prompto/keys/cali_net_rsa`, meaningful only on the host running
//! prompto — to `ssh -i` **on the source host**, where that file is
//! either absent or (on prompto's own host) present but `root:prompto
//! 0640` and unreadable by the SSH user. Every call was therefore either
//! silently rescued by the source host's default key or killed outright:
//!
//! ```text
//! Warning: Identity file /etc/prompto/keys/cali_net_rsa not accessible: Permission denied.
//! cali@10.10.0.12: Permission denied (publickey,...).
//! rsync error: unexplained error (code 255)
//! ```
//!
//! 19 recorded calls, 19 failures, no successes ever. Now `-i` is omitted
//! by default so the source host uses its own SSH config, keys and agent
//! — exactly what a human running the same rsync would get — with an
//! optional `dest_key` override naming a path **on the source host**.
//!
//! No support yet for local-staging-to-remote (would need
//! `ReadWritePaths` widened beyond `/var/lib/prompto`).

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
///
/// `dest_key_path` is a path **on the source host**, or `None` to let the
/// source host's own SSH configuration pick the identity. `None` is the
/// default and the correct choice for a homelab where the boxes already
/// trust each other — passing prompto's own key path here is what broke
/// this tool for its entire life before v0.8.0.
pub fn build_command(
    source_path: &str,
    dest_user: &str,
    dest_ip: &str,
    dest_port: u16,
    dest_key_path: Option<&str>,
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
    // Inner ssh transport, executed BY THE SOURCE HOST. `-i` is omitted
    // unless the caller names a key that exists there; otherwise the
    // source host resolves the identity itself (~/.ssh/config, default
    // keys, agent) exactly as a human running this rsync would.
    // BatchMode + accept-new keep a missing key or host key an explicit
    // failure rather than a hung prompt.
    let identity = match dest_key_path {
        Some(k) => format!(" -i {k}"),
        None => String::new(),
    };
    cmd.push_str(&format!(
        r#" -e 'ssh{identity} -p {dest_port} -o BatchMode=yes -o StrictHostKeyChecking=accept-new'"#
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
/// `dest_key` is an optional identity path **on the source host**. It is
/// deliberately NOT taken from `dest_host.ssh_key`: that is prompto's own
/// path to the key and is meaningless — or unreadable — on the source
/// box. See the module docs.
pub async fn run(
    ssh: &SshClient,
    source_host: &HostConfig,
    source_path: &str,
    dest_host: &HostConfig,
    dest_path: &str,
    dest_key: Option<&str>,
    opts: &RsyncOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExecOutput> {
    validate_path(source_path)?;
    validate_path(dest_path)?;
    if let Some(k) = dest_key {
        validate_path(k)?;
    }
    for ex in opts.excludes {
        validate_exclude(ex)?;
    }
    let cmd = build_command(
        source_path,
        &dest_host.ssh_user,
        &dest_host.ip.to_string(),
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
        // rsync exits 255 when its ssh transport fails. That is almost
        // always the unstated precondition — the source host cannot
        // authenticate to the dest host — so say so instead of leaving
        // the caller to decode "unexplained error (code 255)".
        let stderr = res.stderr.trim();
        if stderr.contains("Permission denied") || res.exit_code == Some(255) {
            bail!(
                "rsync failed (exit={:?}): the SOURCE host {:?} cannot SSH to the DEST host \
                 {}@{} — rsync runs on the source box, so the source box's SSH identity is what \
                 authenticates, not prompto's. Fix by authorising {:?}'s key on {}, or pass \
                 `dest_key` naming an identity file that exists ON {:?}. Underlying error: {}",
                res.exit_code,
                source_host.ip.to_string(),
                dest_host.ssh_user,
                dest_host.ip,
                source_host.ip.to_string(),
                dest_host.ip,
                source_host.ip.to_string(),
                stderr
            );
        }
        bail!("rsync failed (exit={:?}): {}", res.exit_code, stderr);
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
            Some("/home/admin/.ssh/id_rsa"),
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
        assert!(cmd.contains("-i /home/admin/.ssh/id_rsa"));
    }

    /// THE regression. For its whole life this tool passed
    /// `dest_host.ssh_key` — prompto's own inventory path — to `ssh -i`
    /// on the *source* host, where it is absent, or (on prompto's own
    /// host) present as root:prompto 0640 and unreadable. Result: 19
    /// recorded calls, 19 failures, exit 255 "Permission denied".
    ///
    /// Default must now emit NO `-i` at all, so the source host resolves
    /// its own identity the way a human running the same rsync would.
    #[test]
    fn build_command_omits_identity_by_default() {
        let cmd = build_command(
            "/src/",
            "admin",
            "192.0.2.13",
            22,
            None,
            "/dst/",
            &RsyncOptions {
                archive: true,
                delete: false,
                dry_run: false,
                excludes: &[],
            },
        );
        assert!(
            !cmd.contains(" -i "),
            "default must not pass an identity file: {cmd}"
        );
        assert!(
            !cmd.contains("/etc/prompto"),
            "prompto's own key path must never reach the source host: {cmd}"
        );
        // The transport is still pinned to fail fast rather than prompt.
        assert!(cmd.contains("-e 'ssh -p 22 -o BatchMode=yes"));
    }

    #[test]
    fn build_command_emits_excludes_and_dry_run() {
        let excludes = vec![".git".to_string(), "*.log".to_string()];
        let cmd = build_command(
            "/src/",
            "admin",
            "192.0.2.13",
            22,
            Some("/k"),
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
