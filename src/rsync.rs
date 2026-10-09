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
//! `/etc/prompto/keys/id_rsa`, meaningful only on the host running
//! prompto — to `ssh -i` **on the source host**, where that file is
//! either absent or (on prompto's own host) present but `root:prompto
//! 0640` and unreadable by the SSH user. Every call was therefore either
//! silently rescued by the source host's default key or killed outright:
//!
//! ```text
//! Warning: Identity file /etc/prompto/keys/id_rsa not accessible: Permission denied.
//! user@192.0.2.12: Permission denied (publickey,...).
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

use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass, stderr_tail};
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
    ctx: &CallCtx,
    source_host: &HostConfig,
    source_path: &str,
    dest_host: &HostConfig,
    dest_path: &str,
    dest_key: Option<&str>,
    opts: &RsyncOptions<'_>,
    timeout: Option<Duration>,
) -> Result<ExecOutput> {
    let invalid = |e: anyhow::Error| ClassifiedError::refused(ErrorClass::InvalidArgs, e);
    validate_path(source_path).map_err(invalid)?;
    validate_path(dest_path).map_err(invalid)?;
    if let Some(k) = dest_key {
        validate_path(k).map_err(invalid)?;
    }
    for ex in opts.excludes {
        validate_exclude(ex).map_err(invalid)?;
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
            ctx,
            source_host,
            &cmd,
            timeout.or(Some(Duration::from_secs(300))),
            false,
        )
        .await
        .map_err(|e| ClassifiedError::refused(ErrorClass::Internal, format!("{e:#}")))?;
    if !res.ok() {
        let class = classify(&res);
        bail!(ClassifiedError {
            class,
            exit_code: res.exit_code,
            stderr_tail: Some(stderr_tail(&res.stderr)),
            message: explain(class, source_host, dest_host),
            rule: None,
        });
    }
    Ok(res)
}

/// Does stderr carry rsync's own diagnostics (`rsync: …`, `rsync error:
/// …`)? If so rsync started on the source host, and a transport failure
/// is the source→dest hop, not prompto→source.
fn rsync_spoke(stderr: &str) -> bool {
    stderr.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("rsync: ") || l.starts_with("rsync error: ")
    })
}

/// OpenSSH refused the login. Its message lists auth methods —
/// `Permission denied (publickey,password).` — which is what tells it
/// apart from rsync's file errors, `Permission denied (13)`.
fn ssh_auth_refused(stderr: &str) -> bool {
    stderr
        .match_indices("Permission denied (")
        .any(|(i, m)| stderr[i + m.len()..].starts_with(|c: char| c.is_ascii_alphabetic()))
        || stderr.contains("Permission denied, please try again")
        || stderr.contains("Too many authentication failures")
        || stderr.contains("Host key verification failed")
}

/// OpenSSH could not open the connection at all.
fn ssh_connect_failed(stderr: &str) -> bool {
    stderr.contains("ssh: connect to host")
        || stderr.contains("ssh: Could not resolve hostname")
        || stderr.contains("kex_exchange_identification")
        || stderr.contains("Connection closed by")
        || stderr.contains("Connection reset by")
}

fn command_not_found(stderr: &str) -> bool {
    stderr.lines().any(|l| {
        l.contains("rsync: not found")
            || l.contains("rsync: command not found")
            || l.contains("rsync: No such file or directory")
    })
}

/// Map rsync's documented exit codes (rsync(1) "EXIT VALUES") to a class.
/// 255 and 127 are not decided here: they depend on which hop failed.
pub fn class_for_exit(code: i32) -> ErrorClass {
    match code {
        1 | 4 => ErrorClass::RsyncUsage,
        2 | 5 | 6 | 12 | 13 => ErrorClass::RsyncProtocol,
        3 | 10 | 11 | 14 => ErrorClass::RsyncIo,
        23..=25 => ErrorClass::RsyncPartial,
        30 | 35 => ErrorClass::RsyncTimeout,
        127 => ErrorClass::RsyncMissing,
        255 => ErrorClass::SshConnect,
        _ => ErrorClass::RemoteNonzero,
    }
}

/// Classify a failed rsync run, as seen through prompto's ssh to the
/// source host.
///
/// Exit 255 is ambiguous: prompto's own ssh returns it when it can't
/// reach or log into the source host, and rsync returns it when *its*
/// ssh to the dest fails. rsync then adds its own `rsync error:` lines,
/// which is how the two are told apart.
pub fn classify(out: &ExecOutput) -> ErrorClass {
    if out.timed_out {
        return ErrorClass::Timeout;
    }
    let Some(code) = out.exit_code else {
        // Killed by a signal, or prompto failed to feed stdin.
        return ErrorClass::Internal;
    };
    let stderr = out.stderr.as_str();
    // Missing on the source: the shell says so, exit 127. Missing on the
    // dest: rsync reports the remote shell's 127 (3.2+) or a broken
    // protocol stream, 12 (older rsync).
    if command_not_found(stderr) {
        return ErrorClass::RsyncMissing;
    }
    // The transport failing is decided on ssh's own messages, not on
    // 255 alone: when the source path is also bad, rsync can trip over
    // the closed pipe first and exit 12 instead (seen live).
    let auth = ssh_auth_refused(stderr);
    if code == 255 || auth || ssh_connect_failed(stderr) {
        return match (rsync_spoke(stderr), auth) {
            (true, true) => ErrorClass::DestSshAuth,
            (true, false) => ErrorClass::DestSshConnect,
            (false, true) => ErrorClass::SshAuth,
            (false, false) => ErrorClass::SshConnect,
        };
    }
    class_for_exit(code)
}

/// One-line explanation and fix for `class`, naming the hosts involved.
fn explain(class: ErrorClass, source: &HostConfig, dest: &HostConfig) -> String {
    let (src, dst) = (source.ip, dest.ip);
    let du = &dest.ssh_user;
    match class {
        ErrorClass::DestSshAuth => format!(
            "rsync_sync: the SOURCE host {src} reached the DEST host {dst} but was refused as \
             {du:?}. rsync runs on the source box, so the source box's SSH identity is what \
             authenticates, not prompto's. Fix by authorising {src}'s key for {du}@{dst}, or \
             pass `dest_key` naming an identity file that exists ON {src}."
        ),
        ErrorClass::DestSshConnect => format!(
            "rsync_sync: the SOURCE host {src} could not open an SSH connection to the DEST \
             host {dst}:{} (network, firewall or sshd on the dest). prompto reached the \
             source fine.",
            dest.ssh_port
        ),
        ErrorClass::SshAuth => format!(
            "rsync_sync: prompto's own SSH login to the SOURCE host {src} was refused; nothing \
             ran. Check prompto's key in {}@{src}'s authorized_keys.",
            source.ssh_user
        ),
        ErrorClass::SshConnect => format!(
            "rsync_sync: prompto could not SSH to the SOURCE host {src} (down, asleep, or \
             unreachable); nothing ran."
        ),
        ErrorClass::RsyncMissing => {
            format!("rsync_sync: rsync is not installed on {src} (source) or {dst} (dest).")
        }
        ErrorClass::Timeout => "rsync_sync: timed out and was killed; raise timeout_secs \
             for a large tree, or sync a smaller subtree."
            .into(),
        ErrorClass::RsyncPartial => "rsync_sync: rsync ran but some files were not \
             transferred (missing source path, permissions, vanished files)."
            .into(),
        ErrorClass::RsyncIo => "rsync_sync: rsync hit a file or socket I/O error (e.g. the \
             dest parent directory does not exist, or the disk is full)."
            .into(),
        _ => "rsync_sync: rsync failed.".into(),
    }
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

    fn failed(code: Option<i32>, stderr: &str) -> ExecOutput {
        ExecOutput {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code: code,
            timed_out: false,
        }
    }

    #[test]
    fn exit_codes_map_to_documented_classes() {
        use ErrorClass::*;
        let table = [
            (1, RsyncUsage),
            (2, RsyncProtocol),
            (3, RsyncIo),
            (4, RsyncUsage),
            (5, RsyncProtocol),
            (6, RsyncProtocol),
            (10, RsyncIo),
            (11, RsyncIo),
            (12, RsyncProtocol),
            (13, RsyncProtocol),
            (14, RsyncIo),
            (20, RemoteNonzero),
            (22, RemoteNonzero),
            (23, RsyncPartial),
            (24, RsyncPartial),
            (25, RsyncPartial),
            (30, RsyncTimeout),
            (35, RsyncTimeout),
            (127, RsyncMissing),
            (255, SshConnect),
            (42, RemoteNonzero),
        ];
        for (code, class) in table {
            assert_eq!(class_for_exit(code), class, "exit {code}");
            // With no telltale stderr, classify() agrees with the table.
            assert_eq!(classify(&failed(Some(code), "")), class, "exit {code}");
        }
    }

    // Stderr below is verbatim from rsync 3.5.0 + OpenSSH, captured in
    // the same shapes the integration test reproduces.

    #[test]
    fn prompto_to_source_failures_are_ssh_classes() {
        let refused = "ssh: connect to host 192.0.2.5 port 22: Connection refused\n";
        assert_eq!(
            classify(&failed(Some(255), refused)),
            ErrorClass::SshConnect
        );
        let denied = "admin@192.0.2.5: Permission denied (publickey).\n";
        assert_eq!(classify(&failed(Some(255), denied)), ErrorClass::SshAuth);
    }

    /// The documented precondition: the source host can't log into the
    /// dest. rsync's own lines after ssh's say it was rsync's hop.
    #[test]
    fn source_to_dest_failures_are_dest_ssh_classes() {
        let tail = "rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n\
                    rsync error: unexplained error (code 255) at io.c(285) [sender=3.5.0]\n";
        let denied = format!("192.0.2.6: Permission denied (publickey).\n{tail}");
        assert_eq!(
            classify(&failed(Some(255), &denied)),
            ErrorClass::DestSshAuth
        );
        let hostkey = format!("Host key verification failed.\n{tail}");
        assert_eq!(
            classify(&failed(Some(255), &hostkey)),
            ErrorClass::DestSshAuth
        );
        let refused = format!("ssh: connect to host 192.0.2.6 port 22: Connection refused\n{tail}");
        assert_eq!(
            classify(&failed(Some(255), &refused)),
            ErrorClass::DestSshConnect
        );
    }

    /// Before S0.2, any "Permission denied" was blamed on source→dest
    /// SSH, so a file permission error got SSH advice.
    #[test]
    fn file_permission_denied_is_not_an_ssh_failure() {
        let s = "rsync: [sender] send_files failed to open \"/src/secret\": Permission denied (13)\n\
                 rsync error: some files/attrs were not transferred (see previous errors) (code 23)\n";
        assert_eq!(classify(&failed(Some(23), s)), ErrorClass::RsyncPartial);
    }

    /// Verbatim from sbx-t1 (rsync 3.5.0): missing source path AND a dest
    /// that refuses the source's key. rsync exits 12, not 255, yet the
    /// cause to fix is the SSH trust.
    #[test]
    fn dest_auth_failure_masked_as_protocol_error() {
        let s = "ops@192.0.2.12: Permission denied (publickey).\n\
                 rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n\
                 rsync error: error in rsync protocol data stream (code 12) at io.c(285) [sender=3.5.0]\n";
        assert_eq!(classify(&failed(Some(12), s)), ErrorClass::DestSshAuth);
        let c = s.replace(
            "ops@192.0.2.12: Permission denied (publickey).",
            "ssh: connect to host 192.0.2.12 port 22: No route to host",
        );
        assert_eq!(classify(&failed(Some(12), &c)), ErrorClass::DestSshConnect);
    }

    #[test]
    fn missing_rsync_on_either_side() {
        // Source: the shell can't find it.
        let src = "/bin/sh: 1: rsync: not found\n";
        assert_eq!(classify(&failed(Some(127), src)), ErrorClass::RsyncMissing);
        // Dest, rsync >= 3.2: remote shell's 127 passed through.
        let dst = "bash: line 1: rsync: command not found\n\
                   rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n\
                   rsync error: remote command not found (code 127) at io.c(285)\n";
        assert_eq!(classify(&failed(Some(127), dst)), ErrorClass::RsyncMissing);
        // Dest, older rsync: a broken protocol stream, code 12.
        let old = "bash: rsync: command not found\n\
                   rsync: connection unexpectedly closed (0 bytes received so far) [sender]\n\
                   rsync error: error in rsync protocol data stream (code 12) at io.c(226)\n";
        assert_eq!(classify(&failed(Some(12), old)), ErrorClass::RsyncMissing);
    }

    #[test]
    fn prompto_timeout_and_signal() {
        let mut t = failed(None, "ssh command timed out after 300s");
        t.timed_out = true;
        assert_eq!(classify(&t), ErrorClass::Timeout);
        assert_eq!(classify(&failed(None, "")), ErrorClass::Internal);
    }
}
