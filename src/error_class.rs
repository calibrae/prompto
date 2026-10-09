//! Why a tool call failed, as a small machine-readable enum.
//!
//! The usage log used to say only `ok: false`, which made the most-failed
//! tool (`rsync_sync`) impossible to diagnose after the fact. A tool that
//! knows *why* it failed returns a [`ClassifiedError`]; `finish_tool`
//! spots it, puts `error_class`, the exit code and a stderr tail into the
//! MCP error's `data`, and prefixes the message with the class.
//!
//! It is the one enum for every failure path of every tool, and the
//! audit log's `error_class` (`crate::audit`). `authz::authorize`
//! classifies every refusal (`unknown_host`, `refused_capability`,
//! `refused_self_target`, and with a policy `refused_policy` /
//! `approval_required`); argument validation is `invalid_args`; a remote
//! command that ran and failed is classified from its exit status and
//! stderr by [`classify_exec`] (`ssh_connect`, `ssh_auth`, `timeout`,
//! `sudo_guard`, `remote_nonzero`); `rsync_sync` adds its own `rsync_*`
//! and `dest_*` classes. An error that reaches `finish_tool` without a
//! class is a bug: it is reported as `internal`, logged, and counted in
//! [`unclassified_count`], which a test sweeping every tool holds at zero.
//! Names are stable `snake_case` strings.

use crate::ssh::{ExecOutput, SUDO_GUARD_EXIT};
use serde::Serialize;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// A host name that is neither in the inventory nor an alias.
    UnknownHost,
    /// The host exists but lacks the capability the tool needs.
    RefusedCapability,
    /// The target is the calling agent's own machine. Unconditional: no
    /// tool is exempt and no policy can grant it (see `authz`).
    RefusedSelfTarget,
    /// `policy.toml` grants this agent no such call (`crate::policy`).
    RefusedPolicy,
    /// A policy rule matched but demands an approval (ticket or human)
    /// that this prompto cannot take yet, so the call fails closed.
    ApprovalRequired,
    /// An argument failed validation; nothing was run.
    InvalidArgs,
    /// prompto could not reach the target host over SSH.
    SshConnect,
    /// The target host refused prompto's SSH identity (or its host key
    /// changed).
    SshAuth,
    /// The target host could not reach a second host it had to SSH to
    /// (rsync's dest).
    DestSshConnect,
    /// The second host refused the target host's SSH identity — the
    /// documented `rsync_sync` precondition is not met.
    DestSshAuth,
    /// `rsync` is not installed on one of the two hosts.
    RsyncMissing,
    /// rsync exit 1/4: syntax or usage error, unsupported action.
    RsyncUsage,
    /// rsync exit 2/5/6/12/13: protocol incompatibility or a broken
    /// protocol stream.
    RsyncProtocol,
    /// rsync exit 3/10/11/14: selecting files, socket or file I/O.
    RsyncIo,
    /// rsync exit 23/24/25: some files were not transferred.
    RsyncPartial,
    /// rsync exit 30/35: rsync's own I/O timeout.
    RsyncTimeout,
    /// prompto's timeout for the call expired and the command was killed.
    Timeout,
    /// The vault sudo path's guard fired (exit 97): sudo did not read the
    /// password, so the host has a passwordless rule. Nothing ran.
    SudoGuard,
    /// Fetching a secret from vault failed (unreachable, denied, missing
    /// or unusable field). Nothing ran on the host.
    Vault,
    /// A non-SSH service prompto relays to failed (the apytti gateway
    /// behind `claude_exec`).
    Upstream,
    /// Refused by a kill switch (reserved for E5).
    Killed,
    /// A required approval ticket was missing or invalid (reserved for
    /// E6).
    RefusedTicket,
    /// The remote command exited non-zero for a reason not listed above.
    RemoteNonzero,
    /// prompto itself failed (spawning ssh, a signal, …).
    Internal,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownHost => "unknown_host",
            Self::RefusedCapability => "refused_capability",
            Self::RefusedSelfTarget => "refused_self_target",
            Self::RefusedPolicy => "refused_policy",
            Self::ApprovalRequired => "approval_required",
            Self::InvalidArgs => "invalid_args",
            Self::SshConnect => "ssh_connect",
            Self::SshAuth => "ssh_auth",
            Self::DestSshConnect => "dest_ssh_connect",
            Self::DestSshAuth => "dest_ssh_auth",
            Self::RsyncMissing => "rsync_missing",
            Self::RsyncUsage => "rsync_usage",
            Self::RsyncProtocol => "rsync_protocol",
            Self::RsyncIo => "rsync_io",
            Self::RsyncPartial => "rsync_partial",
            Self::RsyncTimeout => "rsync_timeout",
            Self::Timeout => "timeout",
            Self::SudoGuard => "sudo_guard",
            Self::Vault => "vault",
            Self::Upstream => "upstream",
            Self::Killed => "killed",
            Self::RefusedTicket => "refused_ticket",
            Self::RemoteNonzero => "remote_nonzero",
            Self::Internal => "internal",
        }
    }
}

impl ErrorClass {
    /// Every variant, for exhaustive tests and the CLI.
    pub const ALL: &'static [ErrorClass] = &[
        Self::UnknownHost,
        Self::RefusedCapability,
        Self::RefusedSelfTarget,
        Self::RefusedPolicy,
        Self::ApprovalRequired,
        Self::InvalidArgs,
        Self::SshConnect,
        Self::SshAuth,
        Self::DestSshConnect,
        Self::DestSshAuth,
        Self::RsyncMissing,
        Self::RsyncUsage,
        Self::RsyncProtocol,
        Self::RsyncIo,
        Self::RsyncPartial,
        Self::RsyncTimeout,
        Self::Timeout,
        Self::SudoGuard,
        Self::Vault,
        Self::Upstream,
        Self::Killed,
        Self::RefusedTicket,
        Self::RemoteNonzero,
        Self::Internal,
    ];

    /// A refusal: the call was stopped before anything ran, by
    /// authorization (the audit `decision` is `deny`). `invalid_args` is
    /// not one — the caller's input was wrong, nobody refused it.
    pub fn is_refusal(self) -> bool {
        matches!(
            self,
            Self::UnknownHost
                | Self::RefusedCapability
                | Self::RefusedSelfTarget
                | Self::RefusedPolicy
                | Self::ApprovalRequired
                | Self::Killed
                | Self::RefusedTicket
        )
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failure that knows its [`ErrorClass`]. Travels inside
/// `anyhow::Error` and is recovered with `downcast_ref` in `finish_tool`,
/// so handlers that don't classify need no change.
#[derive(Debug)]
pub struct ClassifiedError {
    pub class: ErrorClass,
    pub exit_code: Option<i32>,
    /// Last lines of the remote stderr, see [`stderr_tail`].
    pub stderr_tail: Option<String>,
    pub message: String,
    /// The policy rule that decided a policy refusal (`policy.toml:12`,
    /// or `default-deny`).
    pub rule: Option<String>,
}

impl ClassifiedError {
    /// A failure detected before anything ran: no exit code, no stderr.
    pub fn refused(class: ErrorClass, err: impl fmt::Display) -> Self {
        Self {
            class,
            exit_code: None,
            stderr_tail: None,
            message: err.to_string(),
            rule: None,
        }
    }

    /// A remote command that ran and failed: class from [`classify_exec`],
    /// its exit code, and `message` (which already quotes stderr).
    pub fn exec_failure(out: &ExecOutput, sudo: bool, message: impl Into<String>) -> Self {
        Self {
            class: classify_exec(out, sudo).unwrap_or(ErrorClass::RemoteNonzero),
            exit_code: out.exit_code,
            stderr_tail: None,
            message: message.into(),
            rule: None,
        }
    }

    /// Name the policy rule behind this refusal.
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }

    /// Structured form for the MCP error's `data`. `rule` is present
    /// only on policy decisions.
    pub fn data(&self) -> serde_json::Value {
        let mut d = serde_json::json!({
            "error_class": self.class,
            "exit_code": self.exit_code,
            "stderr_tail": self.stderr_tail,
        });
        if let Some(r) = &self.rule {
            d["rule"] = r.as_str().into();
        }
        d
    }
}

impl ClassifiedError {
    /// The display form, with `request_id` leading the bracketed prefix
    /// when given: `[request_id=… error_class=… exit=…] message | stderr: …`.
    pub fn render(&self, request_id: Option<&str>) -> String {
        let mut out = String::from("[");
        if let Some(id) = request_id {
            out.push_str(&format!("request_id={id} "));
        }
        out.push_str(&format!("error_class={}", self.class));
        if let Some(c) = self.exit_code {
            out.push_str(&format!(" exit={c}"));
        }
        out.push_str(&format!("] {}", self.message));
        if let Some(t) = &self.stderr_tail {
            out.push_str(&format!(" | stderr: {t}"));
        }
        out
    }
}

impl fmt::Display for ClassifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(None))
    }
}

impl std::error::Error for ClassifiedError {}

/// Return early with a [`ClassifiedError`] of class `$class`:
/// `fail!(InvalidArgs, "path {p:?} is empty")`.
#[macro_export]
macro_rules! fail {
    ($class:ident, $($arg:tt)*) => {
        return Err($crate::error_class::ClassifiedError::refused(
            $crate::error_class::ErrorClass::$class,
            format!($($arg)*),
        )
        .into())
    };
}

/// Attach a class to an error that has none. An error that already
/// carries a [`ClassifiedError`] keeps its own class.
pub trait Classify<T> {
    fn class(self, class: ErrorClass) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> Classify<T> for Result<T, E> {
    fn class(self, class: ErrorClass) -> anyhow::Result<T> {
        self.map_err(|e| {
            let e: anyhow::Error = e.into();
            if e.downcast_ref::<ClassifiedError>().is_some() {
                e
            } else {
                ClassifiedError::refused(class, format!("{e:#}")).into()
            }
        })
    }
}

impl<T> Classify<T> for Option<T> {
    fn class(self, class: ErrorClass) -> anyhow::Result<T> {
        self.ok_or_else(|| ClassifiedError::refused(class, "missing value").into())
    }
}

/// Why a remote command failed, or `None` if it succeeded (exit 0, not
/// timed out). `sudo` says whether it ran through prompto's sudo path,
/// where exit 97 with the guard's message is [`ErrorClass::SudoGuard`].
///
/// Exit 255 is OpenSSH's own failure status: the connection or the login
/// failed, told apart by ssh's messages. A remote command can exit 255
/// too; without ssh's messages that is `remote_nonzero`.
pub fn classify_exec(out: &ExecOutput, sudo: bool) -> Option<ErrorClass> {
    if out.timed_out {
        return Some(ErrorClass::Timeout);
    }
    let stderr = out.stderr.as_str();
    match out.exit_code {
        Some(0) => None,
        // Killed by a signal, or prompto failed to feed stdin.
        None => Some(ErrorClass::Internal),
        Some(255) if ssh_auth_refused(stderr) => Some(ErrorClass::SshAuth),
        Some(255) if ssh_connect_failed(stderr) => Some(ErrorClass::SshConnect),
        Some(SUDO_GUARD_EXIT) if sudo && stderr.contains(SUDO_GUARD_MESSAGE) => {
            Some(ErrorClass::SudoGuard)
        }
        Some(_) => Some(ErrorClass::RemoteNonzero),
    }
}

/// What the sudo guard prints on stderr (see `ssh::SUDO_STDIN_SHELL`).
pub const SUDO_GUARD_MESSAGE: &str = "prompto: sudo did not read the password";

/// OpenSSH refused the login. Its message lists auth methods —
/// `Permission denied (publickey,password).` — which is what tells it
/// apart from a file error such as rsync's `Permission denied (13)`.
pub fn ssh_auth_refused(stderr: &str) -> bool {
    stderr
        .match_indices("Permission denied (")
        .any(|(i, m)| stderr[i + m.len()..].starts_with(|c: char| c.is_ascii_alphabetic()))
        || stderr.contains("Permission denied, please try again")
        || stderr.contains("Too many authentication failures")
        || stderr.contains("Host key verification failed")
}

/// OpenSSH could not open the connection at all.
pub fn ssh_connect_failed(stderr: &str) -> bool {
    stderr.contains("ssh: connect to host")
        || stderr.contains("ssh: Could not resolve hostname")
        || stderr.contains("kex_exchange_identification")
        || stderr.contains("Connection closed by")
        || stderr.contains("Connection reset by")
}

static UNCLASSIFIED: AtomicU64 = AtomicU64::new(0);

/// Note an error that reached `finish_tool` with no class. That is a bug
/// in the tool; it is reported as `internal`.
pub fn note_unclassified() {
    UNCLASSIFIED.fetch_add(1, Ordering::Relaxed);
}

/// How many tool errors went unclassified since the process started.
pub fn unclassified_count() -> u64 {
    UNCLASSIFIED.load(Ordering::Relaxed)
}

/// Lines kept by [`stderr_tail`].
pub const TAIL_LINES: usize = 10;
/// Byte cap of [`stderr_tail`].
pub const TAIL_BYTES: usize = 1024;

/// The last [`TAIL_LINES`] non-empty lines of `stderr`, at most
/// [`TAIL_BYTES`] bytes, prefixed with `…` when anything was cut. The end
/// is what names the failure (`rsync error: … (code 23)`); a long
/// "file has vanished" list before it is noise.
pub fn stderr_tail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines.len().saturating_sub(TAIL_LINES);
    let mut tail = lines[start..].join("\n");
    let mut cut = start > 0;
    if tail.len() > TAIL_BYTES {
        let mut from = tail.len() - TAIL_BYTES;
        while !tail.is_char_boundary(from) {
            from += 1;
        }
        tail.drain(..from);
        cut = true;
    }
    if cut {
        tail.insert(0, '…');
    }
    tail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_snake_case_matching_as_str() {
        for c in [
            ErrorClass::UnknownHost,
            ErrorClass::DestSshAuth,
            ErrorClass::RsyncPartial,
            ErrorClass::RemoteNonzero,
        ] {
            assert_eq!(
                serde_json::to_value(c).unwrap(),
                serde_json::Value::String(c.as_str().into())
            );
        }
    }

    #[test]
    fn all_lists_every_variant_once_with_unique_names() {
        let names: std::collections::HashSet<_> =
            ErrorClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ErrorClass::ALL.len());
        // A new variant must be added to ALL: the match below won't
        // compile without it, and the count must then be bumped.
        let n = |c: ErrorClass| match c {
            ErrorClass::UnknownHost
            | ErrorClass::RefusedCapability
            | ErrorClass::RefusedSelfTarget
            | ErrorClass::RefusedPolicy
            | ErrorClass::ApprovalRequired
            | ErrorClass::InvalidArgs
            | ErrorClass::SshConnect
            | ErrorClass::SshAuth
            | ErrorClass::DestSshConnect
            | ErrorClass::DestSshAuth
            | ErrorClass::RsyncMissing
            | ErrorClass::RsyncUsage
            | ErrorClass::RsyncProtocol
            | ErrorClass::RsyncIo
            | ErrorClass::RsyncPartial
            | ErrorClass::RsyncTimeout
            | ErrorClass::Timeout
            | ErrorClass::SudoGuard
            | ErrorClass::Vault
            | ErrorClass::Upstream
            | ErrorClass::Killed
            | ErrorClass::RefusedTicket
            | ErrorClass::RemoteNonzero
            | ErrorClass::Internal => 1,
        };
        assert_eq!(ErrorClass::ALL.iter().map(|c| n(*c)).sum::<usize>(), 24);
    }

    fn out(code: Option<i32>, stderr: &str, timed_out: bool) -> ExecOutput {
        ExecOutput {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code: code,
            timed_out,
        }
    }

    #[test]
    fn classify_exec_names_each_failure() {
        let c = |code, err, sudo| classify_exec(&out(code, err, false), sudo);
        assert_eq!(c(Some(0), "", false), None);
        assert_eq!(
            classify_exec(&out(None, "", true), false),
            Some(ErrorClass::Timeout)
        );
        assert_eq!(c(None, "", false), Some(ErrorClass::Internal));
        assert_eq!(
            c(
                Some(255),
                "ssh: connect to host 192.0.2.1 port 22: Connection refused",
                false
            ),
            Some(ErrorClass::SshConnect)
        );
        assert_eq!(
            c(Some(255), "u@h: Permission denied (publickey).", false),
            Some(ErrorClass::SshAuth)
        );
        assert_eq!(c(Some(255), "", false), Some(ErrorClass::RemoteNonzero));
        let guard =
            "prompto: sudo did not read the password - this host has a passwordless sudo rule";
        assert_eq!(c(Some(97), guard, true), Some(ErrorClass::SudoGuard));
        // Only on the sudo path, and only with the guard's message.
        assert_eq!(c(Some(97), guard, false), Some(ErrorClass::RemoteNonzero));
        assert_eq!(c(Some(97), "", true), Some(ErrorClass::RemoteNonzero));
        assert_eq!(c(Some(1), "nope", false), Some(ErrorClass::RemoteNonzero));
    }

    /// The guard's message in the shipped shell text is the one
    /// `classify_exec` looks for.
    #[test]
    fn guard_message_matches_the_sudo_shell() {
        assert!(crate::ssh::SUDO_STDIN_SHELL.contains(SUDO_GUARD_MESSAGE));
    }

    #[test]
    fn classify_keeps_an_existing_class() {
        let inner: anyhow::Result<()> =
            Err(ClassifiedError::refused(ErrorClass::Timeout, "slow").into());
        let e = inner.class(ErrorClass::Internal).unwrap_err();
        assert_eq!(
            e.downcast_ref::<ClassifiedError>().unwrap().class,
            ErrorClass::Timeout
        );
        let plain: anyhow::Result<()> = Err(anyhow::anyhow!("boom"));
        let e = plain.class(ErrorClass::Vault).unwrap_err();
        let c = e.downcast_ref::<ClassifiedError>().unwrap();
        assert_eq!((c.class, c.message.as_str()), (ErrorClass::Vault, "boom"));
    }

    #[test]
    fn display_leads_with_the_class() {
        let e = ClassifiedError {
            class: ErrorClass::RsyncPartial,
            exit_code: Some(23),
            stderr_tail: Some("rsync error: some files".into()),
            message: "rsync failed".into(),
            rule: None,
        };
        assert_eq!(
            e.to_string(),
            "[error_class=rsync_partial exit=23] rsync failed | stderr: rsync error: some files"
        );
        let r = ClassifiedError::refused(ErrorClass::InvalidArgs, "bad path");
        assert_eq!(r.to_string(), "[error_class=invalid_args] bad path");
        assert_eq!(
            e.render(Some("01ABC")),
            "[request_id=01ABC error_class=rsync_partial exit=23] rsync failed | stderr: rsync error: some files"
        );
    }

    #[test]
    fn data_carries_class_exit_and_tail() {
        let e = ClassifiedError {
            class: ErrorClass::SshConnect,
            exit_code: Some(255),
            stderr_tail: Some("Connection refused".into()),
            message: String::new(),
            rule: None,
        };
        assert_eq!(
            e.data(),
            serde_json::json!({
                "error_class": "ssh_connect",
                "exit_code": 255,
                "stderr_tail": "Connection refused",
            })
        );
    }

    #[test]
    fn survives_anyhow_context_for_downcast() {
        let e = anyhow::Error::new(ClassifiedError::refused(ErrorClass::Timeout, "slow"))
            .context("outer");
        assert_eq!(
            e.downcast_ref::<ClassifiedError>().unwrap().class,
            ErrorClass::Timeout
        );
    }

    #[test]
    fn tail_keeps_short_stderr_whole() {
        assert_eq!(stderr_tail("  a\n\nb  \n"), "  a\nb");
        assert_eq!(stderr_tail(""), "");
    }

    #[test]
    fn tail_keeps_the_last_lines() {
        let s: String = (0..30).map(|i| format!("line {i}\n")).collect();
        let t = stderr_tail(&s);
        assert!(t.starts_with("…line 20\n"), "{t}");
        assert!(t.ends_with("line 29"), "{t}");
        assert_eq!(t.lines().count(), TAIL_LINES);
    }

    #[test]
    fn tail_caps_bytes_on_a_char_boundary() {
        let s = "é".repeat(TAIL_BYTES); // 2 bytes each, one line
        let t = stderr_tail(&s);
        assert!(t.starts_with('…'));
        assert!(t.len() <= TAIL_BYTES + '…'.len_utf8());
    }
}
