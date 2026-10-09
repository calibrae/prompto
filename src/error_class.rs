//! Why a tool call failed, as a small machine-readable enum.
//!
//! The usage log used to say only `ok: false`, which made the most-failed
//! tool (`rsync_sync`) impossible to diagnose after the fact. A tool that
//! knows *why* it failed returns a [`ClassifiedError`]; `finish_tool`
//! spots it, puts `error_class`, the exit code and a stderr tail into the
//! MCP error's `data`, and prefixes the message with the class.
//!
//! `rsync_sync` classifies its own failures, and `authz::authorize`
//! classifies every refusal (`unknown_host`, `refused_capability`,
//! `refused_self_target`). The enum is meant to grow into
//! the audit log's `error_class` (roadmap S4.4: `refused_policy`,
//! `refused_self_target`, `sudo_guard`, …), so names are stable
//! `snake_case` strings and nothing here is rsync-specific except the
//! `rsync_*` variants themselves.

use serde::Serialize;
use std::fmt;

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
            Self::RemoteNonzero => "remote_nonzero",
            Self::Internal => "internal",
        }
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
}

impl ClassifiedError {
    /// A failure detected before anything ran: no exit code, no stderr.
    pub fn refused(class: ErrorClass, err: impl fmt::Display) -> Self {
        Self {
            class,
            exit_code: None,
            stderr_tail: None,
            message: err.to_string(),
        }
    }

    /// Structured form for the MCP error's `data`.
    pub fn data(&self) -> serde_json::Value {
        serde_json::json!({
            "error_class": self.class,
            "exit_code": self.exit_code,
            "stderr_tail": self.stderr_tail,
        })
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
    fn display_leads_with_the_class() {
        let e = ClassifiedError {
            class: ErrorClass::RsyncPartial,
            exit_code: Some(23),
            stderr_tail: Some("rsync error: some files".into()),
            message: "rsync failed".into(),
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
