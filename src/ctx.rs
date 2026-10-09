//! Per-call context: who is calling, from where, and under which request ID.
//!
//! One [`CallCtx`] is built at the top of every tool call and threaded
//! through authorization (`Prompto::authorize`), the SSH layer (which
//! exports the request ID to the remote command) and `finish_tool` (the
//! single emission point for the gain tracker, and later the audit log).
//!
//! The request ID is a ULID: sortable by time, unique without
//! coordination, and returned to the caller on success and error alike,
//! so a caller-side transcript, prompto's logs and the target host's
//! logs can all be joined on it.

use std::net::IpAddr;
use std::time::Instant;
use ulid::Ulid;

/// The calling agent: a role from `agents.toml` (see `crate::agent`), or
/// the pseudo-agents `anonymous` (no valid token, `PROMPTO_AUTH=optional`)
/// and `local` (stdio). Later also OIDC identities (E9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agent {
    pub name: String,
    pub groups: Vec<String>,
}

/// Everything known about one tool call before it runs.
#[derive(Clone, Debug)]
pub struct CallCtx {
    pub request_id: Ulid,
    /// Real client IP (see `caller::resolve_client_ip`). `None` on
    /// transports that carry no address (stdio, unit tests).
    pub caller_ip: Option<IpAddr>,
    /// Set by the auth middleware (`crate::agent`). `None` only with
    /// `PROMPTO_AUTH=off` on HTTP.
    pub agent: Option<Agent>,
    /// Claude session ID sent as context by the client in the
    /// `X-Prompto-Session` header. Context only, never proof of identity.
    pub session_id: Option<String>,
    /// When the call started, for `duration_ms`.
    pub started: Instant,
}

impl CallCtx {
    /// A fresh context with a new request ID, starting now.
    pub fn new(caller_ip: Option<IpAddr>) -> Self {
        Self {
            request_id: Ulid::generate(),
            caller_ip,
            agent: None,
            session_id: None,
            started: Instant::now(),
        }
    }

    /// Attach the caller's identity (agent and session).
    pub fn with_identity(mut self, id: crate::agent::Identity) -> Self {
        self.agent = id.agent;
        self.session_id = id.session_id;
        self
    }

    /// Agent name for log fields: the agent, or `-` with auth off.
    pub fn agent_name(&self) -> &str {
        self.agent.as_ref().map_or("-", |a| a.name.as_str())
    }

    /// The request ID in its canonical 26-char Crockford base32 form.
    pub fn request_id(&self) -> String {
        self.request_id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ctx_gets_its_own_request_id() {
        let a = CallCtx::new(None);
        let b = CallCtx::new(None);
        assert_ne!(a.request_id, b.request_id);
    }

    /// The SSH layer splices the ID into remote command lines unquoted;
    /// that is only safe because a ULID is 26 Crockford base32 chars.
    #[test]
    fn request_id_is_shell_inert() {
        let id = CallCtx::new(None).request_id();
        assert_eq!(id.len(), 26);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()),
            "{id}"
        );
    }
}
