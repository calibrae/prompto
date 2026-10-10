//! Per-call context: who is calling, from where, and under which request ID.
//!
//! One [`CallCtx`] is built at the top of every tool call and threaded
//! through authorization (`Prompto::authorize`), the SSH layer (which
//! exports the request ID to the remote command) and `finish_tool` (the
//! single emission point for the gain tracker and the audit log).
//!
//! The request ID is a ULID: sortable by time, unique without
//! coordination, and returned to the caller on success and error alike,
//! so a caller-side transcript, prompto's logs and the target host's
//! logs can all be joined on it.

use crate::audit::{CallScope, Notes};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
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
    /// `optional` mode: why a caller that presented a credential is
    /// `anonymous` (see `agent::Identity::auth_note`).
    pub auth_note: Option<String>,
    /// When the call started, for `duration_ms`.
    pub started: Instant,
    /// The client's `User-Agent` (HTTP only), for the audit record.
    pub user_agent: Option<String>,
    /// The raw call as the client sent it (tool name and arguments), set
    /// by `Prompto::call_tool`. `None` outside an MCP tool call (`/log`,
    /// unit tests).
    pub call: Option<CallScope>,
    /// What authorization found out, for the audit record: filled in by
    /// `authz` and the policy, read by `finish_tool`.
    pub notes: Arc<Mutex<Notes>>,
    /// `POST /v1/precheck`: authorize as for the real call, but change
    /// nothing — a ticket presented is checked, its nonce not spent.
    pub dry_run: bool,
}

impl CallCtx {
    /// A fresh context with a new request ID, starting now.
    pub fn new(caller_ip: Option<IpAddr>) -> Self {
        Self {
            request_id: Ulid::generate(),
            caller_ip,
            agent: None,
            session_id: None,
            auth_note: None,
            started: Instant::now(),
            user_agent: None,
            call: None,
            notes: Default::default(),
            dry_run: false,
        }
    }

    /// Update the audit notes.
    pub fn note(&self, f: impl FnOnce(&mut Notes)) {
        // A poisoned lock only means another note panicked; the data is
        // plain values and still usable.
        let mut n = self.notes.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut n);
    }

    /// A copy of the audit notes.
    pub fn notes(&self) -> Notes {
        self.notes.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Attach the caller's identity (agent and session).
    pub fn with_identity(mut self, id: crate::agent::Identity) -> Self {
        self.agent = id.agent;
        self.session_id = id.session_id;
        self.auth_note = id.auth_note;
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
