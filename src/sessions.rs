//! Legacy MCP sessions bound to the agent that created them.
//!
//! With `PROMPTO_LEGACY_SESSION_MODE=true`, rmcp builds one `Prompto` per
//! session and the factory snapshots the caller's identity at session
//! creation. Later requests carrying that `Mcp-Session-Id` are routed into
//! the existing instance, so without a check they would run as the
//! creator whatever token they present. [`BoundSessionManager`] records
//! who created each session; the auth middleware refuses a request whose
//! resolved agent is someone else (see [`SessionOwners::check`]).
//!
//! In stateless mode (the default) no session is ever created and the map
//! stays empty.

use crate::agent::{self, Identity};
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::session::{
    EventStore, RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The agent name a session was created by, keyed by session ID. `None`
/// is `PROMPTO_AUTH=off`, where nobody is identified.
#[derive(Clone, Default)]
pub struct SessionOwners(Arc<Mutex<HashMap<String, Option<String>>>>);

/// The name part of an identity — what a session is bound to.
fn owner_of(id: &Identity) -> Option<String> {
    id.agent.as_ref().map(|a| a.name.clone())
}

impl SessionOwners {
    fn insert(&self, session: &SessionId, owner: Option<String>) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session.to_string(), owner);
    }

    fn remove(&self, session: &SessionId) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session.as_ref());
    }

    /// May `who` use `session`? An unknown session is allowed through —
    /// rmcp answers it with its own "session not found". Otherwise the
    /// agent name must match the creator's exactly; `anonymous` is a name
    /// like any other, so an anonymous caller cannot ride an agent's
    /// session and vice versa.
    pub fn check(&self, session: &str, who: &Identity) -> bool {
        match self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session)
        {
            None => true,
            Some(owner) => *owner == owner_of(who),
        }
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A session ID shortened for logs: enough to correlate, not enough to
/// replay (the ID is a bearer handle to someone's session).
pub fn redact(session: &str) -> String {
    let head: String = session.chars().take(8).collect();
    format!("{head}…")
}

/// [`LocalSessionManager`] plus creator bookkeeping. rmcp calls
/// `create_session` inline in the initialize request's future, inside the
/// auth middleware's scope, so [`agent::current`] is the creator.
/// `close_session` runs on DELETE and when the session worker exits (idle
/// timeout included), which keeps the map from growing.
pub struct BoundSessionManager {
    inner: LocalSessionManager,
    owners: SessionOwners,
}

impl BoundSessionManager {
    pub fn new(inner: LocalSessionManager, owners: SessionOwners) -> Self {
        Self { inner, owners }
    }
}

impl SessionManager for BoundSessionManager {
    type Error = <LocalSessionManager as SessionManager>::Error;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        self.owners.insert(&id, owner_of(&agent::current()));
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<rmcp::model::ServerJsonRpcMessage, Self::Error> {
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.owners.remove(id);
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<
        impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static,
        Self::Error,
    > {
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<
        impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static,
        Self::Error,
    > {
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<
        impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static,
        Self::Error,
    > {
        self.inner.resume(id, last_event_id).await
    }

    // No session store is configured, so this is NotSupported today; a
    // restored session would have no recorded owner and pass `check`
    // unbound, hence it is refused here rather than delegated.
    async fn restore_session(
        &self,
        _id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        Ok(RestoreOutcome::NotSupported)
    }

    fn event_store(&self) -> Option<Arc<dyn EventStore>> {
        self.inner.event_store()
    }
}
