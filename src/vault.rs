//! Minimal HashiCorp Vault client — read one KV v2 field, renew our token.
//!
//! Exists for one job: fetching a host's sudo password at call time so
//! prompto can run `sudo -S` on boxes that deliberately don't allow
//! passwordless sudo. The password is used inside prompto and handed to
//! the remote `sudo` over SSH stdin. It is never returned to the MCP
//! caller, never logged, and never placed in a command line where `ps`
//! could see it.
//!
//! Errors are written so they cannot carry a secret: they name the path,
//! the field and Vault's own error text, never a value.

use anyhow::{Context, Result, anyhow, bail};
use std::time::Duration;

pub struct VaultClient {
    addr: String,
    mount: String,
    token: String,
    http: reqwest::Client,
}

// Hand-written so the token can never end up in a `{:?}` log line.
impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("addr", &self.addr)
            .field("mount", &self.mount)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VaultClient {
    pub fn new(addr: impl Into<String>, mount: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            addr: addr.into().trim_end_matches('/').to_string(),
            mount: mount.into().trim_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
        }
    }

    /// Build from `PROMPTO_VAULT_TOKEN` (required), `PROMPTO_VAULT_ADDR`
    /// (default `http://127.0.0.1:8200`) and `PROMPTO_VAULT_MOUNT`
    /// (default `secret`). `None` when no token is configured.
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("PROMPTO_VAULT_TOKEN").ok()?;
        if token.trim().is_empty() {
            return None;
        }
        let addr = std::env::var("PROMPTO_VAULT_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
        let mount = std::env::var("PROMPTO_VAULT_MOUNT").unwrap_or_else(|_| "secret".to_string());
        Some(Self::new(addr, mount, token.trim()))
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Read one string field from a KV v2 secret.
    pub async fn kv2_field(&self, path: &str, field: &str) -> Result<String> {
        let url = format!("{}/v1/{}/data/{}", self.addr, self.mount, path);
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .with_context(|| format!("vault unreachable at {}", self.addr))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .with_context(|| format!("vault returned non-JSON for {path:?}"))?;
        if !status.is_success() {
            // Vault's error array is safe to surface ("permission denied",
            // "missing client token"); it never echoes secret data.
            bail!(
                "vault read of {path:?} failed ({status}): {}",
                body.get("errors").cloned().unwrap_or_default()
            );
        }
        let value = body
            .pointer("/data/data")
            .and_then(|d| d.get(field))
            .ok_or_else(|| anyhow!("vault secret {path:?} has no field {field:?}"))?;
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("vault field {path:?}/{field:?} is not a string"))
    }

    /// Renew our own token. Returns the new lease duration. A periodic
    /// token renewed inside its period never expires, which is what a
    /// long-running service needs.
    pub async fn renew_self(&self) -> Result<Duration> {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .with_context(|| format!("vault unreachable at {}", self.addr))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.context("vault renew-self: non-JSON")?;
        if !status.is_success() {
            bail!(
                "vault token renewal failed ({status}): {}",
                body.get("errors").cloned().unwrap_or_default()
            );
        }
        let secs = body
            .pointer("/auth/lease_duration")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(Duration::from_secs(secs))
    }
}

/// Shape check for a KV path from the inventory. Rejects anything that
/// could walk out of the mount or smuggle a query string.
pub fn validate_kv_path(p: &str) -> Result<()> {
    if p.is_empty() || p.len() > 256 {
        bail!("vault path must be 1..=256 chars");
    }
    if p.starts_with('/') || p.ends_with('/') {
        bail!("vault path {p:?} must not start or end with '/' (no mount prefix either)");
    }
    if p.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        bail!("vault path {p:?} has an empty, '.' or '..' segment");
    }
    if !p
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        bail!("vault path {p:?} may only contain [A-Za-z0-9/._-]");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, http::StatusCode, routing::get};

    const SECRET: &str = "hunter2-do-not-leak";

    /// Fake Vault: one KV v2 secret, plus a path that denies.
    async fn spawn_fake_vault() -> String {
        let app = Router::new()
            .route(
                "/v1/secret/data/infra/default",
                get(|| async {
                    Json(serde_json::json!({
                        "data": { "data": { "password": SECRET, "other": "x" } }
                    }))
                }),
            )
            .route(
                "/v1/secret/data/infra/forbidden",
                get(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({ "errors": ["permission denied"] })),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn reads_a_field() {
        let v = VaultClient::new(spawn_fake_vault().await, "secret", "tok");
        assert_eq!(v.kv2_field("infra/default", "password").await.unwrap(), SECRET);
    }

    /// No error path may carry a secret value — including the case where
    /// the secret exists but the requested field doesn't, where a lazy
    /// implementation would dump the whole map.
    #[tokio::test]
    async fn errors_never_contain_secret_values() {
        let v = VaultClient::new(spawn_fake_vault().await, "secret", "tok");
        for (path, field) in [
            ("infra/default", "nope"),
            ("infra/forbidden", "password"),
            ("infra/missing", "password"),
        ] {
            let err = format!("{:#}", v.kv2_field(path, field).await.unwrap_err());
            assert!(!err.contains(SECRET), "secret leaked into error: {err}");
        }
        let denied = format!("{:#}", v.kv2_field("infra/forbidden", "password").await.unwrap_err());
        assert!(denied.contains("permission denied"), "{denied}");
    }

    #[test]
    fn debug_redacts_token() {
        let v = VaultClient::new("http://x", "secret", "s.supersecrettoken");
        assert!(!format!("{v:?}").contains("supersecrettoken"));
    }

    #[test]
    fn kv_path_validation() {
        validate_kv_path("infra/default").unwrap();
        validate_kv_path("infra/opnsense/calisense").unwrap();
        for bad in ["", "/infra/default", "infra/", "infra/../root", "infra//x", "a?b=c", "a b"] {
            assert!(validate_kv_path(bad).is_err(), "accepted {bad:?}");
        }
    }
}
