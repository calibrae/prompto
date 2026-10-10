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
use std::path::Path;
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
    /// Client trusting only the bundled webpki roots.
    pub fn new(
        addr: impl Into<String>,
        mount: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        let http = http_client(&[]).expect("reqwest client");
        Self::with_http(addr, mount, token, http)
    }

    /// Client that additionally trusts every certificate in the PEM file
    /// at `cacert` — for a Vault behind a private CA. An unreadable file,
    /// or one holding no usable certificate, is an error: falling back to
    /// the bundled roots would only fail later as "vault unreachable".
    pub fn with_cacert(
        addr: impl Into<String>,
        mount: impl Into<String>,
        token: impl Into<String>,
        cacert: &Path,
    ) -> Result<Self> {
        let pem = std::fs::read(cacert)
            .with_context(|| format!("cannot read vault CA file {}", cacert.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("invalid PEM in vault CA file {}", cacert.display()))?;
        if certs.is_empty() {
            bail!(
                "vault CA file {} contains no PEM certificate",
                cacert.display()
            );
        }
        let http = http_client(&certs)
            .with_context(|| format!("vault CA file {} rejected", cacert.display()))?;
        Ok(Self::with_http(addr, mount, token, http))
    }

    fn with_http(
        addr: impl Into<String>,
        mount: impl Into<String>,
        token: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            addr: addr.into().trim_end_matches('/').to_string(),
            mount: mount.into().trim_matches('/').to_string(),
            token: token.into(),
            http,
        }
    }

    /// Build from `PROMPTO_VAULT_TOKEN` (required), `PROMPTO_VAULT_ADDR`
    /// (default `http://127.0.0.1:8200`), `PROMPTO_VAULT_MOUNT` (default
    /// `secret`) and `PROMPTO_VAULT_CACERT` (optional extra PEM roots).
    /// `Ok(None)` when no token is configured; `Err` when the CA file is
    /// set but unusable.
    pub fn from_env() -> Result<Option<Self>> {
        let Ok(token) = std::env::var("PROMPTO_VAULT_TOKEN") else {
            return Ok(None);
        };
        if token.trim().is_empty() {
            return Ok(None);
        }
        let addr = std::env::var("PROMPTO_VAULT_ADDR")
            .unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
        let mount = std::env::var("PROMPTO_VAULT_MOUNT").unwrap_or_else(|_| "secret".to_string());
        match std::env::var("PROMPTO_VAULT_CACERT") {
            Ok(ca) if !ca.trim().is_empty() => {
                Self::with_cacert(addr, mount, token.trim(), Path::new(ca.trim()))
                    .context("PROMPTO_VAULT_CACERT")
                    .map(Some)
            }
            _ => Ok(Some(Self::new(addr, mount, token.trim()))),
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// The same server and token on another KV v2 mount (the approval
    /// secrets' private mount, `crate::approval::PrivateVault`).
    pub fn with_mount(&self, mount: &str) -> Self {
        Self {
            addr: self.addr.clone(),
            mount: mount.trim_matches('/').to_string(),
            token: self.token.clone(),
            http: self.http.clone(),
        }
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

    /// Write a KV v2 secret (replacing every field at `path`). Used only
    /// by the CLI (`prompto approver add --vault-path`), with an operator
    /// token that may write; the server's token only reads.
    pub async fn kv2_put(&self, path: &str, data: serde_json::Value) -> Result<()> {
        let url = format!("{}/v1/{}/data/{}", self.addr, self.mount, path);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "data": data }))
            .send()
            .await
            .with_context(|| format!("vault unreachable at {}", self.addr))?;
        let status = resp.status();
        if !status.is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            bail!(
                "vault write of {path:?} failed ({status}): {}",
                body.get("errors").cloned().unwrap_or_default()
            );
        }
        Ok(())
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

fn http_client(extra_roots: &[reqwest::Certificate]) -> reqwest::Result<reqwest::Client> {
    extra_roots
        .iter()
        .fold(
            reqwest::Client::builder().timeout(Duration::from_secs(5)),
            |b, c| b.add_root_certificate(c.clone()),
        )
        .build()
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
    if p.split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
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
    use std::sync::Arc;

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
        assert_eq!(
            v.kv2_field("infra/default", "password").await.unwrap(),
            SECRET
        );
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
        let denied = format!(
            "{:#}",
            v.kv2_field("infra/forbidden", "password")
                .await
                .unwrap_err()
        );
        assert!(denied.contains("permission denied"), "{denied}");
    }

    /// TLS listener for axum: handshakes each connection before handing
    /// it over. Failed handshakes (an untrusting client) are dropped.
    struct TlsListener {
        tcp: tokio::net::TcpListener,
        tls: tokio_rustls::TlsAcceptor,
    }

    impl axum::serve::Listener for TlsListener {
        type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
        type Addr = std::net::SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                let Ok((tcp, addr)) = self.tcp.accept().await else {
                    continue;
                };
                if let Ok(tls) = self.tls.accept(tcp).await {
                    return (tls, addr);
                }
            }
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.tcp.local_addr()
        }
    }

    /// Fake Vault over HTTPS with a leaf signed by a freshly generated
    /// throwaway test CA. Returns the address and the CA as PEM.
    async fn spawn_tls_fake_vault() -> (String, String) {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let app = Router::new().route(
            "/v1/secret/data/infra/default",
            get(|| async {
                Json(serde_json::json!({ "data": { "data": { "password": SECRET } } }))
            }),
        );
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = TlsListener {
            tcp,
            tls: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        };
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        (format!("https://{addr}"), ca.pem())
    }

    /// A Vault on a private CA is unreachable with the bundled roots and
    /// reachable once that CA is supplied via a CA file.
    #[tokio::test]
    async fn private_ca_needs_cacert() {
        let (addr, ca_pem) = spawn_tls_fake_vault().await;

        let plain = VaultClient::new(&addr, "secret", "tok");
        let err = format!(
            "{:#}",
            plain
                .kv2_field("infra/default", "password")
                .await
                .unwrap_err()
        );
        assert!(err.contains("UnknownIssuer"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("test-only-throwaway-ca.pem");
        std::fs::write(&ca_file, ca_pem).unwrap();
        let trusting = VaultClient::with_cacert(&addr, "secret", "tok", &ca_file).unwrap();
        assert_eq!(
            trusting
                .kv2_field("infra/default", "password")
                .await
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn bad_cacert_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.pem");
        let err = format!(
            "{:#}",
            VaultClient::with_cacert("https://x", "secret", "tok", &missing).unwrap_err()
        );
        assert!(err.contains("cannot read vault CA file"), "{err}");

        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, "not a certificate\n").unwrap();
        let err = format!(
            "{:#}",
            VaultClient::with_cacert("https://x", "secret", "tok", &garbage).unwrap_err()
        );
        assert!(err.contains("no PEM certificate"), "{err}");

        let corrupt = dir.path().join("corrupt.pem");
        std::fs::write(
            &corrupt,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(VaultClient::with_cacert("https://x", "secret", "tok", &corrupt).is_err());
    }

    #[test]
    fn debug_redacts_token() {
        let v = VaultClient::new("http://x", "secret", "s.supersecrettoken");
        assert!(!format!("{v:?}").contains("supersecrettoken"));
    }

    #[test]
    fn kv_path_validation() {
        validate_kv_path("infra/default").unwrap();
        validate_kv_path("infra/router/sudo").unwrap();
        for bad in [
            "",
            "/infra/default",
            "infra/",
            "infra/../root",
            "infra//x",
            "a?b=c",
            "a b",
        ] {
            assert!(validate_kv_path(bad).is_err(), "accepted {bad:?}");
        }
    }
}
