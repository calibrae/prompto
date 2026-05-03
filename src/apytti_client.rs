//! Thin HTTP client for [apytti](../../apytti).
//!
//! apytti is a stateless gateway over `claude -p` (and other AI CLIs).
//! prompto POSTs an `AskRequest` and gets back a `Response` with the
//! final agent text plus session metadata. No auth — apytti rides the
//! local CLI's existing login; prompto talks to it over the homelab
//! LAN.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct AskRequest<'a> {
    pub prompt: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AskResponse {
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct ApyttiClient {
    base_url: String,
    http: reqwest::Client,
}

impl ApyttiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn ask(&self, req: AskRequest<'_>, total_timeout: Duration) -> Result<AskResponse> {
        let url = format!("{}/api/ask", self.base_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .timeout(total_timeout)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("apytti returned {status}: {}", body.trim());
        }
        let parsed: AskResponse = resp.json().await.context("parse apytti response")?;
        if let Some(err) = &parsed.error {
            anyhow::bail!("apytti reported error: {err}");
        }
        Ok(parsed)
    }
}
