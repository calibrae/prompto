//! prompto — bootstrap, transport selection, SIGHUP-driven inventory reload,
//! and the `gain` CLI subcommand.

use anyhow::{Context, Result};
use mcp_gain::Tracker;
use prompto::baselines::BASELINES;
use prompto::inventory::InventoryStore;
use prompto::mcp::Prompto;
use prompto::ssh::SshClient;
use rmcp::{
    ServiceExt,
    transport::{
        stdio,
        streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        },
    },
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub inventory_path: PathBuf,
    pub bind: String,
    pub ssh_bin: PathBuf,
    pub default_timeout: Duration,
    pub stop_vm_step: Duration,
    pub usage_log: PathBuf,
    pub gain_enabled: bool,
}

impl Config {
    fn from_env() -> Self {
        Self {
            inventory_path: env_or("PROMPTO_INVENTORY", "/etc/prompto.toml").into(),
            bind: env_or("PROMPTO_BIND", "0.0.0.0:6337"),
            ssh_bin: env_or("PROMPTO_SSH_BIN", "ssh").into(),
            default_timeout: Duration::from_secs(env_u64("PROMPTO_DEFAULT_TIMEOUT_SECS", 30)),
            stop_vm_step: Duration::from_secs(env_u64("PROMPTO_STOP_VM_STEP_SECS", 30)),
            usage_log: env_or("PROMPTO_USAGE_LOG", "/var/lib/prompto/usage.jsonl").into(),
            gain_enabled: env_bool("PROMPTO_GAIN_ENABLED", true),
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("prompto=info")),
        )
        .with_writer(std::io::stderr)
        .compact()
        .init();
}

#[cfg(unix)]
fn spawn_sighup_reloader(store: InventoryStore) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "failed to install SIGHUP handler — reloads disabled");
                return;
            }
        };
        while sig.recv().await.is_some() {
            match store.reload() {
                Ok(n) => tracing::info!(host_count = n, "inventory reloaded on SIGHUP"),
                Err(e) => tracing::error!(?e, "inventory reload failed — keeping previous"),
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reloader(_store: InventoryStore) {}

fn run_gain_cli(cfg: &Config, args: &[String]) -> Result<()> {
    let mut json = false;
    let mut since_secs: Option<u64> = None;
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--json" => json = true,
            "--since-secs" => {
                let v = iter
                    .next()
                    .context("--since-secs requires a value (seconds)")?;
                since_secs = Some(v.parse().context("--since-secs must be u64 seconds")?);
            }
            other if other.starts_with("--since-secs=") => {
                since_secs = Some(
                    other
                        .trim_start_matches("--since-secs=")
                        .parse()
                        .context("--since-secs must be u64 seconds")?,
                );
            }
            "--help" | "-h" => {
                println!("Usage: prompto gain [--since-secs N] [--json]");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other:?} for `gain`"),
        }
    }
    let tracker = Tracker::new(cfg.usage_log.clone(), true, BASELINES);
    let cutoff = since_secs.map(|s| chrono::Utc::now() - chrono::Duration::seconds(s as i64));
    let summary = tracker.summary(cutoff)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print!(
            "{}",
            mcp_gain::render_text(&summary, &prompto::baselines::header())
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_env();
    let raw_args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch — `prompto gain` runs and exits before tracing /
    // server setup, so it doesn't fight with the running daemon for stderr
    // log noise.
    if raw_args.len() >= 2 && raw_args[1] == "gain" {
        return run_gain_cli(&cfg, &raw_args[2..]);
    }

    init_tracing();
    tracing::info!(?cfg, "prompto starting");

    let store = InventoryStore::load_from(cfg.inventory_path.clone())
        .with_context(|| format!("loading inventory from {}", cfg.inventory_path.display()))?;
    tracing::info!(
        host_count = store.snapshot().hosts.len(),
        "inventory loaded"
    );
    spawn_sighup_reloader(store.clone());

    let ssh = Arc::new(SshClient::new(cfg.ssh_bin.clone(), cfg.default_timeout));
    let tracker = Arc::new(Tracker::new(
        cfg.usage_log.clone(),
        cfg.gain_enabled,
        BASELINES,
    ));
    if cfg.gain_enabled {
        tracing::info!(path = %tracker.path().display(), "gain tracking enabled");
    }

    let prompto = Prompto::new(
        store.clone(),
        ssh.clone(),
        tracker.clone(),
        cfg.stop_vm_step,
    );

    let stdio_mode = raw_args.iter().any(|a| a == "--stdio");

    if stdio_mode {
        tracing::info!("transport: stdio");
        let service = prompto.serve(stdio()).await.context("stdio serve")?;
        service.waiting().await?;
    } else {
        tracing::info!("transport: streamable-http on {}", cfg.bind);
        let listener = tokio::net::TcpListener::bind(&cfg.bind)
            .await
            .with_context(|| format!("bind {}", cfg.bind))?;
        let cancel = CancellationToken::new();

        let mut http_config =
            StreamableHttpServerConfig::default().with_cancellation_token(cancel.child_token());
        match std::env::var("PROMPTO_ALLOWED_HOSTS") {
            Ok(raw) if raw.trim() == "*" => {
                tracing::warn!(
                    "PROMPTO_ALLOWED_HOSTS=* — DNS rebinding protection DISABLED. Ensure the listener is behind a trusted reverse proxy or firewall."
                );
                http_config = http_config.disable_allowed_hosts();
            }
            Ok(raw) => {
                let hosts: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                tracing::info!(?hosts, "Host header allowlist");
                http_config = http_config.with_allowed_hosts(hosts);
            }
            Err(_) => {
                tracing::info!(
                    "Host header allowlist defaults to localhost — set PROMPTO_ALLOWED_HOSTS to accept remote clients."
                );
            }
        }

        let stop_vm_step = cfg.stop_vm_step;
        let service = StreamableHttpService::new(
            move || {
                Ok(Prompto::new(
                    store.clone(),
                    ssh.clone(),
                    tracker.clone(),
                    stop_vm_step,
                ))
            },
            LocalSessionManager::default().into(),
            http_config,
        );

        let app = axum::Router::new().nest_service("/mcp", service);

        let cancel_for_signal = cancel.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_for_signal.cancel();
        });

        axum::serve(listener, app)
            .with_graceful_shutdown(async move { cancel.cancelled().await })
            .await
            .context("http serve")?;
    }

    Ok(())
}
