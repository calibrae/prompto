//! prompto — bootstrap, transport selection, SIGHUP-driven inventory and
//! agents reload, and the `gain` / `agent` CLI subcommands.

use anyhow::{Context, Result};
use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode, Identity};
use prompto::baselines::BASELINES;
use prompto::caller;
use prompto::inventory::InventoryStore;
use prompto::mcp::Prompto;
use prompto::server::{AllowedHosts, HttpParams, build_router};
use prompto::ssh::SshClient;
use prompto::vault::VaultClient;
use rmcp::{ServiceExt, transport::stdio};
use std::net::SocketAddr;
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
    pub agents_path: PathBuf,
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
            agents_path: env_or("PROMPTO_AGENTS", "/etc/prompto/agents.toml").into(),
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

/// SIGHUP re-reads the inventory and `agents.toml`, independently: a bad
/// file keeps its previous version live and logs why, without blocking
/// the other.
#[cfg(unix)]
fn spawn_sighup_reloader(store: InventoryStore, agents: AgentStore) {
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
            match agents.reload() {
                Ok(n) => tracing::info!(agent_count = n, "agents reloaded on SIGHUP"),
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "agents reload failed — keeping previous")
                }
            }
        }
    });
}

/// Keep prompto's vault token alive. A periodic token renewed inside its
/// period never expires; this renews at half the lease, and backs off to
/// five minutes on failure so a vault restart doesn't strand us.
fn spawn_vault_renewal(vault: Arc<VaultClient>) {
    tokio::spawn(async move {
        loop {
            let next = match vault.renew_self().await {
                Ok(lease) => {
                    tracing::info!(lease_secs = lease.as_secs(), "vault token renewed");
                    (lease / 2).max(Duration::from_secs(60))
                }
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "vault token renewal failed; retrying in 5m");
                    Duration::from_secs(300)
                }
            };
            tokio::time::sleep(next).await;
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reloader(_store: InventoryStore, _agents: AgentStore) {}

const AGENT_USAGE: &str = "\
Usage: prompto agent add <name> [--groups a,b]   mint a token (printed once)
       prompto agent list                        list agents (hashes abbreviated)
       prompto agent revoke <name>               disable an agent's token

Edits $PROMPTO_AGENTS (default /etc/prompto/agents.toml). A running server
picks changes up on SIGHUP: systemctl reload prompto";

/// `prompto agent …`: edit `agents.toml`. Only the token's hash is ever
/// written; the token itself goes to stdout once, everything else to
/// stderr, so `prompto agent add x > token-file` captures just the token.
fn run_agent_cli(cfg: &Config, args: &[String]) -> Result<()> {
    let path = &cfg.agents_path;
    let reload_hint = || {
        eprintln!(
            "{} updated. Running servers keep the old list until reloaded: \
             `systemctl reload prompto` (or kill -HUP <pid>).",
            path.display()
        )
    };
    match args.first().map(String::as_str) {
        Some("add") => {
            let mut name = None;
            let mut groups = Vec::new();
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                let list = if a == "--groups" {
                    Some(it.next().context("--groups requires a value")?.as_str())
                } else {
                    a.strip_prefix("--groups=")
                };
                match list {
                    Some(l) => groups.extend(
                        l.split(',')
                            .map(str::trim)
                            .filter(|g| !g.is_empty())
                            .map(String::from),
                    ),
                    None if a.starts_with('-') || name.is_some() => {
                        anyhow::bail!("unexpected argument {a:?}\n{AGENT_USAGE}")
                    }
                    None => name = Some(a.clone()),
                }
            }
            let name = name.with_context(|| format!("agent add needs a name\n{AGENT_USAGE}"))?;
            let mut agents = Agents::from_path(path)?;
            let token = prompto::agent::add_agent(&mut agents, &name, groups)?;
            prompto::agent::write_atomic(path, &agents.to_toml_string()?)?;
            println!("{token}");
            eprintln!(
                "agent {name:?} added. The token above is shown ONCE and is not stored — \
                 save it now (e.g. in ~/.config/prompto/token, mode 0600)."
            );
            reload_hint();
        }
        Some("list") if args.len() == 1 => {
            let agents = Agents::from_path(path)?;
            if agents.agents.is_empty() {
                eprintln!("no agents in {}", path.display());
            }
            println!(
                "{:<24} {:<8} {:<24} {:<21} TOKEN",
                "NAME", "STATUS", "GROUPS", "CREATED"
            );
            for (name, e) in &agents.agents {
                println!(
                    "{:<24} {:<8} {:<24} {:<21} sha256:{}…",
                    name,
                    if e.disabled { "revoked" } else { "active" },
                    if e.groups.is_empty() {
                        "-".to_string()
                    } else {
                        e.groups.join(",")
                    },
                    e.created.as_deref().unwrap_or("-"),
                    &e.token_sha256[..8],
                );
            }
        }
        Some("revoke") if args.len() == 2 => {
            let name = &args[1];
            let mut agents = Agents::from_path(path)?;
            if prompto::agent::revoke_agent(&mut agents, name)? {
                prompto::agent::write_atomic(path, &agents.to_toml_string()?)?;
                eprintln!("agent {name:?} revoked (disabled = true).");
                reload_hint();
            } else {
                eprintln!("agent {name:?} was already revoked; nothing changed.");
            }
        }
        Some("--help" | "-h" | "help") => println!("{AGENT_USAGE}"),
        _ => anyhow::bail!("{AGENT_USAGE}"),
    }
    Ok(())
}

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
    if raw_args.len() >= 2 && raw_args[1] == "agent" {
        return run_agent_cli(&cfg, &raw_args[2..]);
    }

    init_tracing();
    tracing::info!(?cfg, "prompto starting");

    let store = InventoryStore::load_from(cfg.inventory_path.clone())
        .with_context(|| format!("loading inventory from {}", cfg.inventory_path.display()))?;
    tracing::info!(
        host_count = store.snapshot().hosts.len(),
        "inventory loaded"
    );
    // Read before anything else can fail late: a typo such as
    // `requried` must stop the server, not silently mean "off".
    let auth_mode = AuthMode::parse(&env_or("PROMPTO_AUTH", "off"))?;
    let agents = AgentStore::load_from(cfg.agents_path.clone())
        .with_context(|| format!("loading agents from {}", cfg.agents_path.display()))?;
    let agent_count = agents.snapshot().agents.len();
    tracing::info!(
        auth = auth_mode.as_str(),
        agent_count,
        path = %cfg.agents_path.display(),
        "agent tokens loaded"
    );
    if auth_mode == AuthMode::Required && agent_count == 0 {
        tracing::warn!(
            "PROMPTO_AUTH=required with no agents — every HTTP request will get 401 \
             until `prompto agent add` + SIGHUP"
        );
    }
    spawn_sighup_reloader(store.clone(), agents.clone());

    let mut ssh_client = SshClient::new(cfg.ssh_bin.clone(), cfg.default_timeout);
    let needs_vault: Vec<String> = store
        .snapshot()
        .hosts
        .iter()
        .filter(|(_, h)| h.sudo_password_vault_path.is_some())
        .map(|(n, _)| n.clone())
        .collect();
    match VaultClient::from_env()? {
        Some(vault) => {
            let vault = Arc::new(vault);
            tracing::info!(addr = %vault.addr(), hosts = ?needs_vault, "vault-backed sudo enabled");
            spawn_vault_renewal(vault.clone());
            ssh_client = ssh_client.with_vault(vault);
        }
        None if !needs_vault.is_empty() => tracing::warn!(
            hosts = ?needs_vault,
            "these hosts declare sudo_password_vault_path but PROMPTO_VAULT_TOKEN is unset — \
             their sudo calls will fail until it is configured"
        ),
        None => {}
    }
    let ssh = Arc::new(ssh_client);
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
        // Whoever can talk to our stdin launched us: agent `local`.
        let service = prompto
            .with_identity(Identity::local())
            .serve(stdio())
            .await
            .context("stdio serve")?;
        service.waiting().await?;
    } else {
        tracing::info!("transport: streamable-http on {}", cfg.bind);
        let listener = tokio::net::TcpListener::bind(&cfg.bind)
            .await
            .with_context(|| format!("bind {}", cfg.bind))?;
        let cancel = CancellationToken::new();

        // Peers allowed to speak for someone else via X-Real-IP /
        // X-Forwarded-For. Defaults to loopback because prompto binds
        // 127.0.0.1 behind nginx on the same host. Anything not on this
        // list has its forwarding headers ignored outright.
        let trusted_proxies = Arc::new(
            std::env::var("PROMPTO_TRUSTED_PROXIES")
                .ok()
                .and_then(|raw| caller::parse_trusted_proxies(&raw))
                .unwrap_or_else(|| caller::DEFAULT_TRUSTED_PROXIES.to_vec()),
        );
        tracing::info!(
            trusted_proxies = ?trusted_proxies,
            "forwarding headers honoured only from these peers"
        );

        let allowed_hosts = match std::env::var("PROMPTO_ALLOWED_HOSTS") {
            Ok(raw) if raw.trim() == "*" => {
                tracing::warn!(
                    "PROMPTO_ALLOWED_HOSTS=* — DNS rebinding protection DISABLED. Ensure the listener is behind a trusted reverse proxy or firewall."
                );
                AllowedHosts::Disabled
            }
            Ok(raw) => {
                let hosts: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                tracing::info!(?hosts, "Host header allowlist");
                AllowedHosts::List(hosts)
            }
            Err(_) => {
                tracing::info!(
                    "Host header allowlist defaults to localhost — set PROMPTO_ALLOWED_HOSTS to accept remote clients."
                );
                AllowedHosts::Default
            }
        };

        // Sessionless by default — see HttpParams::legacy_session_mode.
        let legacy_session_mode = env_bool("PROMPTO_LEGACY_SESSION_MODE", false);
        tracing::info!(
            legacy_session_mode,
            "pre-2026-07-28 clients served {}",
            if legacy_session_mode {
                "via legacy sessions"
            } else {
                "statelessly (no Mcp-Session-Id; survives redeploys)"
            }
        );

        // `optional` still serves anonymous callers, so /log stays open.
        if auth_mode != AuthMode::Required {
            tracing::warn!(
                auth = auth_mode.as_str(),
                "GET /log is UNAUTHENTICATED — anyone who can reach this listener can read \
                 journals on any inventory host granting sudo_exec. Same limits as the \
                 service_logs tool (sudo_exec gate, unit-name validation, 1..1000 lines), \
                 but no credential is required."
            );
        }

        let app = build_router(HttpParams {
            store,
            ssh,
            tracker,
            stop_vm_step: cfg.stop_vm_step,
            trusted_proxies,
            allowed_hosts,
            legacy_session_mode,
            auth: AuthConfig {
                mode: auth_mode,
                store: agents,
            },
            cancel: cancel.clone(),
        });

        let cancel_for_signal = cancel.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_for_signal.cancel();
        });

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
        .context("http serve")?;
    }

    Ok(())
}
