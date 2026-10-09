//! prompto — bootstrap, transport selection, SIGHUP-driven inventory,
//! agents and policy reload, and the `gain` / `agent` / `policy` CLI
//! subcommands.

use anyhow::{Context, Result};
use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode, Identity};
use prompto::baselines::BASELINES;
use prompto::caller;
use prompto::inventory::InventoryStore;
use prompto::mcp::Prompto;
use prompto::policy::{Policy, PolicyStore};
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
    pub policy_path: PathBuf,
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
            policy_path: env_or("PROMPTO_POLICY", "/etc/prompto/policy.toml").into(),
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

/// Policy and the files it is checked against, for the SIGHUP lint.
/// Present only when auth is on.
#[derive(Clone)]
struct PolicyReload {
    policy: PolicyStore,
    agents: AgentStore,
}

/// Log `policy lint` findings against the live inventory and agents. A
/// finding never stops the server: the policy still loads, and whatever
/// it references that doesn't exist simply grants nothing.
fn log_policy_lint(policy: &Policy, inv: &prompto::inventory::Inventory, agents: &Agents) {
    let tools = Prompto::tool_names();
    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    for f in prompto::policy::lint(policy, inv, agents, &tools) {
        match f.level {
            prompto::policy::Level::Error => {
                tracing::error!(rule = %f.rule, "policy lint: {}", f.message)
            }
            prompto::policy::Level::Warning => {
                tracing::warn!(rule = %f.rule, "policy lint: {}", f.message)
            }
        }
    }
}

/// Startup/reload warnings that make a deny-all policy loud.
fn warn_if_deny_all(policy: &Policy, mode: AuthMode) {
    if let Some(bad) = &policy.invalid {
        tracing::error!(
            since = %bad.since,
            error = %bad.error,
            auth = mode.as_str(),
            "POLICY FILE INVALID — every tool call is DENIED (refused_policy) until a valid \
             file is loaded and the server is reloaded"
        );
    } else if let Some(path) = &policy.missing {
        tracing::warn!(
            path = %path.display(),
            auth = mode.as_str(),
            "POLICY FILE MISSING — every tool call is DENIED (refused_policy) until it \
             exists and the server is reloaded"
        );
    } else if policy.rules.is_empty() {
        tracing::warn!(
            auth = mode.as_str(),
            "policy has no rules — every tool call is DENIED (refused_policy)"
        );
    }
}

/// SIGHUP re-reads the inventory, and — only when auth is on (`policy`
/// is `None` with `PROMPTO_AUTH=off`) — `agents.toml` and `policy.toml`,
/// independently, without one blocking the others. A bad inventory or
/// agents file keeps its previous version live and logs why; a bad
/// policy file fails closed (deny-all, see `PolicyStore::reload`). The
/// policy is then linted against whatever is now live.
#[cfg(unix)]
fn spawn_sighup_reloader(store: InventoryStore, policy: Option<PolicyReload>, mode: AuthMode) {
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
            let Some(p) = &policy else { continue };
            match p.agents.reload() {
                Ok(n) => tracing::info!(agent_count = n, "agents reloaded on SIGHUP"),
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "agents reload failed — keeping previous")
                }
            }
            match p.policy.reload() {
                Ok(n) => tracing::info!(rule_count = n, "policy reloaded on SIGHUP"),
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "policy reload failed — DENYING every call until a valid file is loaded")
                }
            }
            let live = p.policy.snapshot();
            warn_if_deny_all(&live, mode);
            log_policy_lint(&live, &store.snapshot(), &p.agents.snapshot());
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
fn spawn_sighup_reloader(_store: InventoryStore, _policy: Option<PolicyReload>, _mode: AuthMode) {}

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
                "agent {name:?} added. Its token went to stdout, ONCE, and is not stored \
                 anywhere — save it now (e.g. ~/.config/prompto/token, mode 0600)."
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

const POLICY_USAGE: &str = "\
Usage: prompto policy check --agent <name> [--host <host>] --tool <tool> [--sudo]
                                         dry-run one call: decision + deciding rule
       prompto policy lint               check policy.toml against the inventory,
                                         agents.toml and the tool list

Reads $PROMPTO_POLICY (default /etc/prompto/policy.toml), $PROMPTO_INVENTORY
and $PROMPTO_AGENTS. `check` exits 0 when the call would be allowed, 1 when
refused; `lint` exits 1 when it finds errors.";

/// `prompto policy …`: offline view of what the server would decide.
/// Returns the process exit code.
fn run_policy_cli(cfg: &Config, args: &[String]) -> Result<i32> {
    use prompto::authz;
    use prompto::policy::{self, Outcome, Request, Subject, Target};

    let load = || -> Result<(Policy, prompto::inventory::Inventory, Agents)> {
        let p = Policy::from_path(&cfg.policy_path)?;
        let inv = prompto::inventory::Inventory::from_path(&cfg.inventory_path)?;
        let agents = Agents::from_path(&cfg.agents_path)?;
        Ok((p, inv, agents))
    };
    let tools = Prompto::tool_names();
    if AuthMode::parse(&env_or("PROMPTO_AUTH", "off")).ok() == Some(AuthMode::Off) {
        eprintln!(
            "note: PROMPTO_AUTH is off here — a server with this environment does not \
             load or enforce policy."
        );
    }
    match args.first().map(String::as_str) {
        Some("check") => {
            let (mut agent, mut host, mut tool, mut sudo) = (None, None, None, false);
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                let mut val = |flag: &str| -> Result<String> {
                    Ok(it
                        .next()
                        .with_context(|| format!("{flag} requires a value"))?
                        .clone())
                };
                match a.as_str() {
                    "--agent" => agent = Some(val("--agent")?),
                    "--host" => host = Some(val("--host")?),
                    "--tool" => tool = Some(val("--tool")?),
                    "--sudo" => sudo = true,
                    other => anyhow::bail!("unexpected argument {other:?}\n{POLICY_USAGE}"),
                }
            }
            let agent = agent.with_context(|| format!("--agent is required\n{POLICY_USAGE}"))?;
            let tool = tool.with_context(|| format!("--tool is required\n{POLICY_USAGE}"))?;
            if !tools.contains(&tool) {
                anyhow::bail!("unknown tool {tool:?}");
            }
            let root = if authz::ROOT_TOOLS.contains(&tool.as_str()) {
                true
            } else if sudo && !authz::SUDO_FLAG_TOOLS.contains(&tool.as_str()) {
                anyhow::bail!(
                    "{tool} has no sudo variant (--sudo applies to: {})",
                    authz::SUDO_FLAG_TOOLS.join(", ")
                );
            } else {
                sudo
            };
            let (p, inv, agents) = load()?;
            let hostless = authz::HOSTLESS_TOOLS.contains(&tool.as_str());
            let target = match (&host, hostless) {
                (Some(h), false) => {
                    let canon = inv
                        .canonical(h)
                        .with_context(|| format!("unknown host {h:?}"))?;
                    Some(Target::of(canon, inv.get(canon)?))
                }
                (None, false) => anyhow::bail!("{tool} targets a host: --host is required"),
                (Some(_), true) => anyhow::bail!("{tool} targets no host: drop --host"),
                (None, true) => None,
            };
            if !matches!(
                agent.as_str(),
                prompto::agent::ANONYMOUS | prompto::agent::LOCAL
            ) && !agents.agents.contains_key(&agent)
            {
                anyhow::bail!(
                    "unknown agent {agent:?} (not in {})",
                    cfg.agents_path.display()
                );
            }
            let groups = match policy::agent_groups(&agents, &agent) {
                Ok(g) => g,
                Err(msg) => {
                    println!("DENY  rule={}\n{msg}", policy::DEFAULT_DENY);
                    return Ok(1);
                }
            };
            let d = p.decide(&Request {
                agent: Subject {
                    name: &agent,
                    groups: &groups,
                },
                host: target,
                tool: &tool,
                root,
            });
            let verdict = match d.outcome {
                Outcome::Allow => "ALLOW",
                Outcome::ApprovalRequired(_) => "APPROVAL_REQUIRED (refused until tickets ship)",
                Outcome::Deny => "DENY",
            };
            println!("{verdict}  rule={}\n{}", d.rule, d.message);
            eprintln!(
                "(policy only: host capability and the self-target guard are checked too \
                 at call time, before policy)"
            );
            Ok(if d.outcome == Outcome::Allow { 0 } else { 1 })
        }
        Some("lint") if args.len() == 1 => {
            let (p, inv, agents) = load()?;
            let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
            let findings = policy::lint(&p, &inv, &agents, &tools);
            if let Some(path) = &p.missing {
                println!(
                    "warning: {} does not exist — every call is denied",
                    path.display()
                );
            }
            for f in &findings {
                println!("{f}");
            }
            let errors = findings
                .iter()
                .filter(|f| f.level == policy::Level::Error)
                .count();
            eprintln!(
                "{} rules, {errors} errors, {} warnings",
                p.rules.len(),
                findings.len() - errors
            );
            Ok(if errors > 0 { 1 } else { 0 })
        }
        Some("--help" | "-h" | "help") => {
            println!("{POLICY_USAGE}");
            Ok(0)
        }
        _ => anyhow::bail!("{POLICY_USAGE}"),
    }
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
    if raw_args.len() >= 2 && raw_args[1] == "policy" {
        let code = run_policy_cli(&cfg, &raw_args[2..])?;
        std::process::exit(code);
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
    // Off must not depend on agents.toml: an unreadable or malformed file
    // would otherwise stop a box that doesn't use it. It isn't read at
    // all, and SIGHUP leaves it alone. In optional/required a load failure
    // at startup is fatal.
    let agents = if auth_mode == AuthMode::Off {
        if cfg.agents_path.exists() {
            tracing::info!(
                path = %cfg.agents_path.display(),
                "PROMPTO_AUTH=off — agents file ignored"
            );
        }
        None
    } else {
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
        Some(agents)
    };
    // Policy follows agents.toml: not read at all with off (prod stays
    // exactly as before E3), enforced otherwise. A missing file means deny
    // everything — loudly; a malformed one stops the server.
    let policy = if auth_mode == AuthMode::Off {
        if cfg.policy_path.exists() {
            tracing::info!(
                path = %cfg.policy_path.display(),
                "PROMPTO_AUTH=off — policy file ignored"
            );
        }
        None
    } else {
        let policy = PolicyStore::load_from(cfg.policy_path.clone())
            .with_context(|| format!("loading policy from {}", cfg.policy_path.display()))?;
        let live = policy.snapshot();
        tracing::info!(
            rule_count = live.rules.len(),
            path = %cfg.policy_path.display(),
            "policy loaded"
        );
        warn_if_deny_all(&live, auth_mode);
        let agents = agents.clone().unwrap_or_default();
        log_policy_lint(&live, &store.snapshot(), &agents.snapshot());
        Some(policy)
    };
    let reload = match (&agents, &policy) {
        (Some(a), Some(p)) => Some(PolicyReload {
            policy: p.clone(),
            agents: a.clone(),
        }),
        _ => None,
    };
    spawn_sighup_reloader(store.clone(), reload, auth_mode);

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
    let auth = AuthConfig {
        mode: auth_mode,
        store: agents.unwrap_or_default(),
        policy: policy.unwrap_or_default(),
    };

    if stdio_mode {
        tracing::info!("transport: stdio");
        // Whoever can talk to our stdin launched us: agent `local`.
        // Policy applies to `local` like to any agent when auth is on.
        let service = prompto
            .with_identity(Identity::local())
            .with_policy(auth.enforcer())
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
            auth,
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
