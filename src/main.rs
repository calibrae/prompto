//! prompto — bootstrap, transport selection, SIGHUP-driven inventory,
//! agents and policy reload, and the `gain` / `agent` / `policy` /
//! `audit` CLI subcommands.

use anyhow::{Context, Result};
use mcp_gain::Tracker;
use prompto::agent::{AgentStore, Agents, AuthConfig, AuthMode, Identity};
use prompto::approval::{ApprovalConfig, Approvals};
use prompto::audit::{self, Audit, AuditLog};
use prompto::baselines::BASELINES;
use prompto::caller;
use prompto::inventory::InventoryStore;
use prompto::kill::{KillSwitch, Scope as KillScope};
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
    pub audit_path: PathBuf,
    /// `PROMPTO_AUDIT_GROUP`: group for an audit file prompto creates.
    pub audit_group: Option<String>,
    /// `PROMPTO_KILL_FILE` / `PROMPTO_KILL_DIR`.
    pub kill: KillSwitch,
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
            audit_path: env_or("PROMPTO_AUDIT_LOG", audit::DEFAULT_PATH).into(),
            audit_group: std::env::var("PROMPTO_AUDIT_GROUP")
                .ok()
                .filter(|g| !g.trim().is_empty()),
            kill: KillSwitch::from_env(),
        }
    }
}

/// Logs go to stderr (journald captures them under systemd). Audit
/// records (`audit::TARGET`) are always kept at info, whatever
/// `RUST_LOG` says. Under systemd (`JOURNAL_STREAM` set) they go to the
/// journal natively instead, as structured fields prefixed `AUDIT_`
/// (`journalctl AUDIT_AGENT=dev AUDIT_DECISION=deny`), and are left out
/// of the stderr stream so they aren't logged twice.
fn init_tracing() {
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::prelude::*;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("prompto=info"))
        .add_directive(
            format!("{}=info", audit::TARGET)
                .parse()
                .expect("static directive"),
        );
    let stderr = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .compact();
    let journald = std::env::var_os("JOURNAL_STREAM")
        .and_then(|_| tracing_journald::layer().ok())
        .map(|j| j.with_field_prefix(Some("AUDIT".into())));
    match journald {
        Some(j) => tracing_subscriber::registry()
            .with(filter)
            .with(stderr.with_filter(filter_fn(|m| m.target() != audit::TARGET)))
            .with(j.with_filter(filter_fn(|m| m.target() == audit::TARGET)))
            .init(),
        None => tracing_subscriber::registry()
            .with(filter)
            .with(stderr)
            .init(),
    }
}

/// Open the audit log. With auth on it is strict, and a log that can't
/// be opened stops the server: it would refuse every call anyway. With
/// auth off a failure only warns; records go to the journal until the
/// file can be written (each write retries).
fn open_audit(cfg: &Config, mode: AuthMode) -> Result<Audit> {
    let strict = mode != AuthMode::Off;
    let gid = match &cfg.audit_group {
        None => None,
        Some(g) => match audit::resolve_group(g) {
            Ok(gid) => Some(gid),
            Err(e) if strict => {
                return Err(e).with_context(|| format!("PROMPTO_AUDIT_GROUP={g}"));
            }
            Err(e) => {
                tracing::warn!(group = %g, error = %e, "PROMPTO_AUDIT_GROUP ignored");
                None
            }
        },
    };
    let path = cfg.audit_path.clone();
    let log = match AuditLog::open(path.clone(), gid, strict) {
        Ok(log) => log,
        Err(e) if strict => {
            return Err(e).with_context(|| {
                format!(
                    "opening the audit log {} (PROMPTO_AUTH={} refuses every call it \
                     cannot record)",
                    path.display(),
                    mode.as_str()
                )
            });
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "cannot open the audit log — PROMPTO_AUTH=off, so calls continue; records go \
                 to the journal until it can be written"
            );
            AuditLog::unopened(path.clone(), gid, strict)
        }
    };
    tracing::info!(
        path = %path.display(),
        strict,
        "audit log: every tool call is recorded{}",
        if strict {
            "; a call that can't be recorded is refused"
        } else {
            ""
        }
    );
    Ok(Audit::new(log))
}

/// Policy and the files it is checked against, for the SIGHUP lint.
/// Present only when auth is on.
#[derive(Clone)]
struct PolicyReload {
    policy: PolicyStore,
    agents: AgentStore,
    /// Ticket keys are re-read on SIGHUP too (and every minute).
    approvals: Approvals,
}

/// Log `policy lint` findings against the live inventory and agents. A
/// finding never stops the server: the policy still loads, and whatever
/// it references that doesn't exist simply grants nothing.
fn log_policy_lint(policy: &Policy, inv: &prompto::inventory::Inventory, agents: &Agents) {
    let tools = Prompto::tool_names();
    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    let service_user = prompto::policy::service_user_from_env();
    for f in prompto::policy::lint(policy, inv, agents, &tools, &service_user) {
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
             file is written (re-read on the next call, or on SIGHUP)"
        );
    } else if let Some(path) = &policy.missing {
        tracing::warn!(
            path = %path.display(),
            auth = mode.as_str(),
            "POLICY FILE MISSING — every tool call is DENIED (refused_policy) until it \
             exists (re-read on the next call, or on SIGHUP)"
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
                    tracing::error!(error = %format!("{e:#}"), "agents reload failed — REFUSING every agent token until a valid file is read")
                }
            }
            match p.policy.reload() {
                Ok(n) => tracing::info!(rule_count = n, "policy reloaded on SIGHUP"),
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "policy reload failed — DENYING every call until a valid file is loaded")
                }
            }
            let approvals = p.approvals.clone();
            tokio::spawn(async move {
                if approvals.configured() && approvals.load_keys().await.is_ok() {
                    tracing::info!("ticket keys re-read on SIGHUP");
                }
            });
            let live = p.policy.snapshot();
            warn_if_deny_all(&live, mode);
            log_policy_lint(&live, &store.snapshot(), &p.agents.snapshot());
        }
    });
}

/// Tickets and approvals (E6), when a ticket key source is configured
/// and auth is on (with `off` there is no policy, so nothing to approve).
/// Never fatal: a key that can't be read now is retried every minute,
/// and only calls that need a ticket wait for it.
async fn open_approvals(
    mode: AuthMode,
    vault: Option<Arc<VaultClient>>,
    inv: &prompto::inventory::Inventory,
) -> Approvals {
    let Some(cfg) = ApprovalConfig::from_env() else {
        return Approvals::default();
    };
    if mode == AuthMode::Off {
        tracing::info!("PROMPTO_AUTH=off — ticket key settings ignored (no policy, no approvals)");
        return Approvals::default();
    }
    tracing::info!(
        key_vault_path = cfg.key_vault_path.as_deref(),
        key_file = cfg.key_file.as_ref().map(|p| p.display().to_string()),
        approvers = %cfg.approvers_path.display(),
        state = %cfg.state_path.display(),
        private_mount = %cfg.private.mount,
        agent_readable = %cfg.private.agent_readable.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
        "tickets and approvals enabled"
    );
    warn_sudo_prefix_overlap(&cfg, inv);
    // Approval secrets are read from their own mount, with the same token.
    let vault = vault.map(|v| Arc::new(v.with_mount(&cfg.private.mount)));
    let approvals = Approvals::new(cfg, vault);
    if approvals.load_keys().await.is_err() {
        tracing::error!(
            "NO TICKET KEY — calls whose policy rule demands an approval are refused until one \
             can be read (retrying every minute, and on SIGHUP)"
        );
    }
    approvals.spawn_key_refresh();
    approvals
}

/// Approval secrets in the same vault directory as a sudo password: a
/// vault policy written for the passwords likely covers them too. Not
/// fatal (the agent-readable check is), but worth fixing.
fn warn_sudo_prefix_overlap(cfg: &ApprovalConfig, inv: &prompto::inventory::Inventory) {
    let list = prompto::approvers::Approvers::from_path(&cfg.approvers_path).unwrap_or_default();
    let mut paths: Vec<String> = cfg.key_vault_path.iter().cloned().collect();
    paths.extend(
        list.approvers
            .values()
            .filter_map(|e| e.totp_vault_path.clone()),
    );
    for p in paths {
        if let Some(sudo) = sudo_prefix_covering(inv, &cfg.private.mount, &p) {
            tracing::warn!(
                path = %format!("{}/{p}", cfg.private.mount),
                sudo_prefix = %sudo,
                "an approval secret shares a vault prefix with a sudo password; a policy that \
                 lets anything read the passwords likely reads it too — move it to its own mount \
                 (PROMPTO_PRIVATE_MOUNT)"
            );
        }
    }
}

/// The directory of a host's `sudo_password_vault_path` that `path` on
/// `mount` falls under, if any.
fn sudo_prefix_covering(
    inv: &prompto::inventory::Inventory,
    mount: &str,
    path: &str,
) -> Option<prompto::approval::VaultPrefix> {
    let shared = env_or("PROMPTO_VAULT_MOUNT", "secret");
    inv.hosts
        .values()
        .filter_map(|h| h.sudo_password_vault_path.as_deref())
        .map(|p| prompto::approval::VaultPrefix::dir_of(shared.trim_matches('/'), p))
        .find(|d| d.covers(mount, path))
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
re-reads it on the next request after it changes (SIGHUP also works); a file
it cannot parse refuses every token until it is fixed. To stop an agent
temporarily without revoking its token: prompto kill agent <name>";

/// `prompto agent …`: edit `agents.toml`. Only the token's hash is ever
/// written; the token itself goes to stdout once, everything else to
/// stderr, so `prompto agent add x > token-file` captures just the token.
fn run_agent_cli(cfg: &Config, args: &[String]) -> Result<()> {
    let path = &cfg.agents_path;
    let reload_hint = || {
        eprintln!(
            "{} updated. A running server with PROMPTO_AUTH=optional or required \
             re-reads it on its next request (no SIGHUP needed).",
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

const APPROVER_USAGE: &str = "\
Usage: prompto approver add <name> [--vault-path <kv path> [--i-know] | --file <path>]
                            [--issuer <label>] [--replace]
       prompto approver list
       prompto approver revoke <name>

`add` mints a TOTP secret for a human approver, stores it, records the
reference in $PROMPTO_APPROVERS (default /etc/prompto/approvers.toml), and
prints the otpauth:// URI and a QR code ONCE: scan it with an authenticator
app now. --replace re-enrolls an existing approver (lost phone). The server
reads the file on every approval; no reload needed.

Where the secret goes — NOTHING AN AGENT CAN READ MAY HOLD IT (an agent that
reads it approves its own calls):

  --vault-path approvers/<name>
      vault KV v2, field totp_secret, on the PRIVATE mount
      $PROMPTO_PRIVATE_MOUNT (default prompto-private) — a mount only
      prompto's own token may read; see the README, \"Where the approval
      secrets live\", for the vault policy. Uses PROMPTO_VAULT_ADDR/_CACERT
      and a PROMPTO_VAULT_TOKEN that may write there (an operator token,
      not prompto's). Refused if the private mount is $PROMPTO_VAULT_MOUNT
      (default secret; agents are assumed to read all of it) or the path
      is under $PROMPTO_AGENT_READABLE_VAULT_PREFIXES. --i-know skips the
      check against the sudo passwords' vault directories.
  --file <path>   (default: approvers.d/<name>.totp next to the approvers
      file) an owner-only file in a directory owned by the service user.
      Anyone who is root on this machine can read it — and so can any
      agent policy lets run root, or a shell as a user that can sudo,
      here: mark this host prompto_host = true in the inventory and
      `prompto policy lint` flags those grants.";

fn approvers_path() -> PathBuf {
    env_or("PROMPTO_APPROVERS", prompto::approval::DEFAULT_APPROVERS).into()
}

/// `prompto approver …`.
async fn run_approver_cli(cfg: &Config, args: &[String]) -> Result<()> {
    use prompto::approvers::{ApproverEntry, Approvers};
    let path = approvers_path();
    match args.first().map(String::as_str) {
        Some("add") => {
            let (mut name, mut vault_path, mut file, mut issuer, mut replace) =
                (None, None, None, String::from("prompto"), false);
            let mut i_know = false;
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                let mut val = |flag: &str| {
                    it.next()
                        .with_context(|| format!("{flag} needs a value"))
                        .cloned()
                };
                match a.as_str() {
                    "--vault-path" => vault_path = Some(val("--vault-path")?),
                    "--file" => file = Some(PathBuf::from(val("--file")?)),
                    "--issuer" => issuer = val("--issuer")?,
                    "--replace" => replace = true,
                    "--i-know" => i_know = true,
                    s if s.starts_with('-') || name.is_some() => {
                        anyhow::bail!("unexpected argument {s:?}\n{APPROVER_USAGE}")
                    }
                    s => name = Some(s.to_string()),
                }
            }
            let name =
                name.with_context(|| format!("approver add needs a name\n{APPROVER_USAGE}"))?;
            prompto::agent::validate_name("approver", &name)?;
            if vault_path.is_some() && file.is_some() {
                anyhow::bail!("--vault-path and --file are exclusive");
            }
            let mut list = Approvers::from_path(&path)?;
            if list.approvers.contains_key(&name) && !replace {
                anyhow::bail!(
                    "approver {name:?} exists in {}; --replace re-enrolls it",
                    path.display()
                );
            }
            let secret = prompto::totp::mint_secret()?;
            let b32 = prompto::totp::base32_encode(&secret);
            let mut entry = ApproverEntry {
                created: Some(
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
                ..Default::default()
            };
            if let Some(vp) = vault_path {
                prompto::vault::validate_kv_path(&vp)?;
                let private = prompto::approval::PrivateVault::from_env();
                private.check_path(&format!("approver {name}'s TOTP secret"), &vp)?;
                check_sudo_overlap(cfg, &private.mount, &vp, i_know)?;
                let vault = VaultClient::from_env()?
                    .context(
                        "--vault-path needs PROMPTO_VAULT_TOKEN (a token that may write there) and \
                         PROMPTO_VAULT_ADDR",
                    )?
                    .with_mount(&private.mount);
                vault
                    .kv2_put(
                        &vp,
                        serde_json::json!({ prompto::approvers::VAULT_FIELD: b32 }),
                    )
                    .await?;
                entry.totp_vault_path = Some(vp);
            } else {
                let f = match file {
                    Some(f) => f,
                    None => path
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join("approvers.d")
                        .join(format!("{name}.totp")),
                };
                write_secret_file(&f, &b32, replace)?;
                entry.totp_file = Some(f);
            }
            list.approvers.insert(name.clone(), entry);
            prompto::agent::write_atomic(&path, &list.to_toml_string()?)?;
            let uri = prompto::totp::otpauth_uri(&issuer, &name, &secret);
            if let Some(qr) = prompto::totp::qr_terminal(&uri) {
                println!("{qr}");
            }
            println!("{uri}");
            eprintln!(
                "approver {name:?} enrolled in {}. The URI and QR code above were shown ONCE: \
                 scan it with an authenticator app now. The secret is stored only where the \
                 entry points.",
                path.display()
            );
        }
        Some("list") if args.len() == 1 => {
            let list = Approvers::from_path(&path)?;
            if list.approvers.is_empty() {
                eprintln!("no approvers in {}", path.display());
            }
            println!("{:<24} {:<8} {:<21} FACTOR", "NAME", "STATUS", "CREATED");
            for (name, e) in &list.approvers {
                let factor = match (&e.totp_vault_path, &e.totp_file) {
                    (Some(v), _) => format!(
                        "totp vault:{}/{v}",
                        prompto::approval::PrivateVault::from_env().mount
                    ),
                    (_, Some(f)) => format!("totp file:{}", f.display()),
                    _ => "-".into(),
                };
                println!(
                    "{:<24} {:<8} {:<21} {factor}",
                    name,
                    if e.disabled { "revoked" } else { "active" },
                    e.created.as_deref().unwrap_or("-"),
                );
            }
        }
        Some("revoke") if args.len() == 2 => {
            let name = &args[1];
            let mut list = Approvers::from_path(&path)?;
            let e = list
                .approvers
                .get_mut(name)
                .with_context(|| format!("no approver {name:?} in {}", path.display()))?;
            if e.disabled {
                eprintln!("approver {name:?} was already revoked; nothing changed.");
            } else {
                e.disabled = true;
                prompto::agent::write_atomic(&path, &list.to_toml_string()?)?;
                eprintln!(
                    "approver {name:?} revoked: their codes are refused from the next approval."
                );
            }
        }
        Some("--help" | "-h" | "help") => println!("{APPROVER_USAGE}"),
        _ => anyhow::bail!("{APPROVER_USAGE}"),
    }
    Ok(())
}

/// `approver add --vault-path`: refuse a path in the same vault directory
/// as a host's sudo password unless the operator says they know.
fn check_sudo_overlap(cfg: &Config, mount: &str, path: &str, i_know: bool) -> Result<()> {
    let inv = match prompto::inventory::Inventory::from_path(&cfg.inventory_path) {
        Ok(inv) => inv,
        Err(e) if i_know => {
            eprintln!("WARNING: cannot read the inventory ({e:#}); sudo-prefix check skipped");
            return Ok(());
        }
        Err(e) => {
            return Err(e).context(
                "reading the inventory to check the path against the sudo passwords' vault \
                 prefixes (--i-know skips the check)",
            );
        }
    };
    let Some(sudo) = sudo_prefix_covering(&inv, mount, path) else {
        return Ok(());
    };
    let msg = format!(
        "{mount}/{path} is in the same vault directory as a host's sudo password ({sudo}). A \
         vault policy that grants reading the passwords — to an agent gateway, a script, a \
         person — most likely grants this too, and whoever reads a TOTP secret can approve \
         anything. Use the private mount (PROMPTO_PRIVATE_MOUNT) that only prompto's token \
         reads."
    );
    if !i_know {
        anyhow::bail!(
            "{msg}\nRefused; --i-know overrides if that policy really is prompto's alone."
        );
    }
    eprintln!("WARNING (--i-know): {msg}");
    Ok(())
}

/// Write a TOTP secret owner-only, owned like its directory (which the
/// operator creates owned by the service user, as for `keys/`).
fn write_secret_file(path: &std::path::Path, b32: &str, replace: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let d = std::fs::metadata(dir).with_context(|| {
        format!(
            "{} does not exist: create it owned by the service user, e.g. \
             install -d -o prompto -g prompto -m 0700 {}",
            dir.display(),
            dir.display()
        )
    })?;
    if replace {
        let _ = std::fs::remove_file(path);
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(format!("{b32}\n").as_bytes())?;
    f.sync_all()?;
    if let Err(e) = std::os::unix::fs::fchown(&f, Some(d.uid()), Some(d.gid())) {
        let m = f.metadata()?;
        if (m.uid(), m.gid()) != (d.uid(), d.gid()) {
            let _ = std::fs::remove_file(path);
            return Err(e).context("give the secret file to its directory's owner");
        }
    }
    Ok(())
}

const TICKET_USAGE: &str = "\
Usage: prompto ticket keygen   print a fresh ticket key (base64, 32 bytes)

Whoever holds the key can mint any ticket: it must be readable by prompto's
own token or user ONLY. Store it as the `current` field of
PROMPTO_TICKET_KEY_VAULT_PATH (KV v2) on the private mount
$PROMPTO_PRIVATE_MOUNT (default prompto-private, which no other token may
read; prompto refuses one agents can read: all of $PROMPTO_VAULT_MOUNT and
$PROMPTO_AGENT_READABLE_VAULT_PREFIXES),
or as the first line of PROMPTO_TICKET_KEY_FILE (mode 0600, owned by the
service user; any agent with root on this host defeats it — see
prompto_host in the README). To rotate: move the old key to `previous`
(second line), put the new one in `current`, SIGHUP (or wait a minute);
remove `previous` once outstanding tickets have expired (120 s; up to 60
min for scoped approvals).";

/// `prompto ticket …`.
fn run_ticket_cli(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 1 => {
            println!("{}", prompto::ticket::generate_key()?);
            Ok(())
        }
        Some("--help" | "-h" | "help") => {
            println!("{TICKET_USAGE}");
            Ok(())
        }
        _ => anyhow::bail!("{TICKET_USAGE}"),
    }
}

/// Startup: where the kill switches are, and any that are already on.
/// A switch the server can't check stops it (fail closed, see
/// `prompto::kill`): better a failed upgrade than a panic button that
/// silently does nothing.
fn check_kill_switches(kill: &KillSwitch) -> Result<()> {
    if let Err(e) = kill.probe() {
        anyhow::bail!(
            "cannot check the kill switches ({e}): prompto refuses to start rather than run \
             with a kill switch it can't see. Let the user prompto runs as stat {} and search \
             {} (the standard install has /etc/prompto 0750 root:prompto), or point \
             PROMPTO_KILL_FILE / PROMPTO_KILL_DIR somewhere it can.",
            kill.file().display(),
            kill.dir().display()
        );
    }
    tracing::info!(
        file = %kill.file().display(),
        dir = %kill.dir().display(),
        api_dir = %kill.api_dir().map(|d| d.display().to_string()).unwrap_or_default(),
        "kill switches checked on every call (prompto kill …)"
    );
    match kill.list() {
        Ok((kills, ignored)) => {
            for k in kills {
                tracing::warn!(
                    scope = k.scope.as_str(),
                    target = k.target.as_deref(),
                    since = k.since.as_deref(),
                    reason = k.reason.as_deref(),
                    "KILL SWITCH ON — matching calls are refused (killed)"
                );
            }
            for f in ignored {
                tracing::warn!(file = %f, dir = %kill.dir().display(), "not a kill switch file — ignored");
            }
        }
        Err(e) => tracing::error!(error = %format!("{e:#}"), "cannot list kill switches"),
    }
    Ok(())
}

const KILL_USAGE: &str = "\
Usage: prompto kill on [reason…]                stop every tool call (global)
       prompto kill off                         lift the global kill
       prompto kill agent <name> [reason…]      stop one agent's calls
       prompto kill host <name> [reason…]       stop every call to one host
       prompto kill session <id> [reason…]      stop one X-Prompto-Session
       prompto unkill agent|host|session <name> lift a scoped kill
       prompto kill status                      list what is stopped (as root)

The global switch is $PROMPTO_KILL_FILE (default /etc/prompto/kill); scoped
ones are files in kill.d next to it ($PROMPTO_KILL_DIR): agent-<name>,
host-<name>, session-<id>. A running server checks them on every call, so
a change applies to the next call: no restart, no SIGHUP. Creating or
removing the files by hand works the same; the first line is the reason.
Refused calls get error_class `killed` and are audited with the scope.
Each `kill`/`unkill` that changes a switch is audited too (type `kill`:
who, what, reason) in $PROMPTO_AUDIT_LOG; if that fails the switch still
applies and a warning says so. A server that can't check a switch
refuses to start, and refuses calls as `killed` if it can't later.
Agent and session kills need PROMPTO_AUTH=optional or required: with off,
calls carry no agent or session.";

/// Record who set or lifted a switch in the audit log. The switch is
/// already applied: a record that can't be written is reported, never
/// fatal (the panic button wins).
fn audit_kill(cfg: &Config, on: bool, scope: KillScope, target: Option<&str>, reason: &str) {
    let file = cfg.kill.path(scope, target).unwrap_or_default();
    let rec = audit::KillRecord::new(on, scope, target, reason, &file, audit::Operator::current());
    let gid = cfg
        .audit_group
        .as_deref()
        .and_then(|g| audit::resolve_group(g).ok());
    if let Err(e) = audit::append_operator_record(&cfg.audit_path, gid, &rec) {
        eprintln!(
            "WARNING: the kill switch change above IS in effect, but it could not be recorded in \
             the audit log {}: {e}",
            cfg.audit_path.display()
        );
    }
}

/// Record the lifting of a switch that was set over HTTP (`POST
/// /v1/kill`): the global one, or an agent's kill of its own session.
fn audit_kill_api(cfg: &Config, scope: KillScope, session: Option<&str>, agent: Option<&str>) {
    let file = cfg.kill.api_path(scope, agent, session).unwrap_or_default();
    let mut rec =
        audit::KillRecord::new(false, scope, session, "", &file, audit::Operator::current());
    rec.agent = agent.map(str::to_string);
    let gid = cfg
        .audit_group
        .as_deref()
        .and_then(|g| audit::resolve_group(g).ok());
    if let Err(e) = audit::append_operator_record(&cfg.audit_path, gid, &rec) {
        eprintln!(
            "WARNING: the kill switch change above IS in effect, but it could not be recorded in \
             the audit log {}: {e}",
            cfg.audit_path.display()
        );
    }
}

/// `prompto kill …` / `prompto unkill …`: write or remove kill files,
/// and record each change in the audit log.
fn run_kill_cli(cfg: &Config, unkill: bool, args: &[String]) -> Result<()> {
    let kill = &cfg.kill;
    let reason = |rest: &[String]| rest.join(" ");
    let applies = "The running server applies this from its next call (no restart).";
    if matches!(
        args.first().map(String::as_str),
        Some("--help" | "-h" | "help")
    ) {
        println!("{KILL_USAGE}");
        return Ok(());
    }
    if unkill {
        let (Some(kind), Some(name), None) = (args.first(), args.get(1), args.get(2)) else {
            anyhow::bail!("{KILL_USAGE}");
        };
        let scope = KillScope::parse_named(kind)
            .with_context(|| format!("unknown scope {kind:?}\n{KILL_USAGE}"))?;
        let mut lifted = kill.clear(scope, Some(name))?;
        if lifted {
            eprintln!("{kind} {name} kill lifted. {applies}");
            audit_kill(cfg, false, scope, Some(name), "");
        }
        // An agent's own kill of this session (POST /v1/kill).
        if scope == KillScope::Session {
            for agent in kill.clear_agent_sessions(name)? {
                eprintln!("agent {agent}'s own kill of session {name} lifted. {applies}");
                audit_kill_api(cfg, KillScope::AgentSession, Some(name), Some(&agent));
                lifted = true;
            }
        }
        if !lifted {
            eprintln!("{kind} {name} was not killed; nothing changed.");
        }
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("on") => {
            let why = reason(&args[1..]);
            let path = kill.set(KillScope::Global, None, &why)?;
            eprintln!(
                "GLOBAL KILL ON ({}): every tool call and GET /log is refused. {applies} \
                 Lift it with `prompto kill off`.",
                path.display()
            );
            audit_kill(cfg, true, KillScope::Global, None, &why);
        }
        Some("off") if args.len() == 1 => {
            let file = kill.clear(KillScope::Global, None)?;
            if file {
                eprintln!("global kill lifted. {applies}");
                audit_kill(cfg, false, KillScope::Global, None, "");
            }
            // The global kill an approver set over HTTP (POST /v1/kill).
            let api = kill.clear_api_global()?;
            if api {
                eprintln!("global kill set over HTTP lifted. {applies}");
                audit_kill_api(cfg, KillScope::Global, None, None);
            }
            if !file && !api {
                eprintln!("the global kill was not on; nothing changed.");
            }
        }
        Some("status") if args.len() == 1 => {
            if let Err(e) = kill.probe() {
                anyhow::bail!(
                    "cannot check the kill switches as this user ({e}); run it with sudo. \
                     The server itself refuses to start if it can't, and refuses calls as \
                     `killed` if it stops being able to while running."
                );
            }
            let (kills, ignored) = kill.list()?;
            if kills.is_empty() {
                println!("no kill switch is on");
            }
            for k in &kills {
                let target = match (&k.agent, &k.target) {
                    (Some(a), Some(t)) => format!("{a}@{t}"),
                    (_, t) => t.as_deref().unwrap_or("*").to_string(),
                };
                println!(
                    "{:<8} {:<24} since {:<21} {}",
                    k.scope.as_str(),
                    target,
                    k.since.as_deref().unwrap_or("?"),
                    k.reason.as_deref().unwrap_or("")
                );
            }
            for f in ignored {
                // API-directory entries come back as full paths.
                eprintln!(
                    "ignored (not a kill switch file): {}",
                    kill.dir().join(f).display()
                );
            }
        }
        Some(kind) if args.len() >= 2 && KillScope::parse_named(kind).is_some() => {
            let scope = KillScope::parse_named(kind).expect("checked");
            let name = &args[1];
            let why = reason(&args[2..]);
            let path = kill.set(scope, Some(name), &why)?;
            eprintln!("{kind} {name} KILLED ({}). {applies}", path.display());
            audit_kill(cfg, true, scope, Some(name), &why);
            if scope == KillScope::Host
                && let Ok(inv) = prompto::inventory::Inventory::from_path(&cfg.inventory_path)
                && inv.canonical(name).is_none()
            {
                eprintln!(
                    "note: {name:?} is not a host or alias in {} (yet); the kill applies to \
                     calls that name it.",
                    cfg.inventory_path.display()
                );
            }
        }
        _ => anyhow::bail!("{KILL_USAGE}"),
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
            let service_user = policy::service_user_from_env();
            let findings = policy::lint(&p, &inv, &agents, &tools, &service_user);
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

const AUDIT_USAGE: &str = "\
Usage: prompto audit [--agent NAME] [--host HOST] [--tool TOOL] [--since 10m|ISO]
                     [--request-id ID] [--decision allow|deny] [--json]

Reads $PROMPTO_AUDIT_LOG (default /var/lib/prompto/audit.jsonl) and its
rotated siblings (.1, .2.gz, …; only those written since --since). Every
given filter must match; --host matches the host, the name as typed,
rsync's dest, or a host kill. Default output is a table, oldest first;
--json prints the matching records as JSON lines. Kill switch changes
(`prompto kill`/`unkill`) are rows with tool `(kill)` and the operator
in the AGENT column.";

/// `prompto audit …`: query the audit log.
fn run_audit_cli(cfg: &Config, args: &[String]) -> Result<()> {
    let mut f = audit::Filter::default();
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        let mut val = || -> Result<String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => Ok(it
                    .next()
                    .with_context(|| format!("{flag} requires a value"))?
                    .clone()),
            }
        };
        match flag {
            "--agent" => f.agent = Some(val()?),
            "--host" => f.host = Some(val()?),
            "--tool" => f.tool = Some(val()?),
            "--request-id" => f.request_id = Some(val()?),
            "--since" => f.since = Some(audit::parse_since(&val()?, chrono::Utc::now())?),
            "--decision" => {
                let d = val()?;
                if d != "allow" && d != "deny" {
                    anyhow::bail!("--decision must be allow or deny");
                }
                f.decision = Some(d);
            }
            "--json" => json = true,
            "--help" | "-h" => {
                println!("{AUDIT_USAGE}");
                return Ok(());
            }
            other => anyhow::bail!("unexpected argument {other:?}\n{AUDIT_USAGE}"),
        }
    }
    let mut rows = Vec::new();
    let (mut seen, mut bad) = (0usize, 0usize);
    for file in audit::files_to_read(&cfg.audit_path, f.since) {
        for line in audit::read_file(&file)?.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // A fragment left by a cut-short write costs only itself.
            let (found, fragments) = audit::parse_line(line);
            bad += fragments;
            let Some((rec, text)) = found else {
                continue;
            };
            seen += 1;
            if !f.matches(&rec) {
                continue;
            }
            if json {
                println!("{}", audit::json_for_terminal(text));
            } else {
                rows.push(audit::table_row(&rec));
            }
        }
    }
    if !json {
        let head = [
            "TIME (UTC)",
            "AGENT",
            "TOOL",
            "HOST",
            "DECISION",
            "RESULT",
            "DURATION",
            "DETAIL",
        ]
        .map(String::from);
        let mut width = [0usize; 7];
        for r in std::iter::once(&head).chain(&rows) {
            for (w, c) in width.iter_mut().zip(r.iter()) {
                *w = (*w).max(c.chars().count());
            }
        }
        for r in std::iter::once(&head).chain(&rows) {
            let mut line = String::new();
            for (w, c) in width.iter().zip(r.iter()) {
                line.push_str(&format!("{c:<w$}  "));
            }
            line.push_str(&r[7]);
            println!("{}", line.trim_end());
        }
        eprintln!("{} of {seen} records", rows.len());
    }
    if bad > 0 {
        eprintln!("warning: skipped {bad} unreadable fragments (not valid JSON)");
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
    if raw_args.len() >= 2 && (raw_args[1] == "kill" || raw_args[1] == "unkill") {
        return run_kill_cli(&cfg, raw_args[1] == "unkill", &raw_args[2..]);
    }
    if raw_args.len() >= 2 && raw_args[1] == "audit" {
        return run_audit_cli(&cfg, &raw_args[2..]);
    }
    if raw_args.len() >= 2 && raw_args[1] == "approver" {
        return run_approver_cli(&cfg, &raw_args[2..]).await;
    }
    if raw_args.len() >= 2 && raw_args[1] == "ticket" {
        return run_ticket_cli(&raw_args[2..]);
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
    check_kill_switches(&cfg.kill)?;
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
    let mut ssh_client = SshClient::new(cfg.ssh_bin.clone(), cfg.default_timeout);
    let mut vault_client = None;
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
            ssh_client = ssh_client.with_vault(vault.clone());
            vault_client = Some(vault);
        }
        None if !needs_vault.is_empty() => tracing::warn!(
            hosts = ?needs_vault,
            "these hosts declare sudo_password_vault_path but PROMPTO_VAULT_TOKEN is unset — \
             their sudo calls will fail until it is configured"
        ),
        None => {}
    }
    let approvals = open_approvals(auth_mode, vault_client, &store.snapshot()).await;
    if let Some(p) = &policy {
        let asking: Vec<String> = p
            .snapshot()
            .rules
            .iter()
            .filter(|r| r.approval != prompto::policy::Approval::None)
            .map(|r| r.name().to_string())
            .collect();
        if !asking.is_empty() && !approvals.configured() {
            tracing::warn!(
                rules = ?asking,
                "these policy rules demand an approval, and no ticket key is configured \
                 (PROMPTO_TICKET_KEY_VAULT_PATH / PROMPTO_TICKET_KEY_FILE): their calls are \
                 refused (approval_required)"
            );
        }
    }
    if let Some(p) = &policy {
        // Root or the service user's shell on the prompto host reads the
        // approval factors: approvals are off while the policy grants it.
        approvals.gate_on_policy(
            p,
            &store,
            Prompto::tool_names(),
            prompto::policy::service_user_from_env(),
        );
    }
    let reload = match (&agents, &policy) {
        (Some(a), Some(p)) => Some(PolicyReload {
            policy: p.clone(),
            agents: a.clone(),
            approvals: approvals.clone(),
        }),
        _ => None,
    };
    spawn_sighup_reloader(store.clone(), reload, auth_mode);
    let audit = open_audit(&cfg, auth_mode)?;

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
        approvals,
    };

    if stdio_mode {
        tracing::info!("transport: stdio");
        // Whoever can talk to our stdin launched us: agent `local`.
        // Policy applies to `local` like to any agent when auth is on.
        let service = prompto
            .with_identity(Identity::local())
            .with_policy(auth.enforcer())
            .with_audit(audit)
            .with_kill(cfg.kill.clone())
            .serve(stdio())
            .await
            .context("stdio serve")?;
        service.waiting().await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&cfg.bind)
            .await
            .with_context(|| format!("bind {}", cfg.bind))?;
        // The bound address, not `cfg.bind`: with port 0 it is the only
        // place the port shows up (the tests read it from here).
        let local = listener
            .local_addr()
            .map_or_else(|_| cfg.bind.clone(), |a| a.to_string());
        tracing::info!("transport: streamable-http on {local}");
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
            audit,
            kill: cfg.kill.clone(),
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
