//! Tickets and approvals at run time (roadmap E6): the signing keys, the
//! record of used nonces and TOTP steps, the ticket check `authz` runs
//! where policy demands an approval, and what `POST /v1/precheck` and
//! `POST /v1/approve` mint.
//!
//! # Configuration
//!
//! Off unless a key source is set — with no new configuration prompto
//! behaves as before: an `approval = "ticket" | "human"` rule refuses its
//! calls (`approval_required`), now saying that no ticket key is loaded.
//!
//! - `PROMPTO_TICKET_KEY_VAULT_PATH`: KV v2 path (same vault client,
//!   token and CA as the sudo passwords) with fields `current` and,
//!   during a rotation, `previous` — base64 of ≥ 32 random bytes each
//!   (`prompto ticket keygen`).
//! - `PROMPTO_TICKET_KEY_FILE`: the same in a file, current key on the
//!   first line, previous on the second; owner-only (0600). Used when no
//!   vault path is set, or vault can't be read.
//! - `PROMPTO_APPROVERS` (`/etc/prompto/approvers.toml`): see
//!   `crate::approvers`.
//! - `PROMPTO_APPROVAL_STATE` (`/var/lib/prompto/approval-state`): used
//!   nonces and TOTP steps, see below.
//!
//! # Continuity (E11)
//!
//! A restart must not drop a call that would have succeeded, nor reopen
//! a replay:
//!
//! - **The key outlives the process.** It comes from vault or a file,
//!   never from the process's own randomness, so a ticket minted just
//!   before a deploy verifies just after it. Keys are re-read every
//!   minute and on SIGHUP; a failed re-read keeps the keys in hand. If
//!   none can be read at startup, prompto starts anyway (calls that need
//!   no ticket are unaffected), refuses ticketed calls saying why, and
//!   keeps trying.
//! - **Used nonces and TOTP steps outlive the process too.** Each use is
//!   appended to the state file and synced to disk (`fdatasync`) before
//!   the call proceeds — so neither a restart nor a power loss forgets
//!   it — and reloaded
//!   (unexpired entries only) at startup. Resetting them on restart would
//!   leave a window — up to the 120 s TTL for a ticket, 90 s for a TOTP
//!   code — in which the exact call (or approval) could be replayed. That
//!   is narrow and needs the replayer to hold the used ticket, but a
//!   replay of a human-approved `rm` or `systemctl restart` is not
//!   harmless, and one appended line per ticketed call is cheap. If the
//!   file can't be written, ticketed calls are refused (like the strict
//!   audit log) rather than run unrecorded.

use crate::approvers::{self, Approvers, Guard};
use crate::authz;
use crate::ctx::CallCtx;
use crate::error_class::{ClassifiedError, ErrorClass};
use crate::inventory::Inventory;
use crate::policy::Approval;
use crate::ticket::{self, Claims, Expect, KeySet, Replay, Scope};
use crate::vault::VaultClient;
use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `PROMPTO_APPROVERS` default.
pub const DEFAULT_APPROVERS: &str = "/etc/prompto/approvers.toml";
/// `PROMPTO_APPROVAL_STATE` default.
pub const DEFAULT_STATE: &str = "/var/lib/prompto/approval-state";
/// How often keys are re-read.
pub const KEY_REFRESH: Duration = Duration::from_secs(60);

/// Where things are.
#[derive(Clone, Debug, Default)]
pub struct ApprovalConfig {
    /// On [`PrivateVault::mount`].
    pub key_vault_path: Option<String>,
    pub key_file: Option<PathBuf>,
    pub approvers_path: PathBuf,
    pub state_path: PathBuf,
    /// Where vault-held approval factors live, and where they must not.
    pub private: PrivateVault,
}

/// `PROMPTO_PRIVATE_MOUNT` default.
pub const DEFAULT_PRIVATE_MOUNT: &str = "prompto-private";
/// `PROMPTO_VAULT_MOUNT` default: the shared mount (sudo passwords),
/// agent-readable as a whole.
pub const DEFAULT_SHARED_MOUNT: &str = "secret";

/// A location in vault: a KV v2 mount and a path prefix in it (`""`: the
/// whole mount). Matched like a vault policy glob `<mount>/<prefix>*`:
/// a plain string prefix, so `prompto` also covers `prompto-x/…`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPrefix {
    pub mount: String,
    pub prefix: String,
}

impl VaultPrefix {
    pub fn covers(&self, mount: &str, path: &str) -> bool {
        self.mount == mount && path.starts_with(&self.prefix)
    }

    /// The prefix a vault policy granting `path` most likely covers: its
    /// directory (`prompto/sudo-default` → `prompto/`), or the whole
    /// mount for a top-level path.
    pub fn dir_of(mount: &str, path: &str) -> Self {
        let prefix = path.rfind('/').map_or("", |i| &path[..=i]);
        Self {
            mount: mount.to_string(),
            prefix: prefix.to_string(),
        }
    }
}

impl std::fmt::Display for VaultPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}*", self.mount, self.prefix)
    }
}

/// **Nothing an agent can read may be an approval factor or a signing
/// key.** An agent that reads an approver's TOTP secret approves itself;
/// one that reads the ticket key forges any ticket. Agents commonly get
/// read access to vault through a gateway whose policy covers a prefix
/// such as `secret/data/prompto/*` — the very prefix the sudo passwords
/// live under. So the ticket key and the TOTP secrets are read from
/// their own KV v2 mount (`PROMPTO_PRIVATE_MOUNT`, default
/// `prompto-private`) that only prompto's token may read, and prompto
/// refuses any of them that sits under a location agents can read.
///
/// The whole shared mount (`PROMPTO_VAULT_MOUNT`) counts as
/// agent-readable, always: agent gateways cover more and more prefixes
/// there (`prompto/`, `infra/`, `ai/`, `personal/`, …), and a list of
/// them goes stale silently. `PROMPTO_AGENT_READABLE_VAULT_PREFIXES`
/// only adds locations, on other mounts.
#[derive(Clone, Debug)]
pub struct PrivateVault {
    /// The KV v2 mount the ticket key and TOTP secrets are read from.
    pub mount: String,
    /// Locations agents can read.
    pub agent_readable: Vec<VaultPrefix>,
}

impl Default for PrivateVault {
    fn default() -> Self {
        Self::from_parts(DEFAULT_SHARED_MOUNT, None, None)
    }
}

/// Parse `PROMPTO_AGENT_READABLE_VAULT_PREFIXES`: comma-separated; an
/// entry is a path prefix in `shared_mount` (`PROMPTO_VAULT_MOUNT`, the
/// mount sudo passwords are read from), or `<mount>:<prefix>` for
/// another mount (`<mount>:` alone: all of it).
pub fn parse_prefixes(list: &str, shared_mount: &str) -> Vec<VaultPrefix> {
    list.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| match e.split_once(':') {
            Some((m, p)) => VaultPrefix {
                mount: m.trim_matches('/').to_string(),
                prefix: p.trim_start_matches('/').to_string(),
            },
            None => VaultPrefix {
                mount: shared_mount.trim_matches('/').to_string(),
                prefix: e.trim_start_matches('/').to_string(),
            },
        })
        .collect()
}

impl PrivateVault {
    /// From `PROMPTO_PRIVATE_MOUNT`, `PROMPTO_AGENT_READABLE_VAULT_PREFIXES`
    /// and `PROMPTO_VAULT_MOUNT`.
    pub fn from_env() -> Self {
        let shared =
            std::env::var("PROMPTO_VAULT_MOUNT").unwrap_or_else(|_| DEFAULT_SHARED_MOUNT.into());
        Self::from_parts(
            &shared,
            std::env::var("PROMPTO_PRIVATE_MOUNT").ok().as_deref(),
            std::env::var("PROMPTO_AGENT_READABLE_VAULT_PREFIXES")
                .ok()
                .as_deref(),
        )
    }

    /// The shared mount `shared` as a whole, plus the `extra` locations
    /// (`PROMPTO_AGENT_READABLE_VAULT_PREFIXES`, see [`parse_prefixes`]);
    /// entries on the shared mount add nothing and are dropped. `private`
    /// (`PROMPTO_PRIVATE_MOUNT`) defaults to [`DEFAULT_PRIVATE_MOUNT`].
    pub fn from_parts(shared: &str, private: Option<&str>, extra: Option<&str>) -> Self {
        let shared = shared.trim().trim_matches('/');
        let mount = private
            .map(|m| m.trim().trim_matches('/').to_string())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| DEFAULT_PRIVATE_MOUNT.into());
        let mut agent_readable = vec![VaultPrefix {
            mount: shared.to_string(),
            prefix: String::new(),
        }];
        agent_readable.extend(
            parse_prefixes(extra.unwrap_or_default(), shared)
                .into_iter()
                .filter(|p| p.mount != shared),
        );
        Self {
            mount,
            agent_readable,
        }
    }

    /// Refuse `path` (on [`Self::mount`]) if agents can read it. `what`
    /// names it in the error.
    pub fn check_path(&self, what: &str, path: &str) -> Result<()> {
        if let Some(p) = self
            .agent_readable
            .iter()
            .find(|p| p.covers(&self.mount, path))
        {
            bail!(
                "{what} is at vault {}/{path}, under {p}, which agents can read \
                 (PROMPTO_AGENT_READABLE_VAULT_PREFIXES). An agent that reads it could approve \
                 its own calls or forge tickets, so prompto refuses it. Move it to a mount only \
                 prompto's token can read (PROMPTO_PRIVATE_MOUNT, default {DEFAULT_PRIVATE_MOUNT}; \
                 see the README, \"Where the approval secrets live\")",
                self.mount
            );
        }
        Ok(())
    }

    /// [`Self::check_path`] for an approver's factor; files can't be
    /// checked this way (see the README).
    pub fn check_factor(&self, f: &approvers::Factor) -> Result<()> {
        match f {
            approvers::Factor::TotpVault(p) => self.check_path("this approver's TOTP secret", p),
            approvers::Factor::TotpFile(_) => Ok(()),
        }
    }

    /// Everything configured now that agents could read: the ticket key
    /// path and every active approver's vault path. Empty when all is
    /// well.
    pub fn misplaced(&self, key_vault_path: Option<&str>, list: &Approvers) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = key_vault_path
            && let Err(e) = self.check_path("the ticket key (PROMPTO_TICKET_KEY_VAULT_PATH)", p)
        {
            out.push(format!("{e:#}"));
        }
        for (name, e) in list.approvers.iter().filter(|(_, e)| !e.disabled) {
            if let Ok(f) = e.factor()
                && let Err(e) = self.check_factor(&f)
            {
                out.push(format!("approver {name}: {e:#}"));
            }
        }
        out
    }
}

impl ApprovalConfig {
    /// From the environment; `None` when no key source is set.
    pub fn from_env() -> Option<Self> {
        let var = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let key_vault_path = var("PROMPTO_TICKET_KEY_VAULT_PATH");
        let key_file = var("PROMPTO_TICKET_KEY_FILE").map(PathBuf::from);
        if key_vault_path.is_none() && key_file.is_none() {
            return None;
        }
        Some(Self {
            key_vault_path,
            key_file,
            private: PrivateVault::from_env(),
            approvers_path: var("PROMPTO_APPROVERS")
                .unwrap_or_else(|| DEFAULT_APPROVERS.into())
                .into(),
            state_path: var("PROMPTO_APPROVAL_STATE")
                .unwrap_or_else(|| DEFAULT_STATE.into())
                .into(),
        })
    }
}

/// What a call's verified ticket said, kept in its notes so a second
/// authorization in the same call (`rsync_sync`'s dest) doesn't spend
/// the nonce twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketNote {
    pub approval: Approval,
    pub approved_by: Option<String>,
    pub scoped: bool,
    /// A scoped ticket's binding, checked again by the call's other
    /// authorizations.
    pub scope: Option<ticket::Scope>,
}

/// One authorization that needs a ticket: the deciding rule, and whether
/// the call is root-capable there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demand {
    pub rule: String,
    pub root: bool,
}

/// Tickets and approvals; `Default` is "not configured".
#[derive(Clone, Default)]
pub struct Approvals(Option<Arc<Inner>>);

struct Inner {
    cfg: ApprovalConfig,
    vault: Option<Arc<VaultClient>>,
    keys: ArcSwapOption<KeySet>,
    /// Why the last key load failed, for refusals.
    key_error: Mutex<Option<String>>,
    /// Approval secrets configured where agents can read them
    /// ([`PrivateVault::misplaced`]); while any is, approvals are off.
    misplaced: Mutex<Vec<String>>,
    /// Policy lint errors on the host running prompto
    /// (`policy::prompto_host_findings`): root or the service user's
    /// shell there reads the factors. While any is, approvals are off.
    policy_block: Mutex<Vec<String>>,
    state: Mutex<State>,
    guard: Mutex<Guard>,
}

/// Used nonces and TOTP steps, in memory and in the state file.
struct State {
    replay: Replay,
    steps: HashMap<String, u64>,
    file: Result<File, String>,
    path: PathBuf,
    /// Lines in the file, to know when to compact it.
    lines: usize,
}

impl State {
    fn open(path: &Path, now: u64) -> Self {
        let mut s = State {
            replay: Replay::default(),
            steps: HashMap::new(),
            file: Err("not opened".into()),
            path: path.to_path_buf(),
            lines: 0,
        };
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for l in text.lines() {
                    let mut f = l.split(' ');
                    match (f.next(), f.next(), f.next()) {
                        (Some("n"), Some(exp), Some(nonce)) => {
                            if let Ok(exp) = exp.parse() {
                                s.replay.restore(nonce, exp, now);
                            }
                        }
                        (Some("t"), Some(step), Some(name)) => {
                            if let Ok(step) = step.parse::<u64>() {
                                let e = s.steps.entry(name.to_string()).or_default();
                                *e = (*e).max(step);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                s.file = Err(format!("cannot read {}: {e}", path.display()));
                return s;
            }
        }
        s.file = s.compact(now);
        s
    }

    /// Rewrite the file with only what is still live, then append to it.
    fn compact(&mut self, now: u64) -> Result<File, String> {
        use std::os::unix::fs::OpenOptionsExt;
        self.replay.prune(now);
        // A step older than the TOTP window can't be replayed anyway.
        let oldest = crate::totp::step_at(now).saturating_sub(crate::totp::SKEW_STEPS + 1);
        self.steps.retain(|_, s| *s >= oldest);
        let mut text = String::new();
        for (n, exp) in self.replay.iter() {
            text.push_str(&format!("n {exp} {n}\n"));
        }
        for (name, step) in &self.steps {
            text.push_str(&format!("t {step} {name}\n"));
        }
        let tmp = self.path.with_extension("tmp");
        let write = || -> std::io::Result<File> {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            // The rename itself, durable before anything is appended
            // (best effort: not every platform syncs a directory).
            if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                let _ = File::open(dir).and_then(|d| d.sync_all());
            }
            OpenOptions::new().append(true).open(&self.path)
        };
        self.lines = self.replay.len() + self.steps.len();
        write().map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }

    /// Append one line, before the use it records takes effect.
    fn append(&mut self, line: &str, now: u64) -> Result<(), String> {
        if self.lines > 4 * (self.replay.len() + self.steps.len()) + 10_000 {
            self.file = self.compact(now);
        }
        let f = self.file.as_mut().map_err(|e| e.clone())?;
        // Synced before the use it records takes effect: a power loss
        // must not forget a spent nonce or TOTP step while it could
        // still be replayed. `fdatasync` of one appended line measured
        // ~1.7 ms (p99 ~2.5 ms) on the sandbox VMs' virtio disks, against
        // calls that take an SSH round trip (and human approvals). It is
        // done under the state lock, which caps ticketed calls at a few
        // hundred a second — far above what approvals are for.
        f.write_all(format!("{line}\n").as_bytes())
            .and_then(|()| f.sync_data())
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))?;
        self.lines += 1;
        Ok(())
    }
}

/// Why `/v1/approve` refused.
#[derive(Debug)]
pub enum ApproveError {
    /// Locked out until (unix seconds).
    Locked(String, u64),
    /// Wrong, reused or expired code, unknown or revoked approver.
    Refused(String),
    /// The approver's secret or the state file could not be read; not
    /// the caller's fault, not counted.
    Unavailable(String),
}

impl Approvals {
    /// Tickets and approvals with this configuration. Never fails: what
    /// can't be read is retried (keys) or refuses ticketed calls with the
    /// reason (state file, misplaced secrets), so a broken approval setup
    /// can't stop calls that need no approval. `vault` is the client for
    /// the private mount ([`PrivateVault::mount`]).
    pub fn new(cfg: ApprovalConfig, vault: Option<Arc<VaultClient>>) -> Self {
        let state = State::open(&cfg.state_path, ticket::unix_now());
        if let Err(e) = &state.file {
            tracing::error!(
                error = %e,
                "APPROVAL STATE FILE UNUSABLE — calls that need a ticket are refused until it can \
                 be written (PROMPTO_APPROVAL_STATE)"
            );
        }
        let a = Self(Some(Arc::new(Inner {
            cfg,
            vault,
            keys: ArcSwapOption::empty(),
            key_error: Mutex::new(Some("no key loaded yet".into())),
            misplaced: Mutex::new(Vec::new()),
            policy_block: Mutex::new(Vec::new()),
            state: Mutex::new(state),
            guard: Mutex::new(Guard::default()),
        })));
        a.check_placement();
        a
    }

    /// Approvals with a fixed key set, for tests.
    pub fn with_keys(cfg: ApprovalConfig, keys: KeySet) -> Self {
        let a = Self::new(cfg, None);
        if let Some(i) = &a.0 {
            i.keys.store(Some(Arc::new(keys)));
            *i.key_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        a
    }

    /// Approver names the lockout tracks individually (tests).
    pub fn tracked_approver_names(&self) -> usize {
        self.inner().map_or(0, |i| {
            i.guard.lock().unwrap_or_else(|e| e.into_inner()).tracked()
        })
    }

    /// Is a key source configured at all?
    pub fn configured(&self) -> bool {
        self.0.is_some()
    }

    /// The keys in force, if any are loaded.
    pub fn keys(&self) -> Option<Arc<KeySet>> {
        self.0.as_ref()?.keys.load_full()
    }

    /// Replace the keys (tests: rotation).
    pub fn set_keys(&self, keys: KeySet) {
        if let Some(i) = &self.0 {
            i.keys.store(Some(Arc::new(keys)));
        }
    }

    fn inner(&self) -> Option<&Inner> {
        self.0.as_deref()
    }

    /// Check that no approval secret is configured where agents can
    /// read it ([`PrivateVault`]); while one is, every ticket and
    /// approval is refused. Run at startup, with every key refresh and on
    /// SIGHUP. Returns what is misplaced.
    pub fn check_placement(&self) -> Vec<String> {
        let Some(i) = self.inner() else {
            return Vec::new();
        };
        let list = Approvers::from_path(&i.cfg.approvers_path).unwrap_or_default();
        let found = i
            .cfg
            .private
            .misplaced(i.cfg.key_vault_path.as_deref(), &list);
        let mut held = i.misplaced.lock().unwrap_or_else(|e| e.into_inner());
        if !found.is_empty() && *held != found {
            for f in &found {
                tracing::error!(
                    "APPROVALS DISABLED — {f}. Every call that needs a ticket is refused until \
                     this is fixed (checked every minute and on SIGHUP)"
                );
            }
        } else if found.is_empty() && !held.is_empty() {
            tracing::info!("approval secrets are no longer agent-readable; approvals re-enabled");
        }
        *held = found.clone();
        found
    }

    /// Record the live policy's lint errors on the host running prompto
    /// (`policy::prompto_host_findings`); while there are any, every
    /// ticket and approval is refused, as for a misplaced secret. Run at
    /// startup, on SIGHUP and whenever `policy.toml` is re-read.
    pub fn set_policy_block(&self, found: Vec<String>) {
        let Some(i) = self.inner() else { return };
        let mut held = i.policy_block.lock().unwrap_or_else(|e| e.into_inner());
        if !found.is_empty() && *held != found {
            for f in &found {
                tracing::error!(
                    "APPROVALS DISABLED — {f}. Every call that needs a ticket is refused until \
                     this is fixed (checked on SIGHUP and when policy.toml changes)"
                );
            }
        } else if found.is_empty() && !held.is_empty() {
            tracing::info!(
                "the policy no longer grants root or the service user on the prompto host; \
                 approvals re-enabled"
            );
        }
        *held = found;
    }

    /// Keep [`Self::set_policy_block`] in step with the policy: check
    /// `policy` against the inventory live in `inv` now, and again after
    /// every read of `policy.toml` (SIGHUP, or an edit seen on the next
    /// call). `tools` is every tool name; `service_user` is
    /// `PROMPTO_SERVICE_USER`. No-op when approvals aren't configured.
    pub fn gate_on_policy(
        &self,
        policy: &crate::policy::PolicyStore,
        inv: &crate::inventory::InventoryStore,
        tools: Vec<String>,
        service_user: String,
    ) {
        if !self.configured() {
            return;
        }
        let (me, inv) = (self.clone(), inv.clone());
        let check = move |p: &crate::policy::Policy| {
            let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
            me.set_policy_block(crate::policy::prompto_host_findings(
                p,
                &inv.snapshot(),
                &tools,
                &service_user,
            ));
        };
        check(&policy.snapshot());
        policy.on_reload(check);
    }

    /// Read the keys from vault, else the file. On failure the keys in
    /// hand are kept.
    pub async fn load_keys(&self) -> Result<()> {
        let Some(i) = self.inner() else {
            return Ok(());
        };
        self.check_placement();
        let res = read_keys(&i.cfg, i.vault.as_deref()).await;
        let mut err = i.key_error.lock().unwrap_or_else(|e| e.into_inner());
        match res {
            Ok(k) => {
                let old = i.keys.load_full();
                let changed = old.as_ref().is_none_or(|o| {
                    o.current.id != k.current.id
                        || o.previous.as_ref().map(|p| &p.id) != k.previous.as_ref().map(|p| &p.id)
                        || o.source != k.source
                });
                if changed {
                    tracing::info!(
                        source = %k.source,
                        current = %k.current.id,
                        previous = k.previous.as_ref().map(|p| p.id.as_str()),
                        "ticket keys loaded"
                    );
                }
                i.keys.store(Some(Arc::new(k)));
                *err = None;
                Ok(())
            }
            Err(e) => {
                let held = i.keys.load_full().is_some();
                tracing::error!(
                    error = %format!("{e:#}"),
                    keeping_previous = held,
                    "cannot load the ticket keys"
                );
                if !held {
                    *err = Some(format!("{e:#}"));
                }
                Err(e)
            }
        }
    }

    /// Re-read the keys every [`KEY_REFRESH`].
    pub fn spawn_key_refresh(&self) {
        if !self.configured() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEY_REFRESH).await;
                let _ = me.load_keys().await;
            }
        });
    }

    /// Why no ticket can be issued or checked right now, if so.
    pub fn unavailable(&self) -> Option<String> {
        let Some(i) = self.inner() else {
            return Some(
                "this prompto has no ticket key configured (PROMPTO_TICKET_KEY_VAULT_PATH or \
                 PROMPTO_TICKET_KEY_FILE), so it cannot issue or accept tickets"
                    .into(),
            );
        };
        if !i
            .misplaced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            return Some(
                "this prompto keeps an approval secret where agents can read it, so it issues \
                 and accepts no tickets until the operator moves it (see its journal)"
                    .into(),
            );
        }
        if !i
            .policy_block
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            return Some(
                "this prompto's policy grants root or its service user's shell on the host it \
                 runs on, which reads the approval secrets, so it issues and accepts no tickets \
                 until the operator fixes the policy (see its journal)"
                    .into(),
            );
        }
        if i.keys.load().is_none() {
            let why = i
                .key_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_default();
            // The detail (paths, vault's error) is in the journal.
            tracing::debug!(why, "ticket keys unavailable");
            return Some("this prompto could not load its ticket key (see its journal)".into());
        }
        let st = i.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.file.is_err() {
            return Some(
                "this prompto cannot write its approval state file (see its journal)".into(),
            );
        }
        None
    }

    /// S6.4: the deciding rule (`demand`) demands `required`; does the
    /// call carry a ticket that fits it? Spends the ticket's nonce unless
    /// the call is a dry run (precheck) or the ticket is scoped. `on` is
    /// the host for messages.
    pub fn require(
        &self,
        inv: Option<&Inventory>,
        ctx: &CallCtx,
        tool: &str,
        demand: &Demand,
        on: Option<&str>,
        required: Approval,
    ) -> Result<(), ClassifiedError> {
        let rule = demand.rule.as_str();
        let refuse = |msg: String| {
            Err(ClassifiedError::refused(
                ErrorClass::RefusedTicket,
                format!("refused_ticket: {msg}"),
            )
            .with_rule(rule))
        };
        // A second authorization in the same call: the ticket was checked
        // (and spent) by the first.
        if let Some(t) = ctx.notes().ticket {
            if let Some(scope) = &t.scope
                && let Err(e) = scope.check(rule, demand.root)
            {
                return refuse(e);
            }
            if ticket::satisfies(t.approval, required) {
                return Ok(());
            }
            return refuse(format!(
                "the ticket carries approval {:?}, rule {rule} requires {:?}",
                t.approval.as_str(),
                required.as_str()
            ));
        }
        let args = ctx
            .call
            .as_ref()
            .map(|c| c.args.clone())
            .unwrap_or_default();
        let presented = match args.get("ticket") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) => Some(s.as_str()),
            Some(_) => return refuse("the `ticket` argument must be a string".into()),
        };
        let Some(presented) = presented else {
            return Err(ClassifiedError::refused(
                ErrorClass::ApprovalRequired,
                approval_required_message(ctx, tool, rule, on, required, self.unavailable()),
            )
            .with_rule(rule));
        };
        if let Some(why) = self.unavailable() {
            return refuse(why);
        }
        let i = self.inner().expect("available implies configured");
        let keys = i.keys.load_full().expect("available implies keys");
        let claims = match ticket::decode(&keys, presented) {
            Ok(c) => c,
            Err(e) => return refuse(e),
        };
        let (host, dest_host) = authz::bound_hosts(tool, &args, inv);
        let digest = crate::canon::args_sha256(&args);
        let now = ticket::unix_now();
        let expect = Expect {
            agent: ctx.agent_name(),
            session: ctx.session_id.as_deref(),
            tool,
            host: host.as_deref(),
            dest_host: dest_host.as_deref(),
            args_sha256: &digest,
            required,
            rule,
            root: demand.root,
            now,
        };
        if let Err(e) = expect.check(&claims) {
            return refuse(e);
        }
        if !claims.scoped {
            let mut st = i.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.replay.contains(&claims.nonce) {
                return refuse(
                    "ticket was already used (tickets are single-use) — get a new one".into(),
                );
            }
            if !ctx.dry_run {
                st.replay.prune(now);
                if let Err(e) = st.append(&format!("n {} {}", claims.exp, claims.nonce), now) {
                    tracing::error!(error = %e, "cannot record a ticket's use; call refused");
                    return Err(ClassifiedError::refused(
                        ErrorClass::Internal,
                        "refused: prompto cannot record the ticket's use (approval state file), \
                         and never accepts a ticket it could see again. Nothing was run."
                            .to_string(),
                    ));
                }
                if let Err(e) = st.replay.insert(&claims.nonce, claims.exp, now) {
                    return refuse(e);
                }
            }
        }
        let note = TicketNote {
            approval: claims.approval,
            approved_by: claims.approved_by.clone(),
            scoped: claims.scoped,
            scope: claims.scope.clone(),
        };
        ctx.note(|n| n.ticket = Some(note));
        tracing::info!(
            request_id = %ctx.request_id,
            agent = ctx.agent_name(),
            tool,
            approval = claims.approval.as_str(),
            approved_by = claims.approved_by.as_deref(),
            scoped = claims.scoped,
            dry_run = ctx.dry_run,
            "ticket accepted"
        );
        Ok(())
    }

    /// Mint a ticket for the call in `ctx` (`ctx.call` holds its tool and
    /// arguments; its notes, the rules that demanded an approval, see
    /// [`scope_of`]). `scope_minutes`: an "approve similar calls" ticket,
    /// bound to those rules and to the call's root-capability.
    /// `allow_root_scope` must be set for a root-capable call's scope.
    pub fn mint(
        &self,
        inv: Option<&Inventory>,
        ctx: &CallCtx,
        approval: Approval,
        approved_by: Option<String>,
        scope_minutes: Option<u32>,
        allow_root_scope: bool,
    ) -> Result<(String, Claims), String> {
        if let Some(why) = self.unavailable() {
            return Err(why);
        }
        let i = self.inner().expect("available implies configured");
        let keys = i.keys.load_full().expect("available implies keys");
        let call = ctx.call.as_ref().ok_or("no call to mint a ticket for")?;
        let agent = ctx.agent.as_ref().ok_or("no agent identity")?;
        if let Some(m) = scope_minutes
            && (m == 0 || m > ticket::MAX_SCOPE_MINUTES)
        {
            return Err(format!(
                "scope_minutes must be 1..={}",
                ticket::MAX_SCOPE_MINUTES
            ));
        }
        if scope_minutes.is_some() && ctx.session_id.is_none() {
            return Err(
                "a scoped approval needs a session (X-Prompto-Session or `session`): without \
                 one it would cover every session of the agent"
                    .into(),
            );
        }
        let scope = match scope_minutes {
            None => None,
            Some(_) => Some(scope_of(ctx, allow_root_scope)?),
        };
        let (host, dest_host) = authz::bound_hosts(&call.tool, &call.args, inv);
        let now = ticket::unix_now();
        let claims = Claims {
            agent: agent.name.clone(),
            session: ctx.session_id.clone(),
            tool: call.tool.clone(),
            host,
            dest_host,
            args_sha256: match scope_minutes {
                Some(_) => None,
                None => Some(crate::canon::args_sha256(&call.args)),
            },
            approval,
            approved_by,
            iat: now,
            exp: now + scope_minutes.map_or(ticket::TTL_SECS, |m| u64::from(m) * 60),
            nonce: ticket::nonce().map_err(|e| e.to_string())?,
            scoped: scope_minutes.is_some(),
            scope,
        };
        Ok((ticket::mint(&keys, &claims), claims))
    }

    /// Verify an approver's code (S6.3): known, not revoked, not locked
    /// out, a code for current ±1 step that is newer than the last one
    /// accepted. The accepted step is recorded before this returns.
    ///
    /// Unknown, revoked and malformed names fail exactly like a wrong
    /// code — same message, and the same TOTP computation against a
    /// dummy secret — so the answer doesn't say which names exist.
    pub async fn verify_approver(&self, name: &str, code: &str) -> Result<(), ApproveError> {
        const INVALID: &str = "invalid approver or code";
        let i = self
            .inner()
            .ok_or_else(|| ApproveError::Unavailable(self.unavailable().unwrap_or_default()))?;
        // Names come from callers: one that could not be an approver is
        // refused before any lookup, and never tracked (the lockout map
        // is keyed by name).
        if crate::agent::validate_name("approver", name).is_err() {
            tracing::warn!(
                approver = %crate::audit::clamp(name, 64),
                "approval refused: malformed approver name"
            );
            return Err(ApproveError::Refused(INVALID.into()));
        }
        let now = ticket::unix_now();
        let list = Approvers::from_path(&i.cfg.approvers_path).map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "cannot read the approvers file");
            ApproveError::Unavailable(UNVERIFIABLE.into())
        })?;
        let entry = list.approvers.get(name).filter(|e| !e.disabled);
        let known = entry.is_some();
        if let Some(until) = i
            .guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .locked(name, known, now)
        {
            return Err(ApproveError::Locked(name.to_string(), until));
        }
        let fail = |why: &str| {
            let locked = i
                .guard
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fail(name, known, now);
            tracing::warn!(
                approver = name,
                known,
                why,
                locked = locked.is_some(),
                "approval refused"
            );
            match locked {
                Some(until) => ApproveError::Locked(name.to_string(), until),
                None => ApproveError::Refused(why.to_string()),
            }
        };
        let secret = match entry {
            Some(entry) => {
                let unavailable = |e: anyhow::Error| {
                    tracing::error!(approver = name, error = %format!("{e:#}"), "cannot read an approver's TOTP secret");
                    ApproveError::Unavailable(UNVERIFIABLE.into())
                };
                let factor = entry.factor().map_err(unavailable)?;
                if let Err(e) = i.cfg.private.check_factor(&factor) {
                    // Edited in since the last check: approvals off now.
                    self.check_placement();
                    return Err(unavailable(e));
                }
                approvers::secret(&factor, i.vault.as_deref())
                    .await
                    .map_err(unavailable)?
            }
            None => DUMMY_SECRET.to_vec(),
        };
        let step = crate::totp::matching_step(&secret, code, now);
        let Some(step) = step.filter(|_| known) else {
            return Err(fail(INVALID));
        };
        let mut st = i.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.steps.get(name).is_some_and(|&last| step <= last) {
            drop(st);
            return Err(fail("this code was already used — wait for the next one"));
        }
        st.append(&format!("t {step} {name}"), now).map_err(|e| {
            tracing::error!(error = %e, "cannot record a TOTP step; approval refused");
            ApproveError::Unavailable("cannot record the approval (state file)".into())
        })?;
        st.steps.insert(name.to_string(), step);
        drop(st);
        i.guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .succeed(name);
        Ok(())
    }
}

/// What `/v1/approve` says when an approver's factor can't be read —
/// the same for every name (details in the journal).
const UNVERIFIABLE: &str = "cannot verify approver codes right now (see the journal)";

/// The secret an unknown approver's code is checked against, so that
/// path does the same work as a known one. Never matches anything that
/// counts: the result is discarded.
const DUMMY_SECRET: [u8; crate::totp::SECRET_LEN] = [0x5a; crate::totp::SECRET_LEN];

/// What a scoped ticket for the call in `ctx` is bound to: the rules
/// that demanded an approval in its authorization (noted by `authz`),
/// and whether it is root-capable.
///
/// A scope frees the arguments, so for a root-capable call it is "any
/// root command on that host for N minutes" — a root shell in all but
/// name. That is refused unless the approver asked for it explicitly
/// (`allow_root_scope`); the ticket is then still bound to root calls
/// under the same rule(s), never to plain ones, and the reverse.
pub fn scope_of(ctx: &CallCtx, allow_root_scope: bool) -> Result<Scope, String> {
    let demands = ctx.notes().demands;
    if demands.is_empty() {
        return Err("no policy rule demanded an approval for this call".into());
    }
    let root = demands.iter().any(|d| d.root);
    if root && demands.iter().any(|d| !d.root) {
        return Err(
            "a scoped approval cannot cover a call that is root-capable on one host and not on \
             the other"
                .into(),
        );
    }
    if root && !allow_root_scope {
        return Err(
            "this call is root-capable: a scoped approval would cover any root command for its \
             duration. Approve it on its own, or have the approver set allow_root_scope = true"
                .into(),
        );
    }
    let mut rules: Vec<String> = Vec::new();
    for d in demands {
        if !rules.contains(&d.rule) {
            rules.push(d.rule);
        }
    }
    Ok(Scope { root, rules })
}

/// The refusal for a call that needs an approval and carries no ticket:
/// what to do about it.
fn approval_required_message(
    ctx: &CallCtx,
    tool: &str,
    rule: &str,
    on: Option<&str>,
    required: Approval,
    unavailable: Option<String>,
) -> String {
    let on = on.map(|h| format!(" on {h}")).unwrap_or_default();
    let head = format!(
        "approval_required: rule {rule} grants agent {} {tool}{on} only with approval = \"{}\", \
         and this call carries no `ticket`.",
        ctx.agent_name(),
        required.as_str()
    );
    if let Some(why) = unavailable {
        return format!("{head} It is refused: {why}. Ask the operator.");
    }
    match required {
        Approval::Human => format!(
            "{head} A human must approve it: POST /v1/precheck with this exact call (it answers \
             `ask`), then POST /v1/approve with the approver's name and their current TOTP \
             code; retry with the returned ticket as the `ticket` argument (single-use, \
             120 s)."
        ),
        _ => format!(
            "{head} POST /v1/precheck with this exact call returns a ticket; retry with it as \
             the `ticket` argument (single-use, 120 s)."
        ),
    }
}

async fn read_keys(cfg: &ApprovalConfig, vault: Option<&VaultClient>) -> Result<KeySet> {
    let mut errors = Vec::new();
    if let Some(path) = &cfg.key_vault_path {
        // Never even read a key agents could read: it is no key.
        if let Err(e) = cfg
            .private
            .check_path("the ticket key (PROMPTO_TICKET_KEY_VAULT_PATH)", path)
        {
            bail!("{e:#}");
        }
        match vault {
            None => errors.push(format!(
                "PROMPTO_TICKET_KEY_VAULT_PATH={path} but no vault is configured \
                 (PROMPTO_VAULT_TOKEN)"
            )),
            Some(v) => match read_vault_keys(v, path).await {
                Ok(k) => return Ok(k),
                Err(e) => errors.push(format!(
                    "vault {}/{path}: {e:#} (the ticket key is read from the private mount, \
                     PROMPTO_PRIVATE_MOUNT)",
                    v.mount()
                )),
            },
        }
    }
    if let Some(file) = &cfg.key_file {
        match approvers::read_owner_only(file)
            .and_then(|t| KeySet::from_file_text(&t, format!("file:{}", file.display())))
        {
            Ok(k) => {
                if !errors.is_empty() {
                    tracing::warn!(errors = ?errors, "ticket keys: vault unavailable, using the key file");
                }
                return Ok(k);
            }
            Err(e) => errors.push(format!("{}: {e:#}", file.display())),
        }
    }
    bail!("{}", errors.join("; "))
}

async fn read_vault_keys(v: &VaultClient, path: &str) -> Result<KeySet> {
    crate::vault::validate_kv_path(path)?;
    let current =
        ticket::Key::parse(&v.kv2_field(path, "current").await?).context("field `current`")?;
    let previous = match v.kv2_field(path, "previous").await {
        Ok(p) if p.trim().is_empty() => None,
        Ok(p) => Some(ticket::Key::parse(&p).context("field `previous`")?),
        Err(e) if e.to_string().contains("has no field") => None,
        Err(e) => return Err(e),
    };
    Ok(KeySet {
        current,
        previous,
        source: format!("vault:{}/{path}", v.mount()),
    })
}
