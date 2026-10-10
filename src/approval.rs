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
//!   appended to the state file before the call proceeds, and reloaded
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
use crate::ticket::{self, Claims, Expect, KeySet, Replay};
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
    pub key_vault_path: Option<String>,
    pub key_file: Option<PathBuf>,
    pub approvers_path: PathBuf,
    pub state_path: PathBuf,
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
        f.write_all(format!("{line}\n").as_bytes())
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
    /// reason (state file), so a broken approval setup can't stop calls
    /// that need no approval.
    pub fn new(cfg: ApprovalConfig, vault: Option<Arc<VaultClient>>) -> Self {
        let state = State::open(&cfg.state_path, ticket::unix_now());
        if let Err(e) = &state.file {
            tracing::error!(
                error = %e,
                "APPROVAL STATE FILE UNUSABLE — calls that need a ticket are refused until it can \
                 be written (PROMPTO_APPROVAL_STATE)"
            );
        }
        Self(Some(Arc::new(Inner {
            cfg,
            vault,
            keys: ArcSwapOption::empty(),
            key_error: Mutex::new(Some("no key loaded yet".into())),
            state: Mutex::new(state),
            guard: Mutex::new(Guard::default()),
        })))
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

    /// Read the keys from vault, else the file. On failure the keys in
    /// hand are kept.
    pub async fn load_keys(&self) -> Result<()> {
        let Some(i) = self.inner() else {
            return Ok(());
        };
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

    /// S6.4: the deciding rule demands `required`; does the call carry a
    /// ticket that fits it? Spends the ticket's nonce unless the call is
    /// a dry run (precheck) or the ticket is scoped. `on` is the host for
    /// messages.
    #[allow(clippy::too_many_arguments)]
    pub fn require(
        &self,
        inv: Option<&Inventory>,
        ctx: &CallCtx,
        tool: &str,
        rule: &str,
        on: Option<&str>,
        required: Approval,
    ) -> Result<(), ClassifiedError> {
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
    /// arguments). `scope_minutes`: an "approve similar calls" ticket.
    pub fn mint(
        &self,
        inv: Option<&Inventory>,
        ctx: &CallCtx,
        approval: Approval,
        approved_by: Option<String>,
        scope_minutes: Option<u32>,
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
        };
        Ok((ticket::mint(&keys, &claims), claims))
    }

    /// Verify an approver's code (S6.3): known, not revoked, not locked
    /// out, a code for current ±1 step that is newer than the last one
    /// accepted. The accepted step is recorded before this returns.
    pub async fn verify_approver(&self, name: &str, code: &str) -> Result<(), ApproveError> {
        let i = self
            .inner()
            .ok_or_else(|| ApproveError::Unavailable(self.unavailable().unwrap_or_default()))?;
        let now = ticket::unix_now();
        if let Some(until) = i
            .guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .locked(name, now)
        {
            return Err(ApproveError::Locked(name.to_string(), until));
        }
        let fail = |why: &str| {
            let locked = i
                .guard
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fail(name, now);
            tracing::warn!(
                approver = name,
                why,
                locked = locked.is_some(),
                "approval refused"
            );
            match locked {
                Some(until) => ApproveError::Locked(name.to_string(), until),
                None => ApproveError::Refused(why.to_string()),
            }
        };
        let list = Approvers::from_path(&i.cfg.approvers_path).map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "cannot read the approvers file");
            ApproveError::Unavailable("cannot read the approvers file (see the journal)".into())
        })?;
        // Unknown and revoked approvers fail like a wrong code, so the
        // answer doesn't say which names exist.
        let Some(entry) = list.approvers.get(name).filter(|e| !e.disabled) else {
            return Err(fail("invalid approver or code"));
        };
        let factor = entry
            .factor()
            .map_err(|e| ApproveError::Unavailable(e.to_string()))?;
        let secret = approvers::secret(&factor, i.vault.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(approver = name, error = %format!("{e:#}"), "cannot read an approver's TOTP secret");
                ApproveError::Unavailable(format!(
                    "cannot read approver {name}'s TOTP secret (see the journal)"
                ))
            })?;
        let Some(step) = crate::totp::matching_step(&secret, code, now) else {
            return Err(fail("invalid approver or code"));
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
        match vault {
            None => errors.push(format!(
                "PROMPTO_TICKET_KEY_VAULT_PATH={path} but no vault is configured \
                 (PROMPTO_VAULT_TOKEN)"
            )),
            Some(v) => match read_vault_keys(v, path).await {
                Ok(k) => return Ok(k),
                Err(e) => errors.push(format!("vault {path}: {e:#}")),
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
        source: format!("vault:{path}"),
    })
}
