//! Agent identity: static role tokens (roadmap E2).
//!
//! One bearer token per agent *role*, listed in `agents.toml` by the
//! SHA-256 of the token — never the token itself:
//!
//! ```toml
//! [agent.builder]
//! groups = ["build"]
//! token_sha256 = "<64 hex chars>"
//! created = "2026-10-09T12:00:00Z"
//! disabled = false
//! ```
//!
//! The HTTP middleware ([`authenticate_request`]) hashes the presented
//! token and compares it against every entry in constant time, then
//! installs the result in a task-local that the rmcp factory snapshots
//! onto the per-request `Prompto`, exactly like the caller IP.
//!
//! The Claude session ID arrives separately, in `X-Prompto-Session`. It
//! is context for the audit trail, never proof of identity: anyone
//! holding a role token can claim any session.

use crate::ctx::Agent;
use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Agent name for calls without a valid token under `PROMPTO_AUTH=optional`.
pub const ANONYMOUS: &str = "anonymous";
/// Agent name for the stdio transport: whoever started the process.
pub const LOCAL: &str = "local";
/// Prefix of minted tokens, so a leaked one is recognisable in a paste
/// or a secret scanner.
pub const TOKEN_PREFIX: &str = "pto_";
/// Request header carrying the Claude session ID (context only).
pub const SESSION_HEADER: &str = "x-prompto-session";
/// Longest accepted `X-Prompto-Session` value. Claude session IDs are
/// UUIDs (36 chars); this leaves room for other clients' formats while
/// keeping a hostile header out of every log line.
pub const MAX_SESSION_LEN: usize = 128;

/// `PROMPTO_AUTH`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// No authentication; calls carry no agent. Today's behaviour, and
    /// the default so an existing deployment is unchanged.
    #[default]
    Off,
    /// A valid token names the agent; anything else is `anonymous`.
    Optional,
    /// A valid token is mandatory: everything else is a 401.
    Required,
}

impl AuthMode {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "off" => Ok(AuthMode::Off),
            "optional" => Ok(AuthMode::Optional),
            "required" => Ok(AuthMode::Required),
            other => bail!("PROMPTO_AUTH={other:?}: expected off, optional or required"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Off => "off",
            AuthMode::Optional => "optional",
            AuthMode::Required => "required",
        }
    }
}

/// One `[agent.<name>]` entry of `agents.toml`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentEntry {
    #[serde(default)]
    pub groups: Vec<String>,
    /// Lowercase hex SHA-256 of the token.
    pub token_sha256: String,
    /// RFC 3339 timestamp, informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Revoked: the token is refused (401 when required, anonymous plus a
    /// warning when optional). Kept rather than deleted so the name stays
    /// taken and a stale token is reported as revoked, not unknown.
    #[serde(default)]
    pub disabled: bool,
}

/// The parsed, validated `agents.toml`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Agents {
    #[serde(rename = "agent", default)]
    pub agents: BTreeMap<String, AgentEntry>,
}

/// `[a-z0-9][a-z0-9_-]{0,63}`: names land in log fields, audit records
/// and (E8) SSH certificate key IDs, so keep them boring.
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !name.starts_with(['-', '_']);
    if !ok {
        bail!("{kind} {name:?}: use 1-64 of a-z 0-9 - _ (not starting with - or _)");
    }
    Ok(())
}

impl Agents {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let agents: Agents = toml::from_str(s).context("parse agents TOML")?;
        agents.validate()?;
        Ok(agents)
    }

    /// Missing file = no agents; anything else unreadable is an error.
    pub fn from_path(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Self::from_toml_str(&raw).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read agents file {}", path.display())),
        }
    }

    fn validate(&self) -> Result<()> {
        let mut hashes = std::collections::HashSet::new();
        for (name, e) in &self.agents {
            validate_name("agent", name)?;
            if name == ANONYMOUS || name == LOCAL {
                bail!("agent {name:?}: reserved name");
            }
            for g in &e.groups {
                validate_name("group", g).with_context(|| format!("agent {name}"))?;
            }
            parse_digest(&e.token_sha256).with_context(|| format!("agent {name}"))?;
            // Two entries with one token would make the caller's identity
            // depend on table order.
            if !hashes.insert(e.token_sha256.as_str()) {
                bail!("agent {name}: token_sha256 duplicates another agent's");
            }
        }
        Ok(())
    }

    pub fn to_toml_string(&self) -> Result<String> {
        Ok(toml::to_string(self)?)
    }

    /// Look a presented token up. Every entry is compared, in constant
    /// time, whatever matches first — see [`scan`].
    pub fn authenticate(&self, token: &str) -> AuthResult {
        let digest = sha256(token.as_bytes());
        match scan(
            self.agents
                .iter()
                .filter_map(|(n, e)| parse_digest(&e.token_sha256).ok().map(|d| (n, e, d))),
            &digest,
            digests_equal,
        ) {
            None => AuthResult::Unknown,
            Some((name, e)) if e.disabled => AuthResult::Revoked(name.clone()),
            Some((name, e)) => AuthResult::Valid(Agent {
                name: name.clone(),
                groups: e.groups.clone(),
            }),
        }
    }
}

/// Outcome of checking a bearer token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthResult {
    Valid(Agent),
    /// Matches an entry with `disabled = true`.
    Revoked(String),
    /// Matches nothing.
    Unknown,
}

/// The token comparison. `subtle`'s `ct_eq` does not stop at the first
/// differing byte, so response timing says nothing about how close a
/// guess was. (Comparing digests rather than tokens already blunts that;
/// this closes it.)
pub fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Compare `digest` with every entry using `eq`, never returning early,
/// so the time taken depends on the number of agents and not on which
/// one (if any) matched.
fn scan<'a, I>(
    entries: I,
    digest: &[u8; 32],
    eq: impl Fn(&[u8; 32], &[u8; 32]) -> bool,
) -> Option<(&'a String, &'a AgentEntry)>
where
    I: Iterator<Item = (&'a String, &'a AgentEntry, [u8; 32])>,
{
    let mut found = None;
    for (name, entry, d) in entries {
        if eq(&d, digest) && found.is_none() {
            found = Some((name, entry));
        }
    }
    found
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_digest(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("token_sha256 must be 64 lowercase hex characters");
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

/// A fresh token: [`TOKEN_PREFIX`] + 32 bytes from the OS RNG, base64url
/// (256 bits — not guessable, and fine to store only as an unsalted hash).
pub fn mint_token() -> Result<String> {
    use base64::Engine;
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("OS random source failed: {e}"))?;
    Ok(format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    ))
}

/// `agents.toml`, hot-swappable on SIGHUP like the inventory.
#[derive(Clone)]
pub struct AgentStore {
    inner: Arc<ArcSwap<Agents>>,
    path: Option<PathBuf>,
}

impl Default for AgentStore {
    fn default() -> Self {
        Self::new(Agents::default(), None)
    }
}

impl AgentStore {
    pub fn new(agents: Agents, path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(agents)),
            path,
        }
    }

    pub fn load_from(path: PathBuf) -> Result<Self> {
        let agents = Agents::from_path(&path)?;
        Ok(Self::new(agents, Some(path)))
    }

    pub fn snapshot(&self) -> Arc<Agents> {
        self.inner.load_full()
    }

    /// Re-read the file. On error the live store is left unchanged.
    /// Returns the number of agents (disabled included).
    pub fn reload(&self) -> Result<usize> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("no agents path configured — cannot reload"))?;
        let new = Agents::from_path(path)?;
        let n = new.agents.len();
        self.inner.store(Arc::new(new));
        Ok(n)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// HTTP auth configuration: mode, the token store and the policy.
#[derive(Clone, Default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub store: AgentStore,
    /// `policy.toml`. Ignored with `off`; otherwise enforced, and the
    /// default (no rules) denies every call.
    pub policy: crate::policy::PolicyStore,
}

impl AuthConfig {
    /// The policy to enforce on calls: `None` with `PROMPTO_AUTH=off`
    /// (pre-E3 behaviour), the rules plus the live agent store otherwise.
    pub fn enforcer(&self) -> Option<crate::policy::Enforcer> {
        (self.mode != AuthMode::Off).then(|| crate::policy::Enforcer {
            policy: self.policy.clone(),
            agents: self.store.clone(),
        })
    }
}

/// Who is calling, as far as the transport knows. Snapshotted onto each
/// `Prompto` instance and copied into every `CallCtx`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// `None` only with `PROMPTO_AUTH=off`.
    pub agent: Option<Agent>,
    pub session_id: Option<String>,
}

impl Identity {
    /// The stdio transport: whoever launched the process.
    pub fn local() -> Self {
        Self {
            agent: Some(Agent {
                name: LOCAL.into(),
                groups: vec![],
            }),
            session_id: None,
        }
    }

    pub fn anonymous(session_id: Option<String>) -> Self {
        Self {
            agent: Some(Agent {
                name: ANONYMOUS.into(),
                groups: vec![],
            }),
            session_id,
        }
    }
}

tokio::task_local! {
    static IDENTITY: Identity;
}

/// Run `f` with `id` installed as the current identity.
pub async fn scoped<F: std::future::Future>(id: Identity, f: F) -> F::Output {
    IDENTITY.scope(id, f).await
}

/// The current identity, or the empty one when no scope is active.
pub fn current() -> Identity {
    IDENTITY.try_with(Clone::clone).unwrap_or_default()
}

/// Validate an `X-Prompto-Session` value: 1..=[`MAX_SESSION_LEN`] chars
/// of `A-Za-z0-9 . _ : -`. Anything else is dropped (the call proceeds
/// without a session), since the value is context, not a credential.
pub fn parse_session(raw: &str) -> Option<String> {
    let ok = !raw.is_empty()
        && raw.len() <= MAX_SESSION_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    ok.then(|| raw.to_string())
}

/// Extract the bearer token from an `Authorization` header value.
/// `None` for anything that isn't `Bearer <non-empty>`.
pub fn bearer(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    let token = rest.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// What the middleware should do with a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Proceed(Identity),
    /// 401. The string is the reason, for the response body.
    Reject(&'static str),
}

/// The auth decision for one HTTP request, separated from axum so it can
/// be unit-tested. `caller` is only for the warning lines.
pub fn authenticate_request(
    cfg: &AuthConfig,
    authorization: Option<&str>,
    session_header: Option<&str>,
    caller: Option<std::net::IpAddr>,
) -> Decision {
    // Off is today's behaviour, logs included: no identity, and the
    // session header is neither parsed nor warned about.
    if cfg.mode == AuthMode::Off {
        return Decision::Proceed(Identity::default());
    }
    let session_id = match session_header {
        None => None,
        Some(raw) => {
            let s = parse_session(raw);
            if s.is_none() {
                tracing::warn!(
                    caller_ip = ?caller,
                    len = raw.len(),
                    "ignoring malformed X-Prompto-Session header"
                );
            }
            s
        }
    };
    let required = cfg.mode == AuthMode::Required;
    let Some(raw) = authorization else {
        if required {
            return Decision::Reject("missing bearer token");
        }
        return Decision::Proceed(Identity::anonymous(session_id));
    };
    // Past here a credential was presented; failures are worth a warning
    // in both modes. The token itself is never logged.
    let result = match bearer(raw) {
        Some(token) => cfg.store.snapshot().authenticate(token),
        None => AuthResult::Unknown,
    };
    match result {
        AuthResult::Valid(agent) => Decision::Proceed(Identity {
            agent: Some(agent),
            session_id,
        }),
        AuthResult::Revoked(name) => {
            tracing::warn!(
                caller_ip = ?caller,
                agent = %name,
                session_id = session_id.as_deref(),
                mode = cfg.mode.as_str(),
                "revoked agent token presented"
            );
            if required {
                Decision::Reject("revoked token")
            } else {
                Decision::Proceed(Identity::anonymous(session_id))
            }
        }
        AuthResult::Unknown => {
            tracing::warn!(
                caller_ip = ?caller,
                session_id = session_id.as_deref(),
                mode = cfg.mode.as_str(),
                "invalid bearer token presented"
            );
            if required {
                Decision::Reject("invalid bearer token")
            } else {
                Decision::Proceed(Identity::anonymous(session_id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI helpers: edits of agents.toml
// ---------------------------------------------------------------------------

/// Add `name` with a fresh token; returns the token (to print once).
pub fn add_agent(agents: &mut Agents, name: &str, groups: Vec<String>) -> Result<String> {
    validate_name("agent", name)?;
    if name == ANONYMOUS || name == LOCAL {
        bail!("agent {name:?}: reserved name");
    }
    if let Some(e) = agents.agents.get(name) {
        bail!(
            "agent {name:?} already exists{} — choose another name",
            if e.disabled { " (revoked)" } else { "" }
        );
    }
    for g in &groups {
        validate_name("group", g)?;
    }
    let token = mint_token()?;
    agents.agents.insert(
        name.to_string(),
        AgentEntry {
            groups,
            token_sha256: hex(&sha256(token.as_bytes())),
            created: Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            disabled: false,
        },
    );
    agents.validate()?;
    Ok(token)
}

/// Mark `name` disabled. Errors if unknown; idempotent if already revoked.
pub fn revoke_agent(agents: &mut Agents, name: &str) -> Result<bool> {
    let e = agents
        .agents
        .get_mut(name)
        .ok_or_else(|| anyhow!("no agent named {name:?}"))?;
    let changed = !e.disabled;
    e.disabled = true;
    Ok(changed)
}

/// Write `contents` to `path` atomically (temp file in the same
/// directory, fsync, rename). An existing file's mode and owner are kept;
/// a new file is 0640 and takes the directory's group, which on a
/// standard install (`/etc/prompto`, `root:prompto`) is what lets the
/// service read it.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (mode, uid, gid) = match std::fs::metadata(path) {
        Ok(m) => (m.mode() & 0o7777, Some(m.uid()), Some(m.gid())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let d = std::fs::metadata(dir).with_context(|| format!("{}", dir.display()))?;
            (0o640, None, Some(d.gid()))
        }
        Err(e) => return Err(e).with_context(|| format!("{}", path.display())),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        // Restrictive before any content lands, then the final mode.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        // chown is allowed to fail for non-root on a file we own with the
        // same ids already; only report it when it would change something.
        if let Err(e) = std::os::unix::fs::fchown(&f, uid, gid) {
            let m = f.metadata()?;
            if uid.is_some_and(|u| u != m.uid()) || gid.is_some_and(|g| g != m.gid()) {
                return Err(e).context("preserve owner/group");
            }
        }
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agents_with(entries: &[(&str, &str, bool)]) -> Agents {
        let mut a = Agents::default();
        for (name, token, disabled) in entries {
            a.agents.insert(
                name.to_string(),
                AgentEntry {
                    groups: vec!["g".into()],
                    token_sha256: hex(&sha256(token.as_bytes())),
                    created: None,
                    disabled: *disabled,
                },
            );
        }
        a.validate().unwrap();
        a
    }

    fn cfg(mode: AuthMode, a: Agents) -> AuthConfig {
        AuthConfig {
            mode,
            store: AgentStore::new(a, None),
            policy: Default::default(),
        }
    }

    #[test]
    fn auth_mode_parses_and_rejects_typos() {
        assert_eq!(AuthMode::parse("off").unwrap(), AuthMode::Off);
        assert_eq!(AuthMode::parse(" Optional ").unwrap(), AuthMode::Optional);
        assert_eq!(AuthMode::parse("required").unwrap(), AuthMode::Required);
        // A typo must not silently mean "off".
        assert!(AuthMode::parse("requried").is_err());
    }

    #[test]
    fn valid_revoked_and_unknown_tokens() {
        let a = agents_with(&[("alpha", "pto_a", false), ("beta", "pto_b", true)]);
        assert_eq!(
            a.authenticate("pto_a"),
            AuthResult::Valid(Agent {
                name: "alpha".into(),
                groups: vec!["g".into()]
            })
        );
        assert_eq!(a.authenticate("pto_b"), AuthResult::Revoked("beta".into()));
        assert_eq!(a.authenticate("pto_c"), AuthResult::Unknown);
        assert_eq!(a.authenticate(""), AuthResult::Unknown);
    }

    /// The scan compares against every entry even after a match, and the
    /// production comparator is `subtle`'s.
    #[test]
    fn scan_never_stops_early() {
        let a = agents_with(&[
            ("a1", "t1", false),
            ("a2", "t2", false),
            ("a3", "t3", false),
        ]);
        let digest = sha256(b"t1");
        let calls = std::cell::Cell::new(0);
        let hit = scan(
            a.agents
                .iter()
                .map(|(n, e)| (n, e, parse_digest(&e.token_sha256).unwrap())),
            &digest,
            |x, y| {
                calls.set(calls.get() + 1);
                digests_equal(x, y)
            },
        );
        assert_eq!(hit.unwrap().0, "a1");
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn digests_equal_is_exact() {
        let a = sha256(b"x");
        let mut b = a;
        assert!(digests_equal(&a, &b));
        b[31] ^= 1;
        assert!(!digests_equal(&a, &b));
    }

    #[test]
    fn file_validation() {
        let h = hex(&sha256(b"t"));
        let ok = format!("[agent.builder]\ngroups = [\"build\"]\ntoken_sha256 = \"{h}\"\n");
        Agents::from_toml_str(&ok).unwrap();
        for (bad, want) in [
            (format!("[agent.Builder]\ntoken_sha256 = \"{h}\"\n"), "a-z"),
            (
                format!("[agent.anonymous]\ntoken_sha256 = \"{h}\"\n"),
                "reserved",
            ),
            (
                format!("[agent.local]\ntoken_sha256 = \"{h}\"\n"),
                "reserved",
            ),
            (
                "[agent.b]\ntoken_sha256 = \"abc\"\n".into(),
                "64 lowercase hex",
            ),
            (
                format!("[agent.b]\ntoken_sha256 = \"{}\"\n", h.to_uppercase()),
                "64 lowercase hex",
            ),
            (
                format!("[agent.b]\ngroups = [\"Bad Group\"]\ntoken_sha256 = \"{h}\"\n"),
                "group",
            ),
            (
                format!("[agent.a]\ntoken_sha256 = \"{h}\"\n[agent.b]\ntoken_sha256 = \"{h}\"\n"),
                "duplicates",
            ),
            (
                format!("[agent.b]\ntoken = \"x\"\ntoken_sha256 = \"{h}\"\n"),
                "unknown field",
            ),
        ] {
            let err = format!("{:#}", Agents::from_toml_str(&bad).unwrap_err());
            assert!(err.contains(want), "{bad}: {err}");
        }
    }

    #[test]
    fn missing_file_is_no_agents_and_bad_reload_keeps_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agents.toml");
        let store = AgentStore::load_from(path.clone()).unwrap();
        assert!(store.snapshot().agents.is_empty());

        let mut a = Agents::default();
        let tok = add_agent(&mut a, "builder", vec![]).unwrap();
        write_atomic(&path, &a.to_toml_string().unwrap()).unwrap();
        assert_eq!(store.reload().unwrap(), 1);
        assert!(matches!(
            store.snapshot().authenticate(&tok),
            AuthResult::Valid(_)
        ));

        std::fs::write(&path, "this is = = not toml").unwrap();
        assert!(store.reload().is_err());
        assert!(
            matches!(store.snapshot().authenticate(&tok), AuthResult::Valid(_)),
            "a bad file must keep the previous store"
        );
    }

    #[test]
    fn minted_tokens_are_prefixed_long_and_distinct() {
        let a = mint_token().unwrap();
        let b = mint_token().unwrap();
        assert!(a.starts_with(TOKEN_PREFIX));
        assert_eq!(a.len(), TOKEN_PREFIX.len() + 43);
        assert_ne!(a, b);
    }

    #[test]
    fn add_stores_only_the_hash_and_revoke_disables() {
        let mut a = Agents::default();
        let tok = add_agent(&mut a, "builder", vec!["build".into()]).unwrap();
        let text = a.to_toml_string().unwrap();
        assert!(!text.contains(&tok), "token must never be written");
        assert!(text.contains(&hex(&sha256(tok.as_bytes()))));
        assert!(add_agent(&mut a, "builder", vec![]).is_err());
        assert!(add_agent(&mut a, "anonymous", vec![]).is_err());
        assert!(revoke_agent(&mut a, "builder").unwrap());
        assert!(!revoke_agent(&mut a, "builder").unwrap());
        assert_eq!(a.authenticate(&tok), AuthResult::Revoked("builder".into()));
        assert!(revoke_agent(&mut a, "nobody").is_err());
        // Round-trips through the file format.
        let back = Agents::from_toml_str(&a.to_toml_string().unwrap()).unwrap();
        assert!(back.agents["builder"].disabled);
    }

    #[test]
    fn write_atomic_keeps_mode_and_new_files_are_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agents.toml");
        write_atomic(&path, "a").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&path), 0o640);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomic(&path, "b").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temp left"
        );
    }

    #[test]
    fn session_header_bounds() {
        let uuid = "0f8fad5b-d9cb-469f-a165-70867728950e";
        assert_eq!(parse_session(uuid).as_deref(), Some(uuid));
        assert!(parse_session(&"a".repeat(MAX_SESSION_LEN)).is_some());
        assert!(parse_session(&"a".repeat(MAX_SESSION_LEN + 1)).is_none());
        for bad in ["", "a b", "a\nb", "x;rm", "é", "a\"b", "a=b"] {
            assert!(parse_session(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer("Bearer pto_x"), Some("pto_x"));
        assert_eq!(bearer("bearer  pto_x "), Some("pto_x"));
        assert_eq!(bearer("Basic abc"), None);
        assert_eq!(bearer("Bearer "), None);
        assert_eq!(bearer("pto_x"), None);
    }

    #[test]
    fn decisions_per_mode() {
        let a = agents_with(&[("alpha", "good", false), ("beta", "old", true)]);
        let anon = Decision::Proceed(Identity::anonymous(None));
        let alpha = |s: Option<&str>| {
            Decision::Proceed(Identity {
                agent: Some(Agent {
                    name: "alpha".into(),
                    groups: vec!["g".into()],
                }),
                session_id: s.map(Into::into),
            })
        };

        let off = cfg(AuthMode::Off, a.clone());
        assert_eq!(
            authenticate_request(&off, Some("Bearer good"), Some("s1"), None),
            Decision::Proceed(Identity::default()),
            "off ignores the token and the session header alike"
        );

        let opt = cfg(AuthMode::Optional, a.clone());
        assert_eq!(authenticate_request(&opt, None, None, None), anon);
        assert_eq!(
            authenticate_request(&opt, Some("Bearer nope"), None, None),
            anon
        );
        assert_eq!(
            authenticate_request(&opt, Some("Bearer old"), None, None),
            anon
        );
        assert_eq!(
            authenticate_request(&opt, Some("Bearer good"), Some("s1"), None),
            alpha(Some("s1"))
        );

        let req = cfg(AuthMode::Required, a);
        assert!(matches!(
            authenticate_request(&req, None, None, None),
            Decision::Reject(_)
        ));
        assert!(matches!(
            authenticate_request(&req, Some("Bearer nope"), None, None),
            Decision::Reject(_)
        ));
        assert_eq!(
            authenticate_request(&req, Some("Bearer old"), None, None),
            Decision::Reject("revoked token")
        );
        assert_eq!(
            authenticate_request(&req, Some("Bearer good"), Some("bad header!"), None),
            alpha(None),
            "a malformed session header is dropped, not fatal"
        );
    }
}
