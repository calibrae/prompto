//! Signed approval tickets (roadmap S6.1, S6.4).
//!
//! A ticket is prompto's own statement "agent A, in session S, may make
//! this call" — minted by `POST /v1/precheck` (approval `ticket`) or
//! `POST /v1/approve` (approval `human`, after an approver's TOTP code),
//! carried back by the client as the call's `ticket` argument, and
//! checked by `authz` wherever the deciding policy rule has
//! `approval = "ticket" | "human"`.
//!
//! # Format
//!
//! `pt1.<kid>.<claims>.<mac>`:
//!
//! - `kid`: the first 8 hex digits of SHA-256(key), naming the key that
//!   signed it (current or previous, see [`KeySet`]);
//! - `claims`: base64url (no padding) of the JSON [`Claims`];
//! - `mac`: base64url HMAC-SHA256 over `pt1.<kid>.<claims>` (the exact
//!   bytes sent — the claims are never re-serialized before checking).
//!
//! The claims bind the agent, the session (`X-Prompto-Session`), the
//! tool, the canonical host (and `rsync_sync`'s `dest_host`), the
//! SHA-256 of the canonical arguments (`crate::canon`), the approval
//! level and approver, an expiry and a random nonce. A ticket is opaque
//! to clients: they only copy it into the call.
//!
//! # Single use and scope
//!
//! An ordinary ticket is valid for [`TTL_SECS`] and **one** call: its
//! nonce goes into [`Replay`] when a call uses it. A *scoped* ticket —
//! `/v1/approve` with `scope_minutes`, "approve similar calls" — has no
//! arguments digest and may be used for any number of calls until it
//! expires (at most [`MAX_SCOPE_MINUTES`]), by the same agent, session,
//! tool and host(s). See the README for exactly what "similar" covers.

use crate::policy::Approval;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

/// Format/version prefix.
pub const PREFIX: &str = "pt1";
/// Lifetime of an ordinary (single-use, argument-bound) ticket.
pub const TTL_SECS: u64 = 120;
/// Longest "approve similar calls" scope.
pub const MAX_SCOPE_MINUTES: u32 = 60;
/// Longer strings are refused before any parsing.
pub const MAX_TICKET_LEN: usize = 4096;
/// Shortest accepted key.
pub const MIN_KEY_BYTES: usize = 32;
/// Unexpired nonces [`Replay`] holds at most. A ticket lives 120 s, so
/// this is ~800 ticketed calls a second; beyond it, ticketed calls are
/// refused rather than letting an old nonce be forgotten while still
/// replayable.
pub const MAX_LIVE_NONCES: usize = 100_000;

/// What a ticket says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub agent: String,
    /// The `X-Prompto-Session` the ticket was minted for (`null`: a call
    /// without one).
    pub session: Option<String>,
    pub tool: String,
    /// Canonical inventory name of the call's host (`host`, `client`,
    /// `name` or `source_host`); `null` for hostless tools.
    pub host: Option<String>,
    /// `rsync_sync`'s second host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_host: Option<String>,
    /// [`crate::canon::args_sha256`] of the call; `null` exactly when
    /// `scoped`.
    pub args_sha256: Option<String>,
    /// `ticket` (precheck) or `human` (approve).
    pub approval: Approval,
    /// The approver, for `human`.
    pub approved_by: Option<String>,
    /// Unix seconds.
    pub iat: u64,
    pub exp: u64,
    /// 128 random bits, base64url.
    pub nonce: String,
    /// Multi-use, arguments free (see the module docs).
    #[serde(default)]
    pub scoped: bool,
}

/// One HMAC key.
#[derive(Clone)]
pub struct Key {
    pub id: String,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.id)
    }
}

impl Key {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < MIN_KEY_BYTES {
            bail!(
                "ticket key is {} bytes; at least {MIN_KEY_BYTES} are required",
                bytes.len()
            );
        }
        let id = crate::agent::hex(&crate::agent::sha256(&bytes))[..8].to_string();
        Ok(Self { id, bytes })
    }

    /// A key as configured: base64 (standard or url-safe, padded or not)
    /// of at least [`MIN_KEY_BYTES`] bytes.
    pub fn parse(text: &str) -> Result<Self> {
        let t = text.trim();
        let bytes = [&STANDARD, &URL_SAFE, &URL_SAFE_NO_PAD]
            .iter()
            .find_map(|e| e.decode(t).ok())
            .or_else(|| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(t)
                    .ok()
            })
            .ok_or_else(|| anyhow!("ticket key is not base64"))?;
        Self::new(bytes)
    }

    fn mac(&self, data: &[u8]) -> Hmac<Sha256> {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.bytes).expect("HMAC takes any key");
        m.update(data);
        m
    }
}

/// A fresh key, base64 — `prompto ticket keygen`.
pub fn generate_key() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow!("OS random source failed: {e}"))?;
    Ok(STANDARD.encode(b))
}

/// The keys in force: tickets are signed with `current`; `current` and
/// `previous` are both accepted, so a rotation (new current, old one
/// moved to previous) doesn't invalidate tickets already handed out.
#[derive(Clone, Debug)]
pub struct KeySet {
    pub current: Key,
    pub previous: Option<Key>,
    /// Where they came from, for logs (`vault:<path>`, `file:<path>`).
    pub source: String,
}

impl KeySet {
    pub fn find(&self, id: &str) -> Option<&Key> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .find(|k| k.id == id)
    }

    /// Parse a key file: the current key on the first non-comment line,
    /// optionally the previous one on the next.
    pub fn from_file_text(text: &str, source: String) -> Result<Self> {
        let mut keys = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let current = Key::parse(keys.next().context("no key in the file")?)?;
        let previous = keys.next().map(Key::parse).transpose()?;
        if keys.next().is_some() {
            bail!("more than two keys (current, previous) in the file");
        }
        Ok(Self {
            current,
            previous,
            source,
        })
    }
}

/// Sign `claims` with the current key.
pub fn mint(keys: &KeySet, claims: &Claims) -> String {
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    let signed = format!("{PREFIX}.{}.{body}", keys.current.id);
    let mac = keys.current.mac(signed.as_bytes()).finalize().into_bytes();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(mac))
}

/// Check a ticket's form and signature and decode its claims. Says
/// nothing yet about whether it fits the call ([`Expect::check`]).
pub fn decode(keys: &KeySet, ticket: &str) -> Result<Claims, String> {
    if ticket.len() > MAX_TICKET_LEN {
        return Err("ticket is too long".into());
    }
    let parts: Vec<&str> = ticket.split('.').collect();
    let [prefix, kid, body, mac] = parts[..] else {
        return Err("ticket is malformed (expected pt1.<kid>.<claims>.<mac>)".into());
    };
    if prefix != PREFIX {
        return Err(format!("ticket format {prefix:?} is not {PREFIX:?}"));
    }
    let Some(key) = keys.find(kid) else {
        return Err(format!(
            "ticket was signed with key {kid:?}, which this prompto does not hold (rotated out?)"
        ));
    };
    let mac = URL_SAFE_NO_PAD
        .decode(mac)
        .map_err(|_| "ticket signature is not base64url".to_string())?;
    let signed_len = prefix.len() + kid.len() + body.len() + 2;
    key.mac(&ticket.as_bytes()[..signed_len])
        .verify_slice(&mac)
        .map_err(|_| "ticket signature is invalid (tampered with, or not from this prompto)")?;
    let raw = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| "ticket claims are not base64url".to_string())?;
    let c: Claims =
        serde_json::from_slice(&raw).map_err(|e| format!("ticket claims are malformed: {e}"))?;
    // Signed by us, so these hold unless minting has a bug; checked
    // anyway, since a scoped ticket is the one that frees the arguments.
    if c.scoped != c.args_sha256.is_none() {
        return Err("ticket claims are inconsistent (scope vs arguments digest)".into());
    }
    if c.approval == Approval::None {
        return Err("ticket claims carry no approval".into());
    }
    Ok(c)
}

/// The call a ticket must fit.
#[derive(Clone, Debug)]
pub struct Expect<'a> {
    pub agent: &'a str,
    pub session: Option<&'a str>,
    pub tool: &'a str,
    pub host: Option<&'a str>,
    pub dest_host: Option<&'a str>,
    pub args_sha256: &'a str,
    /// What the deciding rule demands.
    pub required: Approval,
    /// Unix seconds.
    pub now: u64,
}

/// Whether `have` satisfies `need`: a human approval also satisfies a
/// rule that only wants a ticket, never the other way round.
pub fn satisfies(have: Approval, need: Approval) -> bool {
    match need {
        Approval::None => true,
        Approval::Ticket => matches!(have, Approval::Ticket | Approval::Human),
        Approval::Human => have == Approval::Human,
    }
}

impl Expect<'_> {
    /// Does `c` fit this call? `Err` says which part does not.
    pub fn check(&self, c: &Claims) -> Result<(), String> {
        if c.exp <= self.now {
            return Err(format!(
                "ticket expired {} s ago — get a new one",
                self.now - c.exp
            ));
        }
        let lifetime = if c.scoped {
            u64::from(MAX_SCOPE_MINUTES) * 60
        } else {
            TTL_SECS
        };
        if c.exp.saturating_sub(c.iat) > lifetime || c.iat > self.now + 5 {
            return Err("ticket lifetime is out of bounds".into());
        }
        if c.agent != self.agent {
            return Err(format!(
                "ticket is for agent {:?}, not {:?}",
                c.agent, self.agent
            ));
        }
        if c.session.as_deref() != self.session {
            return Err(format!(
                "ticket is for session {:?}, this call has {:?} (X-Prompto-Session)",
                c.session.as_deref().map(crate::sessions::redact),
                self.session.map(crate::sessions::redact)
            ));
        }
        if c.tool != self.tool {
            return Err(format!("ticket is for tool {}, not {}", c.tool, self.tool));
        }
        if c.host.as_deref() != self.host {
            return Err(format!(
                "ticket is for host {:?}, not {:?}",
                c.host, self.host
            ));
        }
        if c.dest_host.as_deref() != self.dest_host {
            return Err(format!(
                "ticket is for dest_host {:?}, not {:?}",
                c.dest_host, self.dest_host
            ));
        }
        if !c.scoped && c.args_sha256.as_deref() != Some(self.args_sha256) {
            return Err(
                "ticket was issued for different arguments (any change, even whitespace in a \
                 command, needs a new ticket)"
                    .into(),
            );
        }
        if !satisfies(c.approval, self.required) {
            return Err(format!(
                "ticket carries approval {:?}, the rule requires {:?}",
                c.approval.as_str(),
                self.required.as_str()
            ));
        }
        Ok(())
    }
}

/// A fresh nonce.
pub fn nonce() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow!("OS random source failed: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

/// Nonces of single-use tickets already used, until they expire. Sized
/// by the TTL: an entry is dropped once its ticket has expired (and so
/// can't be replayed anyway), never before.
#[derive(Debug, Default)]
pub struct Replay {
    used: HashMap<String, u64>,
}

impl Replay {
    pub fn contains(&self, nonce: &str) -> bool {
        self.used.contains_key(nonce)
    }

    /// Record `nonce` (expiring at `exp`) as used. `Err` when it already
    /// was, or the set is full of unexpired nonces.
    pub fn insert(&mut self, nonce: &str, exp: u64, now: u64) -> Result<(), String> {
        if self.used.contains_key(nonce) {
            return Err("ticket was already used (tickets are single-use) — get a new one".into());
        }
        if self.used.len() >= MAX_LIVE_NONCES {
            self.prune(now);
            if self.used.len() >= MAX_LIVE_NONCES {
                return Err("too many tickets in use; try again shortly".into());
            }
        }
        self.used.insert(nonce.to_string(), exp);
        Ok(())
    }

    /// Restore an entry from the state file.
    pub fn restore(&mut self, nonce: &str, exp: u64, now: u64) {
        if exp > now {
            self.used.insert(nonce.to_string(), exp);
        }
    }

    /// Forget the nonces of expired tickets.
    pub fn prune(&mut self, now: u64) {
        self.used.retain(|_, exp| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.used.len()
    }

    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &u64)> {
        self.used.iter()
    }
}

/// Unix seconds now.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> KeySet {
        KeySet {
            current: Key::new(vec![7; 32]).unwrap(),
            previous: None,
            source: "test".into(),
        }
    }

    fn claims(now: u64) -> Claims {
        Claims {
            agent: "a".into(),
            session: Some("s1".into()),
            tool: "ssh_exec".into(),
            host: Some("t1".into()),
            dest_host: None,
            args_sha256: Some("d".repeat(64)),
            approval: Approval::Ticket,
            approved_by: None,
            iat: now,
            exp: now + TTL_SECS,
            nonce: nonce().unwrap(),
            scoped: false,
        }
    }

    fn expect(now: u64) -> Expect<'static> {
        Expect {
            agent: "a",
            session: Some("s1"),
            tool: "ssh_exec",
            host: Some("t1"),
            dest_host: None,
            args_sha256: Box::leak("d".repeat(64).into_boxed_str()),
            required: Approval::Ticket,
            now,
        }
    }

    #[test]
    fn round_trip_and_every_binding_is_checked() {
        let now = 1_000_000;
        let k = keys();
        let c = claims(now);
        let t = mint(&k, &c);
        assert!(t.starts_with(&format!("pt1.{}.", k.current.id)));
        let back = decode(&k, &t).unwrap();
        assert_eq!(back, c);
        expect(now).check(&back).unwrap();

        // Each binding, changed on the call side, is refused.
        let mut e = expect(now);
        e.agent = "b";
        assert!(e.check(&back).unwrap_err().contains("agent"));
        let mut e = expect(now);
        e.session = Some("s2");
        assert!(e.check(&back).unwrap_err().contains("session"));
        let mut e = expect(now);
        e.session = None;
        assert!(e.check(&back).unwrap_err().contains("session"));
        let mut e = expect(now);
        e.tool = "ssh_sudo_exec";
        assert!(e.check(&back).unwrap_err().contains("tool"));
        let mut e = expect(now);
        e.host = Some("t2");
        assert!(e.check(&back).unwrap_err().contains("host"));
        let mut e = expect(now);
        e.dest_host = Some("t2");
        assert!(e.check(&back).unwrap_err().contains("dest_host"));
        let mut e = expect(now);
        e.args_sha256 = "e";
        assert!(e.check(&back).unwrap_err().contains("arguments"));
        let mut e = expect(now);
        e.required = Approval::Human;
        assert!(e.check(&back).unwrap_err().contains("requires \"human\""));
        // Expiry: valid until exp, not at it.
        expect(c.exp - 1).check(&back).unwrap();
        assert!(expect(c.exp).check(&back).unwrap_err().contains("expired"));
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let k = keys();
        let t = mint(&k, &claims(1_000_000));
        let parts: Vec<&str> = t.split('.').collect();
        // Claims swapped for others (a different host), old MAC kept.
        let mut other = claims(1_000_000);
        other.host = Some("t2".into());
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&other).unwrap());
        let forged = format!("{}.{}.{body}.{}", parts[0], parts[1], parts[3]);
        assert!(decode(&k, &forged).unwrap_err().contains("signature"));
        // A flipped MAC character.
        let mut bad = t.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(decode(&k, &bad).unwrap_err().contains("signature"));
        // Signed with another key that happens to claim our kid.
        let foreign = KeySet {
            current: Key {
                id: k.current.id.clone(),
                bytes: vec![8; 32],
            },
            previous: None,
            source: "x".into(),
        };
        let f = mint(&foreign, &claims(1_000_000));
        assert!(decode(&k, &f).unwrap_err().contains("signature"));
        assert!(decode(&k, "pt1.x.y").unwrap_err().contains("malformed"));
        assert!(decode(&k, "pt2.a.b.c").unwrap_err().contains("format"));
    }

    #[test]
    fn rotation_accepts_current_and_previous_only() {
        let old = keys();
        let t_old = mint(&old, &claims(1_000_000));
        let rotated = KeySet {
            current: Key::new(vec![9; 32]).unwrap(),
            previous: Some(old.current.clone()),
            source: "test".into(),
        };
        decode(&rotated, &t_old).unwrap();
        let t_new = mint(&rotated, &claims(1_000_000));
        assert!(t_new.contains(&rotated.current.id));
        decode(&rotated, &t_new).unwrap();
        // Rotated twice: the oldest key is gone.
        let twice = KeySet {
            current: Key::new(vec![10; 32]).unwrap(),
            previous: Some(rotated.current.clone()),
            source: "test".into(),
        };
        assert!(decode(&twice, &t_old).unwrap_err().contains("rotated out"));
        decode(&twice, &t_new).unwrap();
    }

    #[test]
    fn scoped_and_unscoped_claims_must_be_consistent() {
        let k = keys();
        let mut c = claims(1_000_000);
        c.scoped = true; // but still has an args digest
        assert!(
            decode(&k, &mint(&k, &c))
                .unwrap_err()
                .contains("inconsistent")
        );
        c.args_sha256 = None;
        decode(&k, &mint(&k, &c)).unwrap();
        let mut c = claims(1_000_000);
        c.args_sha256 = None; // unscoped without a digest
        assert!(
            decode(&k, &mint(&k, &c))
                .unwrap_err()
                .contains("inconsistent")
        );
    }

    /// A scoped ticket ignores the arguments, nothing else; and it may
    /// live up to the scope limit, an ordinary one only the TTL.
    #[test]
    fn scope_frees_only_the_arguments() {
        let now = 1_000_000;
        let mut c = claims(now);
        c.scoped = true;
        c.args_sha256 = None;
        c.approval = Approval::Human;
        c.exp = now + 60 * 60;
        let mut e = expect(now);
        e.args_sha256 = "anything";
        e.required = Approval::Human;
        e.check(&c).unwrap();
        e.host = Some("t2");
        assert!(e.check(&c).is_err());
        let mut c2 = claims(now);
        c2.exp = now + TTL_SECS + 1;
        assert!(expect(now).check(&c2).unwrap_err().contains("lifetime"));
    }

    #[test]
    fn approval_levels() {
        assert!(satisfies(Approval::Human, Approval::Ticket));
        assert!(satisfies(Approval::Human, Approval::Human));
        assert!(satisfies(Approval::Ticket, Approval::Ticket));
        assert!(!satisfies(Approval::Ticket, Approval::Human));
    }

    #[test]
    fn replay_set_refuses_reuse_and_forgets_only_expired() {
        let mut r = Replay::default();
        r.insert("n1", 200, 100).unwrap();
        assert!(
            r.insert("n1", 200, 150)
                .unwrap_err()
                .contains("already used")
        );
        r.prune(199);
        assert!(r.contains("n1"));
        r.prune(200);
        assert!(!r.contains("n1"));
    }

    #[test]
    fn keys_parse_from_base64_and_files() {
        let k = generate_key().unwrap();
        Key::parse(&k).unwrap();
        assert!(
            Key::parse("c2hvcnQ=")
                .unwrap_err()
                .to_string()
                .contains("bytes")
        );
        let set = KeySet::from_file_text(
            &format!("# rotated 2026-10-10\n{k}\n{}\n", generate_key().unwrap()),
            "file".into(),
        )
        .unwrap();
        assert!(set.previous.is_some());
        assert!(KeySet::from_file_text("# nothing\n", "f".into()).is_err());
    }
}
