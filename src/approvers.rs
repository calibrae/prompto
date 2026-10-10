//! Human approvers (roadmap S6.3): who may turn an `ask` into a ticket.
//!
//! The agent and the Claude Code mod run as the same OS user with the
//! same bearer token, so anything the mod can send, the agent can send
//! too. A human approval must therefore carry something the agent cannot
//! produce. The first such factor is TOTP: each approver enrolls an
//! authenticator app (`prompto approver add <name>`), and
//! `POST /v1/approve` needs `{approver, totp_code}` — a code the human
//! reads off their phone and types into the mod's pane.
//!
//! `approvers.toml` (`PROMPTO_APPROVERS`, default
//! `/etc/prompto/approvers.toml`):
//!
//! ```toml
//! [approver.alice]
//! totp_vault_path = "prompto/approvers/alice"   # KV v2, field totp_secret
//! created = "2026-10-10T12:00:00Z"
//!
//! [approver.bob]
//! totp_file = "/etc/prompto/approvers.d/bob.totp"  # base32, mode 0600
//! disabled = true
//! ```
//!
//! The file is read on every approval (they are human-paced), so an edit
//! or `prompto approver revoke` applies to the next one with no reload.
//! The secret is fetched at that moment too and never kept.
//!
//! [`Factor`] is the seam for other approver mechanisms (approval from a
//! separate device, a Kanidm-authenticated page): `/v1/approve` asks the
//! approver's factor to verify what the request carries.
//!
//! # Brute force
//!
//! A 6-digit code with a ±1 step window gives a guesser 3 chances in a
//! million per try. [`Guard`] allows [`MAX_FAILURES`] failed codes per
//! approver within [`FAILURE_WINDOW_SECS`]; the next locks that approver
//! out for [`LOCKOUT_SECS`] (a correct code is refused too while
//! locked). Accepted codes are single-use: a code for a step at or below
//! the approver's last accepted step is refused (and counts as a
//! failure). Lockouts live in memory; the last accepted step is persisted
//! (`crate::approval`), so a restart can't reopen a used code.

use crate::agent::validate_name;
use crate::vault::VaultClient;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Failed codes tolerated per approver within the window.
pub const MAX_FAILURES: usize = 5;
pub const FAILURE_WINDOW_SECS: u64 = 15 * 60;
pub const LOCKOUT_SECS: u64 = 15 * 60;
/// KV v2 field holding a vault-stored secret.
pub const VAULT_FIELD: &str = "totp_secret";
/// Most approvers [`Guard`] tracks failures for (names come from
/// callers, so unknown ones count too, under a bound).
pub const MAX_TRACKED: usize = 4096;

/// One `[approver.<name>]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_vault_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// Where an approver's second factor lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Factor {
    /// TOTP secret in vault KV v2 (`totp_secret` field).
    TotpVault(String),
    /// TOTP secret in a file (base32, owner-only).
    TotpFile(PathBuf),
}

impl ApproverEntry {
    pub fn factor(&self) -> Result<Factor> {
        match (&self.totp_vault_path, &self.totp_file) {
            (Some(p), None) => {
                crate::vault::validate_kv_path(p)?;
                Ok(Factor::TotpVault(p.clone()))
            }
            (None, Some(f)) => Ok(Factor::TotpFile(f.clone())),
            (Some(_), Some(_)) => bail!("set totp_vault_path or totp_file, not both"),
            (None, None) => bail!("no factor: set totp_vault_path or totp_file"),
        }
    }
}

/// `approvers.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approvers {
    #[serde(default, rename = "approver")]
    pub approvers: BTreeMap<String, ApproverEntry>,
}

impl Approvers {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let a: Approvers = toml::from_str(s)?;
        for (name, e) in &a.approvers {
            validate_name("approver", name)?;
            e.factor().with_context(|| format!("approver {name}"))?;
        }
        Ok(a)
    }

    /// A missing file is no approvers.
    pub fn from_path(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml_str(&s).with_context(|| format!("{}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("{}", path.display())),
        }
    }

    pub fn to_toml_string(&self) -> Result<String> {
        Ok(toml::to_string(self)?)
    }
}

/// Read a secret file, refusing one that anyone but its owner can read
/// or write: it is a credential.
pub fn read_owner_only(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).with_context(|| format!("{}", path.display()))?;
    if m.mode() & 0o077 != 0 {
        bail!(
            "{} is mode {:o}; it holds a secret and must be owner-only (chmod 600)",
            path.display(),
            m.mode() & 0o777
        );
    }
    std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))
}

/// Fetch the approver's TOTP secret.
pub async fn secret(factor: &Factor, vault: Option<&VaultClient>) -> Result<Vec<u8>> {
    let text = match factor {
        Factor::TotpFile(p) => read_owner_only(p)?,
        Factor::TotpVault(path) => {
            let v = vault.ok_or_else(|| {
                anyhow!("the secret is in vault, and this prompto has no vault configured")
            })?;
            v.kv2_field(path, VAULT_FIELD).await?
        }
    };
    let s = crate::totp::base32_decode(text.trim())
        .filter(|s| s.len() >= 10)
        .ok_or_else(|| anyhow!("the TOTP secret is not base32 of at least 80 bits"))?;
    Ok(s)
}

/// Failed attempts and lockouts, per approver name.
///
/// Names come from callers, so the map is bounded: an approver listed in
/// `approvers.toml` (`known`) is always tracked, any other name only
/// while fewer than [`MAX_TRACKED`] are. Past that, failures for names
/// not yet tracked go to one shared bucket that locks them all together
/// — guessing at many names costs the guesser, and never grows memory or
/// touches the real approvers' counters. (Malformed names are refused
/// before they get here, see `Approvals::verify_approver`.)
#[derive(Debug, Default)]
pub struct Guard {
    failures: HashMap<String, Vec<u64>>,
    locked_until: HashMap<String, u64>,
    overflow: Vec<u64>,
    overflow_until: u64,
}

impl Guard {
    /// Would a failure for `name` go to the shared bucket?
    fn overflows(&self, name: &str, known: bool) -> bool {
        !known && !self.failures.contains_key(name) && self.failures.len() >= MAX_TRACKED
    }

    /// Is `name` locked out at `now`? Returns the end of the lockout.
    pub fn locked(&self, name: &str, known: bool, now: u64) -> Option<u64> {
        if let Some(t) = self.locked_until.get(name).copied().filter(|&t| t > now) {
            return Some(t);
        }
        (self.overflows(name, known) && self.overflow_until > now).then_some(self.overflow_until)
    }

    /// Count a failure; the [`MAX_FAILURES`]+1-th within the window
    /// locks the approver. Returns the lockout end when it does.
    pub fn fail(&mut self, name: &str, known: bool, now: u64) -> Option<u64> {
        if self.overflows(name, known) {
            self.failures
                .retain(|_, v| v.iter().any(|&t| t + FAILURE_WINDOW_SECS > now));
            self.locked_until.retain(|_, &mut t| t > now);
        }
        if self.overflows(name, known) {
            let f = &mut self.overflow;
            f.retain(|&t| t + FAILURE_WINDOW_SECS > now);
            f.push(now);
            if f.len() > MAX_FAILURES {
                f.clear();
                self.overflow_until = now + LOCKOUT_SECS;
                return Some(self.overflow_until);
            }
            return None;
        }
        let f = self.failures.entry(name.to_string()).or_default();
        f.retain(|&t| t + FAILURE_WINDOW_SECS > now);
        f.push(now);
        if f.len() > MAX_FAILURES {
            f.clear();
            let until = now + LOCKOUT_SECS;
            self.locked_until.insert(name.to_string(), until);
            return Some(until);
        }
        None
    }

    /// A correct code: the failure count starts over.
    pub fn succeed(&mut self, name: &str) {
        self.failures.remove(name);
    }

    /// Names tracked individually (tests).
    pub fn tracked(&self) -> usize {
        self.failures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates() {
        let a = Approvers::from_toml_str(
            "[approver.alice]\ntotp_vault_path = \"prompto/approvers/alice\"\n\n\
             [approver.bob]\ntotp_file = \"/x/bob.totp\"\ndisabled = true\n",
        )
        .unwrap();
        assert_eq!(
            a.approvers["alice"].factor().unwrap(),
            Factor::TotpVault("prompto/approvers/alice".into())
        );
        assert!(a.approvers["bob"].disabled);
        for bad in [
            "[approver.x]\n",
            "[approver.x]\ntotp_file = \"/a\"\ntotp_vault_path = \"p\"\n",
            "[approver.X]\ntotp_file = \"/a\"\n",
            "[approver.x]\ntotp_vault_path = \"../etc\"\n",
            "[approver.x]\ntotp_file = \"/a\"\nsecret = \"inline\"\n",
        ] {
            assert!(Approvers::from_toml_str(bad).is_err(), "{bad}");
        }
        let round = Approvers::from_toml_str(&a.to_toml_string().unwrap()).unwrap();
        assert_eq!(round, a);
    }

    #[test]
    fn lockout_after_max_failures_in_the_window() {
        let mut g = Guard::default();
        let t = 1_000_000;
        for i in 0..MAX_FAILURES as u64 {
            assert_eq!(g.fail("alice", true, t + i), None);
        }
        let until = g.fail("alice", true, t + 10).expect("locked");
        assert_eq!(until, t + 10 + LOCKOUT_SECS);
        assert_eq!(g.locked("alice", true, t + 11), Some(until));
        assert_eq!(g.locked("alice", true, until), None);
        assert_eq!(g.locked("bob", true, t), None);
        // Failures spread beyond the window never lock.
        let mut g = Guard::default();
        for i in 0..20 {
            assert_eq!(g.fail("bob", true, t + i * FAILURE_WINDOW_SECS), None);
        }
        // A success resets the count.
        let mut g = Guard::default();
        for i in 0..MAX_FAILURES as u64 {
            g.fail("c", true, t + i);
        }
        g.succeed("c");
        assert_eq!(g.fail("c", true, t + 9), None);
    }

    /// Many distinct unknown names: the map stops growing at
    /// MAX_TRACKED, the extra names share one bucket that locks them
    /// together, and known approvers are tracked (and lock) on their own.
    #[test]
    fn unknown_names_cannot_grow_the_map() {
        let mut g = Guard::default();
        let t = 1_000_000;
        for i in 0..MAX_TRACKED + 1000 {
            g.fail(&format!("n{i}"), false, t);
        }
        assert_eq!(g.tracked(), MAX_TRACKED);
        // The 1000 overflowing failures locked the shared bucket: any
        // untracked unknown name is locked, a tracked one is not (yet).
        assert!(g.locked("fresh", false, t + 1).is_some());
        assert_eq!(g.locked("n0", false, t + 1), None);
        // A known approver is tracked past the bound and unaffected.
        assert_eq!(g.locked("alice", true, t + 1), None);
        assert_eq!(g.fail("alice", true, t + 1), None);
        assert_eq!(g.tracked(), MAX_TRACKED + 1);
        // Once the window has passed, stale entries are pruned and new
        // names are tracked again.
        let later = t + FAILURE_WINDOW_SECS + LOCKOUT_SECS;
        assert_eq!(g.fail("fresh", false, later), None);
        assert!(g.tracked() <= 2, "{}", g.tracked());
    }

    #[test]
    fn secret_files_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.totp");
        std::fs::write(&p, "MZXW6YTBOIMZXW6YTBOI\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            read_owner_only(&p)
                .unwrap_err()
                .to_string()
                .contains("owner-only")
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_owner_only(&p).is_ok());
    }
}
