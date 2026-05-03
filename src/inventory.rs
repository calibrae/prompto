//! Host inventory — TOML loader + capability gating, hot-reloadable via SIGHUP.

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Wake,
    Exec,
    SudoExec,
    Virt,
    /// Host carries a `claude` CLI prompto can drive (`claude mcp …`).
    /// Add to hosts where you want prompto to manage MCP server registration
    /// remotely — typically the macOS boxes that have npm-installed `claude`.
    ClaudeAdmin,
    /// Host runs an [apytti](https://github.com/calibrae/apytti) gateway
    /// reachable from prompto. Required to use `claude_exec` against this
    /// host. The host's `apytti_url` must be set.
    ClaudeExec,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Wake => "wake",
            Capability::Exec => "exec",
            Capability::SudoExec => "sudo_exec",
            Capability::Virt => "virt",
            Capability::ClaudeAdmin => "claude_admin",
            Capability::ClaudeExec => "claude_exec",
        }
    }
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    pub ip: String,
    #[serde(default)]
    pub mac: Option<String>,
    pub ssh_user: String,
    pub ssh_key: PathBuf,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// URL of the apytti gateway running on this host (e.g. `http://10.10.0.2:7781`).
    /// Required when the `claude_exec` capability is granted.
    #[serde(default)]
    pub apytti_url: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

impl HostConfig {
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Validate self-consistency (called once per load).
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.ip.trim().is_empty() {
            bail!("host {name}: ip is empty");
        }
        if self.ssh_user.trim().is_empty() {
            bail!("host {name}: ssh_user is empty");
        }
        if self.has(Capability::Wake) && self.mac.is_none() {
            bail!("host {name}: wake capability requires `mac`");
        }
        if self.has(Capability::ClaudeExec) && self.apytti_url.is_none() {
            bail!("host {name}: claude_exec capability requires `apytti_url`");
        }
        if let Some(mac) = &self.mac {
            crate::wol::parse_mac(mac).with_context(|| format!("host {name}: invalid mac"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Inventory {
    #[serde(rename = "host", default)]
    pub hosts: HashMap<String, HostConfig>,
}

impl Inventory {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let inv: Inventory = toml::from_str(s).context("parse inventory TOML")?;
        for (name, host) in &inv.hosts {
            host.validate(name)?;
        }
        Ok(inv)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read inventory {}", path.display()))?;
        Self::from_toml_str(&raw)
    }

    pub fn get(&self, name: &str) -> Result<&HostConfig> {
        self.hosts
            .get(name)
            .ok_or_else(|| anyhow!("unknown host {name:?}"))
    }

    /// Look up a host and verify it carries the requested capability.
    pub fn require(&self, name: &str, cap: Capability) -> Result<&HostConfig> {
        let host = self.get(name)?;
        if !host.has(cap) {
            bail!(
                "host {name:?} lacks capability {:?} (granted: {:?})",
                cap.as_str(),
                host.capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
            );
        }
        Ok(host)
    }
}

/// Atomically-swappable wrapper around an `Inventory` so SIGHUP can replace
/// the live config without coordinating with in-flight handlers.
#[derive(Clone)]
pub struct InventoryStore {
    inner: Arc<ArcSwap<Inventory>>,
    path: Option<PathBuf>,
}

impl InventoryStore {
    pub fn new(inv: Inventory, path: Option<PathBuf>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(inv)),
            path,
        }
    }

    pub fn load_from(path: PathBuf) -> Result<Self> {
        let inv = Inventory::from_path(&path)?;
        Ok(Self::new(inv, Some(path)))
    }

    pub fn snapshot(&self) -> Arc<Inventory> {
        self.inner.load_full()
    }

    /// Reload from the path the store was created with. Returns the new host
    /// count or an error (the live store is left unchanged on parse failure).
    pub fn reload(&self) -> Result<usize> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("no inventory path configured — cannot reload"))?;
        let new = Inventory::from_path(path)?;
        let count = new.hosts.len();
        self.inner.store(Arc::new(new));
        Ok(count)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Apply a closure to a mutable copy of the current inventory, write
    /// it back to disk atomically (tmp file + rename), and update the
    /// in-memory snapshot. Re-parses after write to ensure round-trip
    /// validity. Comments and key ordering in the source TOML are NOT
    /// preserved — this is a known tradeoff for v0.6.8 simplicity.
    pub fn edit<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Inventory) -> Result<()>,
    {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("no inventory path configured — cannot persist edits"))?;
        let mut inv = (*self.snapshot()).clone();
        f(&mut inv)?;
        // Validate the modified inventory before writing.
        for (name, host) in &inv.hosts {
            host.validate(name)?;
        }
        let serialized = toml::to_string_pretty(&inv).context("serialize inventory to TOML")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &serialized).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
        // Re-read to populate the snapshot from a freshly-parsed file
        // (catches any silent serialize/deserialize asymmetries).
        let reloaded = Inventory::from_path(path)?;
        self.inner.store(Arc::new(reloaded));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"
[host.alpha]
ip = "192.0.2.12"
mac = "aa:bb:cc:dd:ee:ff"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
ssh_port = 22
capabilities = ["wake", "exec", "sudo_exec", "virt"]

[host.bravo]
ip = "192.0.2.13"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["exec", "sudo_exec"]
"#
    }

    #[test]
    fn parses_two_hosts() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        assert_eq!(inv.hosts.len(), 2);
        let d = inv.get("alpha").unwrap();
        assert_eq!(d.ip, "192.0.2.12");
        assert_eq!(d.ssh_port, 22);
        assert!(d.has(Capability::Wake));
        assert!(d.has(Capability::Virt));
        let g = inv.get("bravo").unwrap();
        assert!(!g.has(Capability::Wake));
        assert_eq!(g.ssh_port, 22, "default ssh_port applies");
    }

    #[test]
    fn require_passes_when_capability_present() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        inv.require("alpha", Capability::Wake).unwrap();
        inv.require("bravo", Capability::Exec).unwrap();
    }

    #[test]
    fn require_fails_when_capability_missing() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        let err = inv.require("bravo", Capability::Wake).unwrap_err();
        assert!(err.to_string().contains("lacks capability"));
    }

    #[test]
    fn require_fails_for_unknown_host() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        let err = inv.require("nonexistent", Capability::Exec).unwrap_err();
        assert!(err.to_string().contains("unknown host"));
    }

    #[test]
    fn rejects_wake_without_mac() {
        let bad = r#"
[host.x]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["wake"]
"#;
        let err = Inventory::from_toml_str(bad).unwrap_err();
        assert!(err.to_string().contains("wake capability requires"));
    }

    #[test]
    fn rejects_invalid_mac() {
        let bad = r#"
[host.x]
ip = "1.2.3.4"
mac = "not-a-mac"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["wake"]
"#;
        assert!(Inventory::from_toml_str(bad).is_err());
    }

    #[test]
    fn store_reload_picks_up_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prompto.toml");
        std::fs::write(&path, sample()).unwrap();

        let store = InventoryStore::load_from(path.clone()).unwrap();
        assert_eq!(store.snapshot().hosts.len(), 2);

        let extended = format!(
            "{}\n[host.charlie]\nip = \"192.0.2.7\"\nssh_user = \"admin\"\nssh_key = \"/k\"\ncapabilities = [\"exec\", \"virt\"]\n",
            sample()
        );
        std::fs::write(&path, extended).unwrap();

        let n = store.reload().unwrap();
        assert_eq!(n, 3);
        assert!(store.snapshot().get("charlie").is_ok());
    }

    #[test]
    fn store_reload_keeps_old_on_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prompto.toml");
        std::fs::write(&path, sample()).unwrap();
        let store = InventoryStore::load_from(path.clone()).unwrap();

        std::fs::write(&path, "this is not toml ===").unwrap();
        assert!(store.reload().is_err());
        assert_eq!(store.snapshot().hosts.len(), 2, "old inventory preserved");
    }
}
