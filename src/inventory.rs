//! Host inventory — TOML loader + capability gating, hot-reloadable via SIGHUP.

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
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

/// Target operating system, declared per host in the inventory.
///
/// prompto's tools shell out to real commands, and those commands differ
/// across platforms in ways that produce *confusing* failures rather than
/// clear ones. Before this existed, `file_stat` against a Mac returned
/// `stat: illegal option -- c` and `file_list` returned a raw BSD usage
/// string — the caller got a shell error with no hint that the tool
/// simply assumed GNU coreutils.
///
/// Defaults to [`Platform::Linux`], which is 24 of the 27 homelab hosts,
/// so existing inventories keep working untouched.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// GNU coreutils + systemd + bash.
    #[default]
    Linux,
    /// BSD userland, launchd, bash present (3.2) but no systemd.
    Macos,
    /// BSD userland, no systemd. On OPNsense the login shell is csh, so
    /// even `a || b` and `2>&1` behave differently from POSIX sh.
    Freebsd,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Freebsd => "freebsd",
        }
    }

    /// GNU coreutils, i.e. `stat -c`, `ls --time-style`, `free -m`.
    /// False on both BSD platforms, which need `stat -f` / `ls -T`.
    pub fn is_gnu(self) -> bool {
        matches!(self, Platform::Linux)
    }

    /// `bash` is on PATH. macOS ships bash 3.2, so `ssh_batch` works
    /// there; OPNsense/FreeBSD has only csh and tcsh, so it cannot.
    pub fn has_bash(self) -> bool {
        matches!(self, Platform::Linux | Platform::Macos)
    }

    /// `systemctl` / `journalctl` exist. launchd is a different model,
    /// not a flag difference, so those tools refuse rather than adapt.
    pub fn has_systemd(self) -> bool {
        matches!(self, Platform::Linux)
    }
}

/// Machine class: real hardware, or a guest on a hypervisor.
///
/// Distinct from [`Platform`], which describes the OS. A host can be
/// FreeBSD on bare metal or FreeBSD in a VM, and the difference decides
/// how you *power it on* — which is the one thing WOL gets wrong.
///
/// Before this existed, `mira` (a Windows guest on doppio) carried a
/// `wake` capability and a `52:54:00:…` MAC — the QEMU/KVM OUI. Calling
/// `host_wake mira` parsed the MAC, broadcast a magic packet at a NIC
/// that does not exist until libvirt creates it, and returned `Ok(())`.
/// Unconditional success, nothing started. The real path was always
/// `virsh start mira`, which is what the MQTT chain on doppio does.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Chassis {
    /// Real hardware. Wakeable by WOL if it has a MAC and the firmware
    /// is configured for it.
    #[default]
    ColdIron,
    /// A guest. Started with `vm_start <hypervisor> <name>`, never WOL.
    Vm,
}

impl Chassis {
    pub fn as_str(self) -> &'static str {
        match self {
            Chassis::ColdIron => "cold_iron",
            Chassis::Vm => "vm",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    /// Literal IPv4/IPv6 address — NOT a hostname. Typed as [`IpAddr`] on
    /// purpose: [`Inventory::require_remote`]'s self-targeting guard compares
    /// this against the MCP caller's source IP, and a value it can't compare
    /// would silently disable that guard. Parsing at load time makes the
    /// unguardable state unrepresentable rather than merely discouraged.
    pub ip: IpAddr,
    #[serde(default)]
    pub mac: Option<String>,
    pub ssh_user: String,
    pub ssh_key: PathBuf,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// Target OS. Defaults to `linux`; set `platform = "macos"` or
    /// `platform = "freebsd"` for hosts with a BSD userland. Tools adapt
    /// where an equivalent command exists and refuse legibly where one
    /// doesn't.
    #[serde(default)]
    pub platform: Platform,
    /// Real hardware or a guest. Defaults to `cold_iron`, so existing
    /// entries need no edit; declaring `vm` disables WOL for the host.
    #[serde(default)]
    pub chassis: Chassis,
    /// Inventory name of the hypervisor hosting this guest. Optional even
    /// for `vm` — some guests (e.g. a VM on someone else's cluster) are
    /// reachable but not ours to start. When present it must name a known
    /// host carrying the `virt` capability, and it makes the wake refusal
    /// actionable: "use vm_start doppio mira" rather than "mira is a VM".
    #[serde(default)]
    pub hypervisor: Option<String>,
    /// URL of the apytti gateway running on this host (e.g. `http://192.0.2.20:7781`).
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
    ///
    /// `ip` needs no check here — it is an [`IpAddr`], so deserialization
    /// already rejected anything unparseable.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.ssh_user.trim().is_empty() {
            bail!("host {name}: ssh_user is empty");
        }
        if self.has(Capability::Wake) && self.mac.is_none() {
            bail!("host {name}: wake capability requires `mac`");
        }
        // WOL cannot start a libvirt guest: a shut-off domain has no NIC
        // listening, so the magic packet lands nowhere while `host_wake`
        // still reports success. Reject the combination at load rather
        // than letting a caller discover it as a silent no-op.
        if self.has(Capability::Wake) && self.chassis == Chassis::Vm {
            let how = match &self.hypervisor {
                Some(h) => format!("`vm_start {h} {name}`"),
                None => "`vm_start <hypervisor> ".to_string() + name + "`",
            };
            bail!(
                "host {name}: `wake` is not valid for chassis=\"vm\" — WOL cannot start a \
                 guest (a shut-off domain has no NIC to receive the packet, and host_wake \
                 would report success having done nothing). Drop `wake` and use {how}."
            );
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
        // Cross-host checks, once every entry has parsed. A `hypervisor`
        // pointing at a typo or at a box that can't run virsh is a
        // promise the refusal message can't keep.
        for (name, host) in &inv.hosts {
            let Some(hv) = host.hypervisor.as_deref() else {
                continue;
            };
            if host.chassis != Chassis::Vm {
                bail!("host {name}: `hypervisor` is only meaningful with chassis = \"vm\"");
            }
            match inv.hosts.get(hv) {
                None => bail!("host {name}: hypervisor {hv:?} is not a host in this inventory"),
                Some(h) if !h.has(Capability::Virt) => {
                    bail!("host {name}: hypervisor {hv:?} lacks the `virt` capability")
                }
                Some(_) => {}
            }
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

    /// Like [`require`], but ALSO refuses if the MCP caller's IP equals
    /// the target host's IP — i.e. the calling agent is asking prompto
    /// to SSH back to its own box. Wasteful (the agent has local Bash)
    /// and a self-escalation vector on prompto's own host (the SSH
    /// session runs as the inventory's `ssh_user`, sidestepping
    /// prompto's systemd hardening).
    ///
    /// `caller_ip` is `None` on transports that don't expose source
    /// addresses (stdio, tests). In that case the self-check is
    /// skipped and only the capability check applies — so legitimate
    /// code paths that don't carry caller info aren't broken.
    ///
    /// That `None` is the *only* way to skip the comparison. Until
    /// v0.6.20 `ip` was a `String` parsed here, and an unparseable value
    /// made the `if let` chain fall through — silently disabling the
    /// guard for that host with no error and no log. `ip` is now an
    /// [`IpAddr`], so the comparison can never be skipped by inventory
    /// content.
    pub fn require_remote(
        &self,
        name: &str,
        caller_ip: Option<IpAddr>,
        cap: Capability,
    ) -> Result<&HostConfig> {
        let host = self.require(name, cap)?;
        if let Some(caller) = caller_ip
            && caller == host.ip
        {
            bail!(
                "refused: target {name:?} is the calling agent's own host (source IP {caller}). \
                 Use your local shell tool instead — routing a same-host shell call through SSH \
                 wastes a round trip and bypasses any local sandboxing."
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
        assert_eq!(d.ip, "192.0.2.12".parse::<IpAddr>().unwrap());
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
    fn require_remote_allows_when_caller_differs_from_target() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        let caller: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        inv.require_remote("alpha", Some(caller), Capability::Exec)
            .unwrap();
    }

    #[test]
    fn require_remote_blocks_when_caller_equals_target() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        // alpha's IP is 192.0.2.12 (per sample)
        let caller: std::net::IpAddr = "192.0.2.12".parse().unwrap();
        let err = inv
            .require_remote("alpha", Some(caller), Capability::Exec)
            .unwrap_err();
        assert!(err.to_string().contains("calling agent's own host"));
        assert!(err.to_string().contains("192.0.2.12"));
    }

    #[test]
    fn require_remote_skips_check_when_caller_is_none() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        // Falls back to plain require: capability still enforced,
        // self-check skipped because the transport doesn't expose it.
        inv.require_remote("alpha", None, Capability::Exec).unwrap();
    }

    #[test]
    fn require_remote_still_enforces_capability() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        let caller: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let err = inv
            .require_remote("bravo", Some(caller), Capability::Wake)
            .unwrap_err();
        assert!(err.to_string().contains("lacks capability"));
    }

    /// Regression: a hostname in `ip` used to load fine and then silently
    /// disable the self-targeting guard for that host (the parse in
    /// `require_remote` failed, the `if let` chain fell through, the call
    /// was allowed). Rejecting at load time is what makes that impossible.
    #[test]
    fn rejects_hostname_in_ip_field() {
        let bad = r#"
[host.x]
ip = "not-an-ip"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["exec"]
"#;
        let err = Inventory::from_toml_str(bad).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid IP address syntax") || msg.contains("IP address"),
            "error should name the IP-syntax problem, got: {msg}"
        );
    }

    /// The whole point of the type change: every host in a loadable
    /// inventory is comparable against a caller IP, so a self-targeting
    /// call cannot slip through on any of them.
    #[test]
    fn every_loadable_host_is_guardable() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        for (name, host) in &inv.hosts {
            let err = inv
                .require_remote(name, Some(host.ip), Capability::Exec)
                .unwrap_err();
            assert!(
                err.to_string().contains("calling agent's own host"),
                "host {name} was not self-guarded"
            );
        }
    }

    /// THE regression. `mira` is a Windows guest on doppio; its entry
    /// carried `wake` and a `52:54:00:…` MAC (the QEMU/KVM OUI), so
    /// `host_wake mira` broadcast a magic packet at a NIC that does not
    /// exist until libvirt creates the domain — and returned Ok(()).
    /// Unconditional success, nothing started.
    #[test]
    fn rejects_wake_on_a_vm() {
        let bad = r#"
[host.doppio]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["virt"]

[host.mira]
ip = "1.2.3.5"
mac = "52:54:00:2b:bd:3c"
ssh_user = "x"
ssh_key = "/k"
chassis = "vm"
hypervisor = "doppio"
capabilities = ["wake", "exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(bad).unwrap_err());
        assert!(err.contains("not valid for chassis"), "{err}");
        // The refusal must name the command that actually works.
        assert!(err.contains("vm_start doppio mira"), "{err}");
    }

    #[test]
    fn vm_without_hypervisor_is_allowed_but_wake_still_refused() {
        // Some guests are reachable but not ours to start (a VM on
        // someone else's cluster). chassis=vm alone is legal.
        let ok = r#"
[host.foreign]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
chassis = "vm"
capabilities = ["exec"]
"#;
        Inventory::from_toml_str(ok).unwrap();

        let bad = ok.replace(r#"capabilities = ["exec"]"#, r#"mac = "52:54:00:1:2:3"
capabilities = ["wake"]"#);
        let err = format!("{:#}", Inventory::from_toml_str(&bad).unwrap_err());
        assert!(err.contains("vm_start <hypervisor> foreign"), "{err}");
    }

    #[test]
    fn hypervisor_must_name_a_known_virt_host() {
        let typo = r#"
[host.mira]
ip = "1.2.3.5"
ssh_user = "x"
ssh_key = "/k"
chassis = "vm"
hypervisor = "dopio"
capabilities = ["exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(typo).unwrap_err());
        assert!(err.contains("not a host in this inventory"), "{err}");

        let no_virt = r#"
[host.plain]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["exec"]

[host.mira]
ip = "1.2.3.5"
ssh_user = "x"
ssh_key = "/k"
chassis = "vm"
hypervisor = "plain"
capabilities = ["exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(no_virt).unwrap_err());
        assert!(err.contains("lacks the `virt` capability"), "{err}");
    }

    #[test]
    fn hypervisor_on_cold_iron_is_rejected() {
        let bad = r#"
[host.dop]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["virt"]

[host.metal]
ip = "1.2.3.5"
ssh_user = "x"
ssh_key = "/k"
hypervisor = "dop"
capabilities = ["exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(bad).unwrap_err());
        assert!(err.contains("only meaningful with chassis"), "{err}");
    }

    /// Counterweight: cold iron with a real MAC still wakes. The fix must
    /// not disable WOL wholesale.
    #[test]
    fn cold_iron_wake_still_allowed() {
        let ok = r#"
[host.doppio]
ip = "1.2.3.4"
mac = "b4:2e:99:3e:c5:81"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["wake", "exec"]
"#;
        let inv = Inventory::from_toml_str(ok).unwrap();
        let d = inv.get("doppio").unwrap();
        assert_eq!(d.chassis, Chassis::ColdIron, "default must be cold_iron");
        assert!(d.has(Capability::Wake));
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
