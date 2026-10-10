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
    /// Windows guest. Declared for honesty rather than support: none of
    /// the POSIX tools apply, so everything that branches on platform
    /// refuses. `mira` is the only one, and it exists in the inventory to
    /// be *addressed*, not shelled into.
    Windows,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Freebsd => "freebsd",
            Platform::Windows => "windows",
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
/// Before this existed, a Windows guest carried a `wake` capability and
/// a `52:54:00:…` MAC — the QEMU/KVM OUI. Calling `host_wake` on it
/// parsed the MAC, broadcast a magic packet at a NIC that does not exist
/// until libvirt creates it, and returned `Ok(())`. Unconditional
/// success, nothing started. The real path was always `virsh start` on
/// its hypervisor.
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

/// How the call's request ID (`PROMPTO_REQUEST_ID`) reaches the remote
/// command. See `ssh::request_id_export` for the mechanics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestIdEnv {
    /// `export PROMPTO_REQUEST_ID=…; ` in front of the remote command,
    /// plus `-o SetEnv`. Needs a POSIX login shell that runs the command
    /// line as given. Default on `linux` and `macos`.
    Export,
    /// `-o SetEnv` only; the command line is left untouched. Arrives only
    /// where sshd has `AcceptEnv PROMPTO_*`. Default on `freebsd` and
    /// `windows`, where the login shell may not be POSIX.
    Setenv,
    /// Nothing: no prefix, no `SetEnv`, no `env` on the vault sudo path.
    /// For keys restricted by `command=`, rrsync or git-shell, which see
    /// (and reject) anything prompto adds to the command line.
    Off,
}

impl RequestIdEnv {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestIdEnv::Export => "export",
            RequestIdEnv::Setenv => "setenv",
            RequestIdEnv::Off => "off",
        }
    }

    /// The behaviour a host gets when it does not set `request_id_env`.
    pub fn default_for(platform: Platform) -> Self {
        match platform {
            Platform::Linux | Platform::Macos => RequestIdEnv::Export,
            Platform::Freebsd | Platform::Windows => RequestIdEnv::Setenv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    /// Literal IPv4/IPv6 address — NOT a hostname. Typed as [`IpAddr`] on
    /// purpose: the self-targeting guard (`authz::authorize`) compares
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
    /// actionable: "use vm_start hypervisor winguest" rather than "winguest is a VM".
    #[serde(default)]
    pub hypervisor: Option<String>,
    /// URL of the apytti gateway running on this host (e.g. `http://192.0.2.20:7781`).
    /// Required when the `claude_exec` capability is granted.
    #[serde(default)]
    pub apytti_url: Option<String>,
    /// Extra names this host answers to. A box can carry a service
    /// identity and a hardware name — e.g. `router` (the role) on a box
    /// everyone calls `minipc`. One machine, so one entry, reachable by
    /// either name.
    ///
    /// Aliases must not collide with a host name or another alias;
    /// both are rejected at load.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Vault KV v2 path (under the configured mount, default `secret`)
    /// holding this host's sudo password, e.g. `infra/default`. When set,
    /// sudo runs as `sudo -k -S` with the password fed over SSH stdin
    /// instead of `sudo -n`. For hosts that deliberately keep a sudo
    /// password — the edge routers — rather than passwordless sudo.
    ///
    /// The password is fetched per call, used inside prompto, and never
    /// returned to the caller, logged, or placed on a command line.
    #[serde(default)]
    pub sudo_password_vault_path: Option<String>,
    /// Field within that secret. Defaults to `password`.
    #[serde(default)]
    pub sudo_password_vault_field: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// How the request ID is passed to remote commands: `export`,
    /// `setenv` or `off`. Unset means the platform default (see
    /// [`RequestIdEnv::default_for`]); read it via
    /// [`HostConfig::request_id_env`].
    #[serde(default, rename = "request_id_env")]
    pub request_id_env_override: Option<RequestIdEnv>,
    /// Other addresses this machine may call prompto from: a second NIC,
    /// Wi-Fi, a VPN address, its IPv6 address. Never used to *reach* the
    /// host — only by the self-targeting guard, which refuses a caller
    /// matching `ip` or any of these. Canonicalized at load
    /// (`::ffff:a.b.c.d` → `a.b.c.d`).
    #[serde(default)]
    pub extra_ips: Vec<IpAddr>,
    /// Policy host groups (`group:<g>` in `policy.toml`), e.g.
    /// `["build", "web"]`. Names follow the agent-group rules
    /// (`[a-z0-9_-]`); they mean nothing outside policy.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Whether `ssh_user` can `sudo` without a password here; unset means
    /// unknown. Informational: prompto's own sudo paths don't read it.
    /// `policy lint` uses it to warn when a rule without `sudo = true`
    /// grants an exec tool on a host where that shell can become root
    /// anyway (`true` or unset, or `ssh_user = "root"`).
    #[serde(default)]
    pub nopasswd_sudo: Option<bool>,
    /// This machine runs prompto. Root on it reads prompto's vault token
    /// (`/etc/prompto/env`), the ticket key and approvers' TOTP files —
    /// every approval factor — so `policy lint` reports an **error** for
    /// any rule that grants root here, or an exec tool where `ssh_user`
    /// can sudo, unless the rule says `crown_jewel_ack = true`.
    #[serde(default)]
    pub prompto_host: bool,
}

impl HostConfig {
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Whether `addr` is one of this machine's addresses (`ip` or
    /// `extra_ips`), compared in canonical form. The self-targeting
    /// guard's whole question.
    pub fn is_own_address(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        self.ip.to_canonical() == addr || self.extra_ips.iter().any(|e| e.to_canonical() == addr)
    }

    /// The effective [`RequestIdEnv`]: the inventory's setting, else the
    /// platform default.
    pub fn request_id_env(&self) -> RequestIdEnv {
        self.request_id_env_override
            .unwrap_or_else(|| RequestIdEnv::default_for(self.platform))
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
        if let Some(path) = &self.sudo_password_vault_path {
            crate::vault::validate_kv_path(path)
                .with_context(|| format!("host {name}: sudo_password_vault_path"))?;
            // A vault path on a host that can't sudo is a typo or a
            // forgotten capability — either way it would never be used.
            if !self.has(Capability::SudoExec) {
                bail!(
                    "host {name}: sudo_password_vault_path is set but the host lacks `sudo_exec`"
                );
            }
        }
        if self.sudo_password_vault_field.is_some() && self.sudo_password_vault_path.is_none() {
            bail!("host {name}: sudo_password_vault_field needs sudo_password_vault_path");
        }
        if self.has(Capability::ClaudeExec) && self.apytti_url.is_none() {
            bail!("host {name}: claude_exec capability requires `apytti_url`");
        }
        if let Some(mac) = &self.mac {
            crate::wol::parse_mac(mac).with_context(|| format!("host {name}: invalid mac"))?;
        }
        for g in &self.groups {
            crate::agent::validate_name("group", g).with_context(|| format!("host {name}"))?;
        }
        if let Some(dup) = self
            .groups
            .iter()
            .enumerate()
            .find(|(i, g)| self.groups[..*i].contains(g))
        {
            bail!("host {name}: group {:?} listed twice", dup.1);
        }
        let mut seen = vec![self.ip.to_canonical()];
        for e in &self.extra_ips {
            let e = e.to_canonical();
            // An unspecified or multicast address is never a caller's
            // source: listing one is a typo that would guard nothing.
            if e.is_unspecified() || e.is_multicast() {
                bail!("host {name}: extra_ips entry {e} is not a unicast address");
            }
            if seen.contains(&e) {
                bail!("host {name}: extra_ips repeats {e} (ip or another entry)");
            }
            seen.push(e);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Inventory {
    #[serde(rename = "host", default)]
    pub hosts: HashMap<String, HostConfig>,
    /// alias -> canonical host name. Built at load, never deserialized.
    #[serde(skip)]
    alias_index: HashMap<String, String>,
}

impl Inventory {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let mut inv: Inventory = toml::from_str(s).context("parse inventory TOML")?;
        for (name, host) in inv.hosts.iter_mut() {
            host.validate(name)?;
            for e in host.extra_ips.iter_mut() {
                *e = e.to_canonical();
            }
        }
        // An extra address belongs to exactly one machine. Claimed by two
        // hosts (or equal to another host's `ip`), the guard would refuse
        // calls between two different machines — a typo, not a policy.
        let mut owner: HashMap<IpAddr, &str> = HashMap::new();
        for (name, host) in &inv.hosts {
            for e in &host.extra_ips {
                if let Some(prev) = owner.insert(*e, name) {
                    bail!("extra_ips address {e} is claimed by both {prev:?} and {name:?}");
                }
            }
        }
        for (name, host) in &inv.hosts {
            if let Some(other) = owner.get(&host.ip.to_canonical())
                && *other != name.as_str()
            {
                bail!(
                    "host {other}: extra_ips address {} is host {name:?}'s ip",
                    host.ip.to_canonical()
                );
            }
        }
        // Alias index. A collision here would make `get()` silently
        // resolve to whichever entry won a HashMap race, so both kinds
        // are load errors.
        let mut alias_index: HashMap<String, String> = HashMap::new();
        for (name, host) in &inv.hosts {
            for a in &host.aliases {
                if a.trim().is_empty() {
                    bail!("host {name}: empty alias");
                }
                if inv.hosts.contains_key(a) {
                    bail!("host {name}: alias {a:?} collides with a host of that name");
                }
                if let Some(prev) = alias_index.insert(a.clone(), name.clone()) {
                    bail!("alias {a:?} claimed by both {prev:?} and {name:?}");
                }
            }
        }
        inv.alias_index = alias_index;
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

    /// Look up by canonical name, falling back to the alias index.
    pub fn get(&self, name: &str) -> Result<&HostConfig> {
        if let Some(h) = self.hosts.get(name) {
            return Ok(h);
        }
        if let Some(canon) = self.alias_index.get(name) {
            return self
                .hosts
                .get(canon)
                .ok_or_else(|| anyhow!("alias {name:?} points at missing host {canon:?}"));
        }
        Err(anyhow!("unknown host {name:?}"))
    }

    /// Canonical name for `name`, resolving an alias if needed.
    pub fn canonical<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        if self.hosts.contains_key(name) {
            return Some(name);
        }
        self.alias_index.get(name).map(String::as_str)
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

    fn extra_ips_inv(alpha_extra: &str, bravo_extra: &str) -> Result<Inventory> {
        Inventory::from_toml_str(&format!(
            r#"
[host.alpha]
ip = "192.0.2.12"
extra_ips = [{alpha_extra}]
ssh_user = "u"
ssh_key = "/k"

[host.bravo]
ip = "192.0.2.13"
extra_ips = [{bravo_extra}]
ssh_user = "u"
ssh_key = "/k"
"#
        ))
    }

    #[test]
    fn extra_ips_are_canonicalized_at_load() {
        let inv = extra_ips_inv(r#""::ffff:198.51.100.4", "2001:db8::4""#, "").unwrap();
        assert_eq!(
            inv.get("alpha").unwrap().extra_ips,
            vec![
                "198.51.100.4".parse::<IpAddr>().unwrap(),
                "2001:db8::4".parse().unwrap()
            ]
        );
    }

    #[test]
    fn extra_ips_are_validated() {
        for (a, b, want) in [
            (r#""not-an-ip""#, "", "IP address"),
            (r#""0.0.0.0""#, "", "not a unicast"),
            (r#""ff02::1""#, "", "not a unicast"),
            (r#""192.0.2.12""#, "", "repeats"),
            (r#""198.51.100.4", "::ffff:198.51.100.4""#, "", "repeats"),
            (r#""198.51.100.4""#, r#""198.51.100.4""#, "claimed by both"),
            (r#""192.0.2.13""#, "", "ip"),
        ] {
            let err = format!("{:#}", extra_ips_inv(a, b).unwrap_err());
            assert!(err.contains(want), "{a} / {b}: {err}");
        }
    }

    /// Regression: a hostname in `ip` used to load fine and then silently
    /// disable the self-targeting guard for that host (the parse in
    /// the self-target guard failed, the `if let` chain fell through, the call
    /// was allowed). Rejecting at load time is what makes that impossible.
    #[test]
    fn groups_are_validated() {
        let inv = |groups: &str| {
            Inventory::from_toml_str(&format!(
                "[host.a]\nip = \"192.0.2.1\"\nssh_user = \"u\"\nssh_key = \"/k\"\ngroups = {groups}\n"
            ))
        };
        assert_eq!(
            inv(r#"["build", "web-1"]"#).unwrap().hosts["a"].groups,
            ["build", "web-1"]
        );
        assert!(inv("[]").unwrap().hosts["a"].groups.is_empty());
        for bad in [r#"["Build"]"#, r#"["a b"]"#, r#"[""]"#, r#"["x", "x"]"#] {
            let e = inv(bad).expect_err(bad);
            assert!(format!("{e:#}").contains("host a"), "{bad}: {e:#}");
        }
    }

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

    /// A typo in `request_id_env` must fail the load (and so a SIGHUP
    /// reload keeps the old inventory), not silently fall back.
    #[test]
    fn request_id_env_is_validated_at_load() {
        let base = "[host.h]\nip = \"192.0.2.5\"\nssh_user = \"u\"\nssh_key = \"/dev/null\"\n";
        for (v, want) in [
            ("export", RequestIdEnv::Export),
            ("setenv", RequestIdEnv::Setenv),
            ("off", RequestIdEnv::Off),
        ] {
            let inv =
                Inventory::from_toml_str(&format!("{base}request_id_env = \"{v}\"\n")).unwrap();
            assert_eq!(inv.get("h").unwrap().request_id_env(), want);
        }
        let err =
            Inventory::from_toml_str(&format!("{base}request_id_env = \"Export\"\n")).unwrap_err();
        assert!(format!("{err:#}").contains("request_id_env"), "{err:#}");
    }

    /// The whole point of the type change: every host in a loadable
    /// inventory is comparable against a caller IP, so a self-targeting
    /// call cannot slip through on any of them.
    #[test]
    fn every_loadable_host_is_guardable() {
        let inv = Inventory::from_toml_str(sample()).unwrap();
        for (name, host) in &inv.hosts {
            let ctx = crate::ctx::CallCtx::new(Some(host.ip));
            let err = crate::authz::authorize(
                &inv,
                None,
                &ctx,
                "ssh_exec",
                name,
                crate::authz::Need::Exists,
            )
            .unwrap_err();
            assert_eq!(
                err.class,
                crate::error_class::ErrorClass::RefusedSelfTarget,
                "host {name} was not self-guarded"
            );
        }
    }

    /// One physical box with two names: `router` (the role) and `minipc`
    /// (the hardware). One machine, one entry, reachable by either name.
    #[test]
    fn alias_resolves_to_the_same_host() {
        let inv = Inventory::from_toml_str(
            r#"
[host.router]
ip = "192.0.2.1"
ssh_user = "admin"
ssh_key = "/k"
aliases = ["minipc"]
capabilities = ["exec"]
"#,
        )
        .unwrap();
        let by_name = inv.get("router").unwrap();
        let by_alias = inv.get("minipc").unwrap();
        assert_eq!(by_name.ip, by_alias.ip);
        assert_eq!(inv.canonical("minipc"), Some("router"));
        assert_eq!(inv.canonical("router"), Some("router"));
        assert_eq!(inv.canonical("nope"), None);
        // Capability gating works through the alias too.
        inv.require("minipc", Capability::Exec).unwrap();
        assert!(inv.require("minipc", Capability::Virt).is_err());
    }

    /// A collision would make `get()` resolve to whichever entry won a
    /// HashMap race — silent and unreproducible. Both kinds are load
    /// errors instead.
    #[test]
    fn rejects_alias_collisions() {
        let with_host = r#"
[host.a]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
aliases = ["b"]
capabilities = ["exec"]

[host.b]
ip = "1.2.3.5"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(with_host).unwrap_err());
        assert!(err.contains("collides with a host"), "{err}");

        let two_claims = r#"
[host.a]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
aliases = ["shared"]
capabilities = ["exec"]

[host.b]
ip = "1.2.3.5"
ssh_user = "x"
ssh_key = "/k"
aliases = ["shared"]
capabilities = ["exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(two_claims).unwrap_err());
        assert!(err.contains("claimed by both"), "{err}");
    }

    #[test]
    fn sudo_vault_path_validation() {
        let base = |extra: &str, caps: &str| {
            format!(
                "[host.edge]\nip = \"1.2.3.4\"\nssh_user = \"cali\"\nssh_key = \"/k\"\n{extra}\ncapabilities = {caps}\n"
            )
        };
        // Good: path + sudo_exec, default field.
        let inv = Inventory::from_toml_str(&base(
            "sudo_password_vault_path = \"infra/default\"",
            "[\"exec\", \"sudo_exec\"]",
        ))
        .unwrap();
        assert_eq!(
            inv.get("edge").unwrap().sudo_password_vault_path.as_deref(),
            Some("infra/default")
        );
        // Path without sudo_exec: would never be used — reject.
        let err = format!(
            "{:#}",
            Inventory::from_toml_str(&base(
                "sudo_password_vault_path = \"infra/default\"",
                "[\"exec\"]"
            ))
            .unwrap_err()
        );
        assert!(err.contains("lacks `sudo_exec`"), "{err}");
        // Field without path.
        let err = format!(
            "{:#}",
            Inventory::from_toml_str(&base(
                "sudo_password_vault_field = \"password\"",
                "[\"exec\", \"sudo_exec\"]"
            ))
            .unwrap_err()
        );
        assert!(err.contains("needs sudo_password_vault_path"), "{err}");
        // Path traversal.
        assert!(
            Inventory::from_toml_str(&base(
                "sudo_password_vault_path = \"infra/../sys\"",
                "[\"exec\", \"sudo_exec\"]"
            ))
            .is_err()
        );
    }

    /// THE regression: a Windows guest carrying `wake` and a QEMU/KVM
    /// `52:54:00:…` MAC made `host_wake` broadcast at a NIC that does not
    /// exist until libvirt creates the domain — and return Ok(()).
    #[test]
    fn rejects_wake_on_a_vm() {
        let bad = r#"
[host.hypervisor]
ip = "1.2.3.4"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["virt"]

[host.winguest]
ip = "1.2.3.5"
mac = "52:54:00:00:00:01"
ssh_user = "x"
ssh_key = "/k"
chassis = "vm"
hypervisor = "hypervisor"
capabilities = ["wake", "exec"]
"#;
        let err = format!("{:#}", Inventory::from_toml_str(bad).unwrap_err());
        assert!(err.contains("not valid for chassis"), "{err}");
        // The refusal must name the command that actually works.
        assert!(err.contains("vm_start hypervisor winguest"), "{err}");
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

        let bad = ok.replace(
            r#"capabilities = ["exec"]"#,
            r#"mac = "52:54:00:1:2:3"
capabilities = ["wake"]"#,
        );
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
[host.workstation]
ip = "1.2.3.4"
mac = "00:11:22:33:44:55"
ssh_user = "x"
ssh_key = "/k"
capabilities = ["wake", "exec"]
"#;
        let inv = Inventory::from_toml_str(ok).unwrap();
        let d = inv.get("workstation").unwrap();
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
