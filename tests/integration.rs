//! End-to-end-ish tests that exercise the public library surface without
//! talking to real hosts. Real SSH/WOL/virsh paths are gated by the host
//! capabilities and require infra to verify — those are smoke-tested
//! manually per CONTRIBUTING.md.

use mcp_gain::Tracker;
use prompto::inventory::{Capability, Inventory, InventoryStore};
use prompto::mcp::Prompto;
use prompto::ssh::SshClient;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn write_inventory(dir: &std::path::Path, body: &str) -> PathBuf {
    let p = dir.join("prompto.toml");
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn full_inventory_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_inventory(
        dir.path(),
        r#"
[host.alpha]
ip = "192.0.2.12"
mac = "aa:bb:cc:dd:ee:ff"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["wake", "exec", "sudo_exec", "virt"]

[host.bravo]
ip = "192.0.2.13"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["exec", "sudo_exec"]
"#,
    );

    let store = InventoryStore::load_from(p).unwrap();
    let inv = store.snapshot();
    assert_eq!(inv.hosts.len(), 2);

    inv.require("alpha", Capability::Wake).unwrap();
    inv.require("alpha", Capability::Virt).unwrap();
    inv.require("bravo", Capability::Exec).unwrap();
    assert!(inv.require("bravo", Capability::Wake).is_err());
    assert!(inv.require("bravo", Capability::Virt).is_err());
    assert!(inv.require("nope", Capability::Exec).is_err());
}

#[test]
fn sighup_style_reload_picks_up_new_host() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_inventory(
        dir.path(),
        r#"
[host.bravo]
ip = "192.0.2.13"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["exec"]
"#,
    );

    let store = InventoryStore::load_from(p.clone()).unwrap();
    assert_eq!(store.snapshot().hosts.len(), 1);

    std::fs::write(
        &p,
        r#"
[host.bravo]
ip = "192.0.2.13"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["exec"]

[host.charlie]
ip = "192.0.2.7"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["exec", "virt"]
"#,
    )
    .unwrap();

    assert_eq!(store.reload().unwrap(), 2);
    assert!(store.snapshot().get("charlie").is_ok());
}

#[test]
fn prompto_can_be_constructed() {
    let inv = Inventory::from_toml_str(
        r#"
[host.alpha]
ip = "192.0.2.12"
mac = "aa:bb:cc:dd:ee:ff"
ssh_user = "admin"
ssh_key = "/etc/prompto/keys/id_rsa"
capabilities = ["wake", "virt", "exec"]
"#,
    )
    .unwrap();
    let store = InventoryStore::new(inv, None);
    let ssh = Arc::new(SshClient::new("ssh".into(), Duration::from_secs(30)));
    let tracker = Arc::new(Tracker::disabled());
    // Just make sure construction doesn't panic and the type is usable.
    let _ = Prompto::new(store, ssh, tracker, Duration::from_secs(30));
}

#[test]
fn host_status_reports_off_for_unroutable_target() {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed non-routable.
    // Use a short timeout so the test runs fast even when the OS holds the
    // SYN for a moment before failing.
    let inv = Inventory::from_toml_str(
        r#"
[host.blackhole]
ip = "192.0.2.1"
ssh_user = "x"
ssh_key = "/dev/null"
ssh_port = 22
capabilities = ["exec"]
"#,
    )
    .unwrap();
    let host = inv.get("blackhole").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let st = rt
        .block_on(prompto::host::status(host, Duration::from_millis(300)))
        .unwrap();
    // Either "off" (timeout) or "unreachable" (ICMP-administratively-prohibited)
    // — both are fine; we only want to assert it isn't "up".
    assert_ne!(st.state, "up", "got state {:?}", st);
}
