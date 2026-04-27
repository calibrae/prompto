//! Per-tool baseline tokens — prompto's slice of the universal
//! [`mcp_gain`] gain registry.
//!
//! Each number is a hand-coded estimate of how many tokens an SSH+bash
//! equivalent of the tool's job would have leaked into an agent's context
//! (banners, virsh table headers, retry chatter, sudoers gripes).
//! Recalibrate after a few weeks of real `prompto_gain` data — the field
//! `baseline_source` in the response carries the version so the numbers
//! stay auditable.

pub const SOURCE: &str = "estimate@v1";

pub const BASELINES: &[(&str, u32)] = &[
    // host_*
    ("host_status", 180),
    ("host_wake", 80),
    ("host_sleep", 120),
    // vm_*
    ("vm_list", 280),
    ("vm_state", 90),
    ("vm_start", 110),
    ("vm_stop", 360),
    ("vm_ensure_up", 420),
    // ssh_*
    ("ssh_exec", 200),
    ("ssh_sudo_exec", 220),
    // mcp_* — wrappers around `claude mcp …`
    ("mcp_list", 200),
    ("mcp_get", 150),
    ("mcp_add", 180),
    ("mcp_remove", 140),
    ("mcp_restart_claudecli", 200),
    ("mcp_status", 280),
    ("mcp_logs", 600),
    ("mcp_reconnect_hint", 200),
    // self — no SSH equivalent, baseline 0 → saved 0
    ("prompto_gain", 0),
];

pub fn header() -> String {
    format!("prompto gain — {SOURCE}")
}
