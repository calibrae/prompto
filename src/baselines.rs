//! Per-tool baseline tokens — prompto's slice of the universal
//! [`mcp_gain`] gain registry.
//!
//! Each number is a hand-coded estimate of how many tokens an SSH+bash
//! equivalent of the tool's job would have leaked into an agent's context
//! (banners, virsh table headers, retry chatter, sudoers gripes).
//! Recalibrate after a few weeks of real `prompto_gain` data — the field
//! `baseline_source` in the response carries the version so the numbers
//! stay auditable.

pub const SOURCE: &str = "estimate@v2";

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
    // ssh_* — bumped from 200/220 in v0.5 to match observed v0.4 reality:
    // post-deploy data showed ssh_exec calls average ~1200 tokens of raw
    // remote stdout. The new built-in filter chain compacts common cases
    // (cargo test/build, git log/diff/show, journalctl, find, ls -l)
    // back below the baseline, restoring honest savings %.
    ("ssh_exec", 1200),
    ("ssh_sudo_exec", 1300),
    // script_*: piped-stdin interpreter invocation. Baseline includes the
    // typical "I tried to ssh+heredoc this and got mangled" round-trip
    // an agent does today (failed attempt + retry + traceback noise).
    ("python_exec", 800),
    ("node_exec", 700),
    ("bash_exec", 500),
    // file_*: typical SSH+cat / SSH+tee leaks banner + file content;
    // a typed wrapper returns just the bytes plus a tight envelope.
    ("file_read", 500),
    ("file_write", 250),
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
