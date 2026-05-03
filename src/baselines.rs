//! Per-tool baseline tokens — prompto's slice of the universal
//! [`mcp_gain`] gain registry.
//!
//! Each number is a hand-coded estimate of how many tokens an SSH+bash
//! equivalent of the tool's job would have leaked into an agent's context
//! (banners, virsh table headers, retry chatter, sudoers gripes).
//! Recalibrate after a few weeks of real `prompto_gain` data — the field
//! `baseline_source` in the response carries the version so the numbers
//! stay auditable.

pub const SOURCE: &str = "estimate@v3";

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
    // ssh_batch: equivalent to N sequential ssh_exec calls. Baseline
    // assumes a modest 5-command batch — that's the median use case
    // (destroying a few snapshots, restarting a handful of services).
    // Heavier batches save proportionally more.
    ("ssh_batch", 6000),
    // claude_exec: agent-as-tool, intelligent compaction. Baseline assumes
    // the equivalent task done via ssh_exec would have pulled ~5 KB of raw
    // output the caller then has to parse — vs the remote agent returning
    // ~200 chars of summary.
    ("claude_exec", 5000),
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
    ("service_control", 350),
    // host_diagnose: composite of uptime + free -m + df -h + ss -tln +
    // systemctl --failed + uname etc. Equivalent to ~5 separate ssh_exec
    // calls — that's the baseline we're measuring against.
    ("host_diagnose", 1500),
    // v0.6.7 additions
    ("ruby_exec", 600),
    ("perl_exec", 500),
    ("deno_exec", 700),
    ("file_list", 600),
    ("file_stat", 250),
    ("port_scan", 200),
    // inventory_*
    // v3 recalibration: returning all 24 hosts is ~5 KB of JSON ≈ 1300
    // tokens. Old 400 baseline was leaking -61% gain.
    ("inventory_list", 1400),
    ("inventory_get_host", 200),
    ("inventory_add_host", 150),
    ("inventory_remove_host", 100),
    ("inventory_grant_capability", 100),
    ("inventory_revoke_capability", 100),
    // rsync_sync: equivalent to a hand-rolled "ssh src 'rsync -av … dst'"
    // dance with full progress lines; baseline assumes ~30 files synced.
    ("rsync_sync", 1500),
    // mcp_* — wrappers around `claude mcp …`
    ("mcp_list", 200),
    ("mcp_get", 150),
    ("mcp_add", 180),
    ("mcp_remove", 140),
    ("mcp_restart_claudecli", 200),
    // v3: probes ALL servers on the client (~3-6 entries) → ~1.3 KB of
    // structured JSON. Old 280 baseline was leaking -16% gain.
    ("mcp_status", 700),
    ("mcp_logs", 600),
    ("mcp_reconnect_hint", 200),
    // self — no SSH equivalent, baseline 0 → saved 0
    ("prompto_gain", 0),
];

pub fn header() -> String {
    format!("prompto gain — {SOURCE}")
}
