//! Per-tool baseline tokens — prompto's slice of the universal
//! [`mcp_gain`] gain registry.
//!
//! Each number estimates how many tokens the **SSH+bash counterfactual**
//! would have leaked into an agent's context: the raw output plus the
//! banners, table headers, retry chatter and sudoers gripes a typed tool
//! avoids. `saved = baseline - actual_output`.
//!
//! # v4 calibration (2026-08-13)
//!
//! v3 numbers were hand-estimates. v4 is derived from **2,745 recorded
//! calls** in `/var/lib/prompto/usage.jsonl`, using the *median* observed
//! output per tool (robust against the odd 250 KB file read) plus a fixed
//! ~60-token round-trip allowance for banner/prompt/envelope.
//!
//! Several v3 numbers were **too generous** and are cut here. That lowers
//! prompto's headline savings figure, which is the point: the gain log is
//! telemetry, not marketing. Where a number is inflated the tool looks
//! good and we learn nothing.
//!
//! Recorded events keep the baseline they were written with, so this
//! change only affects future calls — historical aggregates stay a mix,
//! which is why `SOURCE` is versioned.
//!
//! # Known limitation: content-proportional tools
//!
//! `mcp_gain` supports one flat baseline per tool. That models most tools
//! well — the counterfactual cost of `host_status` is ~180 tokens whatever
//! the answer is. It models two tools badly:
//!
//! * **`file_read`** — the manual equivalent is `ssh host cat file`, which
//!   returns *the same bytes*. Its real saving is the size cap and the
//!   avoided stat-then-cat round-trip, not fewer bytes. Observed median is
//!   583 tokens but the mean is 8099 (one huge read skews it).
//! * **`ssh_exec`** — `cargo test` compacts 1225 → 10 tokens via the filter
//!   chain, while `systemctl is-active` compacts nothing. The true baseline
//!   is per-call, not per-tool.
//!
//! For both, the flat number is a median approximation: small calls read
//! positive, large ones read negative, and it averages out honest. Fixing
//! this properly needs a per-call baseline argument in `mcp_gain::record`
//! (the payload already carries `original_bytes` at the call site) — a
//! shared-crate change, deliberately not made unilaterally here.

pub const SOURCE: &str = "estimate@v4";

pub const BASELINES: &[(&str, u32)] = &[
    // ── host_* ───────────────────────────────────────────────────────
    // Observed medians are tiny (10-13 tok) because these return one
    // structured line. The counterfactual is an ssh with ConnectTimeout
    // plus parsing, or a wakeonlan/python one-liner. v3 numbers hold.
    ("host_status", 180),
    ("host_wake", 80),
    ("host_sleep", 120),
    // Composite probe replacing ~5 round-trips of small commands
    // (uptime/free/df/ss/systemctl --failed/uname). Observed 476 tok on
    // the single recorded call.
    ("host_diagnose", 1400),
    // ── vm_* ─────────────────────────────────────────────────────────
    // `virsh list --all` is a bordered table; the typed form is compact
    // JSON. Observed median 59 tok. v3 numbers hold.
    ("vm_list", 280),
    ("vm_state", 90),
    ("vm_start", 110),
    ("vm_stop", 360),
    ("vm_ensure_up", 420),
    // ── ssh_* ────────────────────────────────────────────────────────
    // v3 had 1200/1300, set from a small v0.4 sample. 2,389 recorded
    // ssh_exec calls since then show median 95 and mean 378 tokens of
    // *filtered* output. The counterfactual is higher than the filtered
    // figure (the filter chain is doing real work on cargo/git/pkg
    // output), but nowhere near 1200 — that number was inflating the
    // headline gain. 500 sits above the observed mean to credit the
    // filtered cases without over-claiming.
    // CONFIDENCE: medium. The log stores filtered bytes only, so the
    // unfiltered counterfactual is inferred, not measured.
    ("ssh_exec", 500),
    ("ssh_sudo_exec", 550), // + sudo/tty noise
    // N sequential ssh_exec calls; median batch ~5.
    ("ssh_batch", 2500),
    // ── agent delegation ─────────────────────────────────────────────
    // v3 claimed 5000 (a 99% saving) on n=1. The premise — remote agent
    // reads ~5 KB and returns a summary — is plausible but unvalidated.
    // Trimmed until there's real volume behind it.
    // CONFIDENCE: low (n=1).
    ("claude_exec", 3000),
    // ── script_* ─────────────────────────────────────────────────────
    // Baseline covers the "ssh + heredoc got mangled, retry" round-trip
    // these replace by piping the body over stdin. v3 numbers assumed a
    // full failed attempt plus traceback; observed medians are ~92-118
    // tok, so the retry allowance is trimmed.
    ("python_exec", 500),
    ("node_exec", 450),
    ("bash_exec", 350),
    ("ruby_exec", 450),
    ("perl_exec", 400),
    ("deno_exec", 450),
    // ── file_* ───────────────────────────────────────────────────────
    // Content-proportional — see the module docs. Median observed read is
    // 583 tok; 900 credits the size cap and the avoided stat-then-cat
    // round-trip. Large reads will score negative, and that is honest:
    // `file_read` of a 200 KB file genuinely does not save tokens over
    // `cat`, it just refuses to blow up.
    ("file_read", 900),
    // Writes are the opposite shape: output is a fixed ack (~26 tok)
    // while the counterfactual is tee-over-ssh plus shell-quoting hell.
    ("file_write", 250),
    ("file_list", 400),
    ("file_stat", 150),
    ("port_scan", 200),
    ("service_control", 350),
    // ── inventory_* ──────────────────────────────────────────────────
    // Counterfactual is `sudo cat /etc/prompto.toml` — 4,844 bytes ≈
    // 1,211 tokens, comments and all. Observed typed output 684 tok.
    // v3's 1400 is supported by the data; kept.
    ("inventory_list", 1400),
    ("inventory_get_host", 200),
    // ── rsync_sync ───────────────────────────────────────────────────
    // NOTE: 19 recorded calls, 19 failures — zero successful samples, so
    // this number is still an estimate and the tool itself needs
    // investigating. Baseline assumes ~30 files with full progress lines.
    // CONFIDENCE: low (no successful calls).
    ("rsync_sync", 1500),
    // ── mcp_* ────────────────────────────────────────────────────────
    ("mcp_list", 200),
    ("mcp_get", 150),
    ("mcp_add", 180),
    ("mcp_remove", 140),
    ("mcp_restart_claudecli", 200),
    // Probes every server on the client (~3-6 entries). Observed 344 tok.
    ("mcp_status", 700),
    // Journal tail. `mcp_logs` is the deprecated alias for `service_logs`
    // — same baseline, recorded separately so the gain log shows when the
    // old name has fallen out of use and the alias can be retired.
    ("service_logs", 400),
    ("mcp_logs", 400),
    ("mcp_reconnect_hint", 200),
    // ── self ─────────────────────────────────────────────────────────
    // No SSH equivalent exists, so it claims nothing. This makes the tool
    // score its own output as pure cost (~322 tok median), dragging the
    // total down slightly. That is the honest direction to be wrong in.
    ("prompto_gain", 0),
];

pub fn header() -> String {
    format!("prompto gain — {SOURCE}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_baseline_keys() {
        let mut seen = HashSet::new();
        for (tool, _) in BASELINES {
            assert!(seen.insert(*tool), "duplicate baseline entry for {tool}");
        }
    }

    /// Drift guard: every tool prompto advertises must have a baseline,
    /// and every baseline must name a real tool. Without this, adding a
    /// tool silently gives it baseline 0 — it would record as pure cost
    /// and quietly drag the reported gain down.
    ///
    /// The advertised list is parsed from the same `Tools: …` sentence in
    /// the server instructions that clients see, so the two cannot drift
    /// apart unnoticed.
    #[test]
    fn baselines_cover_exactly_the_advertised_tools() {
        let info = crate::mcp::instructions();
        let list = info
            .split("Tools: ")
            .nth(1)
            .expect("instructions must contain a `Tools: ` list")
            .split('.')
            .next()
            .expect("tool list must end with a period");
        let advertised: HashSet<&str> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let have: HashSet<&str> = BASELINES.iter().map(|(t, _)| *t).collect();

        let missing: Vec<_> = advertised.difference(&have).collect();
        let extra: Vec<_> = have.difference(&advertised).collect();
        assert!(
            missing.is_empty(),
            "tools advertised with no baseline (they would record as pure cost): {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "baselines for tools that no longer exist: {extra:?}"
        );
    }

    /// A zero baseline means "this tool claims no saving". Only
    /// `prompto_gain` legitimately has one; anywhere else it is a typo
    /// that silently understates gain.
    #[test]
    fn only_prompto_gain_has_a_zero_baseline() {
        for (tool, n) in BASELINES {
            if *n == 0 {
                assert_eq!(*tool, "prompto_gain", "unexpected zero baseline for {tool}");
            }
        }
    }
}
