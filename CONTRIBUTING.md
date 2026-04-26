# Contributing

Single-author project. If you are an LLM agent picking this up, **read `CLAUDE.md` first** (if present in your local clone) — it has the agent persona, mission, lineage references, and roadmap.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

Unit tests cover WOL packet construction, inventory parsing/validation, and capability gating. Integration tests spin up the MCP over stdio against a sandbox inventory and verify the tool surface.

## Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Smoke test before shipping to production

`prompto` controls real machines. Don't deploy a build that hasn't:

1. Built clean (no warnings)
2. Passed `cargo test`
3. Round-tripped a `host_status` against a known-up host from a dev box
4. Sent a real WOL packet to a NIC you can observe

If you're replacing an existing WOL/lifecycle service, ship behind it (both running) until any consumers (Home Assistant switches, cron jobs, etc.) are migrated.
