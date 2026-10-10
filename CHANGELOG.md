# Changelog

## v0.12.1 (unreleased)

Precheck and signed tickets (roadmap E6): policy `approval = "ticket" | "human"` now grants a call that carries a valid ticket, instead of always refusing it.

### What's new

- **`POST /v1/precheck`** (bearer auth, like `/mcp`): runs a call's whole authorization without running it and answers `allow` / `deny` / `ask`, with the deciding `rule` and a `reason`. On a `ticket` rule, `allow` carries a ticket: single-use, valid for 120 s, bound to the agent, session, tool, canonical host(s) and the SHA-256 of the canonical arguments (RFC 8785).
- **`POST /v1/approve`**: a human approver's TOTP code (RFC 6238; single-use codes; lockout after 5 wrong codes in 15 min) turns an `ask` into an `approval = "human"` ticket naming the approver. Optional `scope_minutes` (≤ 60): one ticket for every call by the same agent, session, tool and host(s), decided by the same policy rule(s) and with the same root-capability, whatever the other arguments. A scope for a root-capable call needs `allow_root_scope: true`.
- **Every tool accepts a `ticket` argument**, checked where policy demands one: missing → `approval_required` (the message says how to get one), invalid, forged, expired, replayed or for another call → `refused_ticket`.
- **Keys** from vault KV (`PROMPTO_TICKET_KEY_VAULT_PATH`, fields `current` / `previous`) or an owner-only file (`PROMPTO_TICKET_KEY_FILE`); current and previous both accepted; re-read every minute and on SIGHUP. Used nonces and TOTP steps persist (synced) in `PROMPTO_APPROVAL_STATE` across restarts.
- **Approval secrets are never agent-readable.** The ticket key and vault-held TOTP secrets are read from their own KV mount, `PROMPTO_PRIVATE_MOUNT` (default `prompto-private`), which only prompto's token may read. If either is configured under `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` (default `prompto/,infra/` on `PROMPTO_VAULT_MOUNT`), approvals are turned off with an error saying what to move. `prompto approver add --vault-path` refuses such paths, and paths next to a sudo password unless `--i-know`.
- **Inventory `prompto_host = true`** marks the machine running prompto; `policy lint` reports an error for any rule granting root there (sudo, or exec where the shell can sudo) unless the rule says `crown_jewel_ack = true`.
- **CLI:** `prompto approver add|list|revoke` (prints the `otpauth://` URI and a terminal QR code once; `--i-know`), `prompto ticket keygen`.
- **Audit:** the ticket is removed from `args` and recorded as `ticket_sha256`; `approved_by` is filled in; new record types `precheck` and `approve`.

### Upgrade note — no new config

With neither ticket variable set, nothing is minted or accepted: `approval` rules refuse their calls as in v0.12.0. Visible changes:

1. The `approval_required` message is new (it explains the precheck/approve flow, or says no ticket key is configured) and `policy lint` no longer warns about `approval` rules; the server warns at startup instead when such rules exist and no ticket key is configured.
2. Two new routes, `POST /v1/precheck` and `POST /v1/approve`, behind the same authentication as `/mcp` (unauthenticated with `PROMPTO_AUTH=off`, where they report every call as needing no approval).
3. Audit records may carry `ticket_sha256` / `scope_minutes`, and `args.ticket` is never recorded.
4. `serde_json`'s `float_roundtrip` is on: JSON numbers in arguments now always parse to the nearest double (needed for stable argument digests).

## v0.12.0

Attributable, policed, audited, killable. Every call now has a request ID,
passes one central gate, can carry an agent identity, is checked against a
policy, is written to an audit log with a classified outcome, and can be
stopped at any scope without a restart. Design: `docs/design/agent-identity-audit-certs.md`;
plan: `docs/design/roadmap-v0.12-v0.13.md` (E0 S0.2, E1–E5).

### What's new

- **Request IDs (E1).** Every call gets a ULID, returned on success (a trailing `request_id` field; `vm_list`, which returns an array, gets a second `[request_id=…]` text block) and on error (`[request_id=… error_class=…]` prefix, `error.data.request_id`). Remote commands see it as `PROMPTO_REQUEST_ID` (per-host `request_id_env`: `export` | `setenv` | `off`).
- **One central authorization gate (E1).** Existence, capability, self-target guard, policy — in that order, for every tool, in `authz`.
- **Unconditional self-target guard (E1).** Every tool that contacts a host refuses the caller's own machine (`refused_self_target`), not only the three exec tools; addresses compared canonically; inventory `extra_ips` for multi-homed callers. No policy can lift it.
- **Agent tokens and `PROMPTO_AUTH` (E2).** One bearer token per role, stored as SHA-256 in `/etc/prompto/agents.toml`; `prompto agent add|list|revoke`; `PROMPTO_AUTH=off|optional|required` (default `off`); `X-Prompto-Session` as context; legacy MCP sessions bound to their creator. `agents.toml` is re-read on the first request after it changes (no SIGHUP needed) and fails closed when broken (E5).
- **Policy (E3).** `/etc/prompto/policy.toml`, first match wins, default deny with auth on; root-capable calls are a separate `sudo = true` grant; host groups; `approval` rules fail closed until tickets ship; `prompto policy check|lint`; a bad reload fails closed. Not read with `off`.
- **Audit log (E4).** `/var/lib/prompto/audit.jsonl` (`PROMPTO_AUDIT_LOG`) plus journald `AUDIT_*` fields: who, what, where, arguments (scrubbed of secrets, file contents hashed), decision, rule, outcome. Every call, refusal, `GET /log` and 401. Auth on: nothing runs that can't be recorded. Rotation by rename, no signal (`deploy/logrotate.d/prompto-audit`). `prompto audit [filters]`.
- **Error classes (E0 S0.2, E4).** One `error_class` enum on every failure (`error.data.error_class`, also in the audit record): `unknown_host`, `refused_*`, `approval_required`, `invalid_args`, `ssh_connect`, `ssh_auth`, `timeout`, `sudo_guard`, `remote_nonzero`, `vault`, `upstream`, `internal`, `aborted`, `killed`, and rsync's `rsync_*` / `dest_ssh_*` (with exit code and stderr tail).
- **Kill switches (E5).** `prompto kill on|off|status`, `kill agent|host|session <name> [reason]`, `unkill …`: files under `/etc/prompto` (`kill`, `kill.d/`), checked on every call before anything else, in every auth mode; refused calls are `killed` and audited with the scope. A switch the server can't check fails closed: it won't start, and if it loses access while running, calls are refused as `killed` (`kill switch unreadable`). Every `kill`/`unkill` is itself audited (`"type": "kill"`: on/off, scope, target, reason, who incl. `SUDO_USER`), shown by `prompto audit`; if that record can't be written the switch still applies, with a warning. Session kills need `optional`/`required` (`off` ignores `X-Prompto-Session`).
- **`policy.toml` reloads itself (E5 follow-up).** Like `agents.toml`, it is re-read on the first call after it changes, no SIGHUP needed (SIGHUP still works), with the same fail-closed handling of a broken file.

### Prod upgrade note — no new config (`PROMPTO_AUTH` unset = `off`)

Nothing asks for a token and no policy is read, but these are visible to existing clients:

1. **`request_id` in every result.** Object results gain a trailing `"request_id"` field; `vm_list` gets an extra text block; error messages start with `[request_id=… error_class=…]` and `error.data` is now an object (`error_class`, `exit_code`, `stderr_tail`, `request_id`) instead of `null`. A client that compares result JSON byte for byte, or greps old error wording, needs updating.
2. **Self-target refusals for every tool.** Calls aimed at the caller's own machine (by source IP, behind nginx via `X-Real-IP` from a trusted proxy) are refused for every host-contacting tool, not just `ssh_exec`/`ssh_batch`/`ssh_sudo_exec`: e.g. an agent running `mcp_restart_claudecli`, `mcp_status`, `host_status`, `port_scan`, `bash_exec` or `file_*` against its own client now gets `refused_self_target`. Check the usage log for same-IP calls to those tools before upgrading.
3. **`PROMPTO_REQUEST_ID` on remote commands.** On `linux`/`macos` hosts the command is prefixed with `export PROMPTO_REQUEST_ID=…;` (plus `ssh -o SetEnv`). Set `request_id_env = "off"` in the inventory for any host whose key is restricted by `command=`, rrsync or git-shell, or those calls will be rejected.
4. **The audit file is written.** `/var/lib/prompto/audit.jsonl` (inside the unit's `ReadWritePaths`), agent `-`. With `off`, write failures only warn; there is no switch to turn it off. Install the logrotate snippet and, for readers, the `prompto-audit` group (`deploy/install.sh` does both). Expect roughly one line per call; commands are recorded in full (secrets scrubbed on a best-effort basis).
5. **rsync error classes.** `rsync_sync` failures carry `error_class` (`rsync_*`, `dest_ssh_auth`, `dest_ssh_connect`, …), the exit code and a stderr tail instead of "unexplained error (code 255)"; exit 24 is still a failure (`rsync_partial`).
6. **`inventory_list` / `inventory_get_host` shape.** Each key appears once (the old output repeated `platform`, `chassis`, `aliases`, …; values are unchanged since later keys won), a `request_id_env` field is added, `groups` and `extra_ips` appear when set, and the result has the trailing `request_id`. With `off` no host or field is hidden.
7. **Kill switches are live, and must be checkable.** Nothing changes unless `/etc/prompto/kill` or a file in `/etc/prompto/kill.d/` exists; each call `stat`s those paths. `prompto kill on` is the prod panic button and works with `off`. **The server refuses to start if its user (`prompto`) can't check them** — any `stat` error other than "absent" on `/etc/prompto/kill`, `/etc/prompto/kill.d` or inside `kill.d`, e.g. `/etc/prompto` not searchable by group `prompto`. Before upgrading, check: `sudo -u prompto stat /etc/prompto/kill /etc/prompto/kill.d` must say "No such file or directory" or succeed, never "Permission denied". Fix with `chgrp prompto /etc/prompto && chmod 0750 /etc/prompto` (what `deploy/install.sh` does), or set `PROMPTO_KILL_FILE` elsewhere. If the paths become unreadable while running, calls are refused as `killed` until fixed. `prompto kill …` also appends a `type: kill` record to the audit log (new record type for anything that parses the file).
8. **Other:** `mcp_reconnect_hint`'s text says the client must restart itself locally; `GET /log` refuses the caller's own host (since E1) and answers a kill with 503/403.

**Recommended rollout:**

1. Deploy v0.12.0 with no new config (`off`). Check the points above; watch `prompto audit --since 1h` and the journal for `refused_self_target`.
2. Write `/etc/prompto/policy.toml` (start permissive: `anonymous` and the roles with `tools = ["*"]` plus a `sudo = true` twin on `hosts = ["*"]`; `prompto policy lint`) and mint a token per role (`prompto agent add <role>`); register clients with their token.
3. Set `PROMPTO_AUTH=optional` and restart. Everything still works; calls without a token run as `anonymous` under the anonymous grants. Watch for `agent="anonymous"` in the audit log.
4. Once every client sends a token: drop the `anonymous` grants, narrow the rules, set `PROMPTO_AUTH=required` and restart.
