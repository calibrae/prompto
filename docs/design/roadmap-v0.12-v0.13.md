# prompto — agent identity, policy, audit, approvals, short-lived creds

## Context

prompto knows *what* ran and *where*, never *who*. Five months of usage (8,544 calls) show:
- no caller identity;
- ~90% raw shell (`ssh_exec` alone 84%);
- one workstation making 95% of calls from ~30 sessions;
- failures logged with no reason.

Every agent reaches every host as the same user with one long-lived key.

A market survey found nothing that combines typed machine tools, per-agent identity/policy/audit, and ephemeral machine credentials. Claude Code ≥2.1.287 (installed: 2.1.289) has **mods**: in-process plugins that can hold, rewrite, deny or answer tool calls, show approval panes, and read the session ID. That makes human-in-the-loop, argument-level approval possible from inside the agent's own terminal.

**Goal:** every call is attributable (agent role + Claude session), checked against policy, audited with a request ID, killable at any scope, and optionally human-approved. Then prompto's own SSH access moves to per-call short-lived certificates.

**Decisions taken:**

| Topic | Decision |
|---|---|
| Identity | Role token + session ID. One bearer token per agent role. The mod adds the Claude session ID as context; it is not proof of identity |
| Audit sink | JSONL on mista + journald structured fields first. Central shipping later |
| `ssh_sudo_exec` | Its own policy grant, separate from `ssh_exec` |
| Enforcement | Always server-side in prompto. The mod is UX + context, never the boundary. A call without a valid ticket is refused wherever policy demands one |

## Architecture anchor (from code mapping)

**Request path today:**
- `server.rs` `build_router` adds a `capture_caller_ip` middleware.
- That sets a task-local in `caller.rs`.
- The rmcp factory snapshots it into `Prompto { caller_ip }`.
- Handlers in `mcp.rs` (38 tools) each do `inv.require*` inline, then `finish_tool()` (L490–516), which records to `mcp_gain::Tracker`.
- `ssh.rs::run()` (L202) is the single ssh spawn.
- Errors return as `McpError::internal_error`.

**Pattern to reuse everywhere:**
- task-local → factory snapshot → struct field;
- `ArcSwap` store + SIGHUP reload (`InventoryStore`, `main.rs` `spawn_sighup_reloader`);
- `tests/self_target_guard.rs::spawn_server_with` for end-to-end tests over HTTP;
- `vault.rs` fake-vault axum router for vault tests.

**New deps** (none present today): `sha2`, `hmac`, `subtle`, `ulid`, `getrandom`. Later: `jsonwebtoken` (E9), `ssh-key` or shelling out to `ssh-keygen` (E8).

---

## Epics and stories

### E0 — Spikes & housekeeping (before code)
- **S0.1 Spike: mods see MCP calls.** A 10-line logging mod via `--plugin-dir`. Confirm `tool.call` fires for `mcp__prompto__*`, and note the exact `e.tool` and input field names. Confirm that `next({...e, input})` rewriting reaches the MCP server and that `$.session.id` is available. **Gates E7's design.**
  - **Done 2026-10-04** (Claude Code 2.1.289). Confirmed live with `--plugin-dir` + `claude -p`:
    - `tool.call` fires for `mcp__prompto__*`. `e` carries `tool`, `tool_use_id`, and the arguments as **flat top-level fields** (`e.host`), not `e.input`.
    - `$.session.id()` and `$.session.cwd()` are async and work headless.
    - `next({...e, host: 'calisense'})` reached prompto: the model asked for doppio, prompto probed calisense.
    - `next({...e, ticket: '…'})` passed Claude Code's validation, and prompto accepted the call (unknown field ignored).
  - **Consequence:** a mod can silently redirect or alter calls. That's further proof enforcement must stay server-side, with the ticket bound to the exact arguments.
- **S0.2 `rsync_sync` failure reason.** Classify its errors (precondition vs ssh vs rsync) and surface them in the tool result. It's the most-failed tool (26–72%/month).
- **S0.3 Decide the 7 never-called tools:** `node_exec`, `ruby_exec`, `perl_exec`, `deno_exec`, `mcp_add`, `mcp_remove`, `mcp_restart_claudecli`. Keep or remove; every tool is surface that policy must cover.
- **S0.4 nginx attribution:** add `$host` to the mista access log format. Decide what happens to direct `:6337` access once auth exists. Once auth is in prompto, both paths are equivalent.

### E1 — Call context & central authorization (refactor, no behaviour change)
- **S1.1 `CallCtx`.** `{ request_id: Ulid, caller_ip, agent: Option<Agent>, session_id: Option<String> }`, built per tool call. The `request_id` is returned in every result (success and error).
- **S1.2 `Prompto::authorize(ctx, tool, host, Need)`.** One function replacing the inline `require`/`require_remote` in all 38 handlers. It applies the capability check, the self-target guard, and later the policy (E3) and tickets (E6). The guard is now **unconditional**: before this, `file_write`, `bash_exec` and others lacked it. Every tool that contacts a host refuses the caller's own machine. There is no exemption table: only tools that never contact a host (the hostless ones, and `inventory_get_host`, which uses `authz::lookup`) are outside it. The guard is **not a policy dimension**. E3 and E6 run after it and cannot re-open it. Caller and host IPs are compared canonically (`::ffff:a.b.c.d` = `a.b.c.d`). Mechanical change across `mcp.rs`; existing tests must stay green.
- **S1.3 Thread ctx into SSH.** `SshClient::exec*`/`run()` take `&CallCtx`. The remote side gets `PROMPTO_REQUEST_ID` (via `-o SetEnv` where accepted, otherwise an env prefix in the remote command). This is the hook point for certificates in E8.
- **S1.4 `finish_tool` takes ctx.** It becomes the single emission point for both the gain tracker and the audit record (E4).

### E2 — Agent identity: static role tokens (v0.12.0)
- **S2.1 `agents.toml` + `AgentStore`.** Entries: name, groups, sha256 of the token, `disabled`, created. `ArcSwap`, SIGHUP-reloaded, fail-safe like the inventory.
- **S2.2 CLI.** `prompto agent add <name> [--groups …]` prints the token once and writes only the hash; `agent list`; `agent revoke <name>`.
- **S2.3 Auth middleware.** Reads `Authorization: Bearer`, compares in constant time (`subtle`), sets an `AGENT` task-local. The factory snapshots it into `Prompto`, like `caller_ip`. It also reads the optional `X-Prompto-Session` header (context only).
- **S2.4 `PROMPTO_AUTH=off|optional|required`.** `optional` → unauthenticated calls become `agent=anonymous` and get the anonymous policy. `required` → 401. `GET /log` is gated the same way. stdio is `agent=local`.
- **S2.5 Client registration doc.** `claude mcp add … --header "Authorization: Bearer …"`, or `headersHelper` reading `~/.config/prompto/token` (0600).
- **Tests:** 401 / anonymous / valid / revoked / reload, through `spawn_server_with`.
- **Done (task 005).** Decisions:
  - `agents.toml` is `[agent.<name>]` tables with `groups`, `token_sha256`, `created` and `disabled`. Names are `[a-z0-9_-]`; `anonymous` and `local` are reserved; a duplicate hash is a load error.
  - `agent revoke` sets `disabled = true` and keeps the entry: the name stays taken, and a stale token is logged as revoked, naming the role.
  - CLI edits need SIGHUP, and the CLI says so. The inventory and the agents reload independently; each keeps its previous version on error.
  - A malformed `X-Prompto-Session` (over 128 chars, or outside `A-Za-z0-9._:-`) is dropped with a warning. It is context, so it never fails the call.
  - Attribution lives in the journald `tool call failed` line (`agent`, `session_id`) until E4. Results don't echo the agent.
  - An unknown `PROMPTO_AUTH` value is a startup error.
  - E1 leftover: inventory `extra_ips`, compared by the self-target guard.

### E3 — Policy engine (v0.12.0)
- **S3.1 `policy.toml` + `PolicyStore`.** SIGHUP-reloaded; default deny when auth is required. Rules are agent (or group) × hosts (names, globs, `group:<g>`) × tools (names/globs), with `approval = "none" | "ticket" | "human"`.
- **S3.2 Inventory `groups = [...]`** per host. Validated at load; `inv_check` also validates `policy.toml` against the inventory and `agents.toml`.
- **S3.3 Separate grants:** `ssh_sudo_exec`, `file_write{sudo=true}`, `service_control` and `host_sleep` each need an explicit grant even on `sudo_exec` hosts. Effective permission = policy ∩ host capability.
- **S3.3b No self-target grant.** Policy can only narrow. It has no rule, glob or approval mode that lets an agent target its own machine: the self-target guard (S1.2) runs before policy and is not configurable.
- **S3.4 Decisions name their rule.** Allow and deny both carry `rule = "<file>:<line>"`. Deny messages are actionable ("agent X has no grant for ssh_sudo_exec on mista").
- **S3.5 Dry-run:** `prompto policy check --agent X --host Y --tool Z`.
- **Done (task 007).** Decisions:
  - `policy.toml` is an ordered list of `[[rule]]` tables (`id`, `agents`, `hosts`, `tools`, `sudo`, `approval`). **The first matching rule decides; no match is a deny.** Rules only grant, so order only picks which rule's `approval` applies. An array keeps file order, which `[agent.<name>]` tables would not.
  - `agents` take names or `group:<g>`, never globs. `anonymous` and `local` match only by name. Groups come from the live `AgentStore` at each decision, so a SIGHUP group change or revocation reaches open (legacy) sessions.
  - `hosts` match the inventory name or any alias, with `*`/`?` globs, or `group:<g>` from the new inventory `groups`. Hostless tools skip the host dimension.
  - Root-capable is a **flag on the rule** (`sudo = true`), not a pseudo-tool name. A call is root-capable when it needs `sudo_exec`, or it is `vm_stop`. Rules match only calls of their own kind, so `tools = ["*"]` can't leak root, and a glob can't be written that does.
  - `approval = "ticket" | "human"` refuses with the new class `approval_required` until E6. Lint warns about it.
  - Errors carry `rule` in `error.data`. The journald `tool call failed` line has it too, and allows log `policy allow … rule=…`. The rule is `policy.toml:<line>`, with ` (<id>)` when set, or `default-deny`.
  - Policy is loaded only in optional/required. With `off` it is never read, as with `agents.toml`. A missing file is deny-all with a loud warning; a malformed one is fatal at startup and, on SIGHUP, **fails closed**: deny-all, with `policy file invalid since <time>: <error>` in refusals, until a valid file is loaded (task 008; it used to keep the previous policy).
  - `sudo = true` gates prompto's own root paths only. An exec grant is a shell as `ssh_user`, which is root where that user is root or has passwordless sudo. Inventory `nopasswd_sudo` (optional) feeds a lint warning, and every tool is classified root-capable / arbitrary exec / ordinary, enforced by a test (task 008).
  - With policy on, `inventory_list` lists only hosts the agent has a grant on, and `sudo_password_vault_path` appears only with a `sudo = true` grant on that host (also in `inventory_get_host`). `off` output is unchanged. `tools/list` is not filtered (owner decision, task 008).
  - Lint: an agent group nobody is in is a warning, not an error (owner decision, task 008).
  - `prompto policy lint` (also run at startup and on reload, log only) enumerates every agent × host × tool × root call to find shadowed and dead rules exactly.

### E4 — Audit log (v0.12.0)
- **S4.1 Writer.** Append-only `audit.jsonl` (`0640 prompto:prompto-audit`), plus a `tracing` event with the same fields so journald gets structured fields.
- **S4.2 Record fields:**
  - `ts`, `request_id`, `agent`, `agent_groups`, `session_id`, `client_ip`, `user_agent`;
  - `tool`, `host` (canonical), `queried_as`;
  - `args`, `decision`, `rule`, `approval`, `approved_by`;
  - `exit_code`, `ok`, `error_class`, `duration_ms`, `bytes`.
- **S4.3 Argument redaction:** full commands, with file contents and script bodies as `sha256` + length. Vault-fed secrets never reach args.
- **S4.4 `error_class` enum:** `refused_policy`, `refused_capability`, `refused_self_target`, `refused_ticket`, `killed`, `ssh_connect`, `timeout`, `sudo_guard`, `remote_nonzero`, `internal`.
- **S4.5 Query CLI:** `prompto audit [--agent] [--host] [--tool] [--since] [--request-id] [--json]`.
- **S4.6 Rotation:** a logrotate snippet in `deploy/`; README section.

### E5 — Kill switches (v0.12.0)
- **S5.1 Global kill file** `/etc/prompto/kill`, checked per call, no restart. Every call is refused with a fixed message and audited as `killed`.
- **S5.2 Per-agent:** `agent revoke` or `disabled = true`, then SIGHUP → next call refused.
- **S5.3 Per-host:** drop the host from policy or inventory (already works via SIGHUP); document it.
- **S5.4 Per-session:** `prompto session kill <session_id>` adds to a deny set (in memory + file), so one runaway Claude session stops without revoking its role.

### E6 — Precheck API & signed tickets (v0.12.1)
- **S6.1 Ticket format:** HMAC-SHA256 over `{agent, session_id, tool, host, sha256(canonical args), approval, approved_by, exp, nonce}`. The key comes from vault KV, with a file fallback. TTL 120 s.
- **S6.2 `POST /v1/precheck`** (bearer auth) → `{decision: allow|deny|ask, rule, reason, ticket?}`. A ticket is minted only for `allow`.
- **S6.3 `POST /v1/approve`** → mints a ticket with `approval=human`, `approved_by=<operator>` after the mod's pane confirms. Optional `scope_minutes` for "approve similar calls for N minutes", bound to agent + session + tool + host.
- **S6.4 Every tool's args gain an optional `ticket` field.** `authorize()` verifies the signature, expiry, args hash and session, and checks the nonce isn't reused (single-use LRU, sized for the TTL). Policy `approval = "ticket" | "human"` makes a valid ticket mandatory.
- **S6.5 The ticket is stripped from the audit `args` and its hash is recorded instead.**

### E7 — Claude Code plugin `prompto` (mod) (v0.12.1)
- **S7.1 Plugin scaffold** in the repo under `claude-plugin/`: manifest, `hooks/hooks.json`, `register.ts`, an MCP server entry (prompto URL + `headersHelper`), and a skill teaching agents to prefer typed tools.
- **S7.2 `session.start`:** record `$.session.id`, `cwd`, `repo`, `model`. Send them as `X-Prompto-Session` and context on precheck.
- **S7.3 `tool.call` for `mcp__prompto__*`:** call precheck.
  - `allow` → `next({...e, input: {...input, ticket}})`;
  - `deny` → `{deny: reason}`;
  - `ask` → S7.4.
  - Fail **closed** for tools whose policy requires a ticket (`.catch` → deny); fail open otherwise (prompto still enforces).
- **S7.4 Approval pane.** Shows the host, tool, exact command, a **diff for `file_write`** (fetches the current file via `file_read`), the rule that asked, and the last N audit entries for that host. Buttons: Approve / Approve 10 min / Deny. Approve → `/v1/approve` → continue with the ticket.
- **S7.5 Commands:** `/prompto audit` (this session's calls, live pane), `/prompto kill` (session kill; global kill with confirmation), `/prompto whoami`.
- **S7.6 Tests** with `claude plugin test`: allow / deny / ask flows against a stubbed `$.http`; fail-closed path.
- **S7.7 Deployment:** a local marketplace dir and managed settings with `prependPlugins` (+ `sec-default@builtin`) on agent machines. Document `--safe-mode` / crash behaviour: no mod → no ticket → refused where required.

### E8 — Per-call SSH certificates (v0.13.0)
- **S8.1 Vault SSH engine (infra):** mount `ssh-client-signer`, role `prompto` (allowed users = inventory `ssh_user`s, max TTL 10 m, key-id template). Add `update` on `…/sign/prompto` to the `prompto-read` policy.
- **S8.2 `VaultClient::ssh_sign(role, pubkey, principals, ttl, key_id)`.** Fake-vault test route.
- **S8.3 Ephemeral key:** ed25519 per call (one per `ssh_batch`), held in memory and written `0600` under PrivateTmp only for the ssh invocation, then deleted. `key_id = "prompto agent=<a> session=<s> req=<id>"`.
- **S8.4 `run()` uses `-i <ephemeral> -o CertificateFile=<cert>`** when the host has `ssh_auth = "cert"` in the inventory; falls back to the static key for hosts not yet migrated.
- **S8.5 Host rollout via prompto itself**, the same pattern as the sudo rollout:
  1. sshd drop-in `TrustedUserCAKeys` + `LogLevel VERBOSE` (key ID in logs);
  2. arm a rollback timer;
  3. verify a cert login;
  4. cancel the timer;
  5. later remove prompto's static key from `authorized_keys`.
  - OPNsense uses the `sshd_config.d` drop-in.
- **S8.6 KRL:** a `RevokedKeys` file managed per host for emergencies.

### E9 — OIDC identities from Kanidm (v0.12.x / v0.13)
- **S9.1 JWT validation** (`jsonwebtoken` + JWKS fetch/refresh): issuer, audience, expiry. `preferred_username` → agent, the `groups` claim → policy groups.
- **S9.2 Kanidm:** an OAuth2 client for prompto plus a service account per agent role (aligned with infra's plan: `agent-infragkid`, …).
- **S9.3 Token acquisition** in `headersHelper` and the mod (client credentials). Static tokens stay as break-glass.

### E10 — Docs, wiki, rollout
- **S10.1** README + design note updates per release; wiki prompto page (currently stale at v0.9.1) via bucciarati; palazzo entries.
- **S10.2 Rollout runbook:**
  1. v0.12.0 in `optional` mode;
  2. mint role tokens;
  3. clients add headers;
  4. watch the audit log for `anonymous`;
  5. switch to `required`;
  6. turn on `approval=human` for sudo on mista/git/abbacchio.
- **S10.3** Update the `homelab-add-host` skill (groups, policy, cert auth).

---

## Release map
| Release | Epics |
|---|---|
| v0.12.0 | E0, E1, E2, E3, E4, E5 — attributable, policed, audited, killable (auth `optional`) |
| v0.12.1 | E6, E7 — precheck, tickets, Claude Code plugin with approval pane |
| v0.12.x | E9 — Kanidm OIDC; flip to `required` |
| v0.13.0 | E8 — per-call SSH certificates, static key retired host by host |

## Critical files
- `src/server.rs` — auth middleware, `/v1/precheck`, `/v1/approve`, `/log` gating
- `src/caller.rs` — pattern for the new `agent` task-local (new `src/agent.rs`)
- `src/mcp.rs` — `authorize()`, `finish_tool()` with ctx, `ticket` arg on tool arg structs
- `src/ssh.rs` — ctx threading, certificate options in `run()`
- `src/inventory.rs` — host `groups`, `ssh_auth`
- New: `src/policy.rs`, `src/audit.rs`, `src/ticket.rs`, `src/agent.rs`
- `src/vault.rs` — `ssh_sign`
- `src/main.rs` — SIGHUP reloads for the new stores, `agent` / `audit` / `policy` CLI
- New: `claude-plugin/` (the mod), `deploy/` (logrotate, managed-settings example)
- `tests/self_target_guard.rs` helpers → new `tests/auth_policy.rs`, `tests/tickets.rs`

## Verification
- **Unit:** token hashing / constant-time compare; policy matching (globs, groups, separate sudo grant, default deny); ticket sign/verify (tampered args, expired, replayed nonce, wrong session); audit redaction; kill file.
- **Integration (`spawn_server_with`):** 401 vs anonymous vs agent; policy deny names its rule; audit line written with `request_id` equal to the one in the result; SIGHUP revoke takes effect; kill file refuses everything.
- **Mutation-check** each guard (remove the check → its test must fail), as done for the sudo leak guard.
- **Mod:** `claude plugin test` flows. Live check with `--plugin-dir`: a sudo call on mista opens the pane; Approve runs it; Deny refuses; `--safe-mode` → call refused by prompto for lack of a ticket.
- **Certs (E8):** fake-vault sign test. Live: one host with `ssh_auth="cert"` shows `key_id agent=… req=…` in `journalctl -u ssh`; static-key removal followed by a successful call; rollback timer proven by deliberately breaking the drop-in.
- **Deploy:** the usual doppio build → mista install (now via `ssh_sudo_exec mista` with a fire-and-forget restart). `prompto audit --since 10m` shows the smoke-test calls attributed.
