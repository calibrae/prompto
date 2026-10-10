# Design: agent identity, policy, audit, short-lived credentials

Status: **draft** — targets v0.12 (identity, policy, audit) and v0.13 (per-call SSH certificates).

## Why

prompto today answers *what* ran and *where*, never *who*. Every agent reaches every host as the same SSH user, with one long-lived key, through an unauthenticated endpoint. You cannot audit an agent, revoke one without revoking all, or rotate anything without breaking everything.

### Evidence (usage log, 5 months, 8,544 calls)

- **No caller identity.** The usage log records tool, host, ok, duration, bytes. Attributing calls by client IP is worthless: one workstation produced 95% of the last two weeks' traffic, from ~30 concurrent agent sessions.
- **Raw shell dominates.** `ssh_exec` is 84% of calls; with `ssh_sudo_exec`, `ssh_batch` and `bash_exec`, ~90%. Typed tools are rare (`service_control` 13 calls, `host_diagnose` 1). Seven tools were never called.
- **The typed host field already works as a boundary.** Agents sent guessed names, raw IPs, and once `giorno && true`; exact-match inventory lookup refused all of them.
- **Failures carry no reason.** `rsync_sync` still fails 26–72% per month after its v0.8.0 fix; the log can't say why.

### What exists (survey, 2026-10)

No product combines typed machine tools, per-agent identity/policy/audit, and ephemeral machine credentials. Teleport comes closest (agent identities via `tbot`, per-tool MCP policy, argument-carrying audit, short-lived certs) but ships no machine tools and gates on tool *name* only. Pomerium and Tailscale Aperture also stop at the tool name. Argument-level policy appears only in AWS AgentCore (Cedar over input parameters, SaaS) and small OSS SSH-MCP servers (command templates). All commercial options are US vendors.

The gap prompto can own: **the tool is the unit of identity, policy, audit and credential issuance**, self-hosted, single binary.

## Goals

1. Every call is attributable to a named agent.
2. Policy per agent: which hosts, which tools, and — for typed tools — which arguments.
3. An audit trail that answers "everything agent X did yesterday", joinable with host-side logs by request ID.
4. Agents hold no machine credentials; prompto's own machine access becomes short-lived.
5. Kill switches at every scope, effective without touching hosts.
6. Built from standard parts (OIDC, SSH certificates, JSON logs) so it works the same at home and in a company.

Non-goals: a UI; replacing the IdP; session recording (host-side `sudo` I/O logging covers it).

## 1. Identity (v0.12)

Agents authenticate with `Authorization: Bearer <token>` on `/mcp`. Two token sources, one internal type `Agent { name, groups }`:

- **Static tokens (first).** `/etc/prompto/agents.toml`, one entry per agent: name, groups, **SHA-256 of the token** (never the token). Tokens are minted by `prompto agent add <name>` (prints once). Clients register with `claude mcp add --transport http prompto <url> --header "Authorization: Bearer …"`.
- **OIDC (next).** JWTs from any OIDC provider, validated against its JWKS (issuer, audience, expiry). Agent = a service account in the IdP; name from `preferred_username`/`sub`, groups from the `groups` claim. Disabling the account in the IdP ends access as soon as its token expires.

`PROMPTO_AUTH = off | optional | required` for rollout. `optional` logs unauthenticated calls as `agent=anonymous` and applies the anonymous policy; `required` refuses them with 401. stdio transport is `agent=local`. The default is `off`, which keeps the pre-identity behaviour. A revoked (`disabled`) token is refused with 401 under `required`, and treated as `anonymous` with a warning under `optional`. The Claude session ID travels in `X-Prompto-Session` as context only.

## 2. Policy (v0.12, argument rules in v0.14)

`/etc/prompto/policy.toml`, SIGHUP-reloaded like the inventory, **default deny** once auth is required:

```toml
[agent.infra]
hosts = ["*"]
tools = ["*"]

[agent.builder]
hosts = ["group:build"]                 # inventory gains `groups = [...]`
tools = ["ssh_exec", "rsync_sync", "file_*", "host_status"]

[agent.web-ops]
hosts = ["group:web"]
tools = ["service_control", "service_logs", "file_read"]
[agent.web-ops.args]
service_control.unit = ["nginx", "php-fpm*"]   # v0.14: argument allowlists
file_read.path       = ["/etc/nginx/**", "/var/log/nginx/**"]
```

Effective permission = agent policy ∩ host capabilities, minus the caller's own machine. Every decision names the rule that allowed or denied it.

*As built (v0.12, E3):* the file is an ordered list of `[[rule]]` grants (`agents` × `hosts` × `tools`, plus `sudo` and `approval`), and the first match decides. Root-capable calls need a rule with `sudo = true`, and host groups come from the inventory's `groups`. The sketch above is the shape argument rules (v0.14) will extend. See the README's *Policy* section for the semantics.

**Self-targeting is not a policy dimension.** A call that would contact the caller's own machine is refused (`refused_self_target`) before policy is consulted, for every tool that contacts a host and for every agent, `infra`'s `hosts = ["*"]` included. No rule, approval mode or ticket can grant it, and policy must not grow a way to. The only exceptions are tools that never contact a host (`inventory_list`, `inventory_get_host`, `mcp_reconnect_hint`, `prompto_gain`). An agent acting on its own machine uses its local shell.

**On `ssh_exec`:** a command string can't be policed reliably (`sh -c`, quoting, aliases), so policy treats `ssh_exec`/`bash_exec`/`ssh_sudo_exec` as what they are — a full shell on that host — and grants them per host, not per command. The pressure goes the other way: make typed tools good enough that agents choose them, and grant those widely. The audit log records the full command either way.

**`sudo = true` gates prompto's own root paths, not root on the host** *(E3 follow-up)*. A rule without `sudo = true` never grants `ssh_sudo_exec`, `file_write` with `sudo`, `service_control` and the other root-capable calls. But an exec grant (`authz::ARBITRARY_EXEC_TOOLS`: `ssh_exec`, `ssh_batch`, `bash_exec`, the script runners, `claude_exec`, `mcp_add`, and since E4 `file_write` without `sudo` and `rsync_sync` — writing `~/.bashrc` is code execution) is a shell as `ssh_user`, and that is root wherever the user is `root` or has passwordless sudo: `ssh_exec "sudo -n …"` there is root with no `sudo = true` rule. We don't police command strings (see above). Instead the inventory may say `nopasswd_sudo = true | false` per host (unset = unknown), and `policy lint` warns, once per rule, about exec grants without `sudo = true` on hosts that are `ssh_user = "root"`, `nopasswd_sudo = true` or unset. Every tool is classified in exactly one of root-capable, arbitrary exec or ordinary, and a test enumerating `tools/list` fails on a tool that isn't.

**Known property: pre-policy disclosure.** Existence, capability and self-target checks run before policy (the self-target guard must be unconditional). So an agent with no grant can tell `unknown_host` from `refused_capability` from `refused_self_target`, and probe which host names exist and what they carry. This is accepted and documented, not fixed. `inventory_list` itself shows an agent only the hosts it has a grant on, and `sudo_password_vault_path` only with a `sudo = true` grant there.

**Malformed policy on reload fails closed.** A SIGHUP that finds `policy.toml` malformed replaces the live policy with deny-all (refusals say `policy file invalid since <time>`; the parser's error and the path go to the journal only) until a valid file is loaded. Keeping the previous policy would keep whatever it granted, possibly more than the operator is trying to write. Startup with a malformed file stays fatal.

## 3. Audit log (v0.12)

A new append-only `audit.jsonl` (and the same record to journald as structured fields), separate from the token-savings usage log:

| Field | |
|---|---|
| `ts`, `request_id` | ULID, also returned to the caller |
| `agent`, `agent_groups`, `client_ip`, `user_agent` | who |
| `tool`, `host` (canonical), `queried_as` | what, where |
| `args` | full for commands; file contents and script bodies as `sha256` + length |
| `decision`, `rule` | allow/deny and why |
| `exit_code`, `ok`, `error_class`, `duration_ms`, `bytes` | outcome; `error_class` from a small enum (`refused_policy`, `refused_capability`, `refused_self_target`, `ssh_connect`, `timeout`, `sudo_guard`, `remote_nonzero`, …) |

File mode `0640 prompto:prompto-audit`. Secrets never appear: vault-fed sudo passwords are not arguments.

*As built (v0.12, E4):* `src/audit.rs`; the README's *Audit log* section has the format. Decisions:

- **One record per call, from one place.** `finish_tool` writes it, so a refusal is recorded like any outcome. `Prompto::call_tool` wraps rmcp's dispatch in a scope holding the raw arguments, and records the calls no handler did (arguments that don't parse, unknown tools). `GET /log` is recorded as `service_logs`. `ssh_batch` is one record with the command list; `rsync_sync` adds `dest_host`.
- **401s are audited**, as `type = auth` records with the reason: a revoked token still in use or a hijacked legacy session is exactly what an audit is for, and the journal's warning line alone isn't queryable with the rest. Unauthenticated peers could otherwise grow the file at will, so they are rate-limited per client (IP, IPv6 /64; burst 10, one per 10 s; LRU of 4096 clients) under a global ceiling (burst 60, 1/s): one flooder spends only its own allowance and can't hide another client's 401, and the ceiling bounds growth when many addresses flood. The next record counts what was dropped. A hijack record holds both session IDs shortened as in the journal (`mcp_session`, `session_id`). *(task 010)*
- **Redaction** *(revised in task 010)*: commands whole, including every interpreter's `script` (owner decision); any string over 16 KiB, or `args` over 64 KiB, as `{sha256, len, truncated: true}`; `content` and `ticket` always `{sha256, len}`. A field whose name *is or ends with* a secret word (`password`, `token`, `secret`, `credential`, `api_key`, `private_key`, `authorization`, `cookie`, `_pwd`, …) is `[redacted]`. Exact-or-suffix replaced substring matching: a secret's name ends with what it is (`GITHUB_TOKEN`, `client_secret`, `X-Api-Key`), while substring matching also redacted names that only mention one (`dest_key`, a path; `max_tokens`, `token_file`). There is no bare `key`, so `*_key` names holding key material are listed one by one. Every kept string, the journald event included, then goes through a value scrubber (URL userinfo, secret-named query parameters, headers, long flags and assignments, `Bearer x`, quoted literals in code or JSON). It is best-effort: a positional password or `-p x` (too common to scrub) stays.
- **`auth_note`** *(task 010)*: in `optional` mode a revoked or invalid token falls back to `anonymous`; the record keeps why (`revoked token for <agent>`, `invalid token`), so it can be queried.
- **Client-chosen strings are bounded** *(task 010)*: a typed host name, an unknown tool name, `User-Agent`, the session header, `path` and `reason` are scrubbed and capped (256 chars, `path` 512), so a record stays small whatever the client sends.
- **Records are written at the end of the call.** A call cut off mid-way would leave none, so `Prompto::call_tool` holds a drop guard. If the call's future is dropped before anything recorded it (a handler panic unwinding, the runtime shutting down on stop or restart), the guard writes an `aborted` record carrying the handler's request ID, notes and start time. What is still lost: a `SIGKILL` or power loss (no destructor runs; the journal has nothing either), and a release built with `panic = "abort"` (not this one). In stateless HTTP mode, rmcp does not cancel a handler whose client disconnects: the call finishes and is recorded normally. *(task 010)*
- **`ok` is stricter than the gain log's**: a command that exited non-zero or timed out is not ok, though the tool returned a result; `error_class` then says why (`remote_nonzero`, `timeout`, `ssh_connect`, `sudo_guard` …), classified from the exit status and ssh's messages.
- **`error_class` is the one enum for every failure** (`ErrorClass`). Every error path in the tools now returns a classified error; an unclassified one is a bug, recorded as `internal`, logged, and counted. A test drives every tool in `tools/list` into each failure it can force and fails on any unclassified error. New: `sudo_guard`, `vault`, `upstream`, `killed` (E5, task 011); `refused_ticket` (E6, task 014).
- **Disk full** *(task 010)*: a write that fails with ENOSPC/EDQUOT or comes up short refuses later calls with the cause in the agent's message (`the audit disk is full`), never the path. Below 64 MiB free on the audit filesystem, the journal gets an error every 5 minutes, in every mode. After a short write, the next record is prefixed with `\n` (still one `write(2)`), so it lands on its own line, and the reader recovers a record glued to a fragment by an older build.
- **Failure policy.** Auth on: every gate (`authorize`, `lookup`, `authorize_tool`, `/log`) asks the log before letting a call run; it must be open and its last write must have succeeded, else the call is refused (`internal`). A log that can't be opened stops startup. A write that fails after the call ran can't undo it (the record is in the journal, emitted first), and later calls are refused until a write succeeds — the refusal's own record is the probe. Auth off: always written, failures only warn.
- **Rotation without signals.** One `write(2)` per line on an `O_APPEND` descriptor, so writers never interleave (tested with separate descriptors on one file). Before each write the path's device and inode are compared with the open file's, and a rename or delete reopens it. So logrotate's rename + `create` works with no `postrotate`; `copytruncate` is ruled out because it loses the lines written between its copy and its truncate. Chosen over SIGHUP-reopen because it can't be forgotten in a logrotate config and needs nothing from the unit.
- **journald** gets the record natively (`tracing-journald`, fields prefixed `AUDIT_`) when running under systemd; elsewhere it is a stderr log line.

**Joining with hosts.** v0.12: the request ID is exported to the remote command (`PROMPTO_REQUEST_ID`) and, where the host has `AcceptEnv PROMPTO_*`, visible to its logs. v0.13: carried in the SSH certificate's key ID, which sshd logs on every login.

## 4. Short-lived SSH certificates (v0.13)

Use Vault's SSH secrets engine as the CA (already deployed; no new service).

1. Per call (one per `ssh_batch`), prompto generates an ephemeral ed25519 key pair in memory / a `0600` file under `PrivateTmp`.
2. It asks Vault to sign it: role `prompto`, `ttl=5m`, `valid_principals=<host.ssh_user>`, `key_id="prompto agent=<name> req=<request_id>"`.
3. `ssh -i <key> -o CertificateFile=<cert> …`; both deleted after the call.

Hosts trust the CA (`TrustedUserCAKeys`) and log the key ID. prompto's static key stays in `authorized_keys` during transition as break-glass, then is removed per host. prompto's Vault policy gains `update` on the signer path. Cost: one local Vault round-trip per SSH session.

Rotation becomes a non-event: certificates expire in minutes; the CA key rotates rarely, with hosts trusting old and new during the overlap.

## 5. Kill switches

| Scope | Action | Effect |
|---|---|---|
| Everything | `prompto kill on [reason]` (`/etc/prompto/kill` exists) | Next call |
| One agent, everywhere, for a while | `prompto kill agent <name>` (`kill.d/agent-<name>`) | Next call |
| One agent, for good | `prompto agent revoke` / `disabled = true` (static), or disable in the IdP (OIDC) | Next request (static, no SIGHUP) / token expiry (OIDC) |
| All agents, one host | `prompto kill host <name>` (`kill.d/host-<name>`); or drop it from the inventory, or its CA trust, + SIGHUP | Next call |
| One agent, one host | Drop the host from its policy (re-read on change; SIGHUP also works) | Next call |
| One Claude session | `prompto kill session <id>` (`kill.d/session-<id>`) | Next call |
| Suspected leaked cert | sshd `RevokedKeys` (KRL) | Next connection; certs die within minutes anyway |

*(task 011)* Decisions:

- **Files, checked per call.** A kill switch is a file under `/etc/prompto` (`PROMPTO_KILL_FILE`, `kill.d` next to it or `PROMPTO_KILL_DIR`); its existence is the switch, its first line the reason (sanitized, ≤ 200 chars), its mtime the time. Every call `stat`s the files that could apply to it (global, its agent, its session, every name of every host it targets). Nothing is cached, so there is no reload and nothing to forget; a `stat` is cheap next to an SSH round-trip. Hand-made files work like the CLI's. The server only reads; the CLI writes `0644` files atomically.
- **Before everything else.** The check runs in `Prompto::call_tool` before rmcp parses the arguments, and first in `GET /log`: before host lookup, the self-target guard, policy and the audit preflight. So a killed call says `killed` whatever else is wrong with it, and **a broken audit log can't stop a kill**: the refusal skips the preflight, is written to the journal first and to the file when it can be. A 401 still comes first for an unauthenticated request under `required` — the kill can't be reached without a valid token, which also keeps the reason from unauthenticated peers.
- **Every auth mode.** Global and host switches apply with `off` too (prod's panic button). Agent and session switches need `optional`/`required`, since with `off` calls carry neither. *(Task 012, owner: left as is — `off` keeps ignoring `X-Prompto-Session`, so session kills need `optional`/`required`; documented.)*
- **Audit:** class `killed`, `decision: deny`, plus `kill: {scope, target, since, reason}` in the record and `AUDIT_KILL_*` in the journal.
- **Revoked is not killed.** A revoked token is an authentication failure: a 401 `type: auth` record under `required`, `anonymous` with an `auth_note` under `optional`. `killed` is for a valid caller the operator stopped; `kill agent` is the reversible stop that keeps the token.
- **`agents.toml` reloads itself.** Every authenticated request `stat`s it (inode, size, mtime, ctime) and re-reads it on change, so `agent revoke` needs no SIGHUP. A re-read now fails closed like the policy: a broken file leaves no valid agent until fixed (before task 011 a bad SIGHUP reload kept the previous list, which would keep a half-revoked agent alive).
- **Unreadable fails closed** *(task 012, owner decision; task 011 had it fail open)*. At startup, if the server can't `stat` the global file or search `kill.d` for any reason other than "absent", it refuses to start with an error naming the path (fix the permissions, or point `PROMPTO_KILL_FILE`/`PROMPTO_KILL_DIR` elsewhere): an upgrade surfaces the problem at once instead of shipping a panic button that doesn't work. At runtime (checkable at startup, not any more), every call that needs the path is refused as `killed` with reason `kill switch unreadable: <path>: <error>` and `unreadable: true` in the record, and the journal gets `KILL SWITCH UNREADABLE`.
- **The CLI audits switch changes** *(task 012)*. `prompto kill`/`unkill` appends a `type: kill` record (`action` on/off, `scope`, `target`, `reason`, `file`, `by: {uid, user, sudo_user}`) to the audit file after applying the change. It appends as root without touching the file's owner or mode, and creates a missing file as the server would (`0640`, the directory owner, `PROMPTO_AUDIT_GROUP` or the directory's group). A failed record never undoes or blocks the switch; the CLI says so on stderr. Hand-made switches have no such record.
- **`policy.toml` reloads itself** *(task 012)*, like `agents.toml`: each policy decision `stat`s it and re-reads it on change, failing closed on a bad file exactly as SIGHUP does. Both stores re-read a file modified within the last 2 s on every check (git's "racy" rule), since a second write in the same timestamp tick can leave inode, size, mtime and ctime all unchanged.
- **Set over HTTP** *(task 019)*. `POST /v1/kill` lets an agent stop its own session (the switch names agent *and* session, so a session ID claimed by another role isn't affected), and, with an approver's TOTP code, everything. The service can't write `/etc` (`ProtectSystem=strict`), so these live in `PROMPTO_KILL_API_DIR` (default `/var/lib/prompto/kill.d`), checked, listed and probed like `kill.d`; only the CLI lifts them.
- **Names** are validated before they become paths (agents: the agent rule; hosts/sessions `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`), so nothing escapes `kill.d`; a call naming an invalid host can't match a file. A host switch matches every name of the host (inventory name and aliases).

## 5b. Approvals and tickets (v0.12.1, E6)

*(task 014)* A policy rule can demand an approval (`approval = "ticket" | "human"`). The proof is a ticket prompto signs and checks; the README's *Tickets and approvals* section has the format and the API. Decisions:

- **Threat model.** The agent (an LLM with tools), the Claude Code mod and any script on that workstation run as the same OS user with the same role token. Anything the mod can send, the agent can send. So `/v1/approve` behind the bearer token alone would let the agent approve itself. A human approval must carry a credential the agent can't produce. The first factor is TOTP from the approver's phone, typed into the mod's pane. The agent never sees the secret, and a code it might observe is single-use. `/v1/approve` sits behind the same middleware, so it also needs the role token. The ticket is bound to that token's agent, so an approval for one role can't be spent by another. The approver mechanism is an enum (`approvers::Factor`) so a separate-device or Kanidm-authenticated approval can be added without touching tickets.
- **What a ticket binds.** Agent, session (`X-Prompto-Session`), tool, the canonical host (plus `rsync_sync`'s `dest_host`), the SHA-256 of the RFC 8785 canonical arguments minus `ticket`, approval level, approver, expiry and a 128-bit nonce. JCS was chosen over "the client's JSON bytes" because the mod (JavaScript) and prompto (serde) re-serialize, and over a custom encoding because any client can reproduce it with a library. Integers above 2^53 hash as JavaScript would see them. `serde_json`'s `float_roundtrip` had to be turned on: its default parser isn't correctly rounded, so two spellings of one number could have hashed differently.
- **Where it is checked.** In `authz`, after policy, as step 5 of the same gate (so `/log`, precheck and every tool share it), only when the deciding rule demands an approval. A ticket never grants what policy doesn't, and can't reach the self-target guard. A call that authorizes twice (`rsync_sync`'s two hosts, `vm_ensure_up`) verifies and spends the ticket once; the second authorization checks only that its approval level suffices (the strictest rule wins).
- **Precheck is the real gate, dry.** `POST /v1/precheck` builds the call's context and runs `authz` for each host the tool's handler would authorize (`authz::requirements`), with `dry_run` set: a presented ticket is checked and not spent, and nothing runs. A test drives every tool in `tools/list` through both paths and fails on any disagreement, so the table can't drift from the handlers.
- **The mod** *(task 019, E7)*. Claude Code's MCP connection runs its `headersHelper` once, before mods load and without the session ID, so the mod carries prompto calls itself (HTTP, `X-Prompto-Session`), prechecks exactly the arguments it sends, and never changes them after. It waits for the pane inside the `tool.call` hook, and holds the TOTP code in memory only until `/v1/approve`. A precheck that can't be reached fails open (prompto still refuses what needs a ticket); a failed hook refuses the call. Mods can rewrite calls (S0.1), so nothing here is a boundary.
- **Single use, and scope.** Ordinary tickets are single-use (120 s TTL). "Approve similar calls" (`scope_minutes` ≤ 60) mints a multi-use ticket with no arguments digest, bound to agent, session, tool and host(s) — and *(task 015)* to the call's root-capability and the policy rule(s) that demanded the approval (`ticket::Scope`). Without that, a scope approved for plain `file_write` covered `file_write sudo=true` (the root rule wants `human`, and the scoped ticket is `human`). A root-capable call's scope is refused unless the approve request says `allow_root_scope: true`: freeing the arguments of a root call is a root shell for the scope's duration, which should be an explicit choice, not the default; forbidding it outright would push approvers into approving dozens of single root calls without reading them. Binding the rule by name (`policy.toml:<line>`) means a policy edit that moves it ends the scope — fail-closed and acceptable. It needs a session, or it would cover the whole role. This is stateless (no server-side grant table to lose on restart), at the price that a scope can't be revoked early except by a kill switch (`kill session`) or a key rotation that drops `previous`.
- **Keys survive restarts; so do spent nonces** (E11). The key comes from vault or a file, never from process randomness, so a ticket minted before a deploy verifies after it. If no key can be read at startup, the server still starts, refuses only ticketed calls with the reason, and retries every minute. Used nonces and the last accepted TOTP step per approver are appended to a state file before the call proceeds and reloaded at startup. Resetting them on restart would leave a window (≤ 120 s for a ticket, ≤ 90 s for a code) in which the exact approved call could run twice. Narrow, but a duplicated human-approved `rm` or restart is not harmless, and one line per ticketed call is cheap. If the file can't be written, ticketed calls are refused (like the strict audit log), never run unrecorded. Two processes overlapping during a restart (S11.2) would not share the in-memory set; the file would need re-reading per check then. Open, see the task report.
- **Rotation**: current + previous accepted, the key ID (`kid`) in the ticket picks the key, rotation is a vault/file edit plus SIGHUP or a minute's wait.
- **Lockout** is per approver (5 wrong codes / 15 min → 15 min). An agent can therefore lock a human out by guessing; that is accepted (it shows in the audit as `approve` refusals) because the alternative, unlimited guessing, is worse. Unknown approver names fail like wrong codes — same message, same TOTP computation against a dummy secret — so the endpoint doesn't confirm which names exist. *(task 015)* Names are validated like agent names before any lookup; approvers in the file are always tracked, unknown names only up to 4096, after which they share one counter (a global limiter for name-spraying that never touches real approvers' counters). Residual: a known approver's secret is fetched (file or vault round trip) and an unknown one's isn't, so timing still differs by that I/O; and when the factor store is down, a known name answers `503`, an unknown one `403`.
- **Where the factors live** *(task 015)*. Principle: **nothing an agent can read may be an approval factor or a signing key**. The first version defaulted to `prompto/approvers/<name>` and `prompto/ticket-key` on the sudo passwords' mount, which production agents read through a vault gateway (`secret/data/prompto/*`): an agent could have read a TOTP secret and approved itself, or the key and forged tickets. Now the key and TOTP secrets are read from a separate KV mount (`PROMPTO_PRIVATE_MOUNT`, default `prompto-private`) that only prompto's token may read; prompto turns approvals off when either is agent-readable (it can't inspect other tokens' policies; since task 018 the whole shared mount `PROMPTO_VAULT_MOUNT` counts as agent-readable, because production's read gateway covers far more prefixes than any list kept in step, and `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` only adds locations on other mounts); `prompto approver add` refuses such paths and, without `--i-know`, paths sharing a directory with a sudo password. Files and the env file (vault token) are only as safe as root on the prompto host: `prompto_host = true` makes policy lint report every root grant there as an error unless the rule says `crown_jewel_ack = true`.
- **Durability** *(task 015)*. Each state-file append is `fdatasync`ed before the call proceeds (≈1.7 ms median on the sandbox VMs), so a power loss can't drop a spent nonce or TOTP step inside its TTL.
- **Audit**: never the ticket (a bearer credential until spent), always its SHA-256, on the call and on the precheck/approve record that minted it, so they join.

## 6. Housekeeping before policy

- Decide on the seven never-called tools (`node_exec`, `ruby_exec`, `perl_exec`, `deno_exec`, `mcp_add`, `mcp_remove`, `mcp_restart_claudecli`): every tool is surface an agent reads and policy must cover.
- Make every call attributable: the reverse proxy's access log should include the vhost, and the direct listener should not be reachable around the proxy (or must enforce the same auth — it will, once auth is in prompto itself).
- Add `error_class` to `rsync_sync` failures first; it's the most-failed tool.

## Rollout

| Version | Ships | Mode |
|---|---|---|
| v0.12.0 | Static agent tokens, `policy.toml`, audit log, kill file | `PROMPTO_AUTH=optional`: everything still works, everything is now attributed |
| v0.12.x | OIDC validation; switch to `required` once every client sends a token | |
| v0.13.0 | Per-call Vault SSH certificates; hosts trust the CA; static key retired host by host | |
| v0.14.0 | Host groups in policy, argument-level allowlists for typed tools | |

## Open questions

1. One token per agent *session* or per agent *role*? Per role is manageable; per session gives perfect attribution but needs automated minting (OIDC client credentials make this cheap).
2. Should `ssh_sudo_exec` require a separate policy grant from `ssh_exec` even on hosts with `sudo_exec`? (Proposed: yes.)
3. Audit retention and shipping: journald → central log store, or prompto pushes directly?
4. Does the human operator use prompto with the same identity scheme (an agent named after the person), or keep direct SSH as break-glass only?
