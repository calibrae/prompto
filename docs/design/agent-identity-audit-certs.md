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

**Self-targeting is not a policy dimension.** A call that would contact the caller's own machine is refused (`refused_self_target`) before policy is consulted, for every tool that contacts a host and for every agent, `infra`'s `hosts = ["*"]` included. No rule, approval mode or ticket can grant it, and policy must not grow a way to. The only exceptions are tools that never contact a host (`inventory_list`, `inventory_get_host`, `mcp_reconnect_hint`, `prompto_gain`). An agent acting on its own machine uses its local shell.

**On `ssh_exec`:** a command string can't be policed reliably (`sh -c`, quoting, aliases), so policy treats `ssh_exec`/`bash_exec`/`ssh_sudo_exec` as what they are — a full shell on that host — and grants them per host, not per command. The pressure goes the other way: make typed tools good enough that agents choose them, and grant those widely. The audit log records the full command either way.

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
| One agent, everywhere | Remove/disable in `agents.toml` or the IdP | Next call (static) / token expiry (OIDC) |
| One agent, one host | Drop the host from its policy, SIGHUP | Next call |
| All agents, one host | Drop the host from the inventory, or its CA trust | Next call |
| Everything | `/etc/prompto/kill` exists → every call refused with a fixed message; checked per call, no restart | Immediate |
| Suspected leaked cert | sshd `RevokedKeys` (KRL) | Next connection; certs die within minutes anyway |

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
