# Changelog

## v0.12.1 — 2026-10-10

Precheck and signed tickets (roadmap E6): policy `approval = "ticket" | "human"` now grants a call that carries a valid ticket, instead of always refusing it.

### What's new

- **`POST /v1/precheck`** (bearer auth, like `/mcp`): runs a call's whole authorization without running it and answers `allow` / `deny` / `ask`, with the deciding `rule` and a `reason`. On a `ticket` rule, `allow` carries a ticket: single-use, valid for 120 s, bound to the agent, session, tool, canonical host(s) and the SHA-256 of the canonical arguments (RFC 8785).
- **`POST /v1/approve`**: a human approver's TOTP code (RFC 6238; single-use codes; lockout after 5 wrong codes in 15 min) turns an `ask` into an `approval = "human"` ticket naming the approver. Optional `scope_minutes` (≤ 60): one ticket for every call by the same agent, session, tool and host(s), decided by the same policy rule(s) and with the same root-capability, whatever the other arguments. A scope for a root-capable call needs `allow_root_scope: true`.
- **Every tool accepts a `ticket` argument**, checked where policy demands one: missing → `approval_required` (the message says how to get one), invalid, forged, expired, replayed or for another call → `refused_ticket`.
- **Keys** from vault KV (`PROMPTO_TICKET_KEY_VAULT_PATH`, fields `current` / `previous`) or an owner-only file (`PROMPTO_TICKET_KEY_FILE`); current and previous both accepted; re-read every minute and on SIGHUP. Used nonces and TOTP steps persist (synced) in `PROMPTO_APPROVAL_STATE` across restarts.
- **Approval secrets are never agent-readable.** The ticket key and vault-held TOTP secrets are read from their own KV mount, `PROMPTO_PRIVATE_MOUNT` (default `prompto-private`), which only prompto's token may read. If either is agent-readable, approvals are turned off with an error saying what to move. The whole of `PROMPTO_VAULT_MOUNT` (the sudo passwords' mount) counts as agent-readable; `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` adds other places agents read, as `<mount>:<prefix>`. `prompto approver add --vault-path` refuses such paths, and paths next to a sudo password unless `--i-know`.
- **Inventory `prompto_host = true`** marks the machine running prompto; `policy lint` reports an error for any rule granting root there (sudo, or exec where the shell can sudo), or a shell/file tool there as prompto's own service user (`PROMPTO_SERVICE_USER`, default `prompto`), unless the rule says `crown_jewel_ack = true`. While the live policy has such an error, approvals are off (startup, SIGHUP and every re-read of `policy.toml`), as for a misplaced secret.
- **CLI:** `prompto approver add|list|revoke` (prints the `otpauth://` URI and a terminal QR code once; `--i-know`), `prompto ticket keygen`.
- **Audit:** the ticket is removed from `args` and recorded as `ticket_sha256`; `approved_by` is filled in; new record types `precheck` and `approve`.

### Claude Code plugin (roadmap E7)

- **`claude-plugin/`**: a Claude Code plugin (mod) for prompto. It prechecks every prompto call with exactly the arguments it sends and attaches the ticket. For `approval = "human"` rules it opens an **approval pane**: host, tool, exact command, rule, a diff for `file_write` (read through prompto), the agent's recent calls there; approver name + TOTP code; Approve once / Approve N minutes (root only with an explicit toggle) / Deny with a reason. It sends `X-Prompto-Session` on every call (`transport = "mod"`, the default; `engine` keeps Claude Code's own connection, without a session). It adds `/prompto whoami|audit|kill [global]|approve` and a skill for agents. Enforcement stays prompto's. Tests: `claude plugin test claude-plugin`. See the README's *Claude Code plugin*; managed-settings example in `deploy/claude-managed-settings.example.json`.
- **`GET /v1/whoami`**: the agent, its groups and the session prompto sees.
- **`GET /v1/audit?host=&session=&limit=`**: the caller's own audit records; with `host`, only where policy grants the agent something; never for `anonymous` or with `PROMPTO_AUTH=off`.
- **`POST /v1/kill`**: `scope: "session"` stops the caller's own calls in its own session; `scope: "global"` stops every call and needs an approver's TOTP code. Written to `PROMPTO_KILL_API_DIR` (default `/var/lib/prompto/kill.d`); lifted only with `prompto kill off` / `prompto unkill session <id>`. Audited as `type: kill` with `by.agent`.
- **`/v1/precheck`** answers also say `root` (whether the call is root-capable) on `allow` and `ask`.
- **Hardening after review (task 021):**
  - The approval pane shows **every argument** a ticket covers (the command first, then all the others, never omitted), and for `file_write` the diff or else the whole new content; values over 32 KiB as their head, size and SHA-256 with a "you are approving all N bytes" warning. Control and bidi characters in anything it draws are shown escaped.
  - Claude Code's own permission verdict is asked **before** the pane (a deny costs no code) and before the pane reads the current file for its diff.
  - The plugin warns at session start when a server of the person's shadows the plugin's and `servers` doesn't name it; a pane item whose call was lost on a reload says so instead of hanging; `123 456`-style codes in the name or reason field are refused too; `prompto-headers` refuses a token file whose ACL grants others read.
  - `POST /v1/kill`: `reason` cut to 256 chars and cleaned; at most 100 live session kills per agent and 1000 HTTP switches in all (429 beyond); `PROMPTO_KILL_API_DIR` created `0700`, switches `0600`.
  - `/v1/whoami|audit|kill` take bodies up to 64 KiB, `/v1/precheck|approve` up to 2 MiB (413 beyond).
  - `GET /v1/audit`: scans off the async runtime, at most 30 reads per agent per minute (429), and each read is a new `"type": "audit_read"` audit record.
  - A refused approver name is never written raw (audit records, journal): only its length and a short hash.

### macOS and FreeBSD targets

- **`file_list`** no longer drops entries whose mode carries an indicator (BSD `@` extended attributes, `+` ACL; GNU `+`, `.` SELinux): they come back with `xattrs` / `acl` / `security_context: true`. Device files are listed (`device: "major,minor"`, size 0), symlinks get `link_target`, names keep runs of spaces. A line that still can't be parsed is returned in `unparsed` (at most 20, with `unparsed_count`) instead of vanishing. A path that is a symlink to a directory lists the directory (macOS `/tmp`); on BSD/macOS a symlink to a file is listed as that file. New fields are left out when unset.
- **`rsync_sync`** recognises openrsync (macOS since 15.4): its `rsync(<pid>): error: …` lines mark a source→dest failure (`dest_ssh_auth` / `dest_ssh_connect`, not `ssh_auth`), its exit 1 is `remote_nonzero`, and zsh/csh "command not found" wording is `rsync_missing`.
- **`file_write` with `mode`** works on FreeBSD and macOS: prompto sent `chmod 640 -- <path>`, and BSD `chmod` takes the `--` after the mode as a file name (`chmod: --: No such file or directory`, after the file was written). It now sends `chmod -- 640 <path>`.
- **`ssh_batch` on FreeBSD** runs instead of refusing: a POSIX `/bin/sh` script drives the same protocol there and each command runs under `sh -c` (bash is absent; OPNsense's login shell is csh). Linux and macOS keep the bash script unchanged; `windows` still refuses.
- **Exec-style results carry `error_class`** (as `rsync_sync`'s did): the audit record's class for a non-zero exit, `null` on success. Additive.

### Exec fixes

- **`ssh_sudo_exec` runs a compound command entirely as root on `sudo -n` hosts**, as it already did on vault hosts. A command with shell syntax (`a; b`, `&&`, `|`, redirects, `$`, backquotes, globs, `~`, braces, a leading `VAR=value`) is sent as `sudo -n -- sh -s` with the command on stdin; before, only its first simple command was elevated, and the rest (redirects included) ran as `ssh_user`. A command of plain words is still sent as `sudo -n -- <cmd>`, so narrow sudoers rules keep matching. The root shell also gets `PROMPTO_REQUEST_ID`.
- **`rsync_sync`**: the source host's inner `ssh` gets `-o ConnectTimeout=15`, so an unreachable dest fails as `dest_ssh_connect` in 15 s instead of the OS TCP timeout (75 s to 4 min).
- **New error class `interpreter_missing`** for `python_exec`, `node_exec`, `ruby_exec`, `perl_exec`, `deno_exec` and `bash_exec` when the interpreter isn't installed (the shell's "command not found", exit 127; csh's "Command not found.", exit 1). It was `remote_nonzero`.

### Upgrade note — no new config

With neither ticket variable set, nothing is minted or accepted: `approval` rules refuse their calls as in v0.12.0. Visible changes:

1. The `approval_required` message is new (it explains the precheck/approve flow, or says no ticket key is configured) and `policy lint` no longer warns about `approval` rules; the server warns at startup instead when such rules exist and no ticket key is configured.
2. Two new routes, `POST /v1/precheck` and `POST /v1/approve`, behind the same authentication as `/mcp` (unauthenticated with `PROMPTO_AUTH=off`, where they report every call as needing no approval).
3. Audit records may carry `ticket_sha256` / `scope_minutes`, and `args.ticket` is never recorded.
4. `serde_json`'s `float_roundtrip` is on: JSON numbers in arguments now always parse to the nearest double (needed for stable argument digests).
5. Three more routes, `GET /v1/whoami`, `GET /v1/audit` (each read audited as `audit_read`) and `POST /v1/kill`. Each call also `stat`s `PROMPTO_KILL_API_DIR` (default `/var/lib/prompto/kill.d`; absent = nothing set), which the startup probe checks like `kill.d`. `prompto kill off` and `unkill session` also lift what was set there. Kill records may carry `scope: "agent_session"` and an `agent`. The API directory is `0700` (switches `0600`), so `prompto kill status` reads it as root. A refused approval's `approved_by` is now a length and a hash, not the typed name. The lockout message no longer names the approver.
6. `file_list` on a path that is a symlink to a directory lists the directory (it used to list the link alone); results may carry the new optional fields above, and exec-style results always carry `error_class`.
6. **`ssh_sudo_exec` on `sudo -n` hosts**: a compound command now needs sudo to allow `sh` (`sudo -n -- sh -s`). A host whose sudoers allows only specific commands refuses it (`sudo: a password is required`, `remote_nonzero`) where the first part used to run as root and the rest as `ssh_user`. Plain-word commands are unchanged.
7. **Approval secrets on `PROMPTO_VAULT_MOUNT`**: with `PROMPTO_PRIVATE_MOUNT` set to the same mount as `PROMPTO_VAULT_MOUNT`, approvals are now off whatever the path (it used to be only under `prompto/`, `infra/`, `nxp/`). The private mount is the only valid home. A `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` that names prefixes on `PROMPTO_VAULT_MOUNT` still works (they are covered already); it can no longer narrow the shared mount.
8. `interpreter_missing` replaces `remote_nonzero` for a missing interpreter, in results and the audit log.

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
