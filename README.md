# prompto

MCP server for homelab power & lifecycle (Wake-on-LAN, libvirt), typed SSH exec, remote files, and Claude Code fleet management. Single Rust binary, single endpoint, sibling of [palazzo](https://github.com/calibrae/palazzo) and [bucciarati](https://github.com/calibrae/bucciarati).

> *"prompto"* — Italian for *ready / at your prompt*. Ready when called (wake), at your prompt (exec).

**What's new in v0.12.0** (request IDs, one authorization gate, agent tokens, policy, audit log, error classes, kill switches) and the **upgrade note for existing deployments**: [CHANGELOG.md](CHANGELOG.md).

## Why

A homelab tends to grow three loosely-related control surfaces:

1. A WOL daemon on some always-on host that fires magic packets at sleeping ones.
2. An MQTT/scriptlet glue layer that runs `virsh` for VM lifecycle.
3. Hand-rolled SSH commands from agents, repeated all over the place.

prompto rolls them into one MCP. Single source of authority for power, virt, and exec — typed, capability-gated, behind one HTTP endpoint.

## Tools

Every call is **capability-gated** by the per-host allowlist in the inventory. A host without `wake` cannot be woken, period.

| Capability | Tools |
|---|---|
| — | `host_status` (TCP probe of the SSH port), `port_scan`, `inventory_list`, `inventory_get_host`, `prompto_gain`, `mcp_reconnect_hint` |
| `wake` | `host_wake` — UDP magic packet to the host's MAC. Refused for `chassis = "vm"`. |
| `virt` | `vm_list`, `vm_state`, `vm_start`, `vm_stop` (`dompmsuspend disk` → `shutdown` → `destroy`), `vm_ensure_up` (also needs `wake`: wake host, start VM, wait for SSH) |
| `exec` | `ssh_exec`, `ssh_batch` (N commands, one session), `bash_exec` / `python_exec` / `node_exec` / `ruby_exec` / `perl_exec` / `deno_exec` (script body over stdin), `file_read`, `file_write`, `file_list`, `file_stat`, `rsync_sync`, `host_diagnose` |
| `sudo_exec` | `ssh_sudo_exec`, `host_sleep`, `service_control`, `service_logs` (`mcp_logs` is a deprecated alias), `file_write` with `sudo=true` |
| `claude_admin` | `mcp_list`, `mcp_get`, `mcp_add`, `mcp_remove`, `mcp_status`, `mcp_restart_claudecli` — wrap `claude mcp …` on a client |
| `claude_exec` | `claude_exec` — delegate a task to a Claude agent on the host via its [apytti](https://github.com/calibrae/apytti) gateway |

`ssh_exec` stdout passes through a filter chain (cargo, git, journalctl, systemctl, pkg, k8s, zfs, …) that compacts known-noisy output and names the filter it applied. Compound commands (`;`, `&&`, `||`, `&`, newlines) are never filtered.

**Self-targeting guard.** Every tool that contacts a host refuses one whose `ip` is the calling agent's source IP, with no exceptions: logins, exec, files, `rsync_sync` (both ends), `vm_*`, `mcp_*` (including `mcp_restart_claudecli`), `claude_exec`, `host_wake`, `host_status`, `port_scan` and `GET /log`. The refusal is `error_class = refused_self_target` and reads `refused_self_target: you are calling from <host> (<ip>) — prompto never acts on the caller's own machine; run this in your local shell instead.` An agent that wants something done on its own machine uses its local shell, not a loop through prompto as the inventory's `ssh_user` and around its own sandbox. Only tools that never contact a host are unaffected: `inventory_list`, `inventory_get_host`, `mcp_reconnect_hint`, `prompto_gain`. The guard is not a policy setting, and no future policy or ticket can lift it. Addresses are compared in canonical form, so an IPv4 caller seen as `::ffff:a.b.c.d` is still matched. A machine that can reach prompto from more than one address (a second NIC, Wi-Fi, a VPN, IPv6) lists the others in `extra_ips`. A call from any of them is the same machine and is refused the same way. Behind a reverse proxy, the caller IP comes from `X-Real-IP` / `X-Forwarded-For`, honoured only when the TCP peer is in `PROMPTO_TRUSTED_PROXIES`.

**Request IDs.** Every call gets a ULID `request_id`:

- On success it is a field of the JSON result (`vm_list`, which returns an array, gets it in a second `[request_id=…]` text block instead).
- On error it is in `error.data.request_id` and leads the message: `[request_id=… error_class=…] …`.
- A command that ran and exited non-zero is a result, not an error: exec-style results (`ssh_exec`, `ssh_sudo_exec`, `ssh_batch`, the `*_exec` interpreters, `host_diagnose`, `service_control`, `rsync_sync`) carry `exit_code` and `error_class` — the same class as the audit record (`remote_nonzero`, `ssh_connect`, `timeout`, …), `null` on success.
- `GET /log` returns it in the `X-Prompto-Request-Id` header.
- The [audit record](#audit-log) of the call carries the same ID.
- Classified failures are logged to journald with it.
- The remote command sees it as `PROMPTO_REQUEST_ID`, so host-side logs can be joined with prompto's:
  - On `linux` and `macos` hosts the remote command is prefixed with `export PROMPTO_REQUEST_ID=…;`.
  - On every host prompto also sends it with `ssh -o SetEnv`. sshd delivers that only with `AcceptEnv PROMPTO_*`, and it is the only route on `freebsd` and `windows` hosts, whose login shell may not be POSIX.
  - The per-host `request_id_env` inventory field overrides this (see [Inventory](#inventory)). Set it to `off` for a key restricted by `command=`, rrsync or git-shell: those see the whole command line and reject the prefix.
  - `sudo -n` resets the environment, so commands run through passwordless sudo see the variable only with `Defaults env_keep += "PROMPTO_REQUEST_ID"` in the host's sudoers.
  - On vault hosts (below) the root shell always gets it.

## Quickstart

```bash
cargo build --release
PROMPTO_INVENTORY=./prompto.toml ./target/release/prompto --stdio
```

For HTTP transport (default):

```bash
PROMPTO_INVENTORY=./prompto.toml ./target/release/prompto
# listens on 0.0.0.0:6337 — POST /mcp, GET /log, POST /v1/precheck, POST /v1/approve
```

## Inventory

`/etc/prompto.toml`, one `[host.<name>]` block per machine:

```toml
[host.gpu-rig]
ip = "192.0.2.12"                 # literal IP, not a hostname
mac = "aa:bb:cc:dd:ee:ff"         # needed for wake
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
ssh_port = 22                     # default
capabilities = ["wake", "exec", "sudo_exec", "virt"]

[host.laptop]
ip = "192.0.2.13"
platform = "macos"                # linux (default) | macos | freebsd | windows
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
capabilities = ["exec"]

[host.router]
ip = "192.0.2.1"
platform = "freebsd"
aliases = ["minipc"]              # extra names the host answers to
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
sudo_password_vault_path = "hosts/sudo"   # see "Sudo with a password"
capabilities = ["exec", "sudo_exec"]

[host.winguest]
ip = "192.0.2.30"
chassis = "vm"                    # cold_iron (default) | vm — a vm is never WOL'd
hypervisor = "gpu-rig"            # must be a host with `virt`
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
platform = "windows"
capabilities = []
```

| Field | Meaning |
|---|---|
| `platform` | Target OS. Tools **adapt** where a BSD equivalent exists (`stat -f`, `ls -T`), and **refuse** legibly where the model differs: no systemd tools off Linux; `ssh_batch` runs its commands under `sh -c` on FreeBSD/OPNsense, which have no bash. `windows` is declared so the host can be addressed, not shelled into. |
| `chassis` / `hypervisor` | `vm` makes `host_wake` refuse and point at `vm_start <hypervisor> <name>` instead of broadcasting at a NIC that does not exist yet. |
| `aliases` | One machine, one entry, reachable by either name. Collisions with host names or other aliases are load errors. |
| `apytti_url` | Gateway URL; required with `claude_exec`. |
| `sudo_password_vault_path` / `sudo_password_vault_field` | Vault-held sudo password (field defaults to `password`). Requires `sudo_exec`. |
| `extra_ips` | Other addresses the machine may call prompto from (second NIC, Wi-Fi, VPN, IPv6). Used only by the self-targeting guard, never to reach the host. Literal IPs, canonicalized at load (`::ffff:a.b.c.d` → `a.b.c.d`). Load errors: unspecified or multicast addresses, repeats, and an address claimed by two hosts. |
| `groups` | Policy host groups, matched by `group:<g>` in [`policy.toml`](#policy-policytoml). Names use `[a-z0-9_-]`; repeats are load errors. They mean nothing outside policy. |
| `nopasswd_sudo` | `true` / `false`: whether `ssh_user` can `sudo` without a password. Unset means unknown. Informational: prompto's sudo paths don't read it. `policy lint` warns when a rule without `sudo = true` grants an exec tool on a host where this is `true` or unset, or where `ssh_user` is `root` (see [*`sudo = false` is not "no root"*](#policy-policytoml)). |
| `prompto_host` | `true` on the machine that runs prompto. Root there reads every approval factor — `/etc/prompto/env` (prompto's vault token, which reads the private mount), the ticket key file, approvers' TOTP files — so `policy lint` reports an **error** for any rule that grants root on it: a `sudo = true` grant of a root-capable tool, or an exec tool where `ssh_user` is root or can sudo (`nopasswd_sudo` true or unset, `sudo_exec`, or a `sudo_password_vault_path`). So is a plain grant of a tool that runs as `ssh_user` there (exec tools, `file_*`, `rsync_sync`, `host_diagnose`) when `ssh_user` is prompto's own service user (`PROMPTO_SERVICE_USER`), which reads those files without sudo. A rule that really means it says `crown_jewel_ack = true`. While the live policy has any of these errors, **approvals are off**. See [Where the approval secrets live](#where-the-approval-secrets-live). |
| `request_id_env` | How `PROMPTO_REQUEST_ID` reaches remote commands. `export` adds an `export …;` prefix plus `ssh -o SetEnv`; it is the default on `linux` and `macos`. `setenv` uses `SetEnv` only, leaving the command line untouched; it is the default on `freebsd` and `windows`. `off` sends nothing: no prefix, no `SetEnv`, no `env` on the vault sudo path. Use `off` for keys restricted by `command=`, rrsync or git-shell. Use `setenv` for a non-POSIX login shell on Linux or macOS. Any other value is a load error. |

The whole file is validated at load (unknown hypervisors, alias collisions, `wake` on a VM, malformed vault paths, …). `SIGHUP` reloads it without dropping the listener; a file that fails validation is rejected and the previous inventory stays live.

## Sudo with a password (Vault)

`ssh_sudo_exec` and friends use `sudo -n` by default, which needs a passwordless sudo rule on the target. A host that keeps a sudo password can instead declare where it lives in Vault (KV v2):

```toml
sudo_password_vault_path  = "hosts/sudo"   # under PROMPTO_VAULT_MOUNT
sudo_password_vault_field = "password"     # default
```

prompto fetches the password per call and feeds it to sudo inside the SSH session. It is never returned to the caller, logged, or placed on any command line:

- The remote command is fixed: `sudo -k -S -p '' -- sh -c '<guard>' prompto-sudo env PROMPTO_REQUEST_ID=<ulid> sh -s`. Password, then a marker line, then the caller's command all travel over SSH stdin, so `ps` on either end sees nothing secret.
- `-k` makes sudo ignore cached credentials and read the password every time; the command is only read by the root shell *after* sudo has authenticated, so `x & cat`-style tricks can't reach the password line.
- **The guard** reads one line and requires the marker. If the host *also* has a passwordless rule, sudo never reads stdin, the guard sees the password instead of the marker, and exits **97** without printing it or running anything. Fix such a host by removing the passwordless rule (or the vault path).
- On vault hosts the whole command runs as root under `sh`; on `sudo -n` hosts only its first simple command is elevated.

Vault setup:

```bash
# read-only on the sudo secrets; renew-self/lookup-self come with `default`
vault policy write prompto-read - <<'EOF'
path "secret/data/hosts/*" { capabilities = ["read"] }
EOF

# a PERIODIC orphan token — prompto renews it at half its lease, forever
vault token create -policy=prompto-read -period=768h -orphan \
  -display-name=prompto -field=token
```

Put it in `PROMPTO_VAULT_TOKEN` in the service's env file and **restart** (env is not re-read on SIGHUP). Use `-period`: a token created with a plain TTL is capped at the mount's max TTL, renewal stops extending it (Vault only warns `TTL value is capped`), and it expires no matter how often prompto renews. prompto logs `vault token renewed lease_secs=…` at startup and on every renewal; if the lease shrinks over time, the token isn't periodic.

Without `PROMPTO_VAULT_TOKEN`, prompto starts normally and warns about every host that declares a vault path — their sudo calls fail until it's set.

## Agent identity (`PROMPTO_AUTH`)

Each agent *role* gets a bearer token. prompto stores only the token's SHA-256, in `/etc/prompto/agents.toml` (`PROMPTO_AGENTS`):

```toml
[agent.builder]
groups = ["build"]
token_sha256 = "<64 hex chars>"
created = "2026-10-09T12:00:00Z"
disabled = false
```

| `PROMPTO_AUTH` | No / invalid / revoked token | Valid token |
|---|---|---|
| `off` (default) | Accepted, no agent attached: exactly the behaviour before agent identity existed | Token ignored |
| `optional` | Accepted as agent `anonymous`. An invalid or revoked token is also logged as a warning with the caller IP (never the token) | Agent = the role |
| `required` | **401**: a JSON-RPC error object on `/mcp`, plain text on `GET /log` | Agent = the role |

- The stdio transport is always agent `local`.
- Any other `PROMPTO_AUTH` value stops the server at startup, so a typo can't silently mean `off`.
- Tokens are hashed, then compared in constant time against every entry.
- Agent names use `[a-z0-9_-]`; `anonymous` and `local` are reserved. Names and groups are what [policy](#policy-policytoml) keys on, and what the [audit log](#audit-log) records.
- Every call is attributed in the audit log; failed calls also get a journald line: `tool call failed request_id=… agent="builder" session_id="…"`.
- Tool results don't echo the agent. The caller knows who it is, and an unchanged result shape keeps `off` byte-identical.

**Session context.** A client may send `X-Prompto-Session: <id>` (the Claude session ID). It is context for the logs, never proof of identity: any holder of a role token can claim any session. Values over 128 characters or outside `A-Za-z0-9._:-` are dropped with a warning; the call itself proceeds. With `off` the header is ignored entirely.

**Legacy MCP sessions** (`PROMPTO_LEGACY_SESSION_MODE=true`) are bound to the agent that created them: a request carrying an `Mcp-Session-Id` created by a different agent (`anonymous` included) gets a 401, in `optional` as in `required`.

### Managing tokens

```bash
sudo prompto agent add builder --groups build,ops   # prints the token ONCE on stdout
sudo prompto agent list                             # name, status, groups, created, sha256 prefix
sudo prompto agent revoke builder                   # sets disabled = true; refused from the next request
```

- **`add`** writes only the hash, atomically, keeping the file's mode and owner.
  - A new file is created `0640` with the directory's group. With the standard install (`/etc/prompto` is `root:prompto`), that lets the service read it.
  - Run it as the user that owns the file.
- **`revoke`** keeps the entry with `disabled = true` rather than deleting it.
  - The name stays taken.
  - A stale token is logged as *revoked*, naming the role, instead of just *invalid*.
  - To issue a new token for a role, revoke it and add a new name, or delete the entry by hand and `add` again.
- **Changes apply to the next request, no SIGHUP needed.** With `optional` or `required`, every request `stat`s `agents.toml` and re-reads it when it changed (inode, size, mtime or ctime), whether the CLI or an editor changed it. SIGHUP re-reads it too.
  - A re-read that fails (bad TOML, malformed hash, duplicate token, unreadable) **fails closed**, like the policy: no agent is valid (every token gets 401 under `required`, `anonymous` under `optional`) and `AGENTS FILE INVALID` is logged, until a valid file is read. The previous agents are not kept: a half-finished revoke must not leave the agent working. A malformed file at startup still stops the server.
  - A missing file means no agents.
- **A revoked token** is refused on the very next request with `PROMPTO_AUTH=required`: a 401, recorded as a `type: auth` record with `reason: revoked token`, not as `killed` (it is an authentication failure, and the 401 comes before any tool call). With `optional` it falls back to `anonymous`. Revoking is permanent for that token; to stop an agent for a while and let it resume with the same token, use [`prompto kill agent`](#kill-switches).

**Rollout:**

1. Write `policy.toml` first (see below): `optional` and `required` enforce it, and without one every call is refused. To start permissive, grant `anonymous` and your roles `tools = ["*"]` (plus a `sudo = true` twin) on `hosts = ["*"]`, then narrow.
2. Set `PROMPTO_AUTH=optional`.
3. Mint a token per role.
4. Register clients with their token.
5. Watch the logs for `agent="anonymous"`.
6. Drop the `anonymous` grants and switch to `required`. This needs a restart, since env is read at startup.

## Policy (`policy.toml`)

With `PROMPTO_AUTH=optional` or `required`, every tool call must be granted by `/etc/prompto/policy.toml` (`PROMPTO_POLICY`). With `off` the file is not read at all and nothing changes. A copy to start from is in `deploy/policy.toml.example`.

```toml
[[rule]]
id = "builder-exec"                # optional; names the rule in logs and refusals
agents = ["builder", "group:ops"]  # agent names or group:<g> from agents.toml
hosts = ["build-*", "group:build"] # inventory names/aliases, * ? globs, group:<g>
tools = ["ssh_exec", "file_*", "inventory_*"]

[[rule]]
agents = ["builder"]
hosts = ["build-1"]
tools = ["ssh_sudo_exec", "file_write", "service_control"]
sudo = true                        # this rule grants the root-capable calls
approval = "human"                 # none (default) | ticket | human
```

**Matching.** Rules are read top to bottom; **the first rule that matches decides**, and no match is a deny. Rules only grant (there are no deny rules), so order matters only for which rule's `approval` applies: put the narrow, stricter rule first. A rule matches when:

- **agents**: the agent's name is listed, or `group:<g>` names one of its groups. Groups are read from the *live* `agents.toml` at every call, so a reload that changes them applies to open sessions too. No globs, so a rule never grants an agent nobody named. `anonymous` (no valid token under `optional`) and `local` (stdio) match only by name.
- **hosts**: an entry matches the host's inventory name or any of its aliases (`*` and `?` are wildcards), or is `group:<g>` with `<g>` in the host's inventory `groups`. Tools that target no host (`inventory_list`, `prompto_gain`, `mcp_reconnect_hint`) skip this check: they still need a `tools` match, but a rule grants them whatever its `hosts` say.
- **tools**: an entry matches the tool name (`*`, `?`).
- **sudo**: root-capable calls are a **separate grant**. They match only rules with `sudo = true`, and those rules match only them. So `tools = ["*"]` grants every ordinary tool and nothing that runs as root. Root-capable: `ssh_sudo_exec`, `file_write` with `sudo = true`, `service_control`, `host_sleep`, `service_logs` / `mcp_logs` / `GET /log` (journal via sudo), and `vm_stop`.

**`sudo = false` is not "no root".** `sudo = true` gates prompto's *own* root paths, nothing more. The exec tools (`ssh_exec`, `ssh_batch`, `bash_exec`, `python_exec`, `node_exec`, `ruby_exec`, `perl_exec`, `deno_exec`, `claude_exec`, `mcp_add`, whose stdio command runs on the client, and `file_write` without `sudo` and `rsync_sync`, because writing `~/.bashrc`, a crontab or a user unit is code execution) run whatever the agent sends, as the host's `ssh_user`. So an exec grant on a host is a shell as that user, and that is root wherever the user is `root` or can `sudo` without a password: `ssh_exec "sudo -n …"` needs no `sudo = true` rule there. prompto does not try to police command strings (`sh -c`, quoting and aliases make that unreliable). Grant exec tools only where that shell is acceptable, and mark each host's `nopasswd_sudo` in the inventory so `policy lint` can tell you where it isn't. The list of exec tools lives in one place in the code (`authz::ARBITRARY_EXEC_TOOLS`); every tool is classified as root-capable, exec or ordinary, and a test fails on one that isn't.

**Root on the prompto host.** Mark the machine running prompto `prompto_host = true` in the inventory. A rule that grants root there — `sudo = true` with a root-capable tool, or an exec tool where the shell can sudo — is a lint **error**: root on that machine reads prompto's vault token and key files and can approve or forge anything (see [Where the approval secrets live](#where-the-approval-secrets-live)). So is any plain grant there of a tool that runs as `ssh_user` (the exec tools, `file_*`, `rsync_sync`, `host_diagnose`) when `ssh_user` is prompto's own service user (`PROMPTO_SERVICE_USER`, default `prompto`): that account reads the same files without sudo. If you really mean it, say so on the rule with `crown_jewel_ack = true`. Either error also **turns approvals off** while it is in the live policy — checked at startup, on SIGHUP and whenever `policy.toml` is re-read — with the same `APPROVALS DISABLED — …` log and refusals as a misplaced secret.

**Approval.** A rule with `approval = "ticket"` grants what it matches only to a call that carries a valid ticket from `POST /v1/precheck`; `approval = "human"` only with one from `POST /v1/approve`, which takes a human approver's TOTP code. Without a ticket the call is refused (`approval_required`, saying how to get one), with a bad one `refused_ticket`. See [Tickets and approvals](#tickets-and-approvals). Without a ticket key configured, such a rule refuses everything it matches, as before.

**What policy cannot do.** It only narrows: effective permission = policy ∩ host capability, minus the caller's own machine. The capability check and the self-targeting guard run first and no rule can undo them. A consequence: an agent with no grant at all can still tell `unknown_host` from `refused_capability` from `refused_self_target`, so it can probe which host names exist and what they carry. That is a known, accepted property; the self-targeting guard must stay unconditional, so it can't wait for policy.

**Inventory visibility.** With policy on, `inventory_list` shows an agent only the hosts some rule grants it a host-targeting tool on (any tool, with or without `sudo`, approval rules included; the hostless `inventory_list` grant itself doesn't count). `sudo_password_vault_path` is shown only on hosts where the agent has a `sudo = true` grant; elsewhere the key is left out (not set to `null`, which would claim there is none). `inventory_get_host` hides it the same way. With `off`, both are unchanged.

**Refusals** are classified `refused_policy` (or `approval_required` / `refused_ticket`), carry the deciding rule in `error.data.rule` (`policy.toml:<line>`, with ` (<id>)` when the rule has one, or `default-deny`), and say what is missing:

```
refused_policy: agent builder has no grant for ssh_sudo_exec (root-capable) on build-2 (no rule matched;
root-capable calls need a rule with sudo = true — policy.toml:2 (builder-exec) grants ssh_sudo_exec on
build-2 but without sudo). Ask the operator for a policy.toml rule if you need it.
```

Allowed calls log `policy allow request_id=… agent=… tool=… host=… root=… rule=…` at info level. `GET /log` answers a policy refusal with 403.

**Loading.** Every policy decision `stat`s the file and re-reads it when it changed (inode, size, mtime or ctime), so an edit applies to the **next call**, no SIGHUP needed (`policy file changed — reloaded` in the journal). SIGHUP re-reads it too, independently of the inventory and `agents.toml`. A malformed file at startup stops the server. On a re-read it **fails closed**, whatever triggered it: the previous policy is dropped (it may be broader than the one being written), every call is denied with `policy file invalid since <time>` in the refusal (the parser's error and the file's path go to the journal only, not to agents), and an error is logged (`POLICY FILE INVALID`), until a valid file is written. A **missing** file also means *deny every call*, with a loud warning at startup and on each reload. The server lints the policy at startup and after every SIGHUP, and logs the findings (a change picked up on a call is not linted: run `prompto policy lint`). They never block loading: a rule naming something that doesn't exist simply grants nothing.

**Checking a policy:**

```bash
prompto policy lint     # against $PROMPTO_INVENTORY, $PROMPTO_AGENTS and the tool list; exit 1 on errors
prompto policy check --agent builder --host build-2 --tool ssh_sudo_exec    # ALLOW/DENY + rule; exit 0/1
prompto policy check --agent builder --host build-2 --tool file_write --sudo
```

- **Lint errors:** unknown agents, unknown hosts, host groups no host is in, unknown tools, and root, or the service user's shell or files, granted on a `prompto_host` without `crown_jewel_ack = true` (these two also turn approvals off).
- **Lint warnings:** agent groups nobody is in yet, globs that match nothing, revoked agents, exec grants without `sudo = true` on hosts where that shell can become root (one warning per rule, naming the tools and each host: `ssh_user is root`, `nopasswd_sudo = true`, or `nopasswd_sudo unset`; hosts lacking the tools' capability are skipped), and rules that can never decide a call. Lint finds those by enumerating every agent × host × tool × root combination: a rule is either *shadowed* (an earlier rule always wins; the warning names it), or matches nothing at all (for example `sudo = true` on tools that are never root-capable).
- `policy check` evaluates policy only; capability and the self-targeting guard are checked at call time, before policy.
- `cargo run --example inv_check -- prompto.toml policy.toml agents.toml` runs the same lint.

**Kill one agent on one host:** drop the host from its rules; the next call sees the change. The broader scopes need no policy edit: see [kill switches](#kill-switches).

## Tickets and approvals

A policy rule can demand more than a match: `approval = "ticket"` (the call must be prechecked) or `approval = "human"` (a person must approve this exact call). The proof is a **ticket**: a short string prompto signs, which the client passes back as the call's `ticket` argument. Every tool accepts it; it is not in the tools' advertised schemas (it would cost every client tokens on every `tools/list`); the Claude Code plugin (roadmap E7) will add it for you. Enforcement is always prompto's: a call without a valid ticket is refused wherever policy demands one, whatever the client does.

**The flow:**

```
call without ticket ──► approval_required (the message says which endpoint to use)
POST /v1/precheck  {tool, arguments}           ──► allow + ticket   (approval = "ticket")
                                                ──► ask             (approval = "human")
POST /v1/approve   {tool, arguments, approver, totp_code[, scope_minutes[, allow_root_scope]]} ──► ticket
call with {…arguments, "ticket": "pt1.…"}      ──► runs, once
```

**`POST /v1/precheck`** (same bearer token and `X-Prompto-Session` as `/mcp`; body `{"tool": …, "arguments": {…}, "session": optional}`) runs the call's whole authorization — kill switches, host, capability, self-targeting guard, policy, and any `ticket` already in `arguments` — and **runs nothing**: no SSH, no ticket spent. It answers `{"decision": "allow" | "deny" | "ask", "rule", "reason", "approval", "request_id"}`, plus `error_class` on `deny` and `ticket` + `expires_at` when a `ticket` rule allowed it. `session` in the body, if sent, must match the header.

**`POST /v1/approve`** (body `{"tool", "arguments", "session"?, "approver", "totp_code", "scope_minutes"?, "allow_root_scope"?}`) re-runs the same authorization (no approval for a call policy denies; `409` when no approval is needed), checks the approver's code, and returns a ticket with `approval = "human"` and `approved_by = <approver>`. Status: `200`; `403` deny or wrong code; `429` approver locked out; `400` bad request; `503` tickets unavailable.

**Why TOTP.** The agent and the plugin run as the same OS user with the same bearer token: anything the plugin can send, the agent can send too. So an approval must carry something the agent can't produce, and the first such factor is a TOTP code from the approver's phone (RFC 6238: SHA-1, 6 digits, 30 s, ±1 step). Each code is accepted once per approver (a code for a step at or below the last accepted one is refused), and 5 wrong codes within 15 minutes lock that approver out for 15 minutes (even a correct code is refused meanwhile; other approvers are unaffected). An unknown or revoked approver fails exactly like a wrong code: same answer, and the same TOTP computation against a dummy secret. Approver names must look like agent names (1–64 of `a-z 0-9 - _`); anything else is refused before any lookup. Failures are counted per name for every approver in the file; unknown names are counted too (so a lockout doesn't reveal which names exist), but at most 4096 of them — past that, all further unknown names share one counter and lock out together. The approver mechanism is pluggable (`approvers::Factor`): approval from a separate device or a Kanidm-authenticated page can come later.

**Approvers** live in `$PROMPTO_APPROVERS` (default `/etc/prompto/approvers.toml`), re-read at every approval (no reload):

```bash
# secret in vault KV v2 (field totp_secret) on the PRIVATE mount ($PROMPTO_PRIVATE_MOUNT,
# default prompto-private) — needs PROMPTO_VAULT_ADDR and an operator token that may write there
sudo PROMPTO_VAULT_TOKEN=… prompto approver add alice --vault-path approvers/alice
# or in an owner-only file; create the directory owned by the service user first
sudo install -d -o prompto -g prompto -m 0700 /etc/prompto/approvers.d
sudo prompto approver add bob                     # → /etc/prompto/approvers.d/bob.totp
prompto approver list
sudo prompto approver revoke bob                  # disabled = true; codes refused from the next approval
sudo prompto approver add bob --replace           # re-enroll (lost phone)
```

`add` prints the `otpauth://` URI and a terminal QR code **once**: scan it now. prompto never stores the secret anywhere but where the entry points, reads it at each approval, and refuses a secret file that its group or others can read. `add --vault-path` refuses a path agents can read (below), and one in the same vault directory as a host's `sudo_password_vault_path` unless you pass `--i-know`.

**What "approve similar calls" means.** With `scope_minutes` (1–60), the ticket is valid until it expires for **any number of calls by the same agent, in the same session, to the same tool, on the same host** (for `rsync_sync`: the same source *and* dest host), **decided by the same policy rule(s), and root-capable exactly when the approved call was**, **whatever the other arguments are**. A different tool, host, session, agent, deciding rule (an edit that moves the rule counts: rules are named `policy.toml:<line>`) or root-ness needs a new approval: a scope approved for plain `file_write` never covers `file_write` with `sudo = true`.

**Root scopes are opt-in.** For a root-capable call, freeing the arguments means "any root command on that host" for the scope's duration. `/v1/approve` refuses such a scope (`400`, before checking the code, so it isn't spent) unless the request says `"allow_root_scope": true` — the approver's explicit choice, recorded in the approval's audit `reason`. Prefer single approvals for root. It requires a session (`X-Prompto-Session` or `session`): without one it would cover every session of the agent role. Remember the session ID is context, not proof of identity: anyone with the role's token who learns the session ID can use the scope. Use it for "let me watch it restart these five units", not for open-ended trust.

**The ticket.** `pt1.<kid>.<claims>.<mac>`: `kid` names the signing key (8 hex digits of its SHA-256); `claims` is base64url JSON `{agent, session, tool, host, dest_host?, args_sha256, approval, approved_by, iat, exp, nonce, scoped, scope?}` (`scope` = `{root, rules}` on scoped tickets); `mac` is HMAC-SHA256 over the first three parts. `host` is the canonical inventory name (an alias in the call resolves to it). An ordinary ticket lives **120 s** and is **single-use**: its nonce is recorded when a call uses it, and a replay is `refused_ticket … already used`. A call is checked, in order, for: form and signature, expiry, agent, session, tool, host(s), arguments digest (unless scoped; a scoped ticket's root-ness and rules instead), approval level (`human` satisfies a `ticket` rule, not the reverse), then the nonce. A failed check spends nothing. A ticket on a call whose rule needs no approval is ignored.

**Canonical arguments.** `args_sha256` is the SHA-256 (hex) of the call's `arguments` object **without its top-level `ticket`**, in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON (JCS): keys sorted by UTF-16 code units, no whitespace, minimal string escaping, numbers as ECMAScript prints them (`5.0` → `5`). Absent arguments count as `{}`. So any re-serialization of the same JSON value gets the same ticket, and any change of value (an extra argument, even a default one; one more space in a command) needs a new one. Clients never compute it — prompto does on both sides — but for reference, `{"host":"sbx-t2","cmd":"id -u","ticket":"…"}` canonicalizes to `{"cmd":"id -u","host":"sbx-t2"}`, digest `f77f3663236062c05147ca8f5a6b7a5b77f98a38dae2f3db5935c8f271ebeeca`.

**Keys.** `PROMPTO_TICKET_KEY_VAULT_PATH` names a KV v2 secret on the private mount (`PROMPTO_PRIVATE_MOUNT`; same vault address, token and CA as the sudo passwords) with fields `current` and, during a rotation, `previous`; `PROMPTO_TICKET_KEY_FILE` is the same in a file (current key on the first line, previous on the second, mode `0600`), used when no vault path is set or vault can't be read. A key is base64 of at least 32 random bytes: `prompto ticket keygen`. Tickets are signed with `current` and both are accepted. **Rotation:** move the old key to `previous`, put a new one in `current`, then SIGHUP (or wait: keys are re-read every minute); drop `previous` once outstanding tickets have expired (2 minutes, up to an hour for scoped approvals). Setting neither variable disables tickets: approval rules refuse their calls as before.

**Continuity across restarts.** The key lives in vault or a file, never in the process, so a ticket minted just before a deploy works just after it. Used nonces and the last accepted TOTP step per approver are appended to `$PROMPTO_APPROVAL_STATE` (default `/var/lib/prompto/approval-state`, `0600`) and synced to disk (`fdatasync`, ~2 ms on the sandbox VMs' virtual disks) before the call proceeds — so a power loss can't forget them either — and reloaded at startup (expired entries are dropped), so a restart can't reopen a used ticket or code either. If that file can't be written, calls that need a ticket are refused (`internal`) and the rest run normally; if no key can be read at startup, prompto starts anyway, refuses ticketed calls saying so, and retries every minute. Lockout counters are in memory and reset on restart.

**Audit.** A call's record never contains the ticket: `args` has it removed, and `ticket_sha256` holds its SHA-256; `approval` is the rule's demand and `approved_by` the approver the ticket names. Prechecks and approvals have their own records, `"type": "precheck"` (`decision` `allow`/`deny`/`ask`) and `"type": "approve"` (wrong codes and lockouts included, `approved_by` = the approver named, `scope_minutes`), with the `ticket_sha256` of what they minted, so a call can be joined to the precheck or approval behind it.

**Not covered.** `GET /log` takes no ticket: a `service_logs` rule with an approval refuses it there (use the tool). With `PROMPTO_AUTH=off` there is no policy, so nothing needs or checks a ticket.

### Where the approval secrets live

**Nothing an agent can read may be an approval factor or a signing key.** An agent that can read an approver's TOTP secret computes the codes and approves its own calls; one that can read the ticket key mints any ticket it likes. Agents are often given read access to vault — a gateway whose policy covers `secret/data/prompto/*`, say, for the sudo passwords — so the approval secrets must not sit next to those.

- **Vault: a mount of their own.** The ticket key (`PROMPTO_TICKET_KEY_VAULT_PATH`) and every `totp_vault_path` are read from the KV v2 mount `PROMPTO_PRIVATE_MOUNT` (default `prompto-private`), with prompto's token — not from `PROMPTO_VAULT_MOUNT`. **prompto's token must be the only token with read on that mount**; operators write to it with their own token. Agent gateways, scripts and other services must never be granted anything on it.

  ```bash
  vault secrets enable -path=prompto-private -version=2 kv
  # Grant it in a policy that ONLY prompto's token carries — here the prompto-read policy
  # from "Sudo with a password", if nothing else uses it (a policy edit applies to existing
  # tokens at once; no new token, no restart). No other policy may name prompto-private/.
  vault policy write prompto-read - <<'EOF'
  path "secret/data/hosts/*"     { capabilities = ["read"] }
  path "prompto-private/data/*"  { capabilities = ["read"] }
  EOF
  # operator side, with an operator token: the ticket key and approvers
  prompto ticket keygen | vault kv put -mount=prompto-private ticket-key current=-
  prompto approver add alice --vault-path approvers/alice
  ```

  Then `PROMPTO_TICKET_KEY_VAULT_PATH=ticket-key`. Check that nothing else can read it: `vault policy list`, and grep every policy for `prompto-private`.
- **The startup check.** `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` (default `prompto/,infra/,nxp/`) lists what agents can read: comma-separated path prefixes on `PROMPTO_VAULT_MOUNT`, or `<mount>:<prefix>` for another mount (`<mount>:` = all of it). Prefixes match like a vault policy glob, as plain string prefixes. If the ticket key or an active approver's secret is under one of them, prompto **turns approvals off** — nothing is minted or accepted, calls that need a ticket are refused saying the operator must move a secret — and logs `APPROVALS DISABLED — …` with the path and what to do. It checks at startup, every minute, on SIGHUP and at every approval (`approvers.toml` is re-read each time). Keep the list in step with what your agents' vault access really covers; prompto can't see other tokens' policies. It also warns when an approval secret shares a vault directory with a sudo password.
- **Files** (`totp_file`, `PROMPTO_TICKET_KEY_FILE`) must be owned by the service user, mode `0600` (prompto refuses group/other-readable ones), in a directory only it can enter. **Anyone who is root on the machine running prompto reads them — and `/etc/prompto/env`, whose vault token reads the private mount.** So does any agent that policy lets run root there, or a shell as a user that can sudo there. Mark that machine `prompto_host = true` in the inventory: `policy lint` then reports every such grant — and every grant of a shell or file tool there as the service user itself — as an error (see [Policy](#policy-policytoml)), and approvals stay off while one is in the live policy, unless the rule says `crown_jewel_ack = true`. Don't run prompto on a machine agents administer.

## `GET /log`

```
GET /log?host=<name>&unit=<systemd unit>&lines=<1..1000, default 50>
```

Plain-text journal tail for scripts and dashboards. It has the same gate as `service_logs` (`sudo_exec`, self-targeting guard, policy, unit-name validation) and the same authentication as `/mcp`.

- With `PROMPTO_AUTH` `off` or `optional` it is **unauthenticated**: anyone who can reach the listener can read journals on any `sudo_exec` host. Keep the listener behind a trusted proxy or firewall.
- With `required`, send `Authorization: Bearer <token>`.

## Audit log

Every tool call is recorded, one JSON object per line, in `$PROMPTO_AUDIT_LOG` (default `/var/lib/prompto/audit.jsonl`), whatever `PROMPTO_AUTH` says. That includes refusals (`killed`, `unknown_host`, `refused_capability`, `refused_self_target`, `refused_policy`, `approval_required`), calls whose arguments don't parse, `GET /log` (recorded as `service_logs`), every 401, and every precheck and approval (`"type": "precheck"` / `"approve"`, see [Tickets and approvals](#tickets-and-approvals)). It is separate from the token-savings usage log.

```json
{"ts":"2026-10-09T11:50:02.113Z","type":"tool","request_id":"01M4G…","agent":"builder","agent_groups":["ops"],
 "session_id":"…","client_ip":"192.0.2.10","user_agent":"claude-code/2.1.289","tool":"ssh_exec","host":"build-1",
 "queried_as":"b1","args":{"host":"b1","cmd":"systemctl is-active nginx"},"decision":"allow",
 "rule":"policy.toml:2 (builder-exec)","approval":"none","approved_by":null,"exit_code":0,"ok":true,
 "error_class":null,"duration_ms":212,"bytes":187}
```

- **Who:** `agent` (`anonymous`, `local` for stdio, `-` with auth off), its `agent_groups`, the client's `session_id`, `client_ip` and `user_agent`.
- **What, where:** `tool`; `host` is the inventory name the call resolved to and `queried_as` what the caller typed when that differs (an alias, or an unknown name, with `host` then `null`). `rsync_sync` adds `dest_host` / `dest_queried_as`. `ssh_batch` is one record with the whole `commands` list.
- **`args`:** commands are recorded **in full**: `cmd`, `commands`, every interpreter's `script` (`bash_exec`, `python_exec`, `node_exec`, `ruby_exec`, `perl_exec`, `deno_exec`), `claude_exec`'s `task`. A string over 16 KiB becomes `{"sha256": …, "len": …, "truncated": true}`, and so do whole `args` over 64 KiB. File contents (`file_write`'s `content`) are always `{"sha256": …, "len": …}`. A field *named* like a secret becomes `"[redacted]"`: the name, case- and `-`/`_`-insensitive, is or ends with `password`, `passwd`, `passphrase`, `token`, `secret`, `credential(s)`, `api_key`/`apikey`, `private_key`, `access_key`, `secret_key`, `signing_key`, `auth_key`, `authorization`, `cookie`, `_pwd`, `_pass`, `_pw`, or is `pass`/`pw` (so `dest_key`, a path, is kept). Every kept string is also **scrubbed** of secret *values*: URL userinfo (`https://***@host`), secret-named query parameters (`?token=***`), `Authorization:` and other secret-named headers (`Authorization: ***`), `Bearer ***`, secret-named long flags (`--password ***`, `--api-key=***`, and `["--password", "***"]` in an argv list), assignments (`export TOKEN=***`, `X_API_KEY=***`) and quoted literals in code or JSON (`password = "***"`, `"token": "***"`). A secret the scrubber can't recognise (a positional argument, `-p x`, an innocently named variable) stays: don't put secrets in commands. The vault sudo password is never an argument: it is fetched inside the SSH layer, after the record's arguments were taken from the request.
- **Decision:** `decision` is `allow` (authorization passed), `deny` (refused before anything ran) or `null` (the arguments were invalid before authorization). `rule` is the deciding policy rule, `approval` its approval mode; `approved_by` is the approver named in the call's ticket, and `ticket_sha256` the SHA-256 of the ticket it carried (the ticket itself is removed from `args`).
- **Outcome:** `ok` means the call did what was asked: no error *and* any remote command exited 0 without timing out. It is stricter than the gain log's notion of success, since `ssh_exec` returns a non-zero exit as a result, not an error. When `ok` is false, `error_class` says why (below) and `exit_code` carries the exit status when there is one. `bytes` is the size of the response.
- **401s** have no tool call; they are `"type":"auth"` records with `reason` (`missing bearer token`, `invalid bearer token`, `revoked token`, `session belongs to another agent`) and `path`. They come from unauthenticated peers, so they are rate-limited per client (an IP, or an IPv6 /64: a burst of 10, then one every 10 s; the 4096 most recent clients are tracked) under a global ceiling (a burst of 60, then one per second). One client flooding can't crowd out another's revoked-token 401. The next record written says how many were dropped (`suppressed`). A hijack attempt adds `mcp_session`, the other agent's session ID shortened as in the journal; `session_id` is shortened the same way there. The journal keeps its own warning line for each.
- **`auth_note`:** with `PROMPTO_AUTH=optional`, a caller whose token is revoked or invalid runs as `anonymous`; its records say so (`"auth_note": "revoked token for builder"` / `"invalid token"`).
- **Bounded:** every string a client chooses (a typed host name, an unknown tool name, `User-Agent`, the session header, `path`, `reason`) is scrubbed as above and cut to 256 chars (`path`: 512).
- **`kill`:** a call refused by a [kill switch](#kill-switches) (`error_class: "killed"`, `decision: "deny"`) carries the switch: `"kill": {"scope": "host", "target": "build-1", "since": "2026-10-09T12:00:00Z", "reason": "disk failing"}` (`scope` is `global`, `agent`, `host` or `session`; `global` has no `target`). journald: `AUDIT_KILL_SCOPE`, `AUDIT_KILL_TARGET`, `AUDIT_KILL_REASON`. The `prompto audit` table shows `kill=<scope> <target>` in the detail column.
- **Kill switch changes** made with `prompto kill`/`unkill` are `"type": "kill"` records written by the CLI: `{"ts":…,"type":"kill","request_id":…,"action":"on","scope":"host","target":"build-1","reason":"disk failing","file":"/etc/prompto/kill.d/host-build-1","by":{"uid":0,"user":"root","sudo_user":"alice"}}`. See [kill switches](#kill-switches).
- **`aborted`:** a call cut off before it finished (prompto shut down or the handler panicked mid-call) still gets its record, with `error_class: "aborted"`. Whether the action took effect is unknown.

**`error_class`** is one enum for every failure of every tool, the same one MCP errors carry in `error.data.error_class`: `unknown_host`, `refused_capability`, `refused_self_target`, `refused_policy`, `approval_required`, `invalid_args`, `ssh_connect`, `ssh_auth`, `timeout`, `sudo_guard` (the vault sudo guard, exit 97: the host has a passwordless rule), `remote_nonzero`, `vault`, `upstream` (the apytti gateway behind `claude_exec`), `internal`, `aborted` (audit only, see above), `killed` (a [kill switch](#kill-switches)), rsync's `rsync_*` / `dest_ssh_*`, and `refused_ticket` (a ticket that is malformed, forged, expired, already used or for another call; also a refused approval). An error that reaches the end of a tool without a class is a bug: it is reported as `internal` and logged as `BUG: tool error without an error_class`; a test drives every tool into every failure it can force and fails on one.

**journald.** The same record is a `tracing` event at target `prompto::audit`. Under systemd it goes to the journal as structured fields prefixed `AUDIT_` (`journalctl -u prompto AUDIT_AGENT=builder AUDIT_DECISION=deny`, `-o verbose` to see them; the record's `type` is `AUDIT_RECORD_TYPE`). Outside systemd it is a log line on stderr. It is emitted before the file is written, so the journal has the record even if the write fails.

**Failure policy.** With `PROMPTO_AUTH` `optional` or `required`, no action goes unaudited: a log that can't be opened stops the server at startup, and a call is refused *before it runs* (`internal`, `refused: prompto cannot write its audit log (the audit disk is full)…`, or `cannot be opened` / `the last audit write failed`, and an error in the journal) unless the log is open and the last write succeeded. A write that fails after a call ran (the disk filled mid-call) can't undo it — its record is in the journal — and every later call is refused until a write succeeds again. With `off` the record is still written (agent `-`), but a failure only warns: production keeps working when its audit disk doesn't. Whatever the mode, the journal gets `AUDIT FILESYSTEM NEARLY FULL` (an error, repeated every 5 minutes) while the audit log's filesystem has less than 64 MiB free. A write cut short by a full disk leaves a fragment: the next record starts on a fresh line, and `prompto audit` skips the fragment (and counts it), not the records around it.

**Querying:**

```bash
prompto audit --since 10m                       # table, oldest first
prompto audit --agent builder --decision deny   # every refusal for one agent
prompto audit --host build-1 --tool ssh_sudo_exec --since 2026-10-09T08:00:00Z
prompto audit --request-id 01M4G… --json        # the raw record
```

The table shows every client-supplied string with control characters escaped (`\x1b`, `\u{202e}`), so a crafted tool name or command can't drive your terminal; `--json` prints the records as JSON with those characters `\u`-escaped too. Filters combine; `--host` matches `host`, `queried_as`, rsync's dest, or a host kill's target; `--since` takes `30s`/`10m`/`2h`/`7d`/`1w` or a time (RFC 3339, or `YYYY-MM-DD[THH:MM[:SS]]` in UTC). Rotated siblings (`audit.jsonl.1`, `audit.jsonl.2.gz`, …) are read too, oldest first, skipping those last written before `--since`.

**Permissions and rotation.** prompto creates the file `0640`. The intended layout is `prompto:prompto-audit`, with readers in the `prompto-audit` group: `deploy/install.sh` creates the group and the file that way, and `deploy/logrotate.d/prompto-audit` keeps it so on rotation. Readers also need to traverse `/var/lib/prompto` (`0750 prompto:prompto`), e.g. `setfacl -m g:prompto-audit:x /var/lib/prompto`. If prompto has to create the file itself, `PROMPTO_AUDIT_GROUP` gives it that group (prompto must be a member). Rotation is rename-based and needs no signal: before each write prompto compares the path with the file it has open and reopens after a rename. Don't use `copytruncate`: lines written between its copy and its truncate are lost. The snippet uses `delaycompress`, so the file just rotated away is never compressed while a write may still land in it.

## Kill switches

Stop calls at any scope, effective from the **next call**: no restart, no SIGHUP, in every `PROMPTO_AUTH` mode.

```bash
sudo prompto kill on "incident 42: runaway agent"   # global: every tool call and GET /log
sudo prompto kill off
sudo prompto kill agent builder "looping on file_write"
sudo prompto kill host build-1 "disk failing"       # every agent, on that host
sudo prompto kill session 3f2c…                     # one X-Prompto-Session
sudo prompto unkill agent|host|session <name>
prompto kill status                                 # what is on, since when, why
```

| Scope | File | Refuses |
|---|---|---|
| global | `/etc/prompto/kill` (`PROMPTO_KILL_FILE`) | every tool call, and `GET /log` (503) |
| agent | `kill.d/agent-<name>` | every call by that agent, everywhere |
| host | `kill.d/host-<name>` | every call that targets the host (`host`, `client`, rsync's `source_host` and `dest_host`), by any agent; `GET /log` for it (403) |
| session | `kill.d/session-<id>` | every call carrying that `X-Prompto-Session` |

- **The file is the switch.** `kill.d` sits next to the global file (`/etc/prompto/kill.d`, or `PROMPTO_KILL_DIR`). A file's existence is what counts; its first line, if any, is the reason (shown with control characters removed, cut to 200 chars) and its mtime the time it was set. Writing the files by hand works exactly like the CLI: `sudo touch /etc/prompto/kill`, `echo "disk" | sudo tee /etc/prompto/kill.d/host-build-1`. The CLI writes them `0644` (`kill.d` `0755`) so the service can read them; it only ever reads them (`ProtectSystem=strict` makes `/etc` read-only to it anyway).
- **Checked first, on every call.** Before argument parsing, the host lookup, the self-targeting guard, policy and the audit preflight. A killed call says it is killed, not why it would have failed otherwise, and a broken audit log can't stop a kill. Cost: a `stat` per applicable file per call; nothing is cached, so there is nothing to reload.
- **The refusal** is `error_class: killed`, with a fixed message: what was stopped, since when, the reason, and the command that lifts it. It tells the agent this is deliberate and not to retry:
  ```
  [request_id=… error_class=killed] refused: the operator has stopped every call to host build-1 (host kill switch,
  set 2026-10-09T12:00:00Z, reason: disk failing). Nothing was run. This is deliberate, not a fault: do not retry
  or work around it; stop and tell the user. An operator lifts it with `prompto unkill host build-1`.
  ```
- **Audited** as `killed` with the scope in the record ([`kill`](#audit-log)), written when the log can take it, and always to the journal. The server also logs every switch that is on at startup (`KILL SWITCH ON`).
- **Names:** agents as in `agents.toml`; hosts and sessions are 1–128 of `A-Za-z0-9._:-`, starting with a letter or digit. No `/`, no leading `.`: `kill host ../x` is refused, and a call naming such a host can't match a file. A host switch applies under any of the host's names: a switch set on an alias catches calls using the inventory name, and the other way round. `kill host` warns when the name isn't in the inventory.
- **Agent and session switches need `PROMPTO_AUTH=optional` or `required`.** With `off`, calls carry no agent, and the session header isn't read (by design: `off` behaves as before E2), so `kill session` has no effect there. Global and host switches work in every mode. `kill agent anonymous` stops every caller without a valid token (`optional`); `kill agent local` stops the stdio transport.
- **A switch the server can't check fails closed.** At startup, if the service user can't `stat` the global file or search `kill.d` (any error other than "absent": permission denied, a symlink loop), prompto **refuses to start**, naming the path: fix the permissions, or point `PROMPTO_KILL_FILE` / `PROMPTO_KILL_DIR` somewhere it can. With the standard install (`/etc/prompto` `0750 root:prompto`) it can. If a path becomes uncheckable while running, every call that needs it is refused as `killed`, reason `kill switch unreadable: <path>: <error>` (`"unreadable": true` in the record's `kill`), and the journal gets `KILL SWITCH UNREADABLE` (at most once a minute; each refusal is logged too).
- **Who set it is audited.** Each `prompto kill …` / `unkill …` that changes a switch appends a `"type": "kill"` record to the audit log: `action` (`on`/`off`), `scope`, `target`, `reason`, the kill `file`, and `by` (the real uid, its name, and `SUDO_USER` when run through sudo). `prompto audit` shows them as `(kill)` rows with the operator in the agent column. The CLI appends without touching the file's owner or mode; if the file doesn't exist it creates it as the server would (`0640`, owned by the owner of its directory, group `PROMPTO_AUDIT_GROUP` or the directory's). If the record can't be written the switch **still applies** and the CLI says so on stderr: the panic button wins. A switch made by hand (`touch`) has no such record; the calls it refuses are recorded either way.

**Which tool for which job:**

| To stop… | Do | Effective |
|---|---|---|
| everything, now | `prompto kill on` | next call |
| one agent, for a while | `prompto kill agent <name>` (token unchanged) | next call |
| one agent, for good | `prompto agent revoke <name>` (the token is refused with 401 / runs as `anonymous`) | next request |
| one host, every agent | `prompto kill host <name>`, or drop it from the inventory + SIGHUP | next call |
| one agent on one host | drop the host from that agent's policy rules (no SIGHUP needed) | next call |
| one runaway Claude session | `prompto kill session <id>` (the `session_id` in its audit records) | next call |

## Token-savings analytics

Every tool call appends one JSON line to `$PROMPTO_USAGE_LOG` (default `/var/lib/prompto/usage.jsonl`). Run `prompto gain` (CLI) or call the `prompto_gain` MCP tool to get a per-tool breakdown of tokens saved versus an estimated SSH+bash baseline.

```bash
prompto gain                    # text summary
prompto gain --json             # machine-readable
prompto gain --since-secs 86400 # last 24h
```

Powered by the standalone [`mcp-gain`](https://github.com/calibrae/mcp-gain) crate.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PROMPTO_INVENTORY` | `/etc/prompto.toml` | Path to the host inventory TOML. |
| `PROMPTO_BIND` | `0.0.0.0:6337` | HTTP listen address. |
| `PROMPTO_ALLOWED_HOSTS` | localhost only | Comma-separated Host-header allowlist (DNS-rebinding protection). `*` to disable behind a trusted proxy. |
| `PROMPTO_TRUSTED_PROXIES` | `127.0.0.1, ::1` | Peers whose `X-Real-IP` / `X-Forwarded-For` are believed (self-targeting guard). |
| `PROMPTO_LEGACY_SESSION_MODE` | `false` | MCP sessions off: every request is stateless, so clients survive a prompto restart. `true` only for a client that truly needs `Mcp-Session-Id`. |
| `PROMPTO_SSH_BIN` | `ssh` | Path to the system `ssh` binary. |
| `PROMPTO_DEFAULT_TIMEOUT_SECS` | `30` | Default per-command timeout. |
| `PROMPTO_STOP_VM_STEP_SECS` | `30` | Per-step timeout in the `vm_stop` fallback chain. |
| `PROMPTO_VAULT_TOKEN` | unset | Enables vault-backed sudo. Periodic token — see above. |
| `PROMPTO_VAULT_ADDR` | `http://127.0.0.1:8200` | Vault address. |
| `PROMPTO_VAULT_MOUNT` | `secret` | KV v2 mount holding the sudo secrets. |
| `PROMPTO_VAULT_CACERT` | unset | PEM file (one or more certs) trusted as extra roots for the vault client, on top of the bundled webpki roots — for a vault behind a private CA. The system trust store is not consulted. Unreadable or certificate-less file = startup error. |
| `PROMPTO_AUTH` | `off` | `off`, `optional` or `required`; see [Agent identity](#agent-identity-prompto_auth). Anything else is a startup error. |
| `PROMPTO_AGENTS` | `/etc/prompto/agents.toml` | Agent token hashes. Missing file = no agents; unreadable or malformed = startup error (later: every token refused until fixed). Re-read when it changes. Not read at all with `PROMPTO_AUTH=off`. Also used by `prompto agent`. |
| `PROMPTO_POLICY` | `/etc/prompto/policy.toml` | Policy rules. Missing file = deny every call (loud warning); unreadable or malformed = startup error (later: every call denied until fixed). Re-read when it changes. Not read at all with `PROMPTO_AUTH=off`. Also used by `prompto policy`. |
| `PROMPTO_USAGE_LOG` | `/var/lib/prompto/usage.jsonl` | Append-only event log for `prompto_gain`. |
| `PROMPTO_AUDIT_LOG` | `/var/lib/prompto/audit.jsonl` | The [audit log](#audit-log). Always written; with `PROMPTO_AUTH` on, a log that can't be opened is a startup error. Also used by `prompto audit`. |
| `PROMPTO_AUDIT_GROUP` | unset | Group (name or gid) for an audit file prompto creates itself. |
| `PROMPTO_KILL_FILE` | `/etc/prompto/kill` | The global [kill switch](#kill-switches). Also used by `prompto kill`. |
| `PROMPTO_KILL_DIR` | `<PROMPTO_KILL_FILE>.d` | Agent, host and session kill switches. |
| `PROMPTO_TICKET_KEY_VAULT_PATH` | unset | KV v2 path, on `PROMPTO_PRIVATE_MOUNT`, of the [ticket](#tickets-and-approvals) signing keys (fields `current`, `previous`). Setting this or the next enables tickets (with `PROMPTO_AUTH` on). |
| `PROMPTO_TICKET_KEY_FILE` | unset | The same keys in an owner-only file (current, then previous). The fallback when vault can't be read. |
| `PROMPTO_APPROVERS` | `/etc/prompto/approvers.toml` | Human approvers and where their TOTP secrets are. Read at every approval. Also used by `prompto approver`. |
| `PROMPTO_APPROVAL_STATE` | `/var/lib/prompto/approval-state` | Used ticket nonces and TOTP steps, kept across restarts. |
| `PROMPTO_PRIVATE_MOUNT` | `prompto-private` | KV v2 mount the ticket key and approvers' TOTP secrets are read from. Only prompto's token may read it: see [Where the approval secrets live](#where-the-approval-secrets-live). |
| `PROMPTO_AGENT_READABLE_VAULT_PREFIXES` | `prompto/,infra/,nxp/` | What agents can read in vault: prefixes on `PROMPTO_VAULT_MOUNT`, or `<mount>:<prefix>`. An approval secret under one turns approvals off. |
| `PROMPTO_SERVICE_USER` | `prompto` | The account prompto runs as. A policy grant of a shell or file tool on a `prompto_host` whose `ssh_user` is this user is a lint error and turns approvals off. |
| `PROMPTO_GAIN_ENABLED` | `true` | Toggle gain tracking. |
| `RUST_LOG` | `prompto=info` | Log level. |

Env is read once at startup: changes need a restart. The inventory, `agents.toml` and `policy.toml` (the last two unless `PROMPTO_AUTH=off`) reload on `SIGHUP`, each independently; `agents.toml` and `policy.toml` are also re-read on the first request after they change. Kill switches are read on every call.

CLI:

- `--stdio` selects stdio transport instead of HTTP.
- `gain` runs the analytics report and exits.
- `agent add|list|revoke` manages agent tokens and exits.
- `policy check|lint` dry-runs a call against the policy, or lints it, and exits.
- `audit [filters]` queries the audit log and exits.
- `kill on|off|status`, `kill agent|host|session <name> [reason]`, `unkill agent|host|session <name>` set and lift [kill switches](#kill-switches) and exit.
- `approver add|list|revoke` manages [approvers](#tickets-and-approvals) and exits; `ticket keygen` prints a fresh ticket key.

## Registering with Claude Code

Without auth (`PROMPTO_AUTH=off`):

```bash
claude mcp add --transport http --scope user prompto http://YOUR-HOST:6337/mcp
```

With a role token, inline (the token then lives in `~/.claude.json`):

```bash
claude mcp add --transport http --scope user prompto http://YOUR-HOST:6337/mcp \
  --header "Authorization: Bearer pto_…"
```

Or keep the token in its own file and let Claude Code read it through a `headersHelper`: a command whose stdout is a JSON object of headers.

```bash
install -d -m 0700 ~/.config/prompto
( umask 077; cat > ~/.config/prompto/token )        # paste the token, then Ctrl-D
cat > ~/.config/prompto/headers.sh <<'SH'
#!/bin/sh
printf '{"Authorization": "Bearer %s"}\n' "$(cat "$HOME/.config/prompto/token")"
SH
chmod 0700 ~/.config/prompto/headers.sh
claude mcp add-json --scope user prompto \
  '{"type":"http","url":"http://YOUR-HOST:6337/mcp","headersHelper":"'"$HOME"'/.config/prompto/headers.sh"}'
```

Keep `token` at `0600`. Rotating then means replacing one file, and the token never appears in Claude Code's config or a shell history.

## Deployment

```bash
cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/prompto YOUR-HOST:/tmp/
scp -r deploy/{install.sh,prompto.service,env.example,prompto.toml.example,logrotate.d} YOUR-HOST:/tmp/
ssh YOUR-HOST 'sudo /tmp/install.sh /tmp/prompto'
ssh YOUR-HOST 'sudo systemctl enable --now prompto'
```

Keep the env file (`/etc/prompto/env`) `0640 root:prompto` once it holds a vault token.

Validate an inventory before installing it:

```bash
cargo run --example inv_check -- /path/to/prompto.toml
```

## Family

| Sibling | Port | Role |
|---|---|---|
| [palazzo](https://github.com/calibrae/palazzo) | 6335 | Memory palace — Qdrant + fastembed |
| [bucciarati](https://github.com/calibrae/bucciarati) | 6336 | mdBook wiki — read/write/publish |
| **prompto** | **6337** | **Power, virt, exec, files, fleet management** |
| [mcp-gain](https://github.com/calibrae/mcp-gain) | — | Shared token-savings tracker |

🦀
