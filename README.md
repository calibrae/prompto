# prompto

MCP server for homelab power & lifecycle (Wake-on-LAN, libvirt), typed SSH exec, remote files, and Claude Code fleet management. Single Rust binary, single endpoint, sibling of [palazzo](https://github.com/calibrae/palazzo) and [bucciarati](https://github.com/calibrae/bucciarati).

> *"prompto"* — Italian for *ready / at your prompt*. Ready when called (wake), at your prompt (exec).

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
- `GET /log` returns it in the `X-Prompto-Request-Id` header.
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
# listens on 0.0.0.0:6337 — POST /mcp, GET /log
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
| `platform` | Target OS. Tools **adapt** where a BSD equivalent exists (`stat -f`, `ls -T`), and **refuse** legibly where the model differs: no systemd tools off Linux, no `ssh_batch` without bash (FreeBSD/OPNsense ship csh). `windows` is declared so the host can be addressed, not shelled into. |
| `chassis` / `hypervisor` | `vm` makes `host_wake` refuse and point at `vm_start <hypervisor> <name>` instead of broadcasting at a NIC that does not exist yet. |
| `aliases` | One machine, one entry, reachable by either name. Collisions with host names or other aliases are load errors. |
| `apytti_url` | Gateway URL; required with `claude_exec`. |
| `sudo_password_vault_path` / `sudo_password_vault_field` | Vault-held sudo password (field defaults to `password`). Requires `sudo_exec`. |
| `extra_ips` | Other addresses the machine may call prompto from (second NIC, Wi-Fi, VPN, IPv6). Used only by the self-targeting guard, never to reach the host. Literal IPs, canonicalized at load (`::ffff:a.b.c.d` → `a.b.c.d`). Load errors: unspecified or multicast addresses, repeats, and an address claimed by two hosts. |
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
- Agent names use `[a-z0-9_-]`; `anonymous` and `local` are reserved. Names and groups are what policy (E3) and the audit log (E4) will key on.
- Until those land, the agent and session appear in the journald line of every failed call: `tool call failed request_id=… agent="builder" session_id="…"`.
- Tool results don't echo the agent. The caller knows who it is, and an unchanged result shape keeps `off` byte-identical.

**Session context.** A client may send `X-Prompto-Session: <id>` (the Claude session ID). It is context for the logs, never proof of identity: any holder of a role token can claim any session. Values over 128 characters or outside `A-Za-z0-9._:-` are dropped with a warning; the call itself proceeds.

### Managing tokens

```bash
sudo prompto agent add builder --groups build,ops   # prints the token ONCE on stdout
sudo prompto agent list                             # name, status, groups, created, sha256 prefix
sudo prompto agent revoke builder                   # sets disabled = true
sudo systemctl reload prompto                       # SIGHUP: a running server re-reads agents.toml
```

- **`add`** writes only the hash, atomically, keeping the file's mode and owner.
  - A new file is created `0640` with the directory's group. With the standard install (`/etc/prompto` is `root:prompto`), that lets the service read it.
  - Run it as the user that owns the file.
- **`revoke`** keeps the entry with `disabled = true` rather than deleting it.
  - The name stays taken.
  - A stale token is logged as *revoked*, naming the role, instead of just *invalid*.
  - To issue a new token for a role, revoke it and add a new name, or delete the entry by hand and `add` again.
- **Nothing takes effect until SIGHUP.** The CLI says so after every change.
  - A reload that fails (bad TOML, malformed hash, duplicate token) keeps the previous agents live and logs why.
  - A missing file means no agents.
- **After the reload, a revoked token** is refused on the very next request with `PROMPTO_AUTH=required`. With `optional` it falls back to `anonymous`.

**Rollout:**

1. Set `PROMPTO_AUTH=optional`.
2. Mint a token per role.
3. Register clients with their token.
4. Watch the logs for `agent="anonymous"`.
5. Switch to `required`. This needs a restart, since env is read at startup.

## `GET /log`

```
GET /log?host=<name>&unit=<systemd unit>&lines=<1..1000, default 50>
```

Plain-text journal tail for scripts and dashboards. It has the same gate as `service_logs` (`sudo_exec`, self-targeting guard, unit-name validation) and the same authentication as `/mcp`.

- With `PROMPTO_AUTH` `off` or `optional` it is **unauthenticated**: anyone who can reach the listener can read journals on any `sudo_exec` host. Keep the listener behind a trusted proxy or firewall.
- With `required`, send `Authorization: Bearer <token>`.

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
| `PROMPTO_AGENTS` | `/etc/prompto/agents.toml` | Agent token hashes. Missing file = no agents. Also used by `prompto agent`. |
| `PROMPTO_USAGE_LOG` | `/var/lib/prompto/usage.jsonl` | Append-only event log for `prompto_gain`. |
| `PROMPTO_GAIN_ENABLED` | `true` | Toggle gain tracking. |
| `RUST_LOG` | `prompto=info` | Log level. |

Env is read once at startup: changes need a restart. Only the inventory and `agents.toml` reload on `SIGHUP`, each independently.

CLI:

- `--stdio` selects stdio transport instead of HTTP.
- `gain` runs the analytics report and exits.
- `agent add|list|revoke` manages agent tokens and exits.

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
scp deploy/{install.sh,prompto.service,env.example,prompto.toml.example} YOUR-HOST:/tmp/
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
