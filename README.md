# prompto

MCP server for homelab power & lifecycle (Wake-on-LAN, libvirt) and typed SSH exec. Single Rust binary, single endpoint, sibling of [memqdrant](https://github.com/calibrae/memqdrant) and [bucciarati](https://github.com/calibrae/bucciarati).

> *"prompto"* — Italian for *ready / at your prompt*. Ready when called (wake), at your prompt (exec).

## Why

A homelab tends to grow three loosely-related control surfaces:

1. A WOL daemon on some always-on host that fires magic packets at sleeping ones.
2. An MQTT/scriptlet glue layer that runs `virsh` for VM lifecycle.
3. Hand-rolled SSH commands from agents, repeated all over the place.

prompto rolls them into one MCP. Single source of authority for power, virt, and exec — typed, capability-gated, behind one HTTP endpoint.

## Tools

| Tool | Purpose |
|---|---|
| `host_wake` | UDP magic packet to the host's MAC (broadcast :9). Capability: `wake`. |
| `host_sleep` | SSH + `sudo -n shutdown -h now`. Capability: `sudo_exec`. |
| `host_status` | TCP probe to the host's SSH port: `up` / `off` / `unreachable`. |
| `vm_list` | `virsh list --all` over SSH, parsed to JSON. Capability: `virt`. |
| `vm_state` | `virsh domstate`. Capability: `virt`. |
| `vm_start` | `virsh start`. Capability: `virt`. |
| `vm_stop` | Fallback chain: `dompmsuspend disk` → `shutdown` → `destroy`. Capability: `virt`. |
| `vm_ensure_up` | Wake host, start VM, wait until SSH-reachable. Capabilities: `wake` + `virt`. |
| `ssh_exec` | Run a command over SSH and return stdout/stderr/exit. Capability: `exec`. |
| `ssh_sudo_exec` | Same with `sudo -n`. Capability: `sudo_exec`. |
| `mcp_list` / `mcp_get` / `mcp_add` / `mcp_remove` | Wrap `claude mcp …` on a remote client. Capability: `claude_admin`. |
| `mcp_restart_claudecli` | Best-effort restart of a claudecli (Telegram-bridge) instance. Capability: `claude_admin`. |
| `prompto_gain` | Token-savings analytics — see below. |

Every call is **capability-gated** by the per-host allowlist in `/etc/prompto.toml`. A host without `wake` cannot be woken, period.

## Quickstart

```bash
cargo build --release
PROMPTO_INVENTORY=./prompto.toml ./target/release/prompto --stdio
```

For HTTP transport (default):

```bash
PROMPTO_INVENTORY=./prompto.toml ./target/release/prompto
# listens on 0.0.0.0:6337 — POST /mcp
```

## Inventory

`/etc/prompto.toml`:

```toml
[host.gpu-rig]
ip = "192.0.2.12"
mac = "aa:bb:cc:dd:ee:ff"
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
ssh_port = 22
capabilities = ["wake", "exec", "sudo_exec", "virt"]

[host.workstation]
ip = "192.0.2.13"
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
capabilities = ["exec", "sudo_exec"]   # always-on, no wake; no virt yet

[host.hypervisor]
ip = "192.0.2.7"
ssh_user = "admin"
ssh_key  = "/etc/prompto/keys/id_rsa"
capabilities = ["exec", "virt"]        # no wake, no sudo (needs password)
```

`SIGHUP` reloads the file without dropping the listener.

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
| `PROMPTO_ALLOWED_HOSTS` | localhost only | Comma-separated Host-header allowlist (DNS-rebinding protection). `*` to disable on a trusted LAN. |
| `PROMPTO_SSH_BIN` | `ssh` | Path to the system `ssh` binary. |
| `PROMPTO_DEFAULT_TIMEOUT_SECS` | `30` | Default per-command timeout. |
| `PROMPTO_STOP_VM_STEP_SECS` | `30` | Per-step timeout in `vm_stop` fallback chain. |
| `PROMPTO_USAGE_LOG` | `/var/lib/prompto/usage.jsonl` | Append-only event log for `prompto_gain`. |
| `PROMPTO_GAIN_ENABLED` | `true` | Toggle gain tracking. |
| `RUST_LOG` | `prompto=info` | Log level. |

CLI flags: `--stdio` selects stdio transport instead of HTTP. `gain` runs the analytics report and exits.

## Registering with Claude Code

```bash
claude mcp add --transport http --scope user prompto http://YOUR-HOST:6337/mcp
```

## Deployment

```bash
cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/prompto YOUR-HOST:/tmp/
scp deploy/{install.sh,prompto.service,env.example,prompto.toml.example} YOUR-HOST:/tmp/
ssh YOUR-HOST 'sudo /tmp/install.sh /tmp/prompto'
ssh YOUR-HOST 'sudo systemctl enable --now prompto'
```

## Family

| Sibling | Port | Role |
|---|---|---|
| [memqdrant](https://github.com/calibrae/memqdrant) | 6335 | Memory palace — Qdrant + fastembed |
| [bucciarati](https://github.com/calibrae/bucciarati) | 6336 | mdBook wiki — read/write/publish |
| **prompto** | **6337** | **Power, virt, exec** |
| [mcp-gain](https://github.com/calibrae/mcp-gain) | — | Shared token-savings tracker |

🦀
