---
name: prompto-tools
description: How to work with prompto, the MCP server that runs commands, file and service operations on homelab machines (tools named mcp__…prompto…__ssh_exec, file_read, service_control and so on). Use it before calling any prompto tool, when a prompto call is refused or fails (an error_class such as refused_policy, approval_required, killed or refused_self_target), or when the user asks about approvals, tickets or prompto's audit log.
---

# Working with prompto

prompto gives you typed tools on other machines. Every call is checked by prompto itself. It looks at your agent role (the bearer token), the host's capabilities and the policy, and it writes an audit record. This plugin adds the session ID, asks prompto in advance (`/v1/precheck`), attaches the tickets prompto issues, and shows the user an approval pane when a rule needs a person. The plugin never decides; prompto does.

## Choose the narrowest tool

Use a typed tool where one exists. Its arguments are checked, its result is structured, and the policy can grant it on its own.

| To… | Use | Not |
|---|---|---|
| read or write a file | `file_read`, `file_write` (`sudo: true` for root-owned files), `file_list`, `file_stat` | `ssh_exec "cat …"`, heredocs |
| start, stop, restart or check a unit | `service_control` | `ssh_sudo_exec "systemctl …"` |
| read a unit's journal | `service_logs` | `ssh_sudo_exec "journalctl …"` |
| see whether a host is up | `host_status`, `host_diagnose` | `ssh_exec true` |
| copy a tree between hosts | `rsync_sync` | scp through a shell |
| VMs | `vm_list`, `vm_state`, `vm_start`, `vm_stop`, `vm_ensure_up` | `virsh` in a shell |
| several commands in one go | `ssh_batch` | `a && b && c` in one `ssh_exec` |
| a script | `bash_exec` / `python_exec` … (the body goes over stdin, no quoting) | long `ssh_exec` one-liners |

Use `ssh_exec` only for what no typed tool does. Use `ssh_sudo_exec` only when root is really needed. It is a separate grant, and it is the one most likely to need a human approval.

`inventory_list` shows the hosts you have some grant on. Check it before guessing host names.

## Never call prompto against your own machine

prompto refuses every call aimed at the machine you are calling from (`refused_self_target`), including `host_status`. No policy or ticket can lift this. To act on your own machine, use your local shell. Don't look for another route, such as an alias, an extra IP or a second hop.

## Tickets and approvals

Some policy rules require proof that a call was checked or approved. The plugin handles this for you:

- `approval = "ticket"`: the plugin prechecks the call and attaches the single-use ticket prompto returns. You see nothing.
- `approval = "human"`: the plugin opens the **prompto approval pane**. It shows the host, the exact command (for `file_write`, a diff against the current file) and the rule that asked. The user approves it by typing their approver name and a TOTP code, or denies it with a reason. Your call waits until they decide. Then it either runs or is refused with their reason.

Rules for you:

- **Never ask the user for their TOTP code, and never put a code, a ticket or an approval in a tool argument or in your messages.** The code goes only into the pane. A code typed into the chat is exposed; tell the user that if it happens, and wait for the next one.
- A ticket covers **exactly** the arguments that were approved. Changing anything (one more space, an extra option) means a new approval. So decide the final command before calling, and don't retry a call with "small" changes to get around a refusal.
- If the user denies a call, stop and ask what they want. Don't rephrase the same action as another tool or command.
- "Approve N minutes" lets the user approve similar calls (same tool, same host, this session) for a while. Don't ask for it; it is their choice.
- If the plugin isn't active (safe mode, a session without it), a call that needs a ticket comes back `approval_required`. Tell the user. Don't try to obtain a ticket yourself.

## When a call fails: `error_class`

Errors read `[request_id=… error_class=<class>] …`. Mention the `request_id` when you report a failure: it finds the audit record.

| error_class | Meaning | What to do |
|---|---|---|
| `refused_policy` | No rule grants this agent this tool on this host (the message names what is missing). | Don't work around it with another tool. Tell the user which grant is missing; an operator edits `policy.toml`. |
| `approval_required` | The rule needs a ticket or a human approval, and the call had none. | With the plugin, this means the precheck was unavailable (the message says so): tell the user. Don't hand-craft tickets. |
| `refused_ticket` | The ticket was malformed, expired, already used, for other arguments, or the approval was refused. | Expired or used: call again, and the plugin asks again. Repeated refusals: tell the user. |
| `killed` | An operator (or the user, with `/prompto kill`) stopped calls on purpose. | **Stop.** Don't retry or route around it. Tell the user and quote the reason. |
| `refused_self_target` | The target is your own machine. | Use your local shell instead. |
| `refused_capability` | The host doesn't have that capability (`exec`, `sudo_exec`, `virt`…). | Use a tool the host supports, or tell the user. |
| `unknown_host` | No such host or alias in the inventory. | Check `inventory_list`; don't guess further names. |
| `invalid_args` | The arguments were rejected (a bad path, unit name or value). | Fix the arguments as the message says. |
| `ssh_connect` | The host couldn't be reached over SSH. | Check `host_status`; the host may be asleep (`host_wake`, `vm_ensure_up`) or down. |
| `ssh_auth` | SSH reached the host, but the key was refused. | Tell the user; it is an operator fix. |
| `timeout` | The command ran past its timeout. | Use a longer `timeout_secs` if it should take long; otherwise look at why it hangs. |
| `remote_nonzero` | The command ran and exited non-zero (a result, not an error: read `stdout`, `stderr` and `exit_code`). | Treat it like any failing command. |
| `interpreter_missing` | The `*_exec` tool's interpreter isn't installed there. | Use `bash_exec` or another tool. |
| `sudo_guard` | The vault sudo path refused a host that has a passwordless sudo rule (exit 97). | Tell the user; it is an inventory mismatch. |
| `vault` | prompto couldn't get the host's sudo password from vault. | Tell the user. Don't retry in a loop. |
| `upstream` | `claude_exec`'s gateway on the host failed. | Retry once at most, then report it. |
| `rsync_*`, `dest_ssh_*` | `rsync_sync` failed in rsync, or on the destination's SSH. | Read the message: it says which end and why. |
| `internal` | prompto itself failed, for example its audit log can't be written. Calls are refused until it is fixed. | Stop and tell the user. |

## The user's commands

- `/prompto whoami`: the agent role, its groups and this session, as prompto sees them.
- `/prompto audit [n]`: this session's last prompto calls, from prompto's audit log.
- `/prompto kill [reason]`: stops every call of this agent in this session, at once. Only an operator lifts it (`prompto unkill session <id>`).
- `/prompto kill global`: stops every prompto call by every agent. It needs an approver's TOTP code, typed in the pane.
- `/prompto approve`: reopens the approval pane.
