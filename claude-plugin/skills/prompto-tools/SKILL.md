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
| read or write a file | `file_read`, `file_write` (`sudo: true` for root-owned files), `file_list` (`stat_only: true` for one path's own metadata) | `ssh_exec "cat …"`, `stat`, heredocs |
| start, stop, restart or check a unit | `service_control` | `ssh_sudo_exec "systemctl …"` |
| read a unit's journal | `service_logs` | `ssh_sudo_exec "journalctl …"` |
| see whether a host is up | `host_status`; then `ssh_exec` for `uptime`, `df -h`, `systemctl --failed` | `ssh_exec true` |
| copy a tree between hosts | `rsync_sync` | scp through a shell |
| VMs | `vm_list` (`vm: "<name>"` for one domain's state), `vm_start`, `vm_stop`, `vm_ensure_up` | `virsh` in a shell |
| several commands in one go | `ssh_batch` | `a && b && c` in one `ssh_exec` |
| a script | `bash_exec` (the body goes over stdin, no quoting); another language: `ssh_exec` with a heredoc, `python3 - <<'EOF'` | long `ssh_exec` one-liners |

Use `ssh_exec` only for what no typed tool does. A result that ends with an `[advisor]` line names the typed tool for what you just did: use it next time. Use `ssh_sudo_exec` only when root is really needed. It is a separate grant, and it is the one most likely to need a human approval.

`inventory_list` shows the hosts you have some grant on. Check it before guessing host names. The inventory is operator-managed: if a host is missing or lacks a capability, tell the user.

## What the tools do that their one-line descriptions don't say

- **`ssh_exec` / `ssh_sudo_exec`** run the command in the host's login shell. Known noisy output (cargo, git, journalctl, find, pkg, k8s, …) is compacted by a filter, named in the result's `filter`, with `original_bytes`; compound commands (`;`, `&&`, `||`, `&`, newlines) are never filtered. A command that exits non-zero is a result (`exit_code`, `error_class: remote_nonzero`), not an error.
- **Sudo:** `ssh_sudo_exec` runs the **whole** command as root, every part of `a; b`, pipes and redirects included. A command of plain words goes through `sudo -n -- <cmd>` (so a narrow sudoers rule can match it); anything else through a root `sh` reading the command on stdin. On a host whose sudo needs a password, prompto fetches it from its vault: the password never reaches you. `file_write` with `sudo: true`, `service_control`, `service_logs` and `host_sleep` run as root too, and all need the host's `sudo_exec` capability and a `sudo = true` grant. `file_read` and `file_list` read as the ssh user only: for a root-only file, `ssh_sudo_exec "cat <path>"`.
- **`ssh_batch`** runs the commands one after the other in one SSH session (`bash -c` each, `sh -c` on FreeBSD), and stops at the first failure unless `fail_fast: false` (skipped commands get `exit_code: null`). Its output is not filtered, so keep the commands tight. Use it for three or more commands on one host; the advisor says so after the fourth `ssh_exec`.
- **`rsync_sync`** runs rsync **on `source_host`**, which logs into `dest_host` as dest's inventory `ssh_user` with its own SSH setup: prompto's keys are not there. If the two hosts don't already trust each other, it fails with `dest_ssh_auth`; `dest_key` names a key file **on the source host**, and is usually best left out. A trailing `/` on `source_path` copies the directory's contents, without it the directory itself. The result is rsync's `--stats` block. Use it rather than a series of `file_write` calls.
- **`file_read`** returns at most `max_bytes` (64 KB by default, 1 MB at most); `truncated: true` means there is more. **`file_list`** follows a symlink to a directory; entries carry `mode`, `size`, `owner`, `group`, `mtime`, `is_dir`, `is_link` and, when set, `link_target`, ACLs and xattrs; a line it can't parse comes back in `unparsed`. `stat_only: true` returns `{ stat: { path, mode, size, owner, group, mtime, kind }, raw }` for the path itself. Paths take no whitespace or shell metacharacters.
- **`file_write`** sends `content` over stdin, so nothing needs quoting; `mode` (octal, `"0644"`) is applied after the write.
- **`service_control`** `status` drops the journal tail; read it with `service_logs` (`lines`, default 50). Both need systemd: on macOS or FreeBSD hosts use `ssh_exec` with `launchctl` / `service`.
- **`vm_list`** with `vm` returns that domain's row (`[{name, state}]`), or an error if there is no such domain. **`vm_ensure_up`** wakes the hypervisor if it is down, waits for its SSH, then starts the VM if it isn't running: one call before VM work. **`vm_stop`** tries a suspend to disk, then a clean shutdown, then destroy, each step with `step_timeout_secs`.
- **`host_sleep`** powers the host off; `host_wake` brings it back where the host has `wake`.
- **A tool that no longer exists** (`host_diagnose`, `file_stat`, `vm_state` since v0.12.3; the interpreter runners and `mcp_*` since v0.12.2) is refused with what replaces it.

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
| `interpreter_missing` | `bash_exec`: bash isn't installed there (FreeBSD, OPNsense). | Use `ssh_exec`, which runs the host's own shell. |
| `sudo_guard` | The vault sudo path refused a host that has a passwordless sudo rule (exit 97). | Tell the user; it is an inventory mismatch. |
| `vault` | prompto couldn't get the host's sudo password from vault. | Tell the user. Don't retry in a loop. |
| `rsync_*`, `dest_ssh_*` | `rsync_sync` failed in rsync, or on the destination's SSH (`dest_ssh_auth`: the source host can't log into the destination). | Read the message: it says which end and why. For `dest_ssh_auth`, tell the user the two hosts don't trust each other. |
| `internal` | prompto itself failed, for example its audit log can't be written. Calls are refused until it is fixed. | Stop and tell the user. |

## The user's commands

- `/prompto whoami`: the agent role, its groups and this session, as prompto sees them.
- `/prompto audit [n]`: this session's last prompto calls, from prompto's audit log.
- `/prompto kill [reason]`: stops every call of this agent in this session, at once. Only an operator lifts it (`prompto unkill session <id>`).
- `/prompto kill global`: stops every prompto call by every agent. It needs an approver's TOTP code, typed in the pane.
- `/prompto approve`: reopens the approval pane.
