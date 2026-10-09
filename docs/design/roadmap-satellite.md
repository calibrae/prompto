# prompto satellite — agents on machines you don't own

Status: **idea, not scheduled.** It comes after v0.12.1 (E6 tickets, E7 Claude Code plugin), whose approval model it reuses. Working name: *satellite* (binary) and *relay* (WAN server). The final name is to be chosen, Italian and non-JoJo (candidates: *ponte*, *staffetta*).

## Context

A project with coworkers who have machines you don't, say a client's build box or a platform you lack. Today the loop goes like this:

1. You build.
2. You share the build.
3. They share their screen and run it.
4. It fails.
5. They send you the log.
6. You paste the log back into the agent, and the loop starts again.

Every round trip goes through a human relaying text.

Screen and terminal sharing tools (TeamViewer, tmate, Upterm, sshx) put a *human* on a remote terminal through a relay. None of them gives an *agent* a typed, approval-gated, audited tool surface on someone else's machine, with that machine's owner in control.

**Goal:** a coworker runs one small binary and reads you a pairing code. Your agent can then work on their machine through prompto: run, read, write and ship files, within a scope they set. The coworker approves what the agent does, can watch it live, and can stop it at any moment. Both sides keep an audit trail with the same request IDs.

**Principles:**

| Topic | Decision |
|---|---|
| Who is in charge | The machine's owner. Every action is approved on *their* side, per call or for a time-boxed scope. Default is ask |
| Reachability | The satellite dials **out** to the relay (WSS on 443). There are no inbound ports and no NAT configuration. Peer-to-peer comes later, as an optimisation |
| Relay trust | None. Traffic is end-to-end encrypted between prompto and the satellite, so the relay forwards ciphertext and could be run by anyone |
| Privilege | The satellite runs as the coworker's user, in one workspace directory, with no root. It escalates only if the owner explicitly grants it for the session |
| Agent side | To prompto a satellite is just another host (`transport = "relay"`). Policy, audit, request IDs, kill switches and error classes all apply unchanged |
| Footprint | A single static Rust binary per platform (Linux, macOS, Windows). No install, no service. It exits when the session ends |

## Architecture

```
agent ──MCP──► prompto ──E2E channel──► relay (WAN, e.g. a small VPS) ◄──outbound WSS── satellite
               policy, audit,           rendezvous by session id,          on the coworker's machine:
               tickets                  forwards ciphertext only           approval prompt, live view,
                                                                           local audit, Ctrl-C = stop
```

**Pairing:**
1. prompto creates a session and gets a short code from the relay (e.g. `7-purple-otter`).
2. You read the code to the coworker.
3. The coworker runs `satellite join 7-purple-otter`.
4. Both ends run a PAKE (SPAKE2) over the relay to derive the session key. The relay sees only the session id, never anything that lets it read or forge traffic.
5. Both ends display a short fingerprint so the two people can compare it out loud.

---

## Epics and stories

### P0 — Spikes
- **P0.1 Transport.** Choose between WSS (tokio-tungstenite) and QUIC (quinn) for the satellite→relay leg. Criteria: works behind corporate proxies and captive Wi-Fi (WSS on 443 almost always does), multiplexing several concurrent calls plus a live output stream, and reconnects.
- **P0.2 Crypto stack.** SPAKE2 (`spake2` crate) for pairing, then a Noise or XChaCha20-Poly1305 channel keyed from the PAKE. Decide framing and nonce handling, and prove replay rejection.
- **P0.3 Cross-platform satellite.** Static builds for linux-musl x86_64 and aarch64, macOS universal, and Windows MSVC. Measure size. Check process spawning, PTY needs and path handling on Windows.
- **P0.4 Approval UX in a plain terminal.** A prompt that shows the command or diff, accepts approve, approve for N minutes or deny, keeps streaming output, and survives a terminal resize. Test it with a non-developer.

### P1 — Protocol
- **P1.1 Session model.** Session id, two roles (controller = prompto, satellite), lifetime (owner-set, default 2 h), idle timeout and explicit end.
- **P1.2 Messages.** JSON-RPC over encrypted frames:
  - `exec` (argv or shell, cwd, env allowlist, timeout, streamed stdout/stderr, exit);
  - `read`, `write` (with content hash), `list`, `stat`;
  - `push` and `pull` for files and trees, chunked and resumable;
  - `cancel`;
  - `approval_request` and `approval_response`;
  - `bye`.
  Each message carries the prompto `request_id`.
- **P1.3 Versioning and capabilities** negotiated at pairing. An unknown message is refused, never ignored.
- **P1.4 Replay and ordering:** sequence numbers per direction, and the channel is rejected on a gap or a repeat.

### P2 — Relay server
- **P2.1 Rendezvous.**
  - Pair two connections by session id.
  - Forward frames and buffer nothing beyond a small window.
  - Don't parse payloads.
  - Codes are single-use and expire in 10 minutes.
- **P2.2 Abuse limits:** connections per IP, sessions per IP, bandwidth per session, maximum session length, and a global cap. The relay should be cheap to run and boring to attack.
- **P2.3 Deployment:** one binary behind TLS on 443, a systemd unit, health endpoint and minimal metrics (sessions, bytes). No database.
- **P2.4 Relay logs** hold only session id, IPs, byte counts and durations, never content (it has none). Retention is short.

### P3 — Satellite binary
- **P3.1 `satellite join <code>`.** Pair, show the fingerprint and the requesting agent and session, then ask for the scope:
  - workspace directory (default: the current one);
  - allowed actions (exec, read, write, push);
  - duration;
  - whether network access by agent commands is OK (informational, can't be enforced).
- **P3.2 Workspace scoping.**
  - All paths resolve inside the workspace (canonicalized, symlinks checked). Paths outside are refused.
  - Commands run with the workspace as cwd.
  - This is best-effort containment, not a sandbox, and the docs say so.
  - Optional OS sandbox where cheap: `sandbox-exec` profile on macOS, Landlock on Linux, Job objects on Windows.
- **P3.3 Approvals.**
  - Every request is held until the owner answers.
  - "Approve for N minutes" is bounded to the same action type and workspace.
  - Writes show a diff, and pushes show a file list and sizes.
  - Deny accepts an optional reason, which is returned to the agent.
- **P3.4 Live view.** Streamed output of running commands is shown to the owner as it happens. A status line shows who is connected, the time left and the current action.
- **P3.5 Stop.**
  - Ctrl-C or `q` ends the session and kills the running process tree.
  - A closed terminal ends it too.
  - So does the session lifetime expiring.
  - There is no reconnect without a new code.
- **P3.6 Local audit.** A JSONL file in the workspace (or `~/.satellite/`) records every request, decision, exit code and request id, in a format the coworker can read and keep.
- **P3.7 No persistence.** No install, no autostart, no background service, no stored credentials. Running it again requires a new code.

### P4 — prompto integration
- **P4.1 Relay hosts.** An inventory host with `transport = "relay"`, created per session (ephemeral, named by the owner at pairing, e.g. `ext-ana-build`) and gone when the session ends.
- **P4.2 Tools.**
  - `satellite_invite` creates a session and returns the code to read out.
  - `satellite_status` reports the connection, granted scope and time left.
  - `satellite_end` closes the session.
  - Existing tools work on relay hosts where they make sense (`ssh_exec` becomes `exec`, `file_*`, `service_logs` no). Unsupported tools are refused with `refused_capability`.
- **P4.3 File transfer:** `push` and `pull` replace `rsync_sync` for relay hosts, sending a local build into the workspace and fetching logs and artifacts back. Chunked, hashed and resumable.
- **P4.4 Pipeline.** Calls go through the same `authorize()` steps: policy (new host group `external`), the audit record (with `transport: relay` and the satellite owner's approval decision) and kill switches (`prompto kill host ext-…` ends the session).
- **P4.5 Self-target guard.** It doesn't apply: a relay host is never the caller's machine by construction. The guard stays unconditional for SSH hosts.

### P5 — Approvals, from the E6/E7 design
- **P5.1 Approver.** The satellite owner is the approver for relay hosts. A prompto-side `approval = "human"` rule can add *your* approval on top (two-person rule for sensitive actions).
- **P5.2 Approval results** come back as E6 tickets bound to the exact arguments, and the audit records `approved_by = <satellite owner label>`.
- **P5.3 The agent-side plugin (E7)** shows "waiting for approval on ext-ana-build", with the denial reason when one comes back.

### P6 — Peer-to-peer (later)
- **P6.1** QUIC hole punching with the relay as signalling server. Fall back to relaying when it fails. Same E2E channel, so the relay's role shrinks but trust doesn't change.

### P7 — Threat model and hardening
- **P7.1 Threat model document**, covering:
  - a malicious or compromised relay: confidentiality and integrity hold through E2E encryption; it can deny service;
  - a compromised agent or prompto: the owner's approval and the scope are the limit;
  - a malicious satellite (for example, feeding the agent poisoned output): treat satellite output as untrusted data;
  - a stolen pairing code: single use, short-lived, fingerprint check;
  - social engineering of the owner: a clear prompt that names the agent, the session and the requesting person.
- **P7.2 Signed releases:**
  - macOS Developer ID plus notarization;
  - Windows code signing (Authenticode);
  - checksums and minisign signatures for every artifact;
  - a reproducible-build note.
- **P7.3 Fuzzing** of the frame parser and the message decoder.

### P8 — Docs and onboarding
- **P8.1 One page for the coworker:** what it is, the one command, what they'll see, how to stop, and where their local audit is. Written for a non-developer.
- **P8.2 Operator page:** relay deployment, the prompto config, and the policy for `external` hosts.

---

## Release map

| Release | Epics |
|---|---|
| (needs) | v0.12.1: E6 tickets and E7 plugin. Their approval model is reused here |
| satellite 0.1 | P0, P1, P2, P3 (exec/read/write, per-call approval), P4.1–P4.2, P8.1. Usable end to end with one coworker |
| satellite 0.2 | P3.3 time-boxed approvals and diffs, P4.3 push/pull, P4.4 full pipeline, P5 tickets, P7 |
| later | P6 peer-to-peer, P3.2 OS sandboxes |

## Open questions
1. Separate repo, or a workspace in prompto (`crates/satellite`, `crates/relay`)? The satellite must build for Windows; prompto doesn't today.
2. Should the satellite also be usable *without* prompto, by any MCP client, as a standalone tool? That would widen the audience but duplicate policy and audit.
3. Licensing and distribution: binaries handed to coworkers outside the homelab need signing (P7.2), and a stable download URL.
