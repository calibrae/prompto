// The prompto plugin: context and approvals for prompto's tool calls.
//
// prompto enforces; this module only helps. For each call to a prompto
// tool it asks /v1/precheck about exactly the arguments it will send,
// attaches the ticket prompto mints and, where a rule wants a human,
// opens a pane where a person types an approver name and a TOTP code.
// With `transport: mod` (the default) it also sends the call itself, so
// that X-Prompto-Session rides on it: Claude Code's own MCP connection
// takes its headers once, from a helper run before any session exists.
//
// The pane shows the approver everything the ticket will cover: every
// argument (the command first), file_write's content as a diff or whole,
// and a value too long to draw as its head, its size and its SHA-256.
// Everything drawn goes through `clean` first: arguments, reasons and
// audit lines come from the model or the network, and must not drive the
// terminal (escape sequences, bidi overrides).
//
// The TOTP code is held in one variable (`codes`) from the keystroke to
// the /v1/approve request, then deleted: never in $.state, $.store, a log
// line, a toast, a tool argument or the transcript. No request body is
// ever logged.

import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallResult } from 'claude-code'

import type { PromptoPending } from '../types'
import { unifiedDiff } from './diff'
import {
  CODE_IN_FIELD,
  HELP,
  SHOW_MAX,
  argView,
  argsOf,
  auditLine,
  clean,
  commandOf,
  configFrom,
  cutNote,
  errorText,
  hostOf,
  looksLikeCode,
  refusal,
  rpcMessage,
  scopeKey,
  sha256,
  textOf,
  toolPattern,
  utf8,
} from './util'
import type { Config, McpBlock, Precheck } from './util'

type $ = EngineInterface

const PANE = 'prompto-approval'
/** How long a call waits for a person before it is refused. */
const WAIT_MS = 10 * 60 * 1000
const VERSION = '0.1.0'
const USER_AGENT = `prompto-claude-plugin/${VERSION}`
/** Where bin/prompto-headers reads the token: the only place it is looked for. */
const TOKEN_FILE = '~/.config/prompto/token'

const pending = atom({ plugin: 'prompto', key: 'pending' } as const, [] as PromptoPending[], { shape: 'pending-2' })

type Settings = {
  options: Readonly<Record<string, unknown>>
  transport: 'mod' | 'engine'
  scopeMinutes: number
}
let S: Settings = { options: {}, transport: 'mod', scopeMinutes: 10 }

type Decision = { kind: 'approved'; ticket?: string } | { kind: 'denied'; reason: string }

/** A call waiting in the pane, by tool_use_id: what /v1/approve needs. */
type Waiter = {
  tool: string
  args: Record<string, unknown>
  session: string | undefined
  root: boolean
  decision?: Decision
}

const waiters = new Map<string, Waiter>()
/** The TOTP code being typed, per pending request. Nothing else holds it. */
const codes = new Map<string, string>()
const approverDrafts = new Map<string, string>()
const reasons = new Map<string, string>()
/** "Approve for N minutes" tickets: session|tool|host|dest -> ticket. */
const scopes = new Map<string, { ticket: string; expiresAt: number }>()
let interactive = true
let killCount = 0

// The Authorization header, read through bin/prompto-headers (which holds
// the 0600 check) once, and again after a 401. Kept in memory only.
let auth: string | undefined
// Set only for a prompto in legacy MCP session mode.
let mcpSession: string | undefined
let rpcId = 0

class Unreachable extends Error {}

type Reply = { status: number; json: unknown; text: string; headers: Record<string, string> }

function cfgOf($: $): Config {
  return configFrom(S.options, $.plugin.root)
}

/** The session prompto is told: none on Claude Code's own connection. */
async function sessionOf($: $): Promise<string | undefined> {
  return S.transport === 'mod' ? $.session.id() : undefined
}

async function authorization($: $, cfg: Config, fresh: boolean): Promise<string> {
  if (auth !== undefined && !fresh) return auth
  let run
  try {
    run = await $.process.run(['sh', cfg.helper], { timeoutMs: 10_000 })
  } catch (err) {
    throw new Unreachable(`cannot run prompto-headers: ${String(err)}`)
  }
  if (run.exitCode !== 0) throw new Unreachable(run.stderr.trim() || `prompto-headers exited ${run.exitCode}`)
  let header: unknown
  try {
    header = (JSON.parse(run.stdout) as Record<string, unknown>).Authorization
  } catch {
    header = undefined
  }
  if (typeof header !== 'string') throw new Unreachable('prompto-headers printed no Authorization header')
  auth = header
  return header
}

/** One request to prompto with the token and the session; a 401 re-reads the token once. */
async function request(
  $: $,
  cfg: Config,
  session: string | undefined,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown,
  extra?: Record<string, string>,
): Promise<Reply> {
  for (const fresh of [false, true]) {
    const headers: Record<string, string> = {
      Authorization: await authorization($, cfg, fresh),
      'User-Agent': USER_AGENT,
      ...extra,
    }
    if (session !== undefined) headers['X-Prompto-Session'] = session
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    let res
    try {
      res = await $.http.fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    } catch (err) {
      throw new Unreachable(`prompto at ${cfg.base} is unreachable: ${String(err)}`)
    }
    if (res.status === 401 && !fresh) continue
    let json: unknown
    try {
      json = JSON.parse(res.text)
    } catch {
      json = undefined
    }
    return { status: res.status, json, text: res.text, headers: res.headers }
  }
  throw new Unreachable('unreachable')
}

/**
 * `POST /v1/precheck` for exactly these arguments. No `answer` when there
 * is no usable one (unreachable, an older prompto, an error status).
 */
async function precheck(
  $: $,
  cfg: Config,
  session: string | undefined,
  tool: string,
  args: Record<string, unknown>,
): Promise<{ answer?: Precheck; why?: string }> {
  let r: Reply
  try {
    r = await request($, cfg, session, 'POST', `${cfg.base}/v1/precheck`, { tool, arguments: args })
  } catch (err) {
    return { why: (err as Error).message }
  }
  const j = r.json as Precheck | undefined
  if (r.status === 200 && j && ['allow', 'deny', 'ask'].includes(j.decision)) return { answer: j }
  return { why: `POST /v1/precheck answered HTTP ${r.status}${errorText(r.json)}` }
}

type CallOutcome = { ok: true; content: McpBlock[] } | { ok: false; message: string }

async function rpc($: $, cfg: Config, session: string | undefined, method: string, params: unknown): Promise<Reply> {
  const extra: Record<string, string> = { Accept: 'application/json, text/event-stream' }
  if (mcpSession) extra['Mcp-Session-Id'] = mcpSession
  rpcId += 1
  return request($, cfg, session, 'POST', cfg.mcpUrl, { jsonrpc: '2.0', id: rpcId, method, params }, extra)
}

async function handshake($: $, cfg: Config, session: string | undefined): Promise<void> {
  mcpSession = undefined
  const r = await rpc($, cfg, session, 'initialize', {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 'prompto-claude-plugin', version: VERSION },
  })
  mcpSession = r.headers['mcp-session-id']
  if (mcpSession) {
    const extra = { Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': mcpSession }
    await request($, cfg, session, 'POST', cfg.mcpUrl, { jsonrpc: '2.0', method: 'notifications/initialized' }, extra)
  }
}

/** `tools/call` with exactly `args`. Rejects with Unreachable on no answer. */
async function callTool(
  $: $,
  cfg: Config,
  session: string | undefined,
  tool: string,
  args: Record<string, unknown>,
): Promise<CallOutcome> {
  const params = { name: tool, arguments: args }
  let r = await rpc($, cfg, session, 'tools/call', params)
  let m = rpcMessage(r.text)
  if (!m && r.status >= 400 && r.status < 500 && /session/i.test(r.text)) {
    // A prompto that wants MCP sessions: handshake once, then retry.
    await handshake($, cfg, session)
    r = await rpc($, cfg, session, 'tools/call', params)
    m = rpcMessage(r.text)
  }
  if (!m) return { ok: false, message: `prompto answered HTTP ${r.status}: ${r.text.slice(0, 500)}` }
  if (m.error) {
    const e = m.error as Record<string, unknown>
    return { ok: false, message: String(e.message ?? JSON.stringify(e)) }
  }
  const res = (m.result ?? {}) as { content?: McpBlock[]; isError?: boolean }
  const content = Array.isArray(res.content) ? res.content : []
  return res.isError ? { ok: false, message: textOf(content) } : { ok: true, content }
}

/** Send the call, the plugin's own way, with exactly `args` plus the ticket. */
async function sendMod(
  $: $,
  tool: string,
  args: Record<string, unknown>,
  session: string | undefined,
  ticket: string | undefined,
): Promise<ToolCallResult> {
  let out: CallOutcome
  try {
    out = await callTool($, cfgOf($), session, tool, ticket === undefined ? args : { ...args, ticket })
  } catch (err) {
    return { deny: `prompto plugin: ${(err as Error).message}` }
  }
  return out.ok ? ({ result: out.content } as ToolCallResult) : { deny: out.message }
}

/**
 * Claude Code's own permission verdict. A deny refuses. An ask is put to
 * the person when `askPerson` (the plugin sends the call itself, and no
 * approval pane will ask); else it counts as answered: by the pane, or by
 * Claude Code itself when the call reaches it (`engine`).
 */
async function permitted(
  $: $,
  mcpTool: string,
  tool: string,
  args: Record<string, unknown>,
  askPerson = true,
): Promise<true | { deny: string }> {
  const v = await $.tool.check({ tool: mcpTool, input: args })
  if (v.decision === 'allow') return true
  if (v.decision === 'deny') return { deny: v.reason ?? "denied by Claude Code's permission settings" }
  if (!askPerson) return true
  if (!interactive) return { deny: `Claude Code's permission settings ask before ${mcpTool} runs, and nobody is here to answer` }
  try {
    const pick = await $.ui.ask(`Allow prompto ${tool} on ${clean(hostOf(tool, args) ?? '-')}?\n${commandOf(tool, args).slice(0, 300)}`, {
      options: ['Allow', 'Deny'],
      header: 'prompto',
    })
    return pick === 'Allow' ? true : { deny: 'the user denied this call' }
  } catch {
    return { deny: 'the user dismissed the permission question' }
  }
}

async function patch($: $, id: string, change: (p: PromptoPending) => Partial<PromptoPending>): Promise<void> {
  await update($, pending, list => list.map(p => (p.id === id ? { ...p, ...change(p) } : p)))
}

/** Wait a moment. A `$` call in flight doesn't count against the hook's budget; a promise of its own would. */
async function pause($: $): Promise<void> {
  try {
    await $.process.run(['sleep', '0.25'], { timeoutMs: 5000 })
  } catch {
    await $.clock.sleep(250)
  }
}

function blank(id: string, kind: PromptoPending['kind'], approver: string): PromptoPending {
  return {
    id,
    kind,
    tool: '',
    host: null,
    main: null,
    fields: [],
    contentSum: null,
    path: null,
    rule: null,
    reason: '',
    root: false,
    diff: null,
    diffNote: null,
    audit: [],
    auditNote: null,
    approver,
    rootScope: false,
    message: null,
    isBusy: false,
    generation: 0,
    stale: false,
  }
}

/** Put the call in the pane and wait for the person's decision. */
async function waitForHuman(
  $: $,
  id: string,
  signal: AbortSignal,
  mcpTool: string,
  tool: string,
  args: Record<string, unknown>,
  session: string | undefined,
  a: Precheck,
): Promise<Decision> {
  const w: Waiter = { tool, args, session, root: a.root === true }
  waiters.set(id, w)
  const { main, fields } = argView(args)
  const content = tool === 'file_write' && typeof args.content === 'string' ? utf8(args.content) : null
  const item: PromptoPending = {
    ...blank(id, 'call', String((await $.store.get('approver')) ?? '')),
    tool,
    host: hostOf(tool, args),
    main,
    fields,
    contentSum: content ? `${content.length} bytes, sha256 ${sha256(content)}` : null,
    path: typeof args.path === 'string' ? args.path : null,
    rule: a.rule ?? null,
    reason: a.reason ?? '',
    root: a.root === true,
    diffNote: tool === 'file_write' ? 'loading the current file…' : null,
    auditNote: 'loading…',
  }
  try {
    await update($, pending, list => [...list.filter(p => p.id !== id), item])
    const opened = await $.ui.open({ id: PANE, title: `prompto: approve ${tool}`, focus: true, closeOnEscape: true })
    $.ui.status(`prompto: ${tool} on ${item.host ?? '-'} waits for an approval${opened.isPlaced ? '' : ' (run /prompto approve)'}`)
    await enrich($, id, mcpTool, tool, args, session)
    const deadline = (await $.clock.now()) + WAIT_MS
    while (!w.decision) {
      if (signal.aborted) w.decision = { kind: 'denied', reason: 'the turn was interrupted' }
      else if ((await $.clock.now()) > deadline) w.decision = { kind: 'denied', reason: 'no decision within 10 minutes' }
      else await pause($)
    }
    return w.decision
  } finally {
    waiters.delete(id)
    codes.delete(id)
    approverDrafts.delete(id)
    reasons.delete(id)
    const left = await update($, pending, list => list.filter(p => p.id !== id))
    if (left.length === 0) {
      $.ui.status(undefined)
      await $.ui.close({ id: PANE }).catch(() => undefined)
    }
  }
}

/**
 * The diff (file_write) and the recent audit lines, both through prompto
 * and its policy. The current file is read only where Claude Code's own
 * settings allow file_read outright: the pane asks nobody for it.
 */
async function enrich($: $, id: string, mcpTool: string, tool: string, args: Record<string, unknown>, session: string | undefined) {
  const cfg = cfgOf($)
  const host = typeof args.host === 'string' ? args.host : undefined
  if (tool === 'file_write' && host && typeof args.path === 'string') {
    const path = args.path
    const after = typeof args.content === 'string' ? args.content : ''
    const readArgs = { host, path, max_bytes: 1048576 }
    let diff: string | null = null
    let note: string | null = null
    const readTool = mcpTool.replace(/__file_write$/, '__file_read')
    let verdict: 'allow' | 'deny' | 'ask' | 'absent'
    try {
      verdict = (await $.tool.check({ tool: readTool, input: readArgs })).decision
    } catch {
      // A settings deny rule naming an MCP tool takes it out of the
      // session, and the check throws: no read either way.
      verdict = 'absent'
    }
    const pc = verdict === 'allow' ? await precheck($, cfg, session, 'file_read', readArgs) : { answer: undefined, why: undefined }
    if (verdict !== 'allow') {
      const why =
        verdict === 'absent'
          ? 'file_read is not in this session (a Claude Code deny rule removes it)'
          : `your Claude Code settings ${verdict === 'deny' ? 'deny' : 'ask before'} file_read`
      note = `diff unavailable: ${why}; the full new content is shown instead`
    } else if (!pc.answer) note = `cannot check read access: ${pc.why}`
    else if (pc.answer.decision === 'deny') note = `no read grant: ${pc.answer.reason ?? pc.answer.error_class}`
    else if (pc.answer.decision === 'ask') note = 'no diff: reading the file needs a human approval of its own'
    else {
      try {
        const got = await callTool($, cfg, session, 'file_read', pc.answer.ticket ? { ...readArgs, ticket: pc.answer.ticket } : readArgs)
        if (got.ok) {
          const body = JSON.parse(textOf(got.content)) as { content?: string; truncated?: boolean }
          diff = unifiedDiff(body.content ?? '', after, path)
          if (diff === '') note = 'no change: the file already has this content'
          if (body.truncated) note = 'the current file is over 1 MiB: diffed against its first 1 MiB'
        } else if (/no such file|not found/i.test(got.message)) {
          diff = unifiedDiff('', after, path)
          note = 'new file'
        } else note = `file_read failed: ${got.message.slice(0, 300)}`
      } catch (err) {
        note = `file_read failed: ${(err as Error).message}`
      }
    }
    if (diff && diff.length > SHOW_MAX) {
      // Too long to draw whole; a diff cut mid-hunk doesn't parse.
      note = `the diff is too long to show (${diff.length} chars); the new content is shown instead`
      diff = null
    }
    await patch($, id, () => ({ diff: diff || null, diffNote: note }))
  }
  let audit: string[] = []
  let auditNote: string | null = null
  if (host) {
    try {
      const r = await request($, cfg, session, 'GET', `${cfg.base}/v1/audit?host=${encodeURIComponent(host)}&limit=5`)
      if (r.status === 200) {
        audit = (((r.json as { records?: unknown[] })?.records ?? []) as Record<string, unknown>[]).map(auditLine)
        if (audit.length === 0) auditNote = 'no earlier calls by this agent on this host'
      } else if (r.status === 404) auditNote = 'this prompto has no /v1/audit'
      else auditNote = `not shown (HTTP ${r.status}${errorText(r.json)})`
    } catch (err) {
      auditNote = `not shown: ${(err as Error).message}`
    }
  }
  await patch($, id, () => ({ audit, auditNote }))
}

// ---------------------------------------------------------------------------
// The pane's actions. The code is taken out of `codes` before anything else.
// ---------------------------------------------------------------------------

async function approvePressed($: $, id: string, minutes: number | undefined): Promise<void> {
  const code = (codes.get(id) ?? '').trim()
  codes.delete(id)
  const p = (await read($, pending)).find(x => x.id === id)
  if (!p || p.isBusy) return
  const approver = (approverDrafts.get(id) ?? p.approver).trim()
  if (!/^[0-9]{6}$/.test(code)) return patch($, id, q => ({ message: 'Type the 6-digit TOTP code first.', generation: q.generation + 1 }))
  if (!approver) return patch($, id, q => ({ message: 'Type the approver name.', generation: q.generation + 1 }))
  if (looksLikeCode(approver)) {
    // A code typed into the name field: never send it, store it or draw it.
    approverDrafts.delete(id)
    return patch($, id, q => ({ approver: '', message: CODE_IN_FIELD, generation: q.generation + 1 }))
  }
  await patch($, id, () => ({ isBusy: true, message: null, approver }))
  if (p.kind === 'kill-global') return killGlobal($, id, approver, code)
  const w = waiters.get(id)
  if (!w) return markStale($, id)
  let r: Reply
  try {
    r = await request($, cfgOf($), w.session, 'POST', `${cfgOf($).base}/v1/approve`, {
      tool: w.tool,
      arguments: w.args,
      approver,
      totp_code: code,
      ...(minutes ? { scope_minutes: minutes, allow_root_scope: w.root ? true : undefined } : {}),
    })
  } catch (err) {
    return patch($, id, q => ({ isBusy: false, message: (err as Error).message, generation: q.generation + 1 }))
  }
  const j = (r.json ?? {}) as { ticket?: unknown; expires_at?: unknown; reason?: unknown; error?: unknown }
  if (r.status === 200 && typeof j.ticket === 'string') {
    // Remembered once it proved right, so a typo never becomes the default.
    await $.store.set('approver', approver)
    if (minutes) {
      const expiresAt = typeof j.expires_at === 'number' ? j.expires_at : (await $.clock.now()) / 1000 + minutes * 60
      scopes.set(scopeKey(w.session, w.tool, w.args), { ticket: j.ticket, expiresAt })
    }
    w.decision = { kind: 'approved', ticket: j.ticket }
    return patch($, id, () => ({ message: `approved by ${approver}` }))
  }
  if (r.status === 409) {
    // No approval is needed any more (the policy changed): send it as is.
    w.decision = { kind: 'approved' }
    return
  }
  const what = r.status === 429 ? 'locked out' : r.status === 403 ? 'refused' : `HTTP ${r.status}`
  const why = String(j.reason ?? j.error ?? r.text.slice(0, 300))
  return patch($, id, q => ({ isBusy: false, message: `${what}: ${why}`, generation: q.generation + 1 }))
}

/** The call behind a pane item is gone (a reload): say so, never wait on it. */
async function markStale($: $, id: string): Promise<void> {
  await patch($, id, q => ({
    isBusy: false,
    stale: true,
    message: 'stale: the call was lost when the plugin reloaded. Ask the agent to retry it; Deny dismisses this.',
    generation: q.generation + 1,
  }))
}

async function denyPressed($: $, id: string): Promise<void> {
  codes.delete(id)
  const reason = (reasons.get(id) ?? '').trim() || 'no reason given'
  if (looksLikeCode(reason)) {
    // The reason goes to the model: a code typed there must not.
    reasons.delete(id)
    return patch($, id, q => ({ message: CODE_IN_FIELD, generation: q.generation + 1 }))
  }
  const w = waiters.get(id)
  if (w) w.decision = { kind: 'denied', reason }
  else await dropPending($, id)
}

async function dropPending($: $, id: string): Promise<void> {
  codes.delete(id)
  approverDrafts.delete(id)
  reasons.delete(id)
  const left = await update($, pending, list => list.filter(p => p.id !== id))
  if (left.length === 0) await $.ui.close({ id: PANE }).catch(() => undefined)
}

async function killGlobal($: $, id: string, approver: string, code: string): Promise<void> {
  const reason = (reasons.get(id) ?? '').trim() || 'from the prompto plugin'
  if (looksLikeCode(reason)) {
    reasons.delete(id)
    return patch($, id, q => ({ isBusy: false, message: CODE_IN_FIELD, generation: q.generation + 1 }))
  }
  let r: Reply
  try {
    r = await request($, cfgOf($), await sessionOf($), 'POST', `${cfgOf($).base}/v1/kill`, {
      scope: 'global',
      approver,
      totp_code: code,
      reason,
    })
  } catch (err) {
    return patch($, id, q => ({ isBusy: false, message: (err as Error).message, generation: q.generation + 1 }))
  }
  if (r.status !== 200) {
    return patch($, id, q => ({ isBusy: false, message: `HTTP ${r.status}${errorText(r.json)}`, generation: q.generation + 1 }))
  }
  await $.store.set('approver', approver)
  await dropPending($, id)
  $.ui.toast('prompto: GLOBAL KILL ON. Every call is refused until an operator runs `prompto kill off`.', { timeoutMs: 10_000 })
}

/** `/prompto …`. */
async function command($: $, args: string): Promise<{ text: string }> {
  const [sub = 'help', ...rest] = args.trim().split(/\s+/).filter(Boolean)
  const cfg = cfgOf($)
  const session = await sessionOf($)
  const get = (path: string) => request($, cfg, session, 'GET', `${cfg.base}/v1/${path}`)
  switch (sub) {
    case 'whoami': {
      const r = await get('whoami')
      if (r.status !== 200) return { text: `prompto at ${cfg.base}: HTTP ${r.status}${errorText(r.json)}` }
      const j = r.json as { agent?: string | null; groups?: string[]; session?: string | null; auth?: string }
      const groups = j.groups?.length ? ` (groups: ${j.groups.join(', ')})` : ''
      const engine = S.transport === 'engine' ? ' (transport: engine, so calls carry no session)' : ''
      return {
        text: [
          `agent:   ${j.agent ?? '(none: PROMPTO_AUTH=off)'}${groups}`,
          `session: ${j.session ?? '(none)'}${engine}`,
          `auth:    ${j.auth ?? '?'}`,
          `prompto: ${cfg.base}`,
        ].join('\n'),
      }
    }
    case 'audit': {
      if (session === undefined) return { text: 'transport: engine. Calls carry no session, so there is no "this session" to show.' }
      const n = Math.min(200, Math.max(1, Number(rest[0]) || 20))
      const r = await get(`audit?session=${encodeURIComponent(session)}&limit=${n}`)
      if (r.status !== 200) return { text: `prompto: HTTP ${r.status}${errorText(r.json)}` }
      const recs = ((r.json as { records?: unknown[] }).records ?? []) as Record<string, unknown>[]
      return { text: recs.length ? recs.map(auditLine).join('\n') : `no prompto calls in session ${session} yet` }
    }
    case 'kill': {
      if (rest[0] === 'global') {
        killCount += 1
        const id = `kill-${killCount}`
        const item: PromptoPending = {
          ...blank(id, 'kill-global', String((await $.store.get('approver')) ?? '')),
          tool: 'kill',
          reason: "Every tool call, by every agent, is refused until an operator runs `prompto kill off`. Needs an approver's TOTP code.",
        }
        if (rest.length > 1) reasons.set(id, rest.slice(1).join(' '))
        await update($, pending, list => [...list, item])
        await $.ui.open({ id: PANE, title: 'prompto: global kill', focus: true, closeOnEscape: true })
        return { text: 'Type the approver name and TOTP code in the prompto pane to stop every prompto call.' }
      }
      if (session === undefined) return { text: 'transport: engine. Calls carry no session to kill; ask the operator: `prompto kill agent <name>`.' }
      const r = await request($, cfg, session, 'POST', `${cfg.base}/v1/kill`, { scope: 'session', reason: rest.join(' ') || 'from /prompto kill' })
      if (r.status !== 200) return { text: `prompto: HTTP ${r.status}${errorText(r.json)}` }
      return { text: String((r.json as { reason?: string }).reason ?? 'killed') }
    }
    case 'approve': {
      const list = await read($, pending)
      if (list.length === 0) return { text: 'No prompto approval is waiting.' }
      await $.ui.open({ id: PANE, title: 'prompto: approval needed', focus: true, closeOnEscape: true })
      return { text: `${list.length} prompto approval(s) waiting: see the pane.` }
    }
    default:
      return { text: HELP }
  }
}

/**
 * Claude Code drops this plugin's MCP server when a server the person
 * configured has the same URL, and the tools then go by that server's
 * name. Unless `servers` names it, the plugin wouldn't see those calls:
 * say so, once, at the start of the session.
 */
async function warnIfShadowed($: $, servers: readonly string[]): Promise<void> {
  let r
  try {
    r = await $.mcp.connect('prompto')
  } catch (err) {
    $.ui.log(`cannot tell which MCP server serves prompto: ${clean((err as Error).message)}`)
    return
  }
  if (!r.isConnected) {
    // Most often the token file: run the headers helper, whose refusal
    // says what is wrong with it (missing, mode, owner, ACL). Its output
    // on success is the header itself, kept in memory only.
    let why = ''
    try {
      await authorization($, cfgOf($), true)
    } catch (err) {
      why = `\nThe token file ${TOKEN_FILE} is the likely cause: ${clean((err as Error).message)}`
    }
    $.ui.log(`the plugin's MCP server is not connected (${r.reason}): ${clean(r.message)}${why}`)
    return
  }
  if (r.server.startsWith('plugin:')) return
  const asTool = r.server.replace(/[^A-Za-z0-9_-]/g, '_')
  if (servers.includes(r.server) || servers.includes(asTool)) return
  const name = clean(r.server)
  const msg =
    `Claude Code serves prompto through your MCP server "${name}" (same URL as the plugin's), ` +
    `and the plugin option \`servers\` doesn't name it: its calls get no precheck, ticket, approval pane or session. ` +
    `Add "${name}" to \`servers\`, or remove that server.`
  $.ui.log(msg)
  $.ui.toast(msg, { timeoutMs: 15_000 })
}

export const register: Register = (on, options) => {
  S = {
    options,
    transport: options.transport === 'engine' ? 'engine' : 'mod',
    scopeMinutes: Math.min(60, Math.max(1, Math.round(Number(options.scope_minutes) || 10))),
  }
  const servers = String(options.servers ?? 'prompto')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean)
  const PROMPTO_TOOL = toolPattern(servers.join(','))

  on('session.start', async ($, e, next) => {
    interactive = e.isInteractive
    try {
      await $.command.register({
        name: 'prompto',
        description: "prompto: whoami, this session's audit, kill this session (or everything), the approval pane",
        argumentHint: 'whoami | audit [n] | kill [global] [reason] | approve',
      })
    } catch (err) {
      // The calls are what matter; the command is a convenience.
      $.ui.log(`prompto: /prompto is unavailable: ${(err as Error).message}`)
    }
    await warnIfShadowed($, servers)
    return next(e)
  })

  on('tool.call', { tool: PROMPTO_TOOL }, async ($, e, next) => {
    const tool = PROMPTO_TOOL.exec(e.tool)?.[1] ?? ''
    const args = argsOf(e as Record<string, unknown>)
    const session = await sessionOf($)
    const cfg = cfgOf($)
    const isMod = S.transport === 'mod'

    // A standing "approve for N minutes" for this tool and host?
    const key = scopeKey(session, tool, args)
    const scope = scopes.get(key)
    const scoped = scope && scope.expiresAt * 1000 > (await $.clock.now()) && args.ticket === undefined ? scope.ticket : undefined
    let pc = await precheck($, cfg, session, tool, scoped ? { ...args, ticket: scoped } : args)
    if (scoped && pc.answer?.decision === 'deny' && pc.answer.error_class === 'refused_ticket') {
      scopes.delete(key)
      pc = await precheck($, cfg, session, tool, args)
    }
    const covered = scoped !== undefined && pc.answer?.decision === 'allow' && !pc.answer.ticket

    if (!pc.answer) {
      // Fail open: prompto still decides. A call that needs a ticket comes
      // back approval_required, and the model reads why none was asked for.
      $.ui.status('prompto: precheck unavailable; prompto itself decides')
      if (isMod) {
        const ok = await permitted($, e.tool, tool, args)
        if (ok !== true) return ok
      }
      const out = isMod ? await sendMod($, tool, args, session, undefined) : await next(e)
      if (out.deny !== undefined && out.deny.includes('approval_required')) {
        return { deny: `${out.deny}\n(prompto plugin: /v1/precheck was unavailable, ${pc.why}, so no ticket or approval could be asked for.)` }
      }
      return out
    }

    const a = pc.answer
    if (a.decision === 'deny') return { deny: refusal(a) }

    let ticket: string | undefined
    if (a.decision === 'allow') {
      if (isMod) {
        const ok = await permitted($, e.tool, tool, args)
        if (ok !== true) return ok
      }
      // A fresh ticket, or the scoped one precheck just found valid.
      ticket = a.ticket ?? (covered ? scoped : undefined)
    } else {
      // ask: a person must approve this exact call (that is the permission too).
      if (!interactive) {
        return {
          deny: `${refusal({ ...a, error_class: 'approval_required' })}\nA human must approve it, and this session has nobody to show the approval pane to. Run it from an interactive Claude Code session with the prompto plugin.`,
        }
      }
      // Claude Code's verdict first: a call its settings deny never costs a
      // code. Its `ask` is answered by the pane, as in `engine`: the code
      // the person types there is their answer (one prompt, not two).
      const ok = await permitted($, e.tool, tool, args, false)
      if (ok !== true) return ok
      const decision = await waitForHuman($, e.tool_use_id, next.signal, e.tool, tool, args, session, a)
      if (decision.kind === 'denied') return { deny: `prompto: the human approver refused this call: ${decision.reason}` }
      ticket = decision.ticket
    }
    if (!isMod) return next(ticket === undefined ? e : ({ ...e, ticket } as typeof e))
    return sendMod($, tool, args, session, ticket)
  }).catch(($, e, next) =>
    next.called
      ? next(e)
      : {
          deny: `prompto plugin: ${next.error.kind === 're-entry' ? 'a prompto call was raised inside another hook' : 'its hook failed'}${next.error.message ? ` (${next.error.message})` : ''}; the call was not sent.`,
        },
  )

  // The person closed the pane: whatever waits in it is refused.
  on('ui.close', { id: PANE }, async ($, e, next) => {
    if (e.origin.kind === 'person') {
      for (const w of waiters.values()) w.decision ??= { kind: 'denied', reason: 'the approval pane was closed' }
      for (const p of await read($, pending)) if (p.kind === 'kill-global') await dropPending($, p.id)
    }
    return next(e)
  })

  on('command.run', { command: 'prompto' }, async ($, e) => {
    try {
      return await command($, e.args)
    } catch (err) {
      return { text: `prompto: ${(err as Error).message}` }
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const list = await read($, pending)
    const p = list[0]
    if (!p) return <Text dimColor>No prompto approval is waiting.</Text>
    if (e.surface === 'mobile') {
      return (
        <Text>
          prompto: {clean(p.tool)} on {clean(p.host ?? '-')} waits for an approval. Approve it from a terminal or the desktop app.
        </Text>
      )
    }
    const { Button, Input, Code } = $.ui.resolve(e)
    const isKill = p.kind === 'kill-global'
    const minutes = S.scopeMinutes
    // A call whose hook is gone (the plugin reloaded) can't be approved.
    const stale = p.stale || (p.kind === 'call' && !waiters.has(p.id))
    const canScope = !isKill && !stale && (!p.root || p.rootScope)
    const host = clean(p.host ?? '-')
    const cuts = [p.main, ...p.fields].map(f => (f ? cutNote(f) : null)).filter(Boolean) as string[]
    // file_write's content: the diff when there is one, else drawn whole.
    const asDiff = (key: string) => p.tool === 'file_write' && key === 'content' && p.diff !== null
    return (
      <Box flexDirection="column" gap={1}>
        <Box flexDirection="column">
          <Text bold>
            {isKill ? 'Stop every prompto call (global kill)' : `${clean(p.tool)} on ${host}`}
            {p.root ? <Text color="red"> · root-capable</Text> : ''}
          </Text>
          {p.rule ? <Text dimColor>rule {clean(p.rule)}</Text> : ''}
          {p.reason ? <Text dimColor>{clean(p.reason)}</Text> : ''}
        </Box>
        {stale ? <Text color="red">stale: the call was lost when the plugin reloaded. Ask the agent to retry it; Deny dismisses this.</Text> : ''}
        {p.main ? (
          <Box flexDirection="column">
            <Text bold>{p.main.key}:</Text>
            <Code source={p.main.text} language="sh" />
          </Box>
        ) : (
          ''
        )}
        {isKill ? (
          ''
        ) : (
          <Box key="args" flexDirection="column">
            <Text dimColor>{p.main ? 'and every other argument the approval covers:' : 'every argument the approval covers:'}</Text>
            {p.fields.length === 0 ? <Text dimColor>  (none)</Text> : ''}
            {p.fields.map((f, i) =>
              asDiff(f.key) ? (
                <Text key={`arg-${i}`}>  {clean(f.key)} = {p.contentSum}: the diff below</Text>
              ) : f.text.includes('\n') || f.text.length > 100 ? (
                <Box key={`arg-${i}`} flexDirection="column">
                  <Text>  {clean(f.key)}{f.key === 'content' && p.contentSum ? ` (${p.contentSum})` : ''}:</Text>
                  <Code source={f.text} />
                </Box>
              ) : (
                <Text key={`arg-${i}`}>  {clean(f.key)} = {f.text}</Text>
              ),
            )}
          </Box>
        )}
        {cuts.map(c => (
          <Text color="yellow">{c}</Text>
        ))}
        {p.diff ? <Code source={clean(p.diff)} format="diff" path={p.path ?? undefined} /> : ''}
        {p.diffNote ? <Text dimColor>{p.diffNote.startsWith('diff ') ? '' : 'diff: '}{clean(p.diffNote)}</Text> : ''}
        {p.audit.length > 0 || p.auditNote ? (
          <Box flexDirection="column">
            <Text dimColor>recent calls by this agent on {host}:</Text>
            {p.audit.map(line => (
              <Text dimColor>  {clean(line)}</Text>
            ))}
            {p.auditNote ? <Text dimColor>  {clean(p.auditNote)}</Text> : ''}
          </Box>
        ) : (
          ''
        )}
        <Box flexDirection="column">
          <Input
            key={`approver-${p.generation}`}
            label="Approver"
            value={p.approver}
            placeholder="your approver name"
            onInput={v => void approverDrafts.set(p.id, v)}
            onSubmit={v => void approverDrafts.set(p.id, v)}
          />
          <Input
            key={`totp-${p.generation}`}
            label="TOTP code"
            placeholder={isKill ? '6 digits, Enter kills' : '6 digits from your authenticator, Enter approves once'}
            autoFocus
            submitLabel={isKill ? 'kill' : 'approve once'}
            onInput={v => void codes.set(p.id, v)}
            onSubmit={v => {
              codes.set(p.id, v)
              void approvePressed($, p.id, undefined)
            }}
          />
          <Input
            key={`reason-${p.generation}`}
            label={isKill ? 'Reason' : 'Deny reason'}
            placeholder={isKill ? 'why (recorded)' : 'optional; the model reads it'}
            submitLabel={isKill ? 'keep' : 'deny'}
            onInput={v => void reasons.set(p.id, v)}
            onSubmit={v => {
              reasons.set(p.id, v)
              if (!isKill) void denyPressed($, p.id)
            }}
          />
        </Box>
        <Box flexDirection="row" gap={2}>
          {stale ? (
            ''
          ) : (
            <Button key="approve" variant="primary" hotkey="a" onPress={() => void approvePressed($, p.id, undefined)}>
              {isKill ? 'Kill everything' : 'Approve once'}
            </Button>
          )}
          {canScope ? (
            <Button key="approve-scope" hotkey="m" onPress={() => void approvePressed($, p.id, minutes)}>
              {`Approve ${minutes} min`}
            </Button>
          ) : (
            ''
          )}
          {!isKill && !stale && p.root ? (
            <Button key="root-scope" hotkey="r" dimColor onPress={() => void patch($, p.id, q => ({ rootScope: !q.rootScope }))}>
              {`${p.rootScope ? '[x]' : '[ ]'} allow a ${minutes} min root scope`}
            </Button>
          ) : (
            ''
          )}
          <Button key="deny" hotkey="d" onPress={() => void denyPressed($, p.id)}>
            {isKill ? 'Cancel' : 'Deny'}
          </Button>
        </Box>
        <Text dimColor>Tab moves between fields and buttons · Esc closes the pane{isKill ? '' : ' (and refuses the call)'}</Text>
        {p.isBusy ? <Text dimColor>asking prompto…</Text> : ''}
        {p.message ? <Text color="yellow">{clean(p.message)}</Text> : ''}
        {list.length > 1 ? <Text dimColor>{list.length - 1} more waiting</Text> : ''}
      </Box>
    )
  })
}
