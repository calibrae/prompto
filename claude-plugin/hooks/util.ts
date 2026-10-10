// Pure helpers: no `$`, nothing of the engine's.

/** The keys a tool.call input carries beside the tool's own arguments. */
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId', 'requestMeta', 'consent'])
/** Chars of one value the approval pane draws; past it, the head and a warning. */
export const SHOW_MAX = 32 * 1024
/** What runs, in the order the pane looks for it: drawn first, highlighted. */
export const MAIN_KEYS = ['cmd', 'script', 'commands'] as const

export type Config = {
  /** `http://host:6337/mcp` */
  mcpUrl: string
  /** `http://host:6337` */
  base: string
  /** The headers helper, `<plugin root>/bin/prompto-headers`. */
  helper: string
}

export function configFrom(options: Readonly<Record<string, unknown>>, root: string): Config {
  const mcpUrl = String(options.url ?? 'http://localhost:6337/mcp')
    .trim()
    .replace(/\/+$/, '')
  return {
    mcpUrl,
    base: mcpUrl.replace(/\/mcp$/, ''),
    helper: `${root}/bin/prompto-headers`,
  }
}

/** The tool's own arguments: `e` minus the keys the engine adds, as plain JSON. */
export function argsOf(e: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(e)) if (!RESERVED.has(k)) out[k] = v
  return JSON.parse(JSON.stringify(out)) as Record<string, unknown>
}

export function hostOf(tool: string, args: Record<string, unknown>): string | null {
  const h = args.host ?? args.source_host
  if (tool === 'rsync_sync' && typeof args.dest_host === 'string') return `${String(h)} -> ${args.dest_host}`
  return typeof h === 'string' ? h : null
}

/**
 * Terminal hazards: C0 and C1 controls (newline and tab aside), DEL, and the
 * invisible formatting characters that reorder or hide text: bidi
 * embeddings, overrides and isolates (U+202A-U+202E, U+2066-U+2069), marks,
 * zero-width characters, the BOM.
 */
const HAZARD = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g

/** `s` safe to draw: every hazard shown as an escape (`\x1b`, `\u{202e}`), never acted on. */
export function clean(s: string): string {
  return s.replace(HAZARD, c => {
    const n = c.charCodeAt(0)
    return n < 0x100 ? `\\x${n.toString(16).padStart(2, '0')}` : `\\u{${n.toString(16)}}`
  })
}

/** UTF-8 bytes of `s`. */
export function utf8(s: string): Uint8Array {
  const out: number[] = []
  for (const ch of s) {
    let c = ch.codePointAt(0)!
    if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd // a lone surrogate, as JSON.stringify would not keep it
    if (c < 0x80) out.push(c)
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
  }
  return Uint8Array.from(out)
}

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

/** SHA-256 of `bytes`, hex: the pane's fingerprint of a value it can't draw whole. */
export function sha256(bytes: Uint8Array): string {
  const len = bytes.length
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6)
  padded.set(bytes)
  padded[len] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(padded.length - 8, Math.floor(len / 0x20000000))
  view.setUint32(padded.length - 4, (len << 3) >>> 0)
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4)
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!
      const b = w[i - 2]!
      const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)
      const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10)
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, hh] = [h[0]!, h[1]!, h[2]!, h[3]!, h[4]!, h[5]!, h[6]!, h[7]!]
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) >>> 0
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      hh = g
      g = f
      f = e
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      a = (t1 + t2) >>> 0
    }
    const add = [a, b, c, d, e, f, g, hh]
    for (let i = 0; i < 8; i++) h[i] = (h[i]! + add[i]!) >>> 0
  }
  return [...h].map(x => x.toString(16).padStart(8, '0')).join('')
}

/**
 * One argument as the pane draws it: `text` is safe to draw ([`clean`]),
 * whole up to [`SHOW_MAX`] chars; past that its head, and `cut` says how
 * much is approved in all, and its SHA-256.
 */
export type Field = {
  key: string
  text: string
  cut: { bytes: number; sha256: string } | null
}

export function fieldOf(key: string, value: unknown): Field {
  const raw =
    typeof value === 'string'
      ? value
      : Array.isArray(value) && value.every(v => typeof v === 'string') && key === 'commands'
        ? value.join('\n')
        : JSON.stringify(value, null, typeof value === 'object' && value !== null ? 2 : undefined) ?? String(value)
  if (raw.length <= SHOW_MAX) return { key, text: clean(raw), cut: null }
  const bytes = utf8(raw)
  return { key, text: clean(raw.slice(0, SHOW_MAX)), cut: { bytes: bytes.length, sha256: sha256(bytes) } }
}

/** The warning under a value drawn in part. */
export function cutNote(f: Field): string | null {
  if (!f.cut) return null
  return `${f.key} truncated in this view (first ${SHOW_MAX} chars shown): you are approving all ${f.cut.bytes} bytes, sha256 ${f.cut.sha256}`
}

/**
 * Everything a call's ticket covers, for the approver: the main field
 * (cmd, script or commands) first, then every other argument in
 * order, `ticket` aside. Nothing is left out; `fields` holds file_write's
 * `content` too, which the pane draws as a diff when it has one.
 */
export function argView(args: Record<string, unknown>): { main: Field | null; fields: Field[] } {
  const mainKey = MAIN_KEYS.find(k => args[k] !== undefined)
  const main = mainKey === undefined ? null : fieldOf(mainKey, args[mainKey])
  const fields = Object.entries(args)
    .filter(([k]) => k !== 'ticket' && k !== mainKey)
    .map(([k, v]) => fieldOf(k, v))
  return { main, fields }
}

/** What the call will do, in a line or a few: for a question, not for approval. */
export function commandOf(tool: string, args: Record<string, unknown>): string {
  const { main, fields } = argView(args)
  if (main) return main.text
  const shown = fields.filter(f => !(tool === 'file_write' && f.key === 'content'))
  return shown.map(f => `${f.key}=${f.text}`).join(' ')
}

/** Where an "approve for N minutes" ticket applies: session, tool, host(s). */
export function scopeKey(session: string | undefined, tool: string, args: Record<string, unknown>): string {
  const host = args.host ?? args.source_host ?? ''
  return [session ?? '', tool, String(host), String(args.dest_host ?? '')].join('|')
}

export function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** The tool-name pattern of the prompto servers: `mcp__<server>__<tool>`. */
export function toolPattern(servers: string): RegExp {
  const names = ['plugin_prompto_prompto', ...servers.split(',').map(s => s.trim()).filter(Boolean)]
  return new RegExp(`^mcp__(?:${names.map(escapeRe).join('|')})__(.+)$`)
}

export type Precheck = {
  decision: 'allow' | 'deny' | 'ask'
  rule?: string | null
  reason?: string
  approval?: string
  root?: boolean
  ticket?: string
  expires_at?: number
  error_class?: string
  request_id?: string
}

/** prompto's refusal, with its rule. */
export function refusal(a: Precheck): string {
  const rule = a.rule && !(a.reason ?? '').includes(a.rule) ? ` [rule ${a.rule}]` : ''
  return `prompto refused this call (${a.error_class ?? 'deny'}): ${a.reason ?? ''}${rule}`
}

export type McpBlock = { type: string; text?: string; [k: string]: unknown }

export function textOf(content: readonly McpBlock[]): string {
  return content
    .map(b => (typeof b.text === 'string' ? b.text : ''))
    .filter(Boolean)
    .join('\n')
}

/** The JSON-RPC message in a reply body: plain JSON, or an SSE `data:` line. */
export function rpcMessage(text: string): Record<string, unknown> | undefined {
  for (const c of [text, ...text.split('\n').map(l => l.replace(/^data: ?/, ''))]) {
    const t = c.trim()
    if (!t.startsWith('{')) continue
    try {
      const m = JSON.parse(t) as Record<string, unknown>
      if ('result' in m || 'error' in m) return m
    } catch {
      // not this line
    }
  }
  return undefined
}

/** `error` or `reason` of a JSON error body, as `: <text>`. */
export function errorText(json: unknown): string {
  const j = json as Record<string, unknown> | undefined
  const msg = j?.error ?? j?.reason
  return typeof msg === 'string' ? `: ${clean(msg)}` : ''
}

/** One audit record as a line, safe to draw. */
export function auditLine(r: Record<string, unknown>): string {
  return clean(auditText(r))
}

function auditText(r: Record<string, unknown>): string {
  const s = (k: string) => (typeof r[k] === 'string' ? (r[k] as string) : '')
  const time = s('ts').slice(11, 19)
  if (s('type') === 'kill') return `${time} kill ${s('action')} ${s('scope')} ${s('target')} ${s('reason')}`.trim()
  const args = (r.args ?? {}) as Record<string, unknown>
  const what = ['cmd', 'script'].map(k => args[k]).find(v => typeof v === 'string') as string | undefined
  const kind = s('type') === 'tool' ? '' : `${s('type')}:`
  // A precheck or an approval is a decision, not a run.
  const decided = s('type') === 'tool' ? '' : s('decision')
  const outcome = decided || (r.ok === true ? 'ok' : s('error_class') || 'failed')
  const by = s('approved_by') ? ` by=${s('approved_by')}` : ''
  return `${time} ${kind}${s('tool')} ${s('host')} ${outcome}${by} ${(what ?? '').replace(/\s+/g, ' ').slice(0, 60)}`.trim()
}

/**
 * Text that may hold a TOTP code typed into the wrong field: a run of
 * exactly 6 digits, 6 digits split by spaces or hyphens (`123 456`,
 * `12-34-56`, `1234-56`), or more in groups of at most 3 (`123 456 7`).
 * The name and the reason fields refuse it. Dates (`2026-10-10`) and
 * plain longer numbers pass.
 */
export function looksLikeCode(text: string): boolean {
  for (const run of text.match(/[0-9]+(?:[ -][0-9]+)*/g) ?? []) {
    const groups = run.split(/[ -]/)
    if (groups.some(g => g.length === 6)) return true
    const digits = groups.join('').length
    if (groups.length > 1 && (digits === 6 || (digits > 6 && groups.every(g => g.length <= 3)))) return true
  }
  return false
}

export const CODE_IN_FIELD =
  'That looks like a TOTP code in the wrong field: it was cleared and not sent. The code goes in the TOTP field only.'

export const HELP = [
  '/prompto whoami          the agent, its groups and this session as prompto sees them',
  "/prompto audit [n]       this session's last n prompto calls (default 20)",
  '/prompto kill [reason]   stop this session\'s calls: a stop for a cooperative session (this plugin);',
  '                         the session ID is the client\'s word, so `prompto kill agent <name>` is the real stop',
  "/prompto kill global     stop every prompto call (needs an approver's TOTP code, in the pane)",
  '/prompto approve         show the approval pane',
].join('\n')
