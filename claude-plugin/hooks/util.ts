// Pure helpers: no `$`, nothing of the engine's.

/** The keys a tool.call input carries beside the tool's own arguments. */
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId', 'requestMeta', 'consent'])
const ARGS_PREVIEW = 4000

export type Config = {
  /** `http://host:6337/mcp` */
  mcpUrl: string
  /** `http://host:6337` */
  base: string
  tokenFile: string
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
    tokenFile: String(options.token_file ?? '~/.config/prompto/token'),
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
  const h = args.host ?? args.client ?? args.source_host
  if (tool === 'rsync_sync' && typeof args.dest_host === 'string') return `${String(h)} -> ${args.dest_host}`
  return typeof h === 'string' ? h : null
}

/** What the call will do, as a person reads it. */
export function commandOf(tool: string, args: Record<string, unknown>): string {
  for (const k of ['cmd', 'script', 'task']) {
    const v = args[k]
    if (typeof v === 'string') return v
  }
  if (Array.isArray(args.commands)) {
    return args.commands.map(c => (typeof c === 'string' ? c : JSON.stringify(c))).join('\n')
  }
  const shown: Record<string, unknown> = { ...args }
  if (tool === 'file_write' && typeof shown.content === 'string') {
    shown.content = `<${shown.content.length} chars: see the diff>`
  }
  delete shown.ticket
  const text = JSON.stringify(shown, null, 2)
  return text.length > ARGS_PREVIEW ? `${text.slice(0, ARGS_PREVIEW)}\n… (${text.length} chars)` : text
}

/** Where an "approve for N minutes" ticket applies: session, tool, host(s). */
export function scopeKey(session: string | undefined, tool: string, args: Record<string, unknown>): string {
  const host = args.host ?? args.client ?? args.source_host ?? ''
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
  const rule = a.rule ? ` [rule ${a.rule}]` : ''
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
  return typeof msg === 'string' ? `: ${msg}` : ''
}

/** One audit record as a line. */
export function auditLine(r: Record<string, unknown>): string {
  const s = (k: string) => (typeof r[k] === 'string' ? (r[k] as string) : '')
  const time = s('ts').slice(11, 19)
  if (s('type') === 'kill') return `${time} kill ${s('action')} ${s('scope')} ${s('target')} ${s('reason')}`.trim()
  const args = (r.args ?? {}) as Record<string, unknown>
  const what = ['cmd', 'script', 'task'].map(k => args[k]).find(v => typeof v === 'string') as string | undefined
  const kind = s('type') === 'tool' ? '' : `${s('type')}:`
  const outcome = r.ok === true ? 'ok' : s('error_class') || (s('decision') === 'allow' ? 'allowed' : s('decision') || 'failed')
  const by = s('approved_by') ? ` by=${s('approved_by')}` : ''
  return `${time} ${kind}${s('tool')} ${s('host')} ${outcome}${by} ${(what ?? '').replace(/\s+/g, ' ').slice(0, 60)}`.trim()
}

export const HELP = [
  '/prompto whoami          the agent, its groups and this session as prompto sees them',
  "/prompto audit [n]       this session's last n prompto calls (default 20)",
  '/prompto kill [reason]   stop every call of this agent in this session (an operator lifts it)',
  "/prompto kill global     stop every prompto call (needs an approver's TOTP code, in the pane)",
  '/prompto approve         show the approval pane',
].join('\n')
