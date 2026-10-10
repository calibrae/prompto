// A fake prompto for the plugin's tests: answers $.http.fetch the way the
// real server does, and records every request.

import type { On } from 'claude-code'

export type Seen = { method: string; url: string; path: string; headers: Record<string, string>; body: any }

export type Fake = {
  seen: Seen[]
  /** What /v1/precheck answers, per tool. */
  precheck: Record<string, any>
  /** The code /v1/approve accepts. */
  code: string
  /** /v1/approve's reason for a wrong code. */
  refusal: string
  /** tools/call answers, per tool: a result object or { error }. */
  results: Record<string, any>
  /** /v1/audit records. */
  audit: any[]
  /** Throw from fetch for these paths (unreachable). */
  down: string[]
  /** `$.store`, in memory. */
  store: Map<string, unknown>
  calls: () => Seen[]
  approvals: () => Seen[]
  logs: string[]
}

/** Install the fake and the engine stubs every test needs. */
export type Opts = {
  /**
   * Claude Code's permission verdict, for every tool or per MCP tool name;
   * `absent`: the tool isn't in the session (a deny rule took it out), and
   * the check throws, as Claude Code's does.
   */
  check?: 'allow' | 'ask' | 'deny' | ((tool: string) => 'allow' | 'ask' | 'deny' | 'absent')
  /** Tool names `$.tool.check` was asked about, in order. */
  checked?: string[]
  /** What `$.mcp.connect('prompto')` answers: the server's name (default the plugin's own), or `null`: not connected. */
  mcpServer?: string | null
  /** The person's pick when asked (AskUserQuestion). */
  answer?: string
  /** The headers helper fails (no token file). */
  noToken?: boolean
  /** `$.session.id` throws. */
  sessionThrows?: boolean
  /** Record what the plugin writes to `$.state`. */
  stateWrites?: string[]
  /** Questions asked through AskUserQuestion. */
  asked?: string[]
  /** `/prompto` can't be registered (another command has the name). */
  commandTaken?: boolean
  /** What `$.store` holds at the start. */
  store?: Record<string, unknown>
  /** The mocked clock: `sleep` waits on it (so the hook's polling waits for the test). */
  clock?: { sleep: (ms: number) => Promise<void> }
}

export function install(on: On, opts: Opts = {}): Fake {
  const fake: Fake = {
    seen: [],
    precheck: {},
    code: '123456',
    refusal: 'invalid approver or code',
    results: {},
    audit: [],
    down: [],
    store: new Map(Object.entries(opts.store ?? {})),
    calls: () => fake.seen.filter(s => s.path === '/mcp'),
    approvals: () => fake.seen.filter(s => s.path === '/v1/approve'),
    logs: [],
  }
  on('process.run', ($, e) => {
    if (e.argv[0] === 'sh') {
      return opts.noToken
        ? { value: { exitCode: 1, stdout: '', stderr: 'prompto-headers: no token file /x' } }
        : { value: { exitCode: 0, stdout: '{"Authorization": "Bearer pto_test"}\n', stderr: '' } }
    }
    if (e.argv[0] === 'sleep' && opts.clock) {
      return opts.clock.sleep(Number(e.argv[1]) * 1000).then(() => ({ value: { exitCode: 0, stdout: '', stderr: '' } }))
    }
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  on('session.id', () => {
    if (opts.sessionThrows) throw new Error('no session today')
    return { value: 'sess-test' }
  })
  on('tool.call', { tool: 'AskUserQuestion' }, ($, e) => {
    const q = (e as { questions: { question: string }[] }).questions[0]!
    opts.asked?.push(q.question)
    return { result: { questions: [q], answers: { [q.question]: opts.answer ?? 'Deny' } } } as never
  })
  if (opts.stateWrites) {
    const writes = opts.stateWrites
    on('state.set', ($, e, next) => {
      writes.push(JSON.stringify(e.value))
      return next(e)
    })
  }
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('tool.check', ($, e) => {
    opts.checked?.push(e.tool)
    const c = opts.check ?? 'allow'
    const decision = typeof c === 'function' ? c(e.tool) : c
    if (decision === 'absent') throw new Error(`no tool named "${e.tool}" in this session`)
    return { decision }
  })
  on('mcp.connect', () =>
    opts.mcpServer === null
      ? { value: { isConnected: false, reason: 'failed', message: 'unauthorized: missing bearer token' } }
      : { value: { isConnected: true, server: opts.mcpServer ?? 'plugin:prompto:prompto' } },
  )
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.close', () => ({ value: undefined }))
  on('store.get', ($, e) => ({ value: fake.store.get(e.key) }))
  on('store.set', ($, e) => {
    fake.store.set(e.key, JSON.parse(JSON.stringify(e.value)))
    return { value: undefined }
  })
  on('store.keys', () => ({ value: [...fake.store.keys()] }))
  on('ui.status', ($, e) => {
    fake.logs.push(`status:${JSON.stringify(e)}`)
    return { value: undefined }
  })
  on('ui.toast', ($, e) => {
    fake.logs.push(`toast:${JSON.stringify(e)}`)
    return { value: undefined }
  })
  on('ui.log', ($, e) => {
    fake.logs.push(`log:${JSON.stringify(e)}`)
    return { value: undefined }
  })
  on('command.register', ($, e) => {
    if (opts.commandTaken) throw new Error(`"/${e.name}" refused: it is the plugin's /prompto:prompto`)
    return { value: { command: e.name } }
  })
  on('http.fetch', ($, e) => {
    const url = new URL(e.url)
    const headers = { ...(e.init?.headers ?? {}) }
    const body = e.init?.body ? JSON.parse(e.init.body) : undefined
    const s: Seen = { method: e.init?.method ?? 'GET', url: e.url, path: url.pathname, headers, body }
    fake.seen.push(s)
    if (fake.down.includes(url.pathname)) throw new Error('connect ECONNREFUSED')
    const reply = (status: number, json: unknown) => ({
      value: { status, ok: status < 300, headers: { 'content-type': 'application/json' }, text: JSON.stringify(json) },
    })
    if (headers.Authorization !== 'Bearer pto_test') return reply(401, { error: 'no token' })
    switch (url.pathname) {
      case '/v1/precheck':
        return reply(200, fake.precheck[body.tool] ?? { decision: 'allow', rule: 'policy.toml:1', approval: 'none', root: false })
      case '/v1/approve':
        if (body.totp_code !== fake.code) return reply(403, { decision: 'deny', reason: fake.refusal })
        return reply(200, { decision: 'allow', ticket: `pt1.human.${body.scope_minutes ?? 0}`, expires_at: 4102444800, scoped: !!body.scope_minutes })
      case '/v1/audit':
        return reply(200, { records: fake.audit, count: fake.audit.length })
      case '/v1/whoami':
        return reply(200, { agent: 'tester', groups: ['ops'], session: headers['X-Prompto-Session'] ?? null, auth: 'required' })
      case '/v1/kill':
        return reply(200, { killed: { scope: body.scope }, reason: `killed ${body.scope}` })
      case '/mcp': {
        const r = fake.results[body.params.name] ?? { content: [{ type: 'text', text: JSON.stringify({ ran: body.params.arguments }) }], isError: false }
        const msg = 'error' in r ? { jsonrpc: '2.0', id: body.id, error: r.error } : { jsonrpc: '2.0', id: body.id, result: r }
        return { value: { status: 200, ok: true, headers: { 'content-type': 'text/event-stream' }, text: `data: ${JSON.stringify(msg)}\n\n` } }
      }
    }
    return reply(404, { error: 'not found' })
  })
  return fake
}
