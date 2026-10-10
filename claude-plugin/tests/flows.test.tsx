// The plugin's flows against a fake prompto (tests/fake.ts): allow, deny,
// ask (the pane), fail-open/closed, tickets bound to the exact arguments,
// and the TOTP code never kept anywhere.

import { test, expect, mock } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import { install } from './fake'
import type { Fake } from './fake'

const PANE_PROPS = {
  title: 'prompto',
  isFocused: true,
  bodyColumns: 120,
  placement: 'inline' as const,
  scroll: { offset: 0, bodyRows: 40 },
}
const CODE = '123456'

async function start($: Engine, interactive = true) {
  await $.session.start({ cwd: '/', surface: interactive ? 'terminal' : null, isInteractive: interactive })
}

/**
 * The pane, once it shows a waiting request whose details have loaded
 * (the hook is polling for the person's decision meanwhile).
 */
async function paneReady($: Engine, clock: { settle: () => Promise<void> }) {
  const ui = await $.ui.mount({ plugin: 'prompto', surface: 'terminal', component: 'Pane', requestId: 'prompto-approval', props: PANE_PROPS })
  for (let i = 0; i < 500; i++) {
    if ((await ui.find({ key: 'approve' })) && !(await ui.find({ type: 'Text', text: /loading/ }))) return ui
    await clock.settle()
  }
  throw new Error('the pane never showed a waiting request')
}

/** Let the hook see a decision: its polling sleeps on the mocked clock. */
async function done<T>(clock: { advance: (ms: number) => Promise<void> }, call: Promise<T>): Promise<T> {
  let settled = false
  void call.then(
    () => (settled = true),
    () => (settled = true),
  )
  for (let i = 0; i < 100 && !settled; i++) await clock.advance(300)
  return call
}

async function shows(ui: { find: (q: { type?: string; text?: RegExp }) => Promise<unknown> }, text: RegExp) {
  return (await ui.find({ type: 'Text', text })) !== undefined
}

/** JSON with sorted keys: equal values, equal text (what the args digest sees). */
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v && typeof v === 'object') {
    return `{${Object.keys(v)
      .sort()
      .map(k => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`)
      .join(',')}}`
  }
  return JSON.stringify(v)
}

function withoutTicket(a: Record<string, unknown>) {
  const { ticket: _t, ...rest } = a
  return rest
}

const ASK = { decision: 'ask', rule: 'policy.toml:36 (ops-root-t2-human)', approval: 'human', root: true, reason: 'rule requires a human approval' }

// ---------------------------------------------------------------------------

test('allow without a ticket: sent once, exactly as asked, with the session', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu1', host: 'h1', cmd: 'id -u' })
  expect(out.deny).toBeUndefined()
  expect(JSON.stringify(out.result)).toContain('ran')
  const [pre] = fake.seen.filter(s => s.path === '/v1/precheck')
  expect(pre!.body).toEqual({ tool: 'ssh_exec', arguments: { host: 'h1', cmd: 'id -u' } })
  expect(fake.calls()).toHaveLength(1)
  expect(fake.calls()[0]!.body.params).toEqual({ name: 'ssh_exec', arguments: { host: 'h1', cmd: 'id -u' } })
  for (const s of fake.seen) expect(s.headers['X-Prompto-Session']).toBe('sess-test')
})

test('allow with a ticket: the ticket rides on exactly the prechecked arguments', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  fake.precheck.bash_exec = { decision: 'allow', rule: 'policy.toml:9', approval: 'ticket', ticket: 'pt1.minted', root: false }
  await start($)
  // Odd key order, nesting and a default-looking value: none may change.
  const args = { script: 'id -u ', host: 'h1', env: { B: '2', A: '1' }, timeout_secs: 30 }
  const out = await $.tool.call({ tool: 'mcp__prompto__bash_exec', tool_use_id: 'tu2', ...args })
  expect(out.deny).toBeUndefined()
  const pre = fake.seen.find(s => s.path === '/v1/precheck')!
  const sent = fake.calls()[0]!.body.params.arguments
  expect(sent.ticket).toBe('pt1.minted')
  expect(canon(withoutTicket(sent))).toBe(canon(pre.body.arguments))
  expect(canon(pre.body.arguments)).toBe(canon(args))
})

test('deny: refused with prompto\'s reason and rule, nothing sent', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  fake.precheck.ssh_sudo_exec = {
    decision: 'deny',
    error_class: 'refused_policy',
    rule: 'default-deny',
    reason: 'agent tester has no grant for ssh_sudo_exec on h2',
  }
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu3', host: 'h2', cmd: 'id' })
  expect(out.deny).toContain('refused_policy')
  expect(out.deny).toContain('no grant for ssh_sudo_exec on h2')
  expect(out.deny).toContain('default-deny')
  // The rule once: precheck reasons often name it already.
  fake.precheck.ssh_sudo_exec = { decision: 'deny', error_class: 'approval_required', rule: 'r1', reason: 'rule r1 requires a human approval' }
  const again = await $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu3b', host: 'h2', cmd: 'id' })
  expect(again.deny!.split('r1').length - 1).toBe(1)
  expect(fake.calls()).toHaveLength(0)
})

test('ask: the pane shows the call, the code approves it, the ticket goes on the same arguments', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { store: { approver: 'alice' }, clock })
  fake.precheck.ssh_sudo_exec = ASK
  fake.audit = [{ ts: '2026-10-10T12:00:01.000Z', type: 'tool', tool: 'ssh_exec', host: 'h2', ok: true, args: { cmd: 'uptime' } }]
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu4', host: 'h2', cmd: 'systemctl restart nginx' })
  const ui = await paneReady($, clock)
  expect(await shows(ui, /ssh_sudo_exec on h2/)).toBe(true)
  expect(await shows(ui, /root-capable/)).toBe(true)
  expect(await shows(ui, /rule policy.toml:36 \(ops-root-t2-human\)/)).toBe(true)
  expect(await shows(ui, /uptime/)).toBe(true)
  const code = await ui.find({ type: 'Code' })
  expect(code?.props.source).toBe('systemctl restart nginx')
  expect(fake.calls()).toHaveLength(0)
  expect(await ui.find({ key: 'approve-scope' })).toBeUndefined() // root: no scope without the toggle
  await ui.input({ key: 'totp-0', text: CODE, kind: 'change' })
  await ui.press({ key: 'approve' })
  const out = await done(clock, call)
  expect(out.deny).toBeUndefined()

  const [ap] = fake.approvals()
  expect(ap!.body.approver).toBe('alice')
  expect(ap!.body.totp_code).toBe(CODE)
  expect(ap!.body.scope_minutes).toBeUndefined()
  const sent = fake.calls()[0]!.body.params.arguments
  expect(sent.ticket).toBe('pt1.human.0')
  expect(canon(withoutTicket(sent))).toBe(canon(ap!.body.arguments))
  expect(canon(ap!.body.arguments)).toBe(canon({ host: 'h2', cmd: 'systemctl restart nginx' }))
  expect(await shows(ui, /No prompto approval is waiting/)).toBe(true)
})

test('ask: a wrong code says so and the next one works; Enter in the code field approves', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { store: { approver: 'alice' }, clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu5', host: 'h2', cmd: 'id -u' })
  const ui = await paneReady($, clock)
  await ui.input({ key: 'totp-0', text: '000000' })
  expect(await shows(ui, /refused: invalid approver or code/)).toBe(true)
  expect(await ui.find({ key: 'totp-1' })).toBeDefined()
  expect(fake.calls()).toHaveLength(0)
  // The field was drawn anew under a new key; submit the right code.
  await ui.input({ key: 'totp-1', text: CODE })
  const out = await done(clock, call)
  expect(out.deny).toBeUndefined()
  expect(fake.approvals()).toHaveLength(2)
  expect(fake.calls()).toHaveLength(1)
})

test('ask: deny with a reason refuses the call and sends nothing', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu6', host: 'h2', cmd: 'rm -rf /srv' })
  const ui = await paneReady($, clock)
  await ui.input({ key: 'reason-0', text: 'not on a Friday', kind: 'change' })
  await ui.press({ key: 'deny' })
  const out = await done(clock, call)
  expect(out.deny).toContain('the human approver refused this call: not on a Friday')
  expect(fake.approvals()).toHaveLength(0)
  expect(fake.calls()).toHaveLength(0)
})

test('ask: no decision within 10 minutes refuses the call', { timeoutMs: 60_000 }, async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu8', host: 'h2', cmd: 'id' })
  await paneReady($, clock)
  await clock.advance(11 * 60 * 1000)
  const out = await done(clock, call)
  expect(out.deny).toContain('no decision within 10 minutes')
  expect(fake.calls()).toHaveLength(0)
})

test('ask in a non-interactive session: refused at once, no pane', async ($, on) => {
  const clock = mock.clock(on)
  // A pane would wait on this clock, which never moves here: the test would time out.
  const fake = install(on, { clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($, false)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu9', host: 'h2', cmd: 'id' })
  expect(out.deny).toContain('approval_required')
  expect(out.deny).toContain('nobody to show the approval pane to')
  expect(fake.logs.join('')).not.toContain('waits for an approval')
  expect(fake.calls()).toHaveLength(0)
})

test('approve for N minutes (not root): later calls to the same tool and host need no pane', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { store: { approver: 'bob' }, clock })
  fake.precheck.service_control = { ...ASK, root: false }
  await start($)
  const first = $.tool.call({ tool: 'mcp__prompto__service_control', tool_use_id: 'tu10', host: 'h2', unit: 'nginx', action: 'restart' })
  const ui = await paneReady($, clock)
  await ui.input({ key: 'totp-0', text: CODE, kind: 'change' })
  await ui.press({ key: 'approve-scope' })
  expect((await done(clock, first)).deny).toBeUndefined()
  expect(fake.approvals()[0]!.body.scope_minutes).toBe(10)
  expect(fake.approvals()[0]!.body.allow_root_scope).toBeUndefined()

  // The next call: precheck sees the scoped ticket, which covers it.
  fake.precheck.service_control = { decision: 'allow', rule: ASK.rule, approval: 'human', reason: 'the ticket in `arguments` is valid' }
  const second = await $.tool.call({ tool: 'mcp__prompto__service_control', tool_use_id: 'tu11', host: 'h2', unit: 'php-fpm', action: 'restart' })
  expect(second.deny).toBeUndefined()
  const pre = fake.seen.filter(s => s.path === '/v1/precheck').at(-1)!
  expect(pre.body.arguments.ticket).toBe('pt1.human.10')
  expect(fake.calls().at(-1)!.body.params.arguments).toEqual({ host: 'h2', unit: 'php-fpm', action: 'restart', ticket: 'pt1.human.10' })
  expect(fake.approvals()).toHaveLength(1)
  await ui.unmount()
  // Another host: the scope doesn't apply.
  fake.precheck.service_control = { ...ASK, root: false }
  const third = $.tool.call({ tool: 'mcp__prompto__service_control', tool_use_id: 'tu12', host: 'h3', unit: 'nginx', action: 'restart' })
  const ui2 = await paneReady($, clock)
  expect(await shows(ui2, /service_control on h3/)).toBe(true)
  expect(fake.seen.filter(s => s.path === '/v1/precheck').at(-1)!.body.arguments.ticket).toBeUndefined()
  await ui2.press({ key: 'deny' })
  expect((await done(clock, third)).deny).toContain('refused')
})

test('a root scope needs the explicit toggle, and says so to prompto', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { store: { approver: 'bob' }, clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu13', host: 'h2', cmd: 'id' })
  const ui = await paneReady($, clock)
  expect(await ui.find({ key: 'approve-scope' })).toBeUndefined()
  await ui.press({ key: 'root-scope' })
  expect(await ui.find({ key: 'approve-scope' })).toBeDefined()
  await ui.input({ key: 'totp-0', text: CODE, kind: 'change' })
  await ui.press({ key: 'approve-scope' })
  expect((await done(clock, call)).deny).toBeUndefined()
  expect(fake.approvals()[0]!.body.allow_root_scope).toBe(true)
  expect(fake.approvals()[0]!.body.scope_minutes).toBe(10)
})

test('the TOTP code is never kept: not in state, store, logs, results or other requests', async ($, on) => {
  const clock = mock.clock(on)
  const session = mock.session(on)
  const stateWrites: string[] = []
  const fake = install(on, { store: { approver: 'alice' }, clock, stateWrites })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const secret = '271828'
  fake.code = secret
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu14', host: 'h2', cmd: 'id' })
  const ui = await paneReady($, clock)
  // A wrong one first, then the right one; both typed, both sent.
  await ui.input({ key: 'totp-0', text: '314159', kind: 'change' })
  await ui.press({ key: 'approve' })
  const drawnAfterWrong = JSON.stringify(await ui.drawn())
  await ui.input({ key: 'totp-1', text: secret, kind: 'change' })
  await ui.press({ key: 'approve' })
  const out = await done(clock, call)
  expect(out.deny).toBeUndefined()
  expect(stateWrites.length).toBeGreaterThan(2)

  const everything = [
    drawnAfterWrong,
    JSON.stringify(await ui.drawn()),
    ...stateWrites,
    JSON.stringify([...fake.store.entries()]),
    JSON.stringify(session.appended()),
    JSON.stringify(out),
    ...fake.logs,
    ...fake.seen.filter(s => s.path !== '/v1/approve').map(s => JSON.stringify(s)),
  ].join('\n')
  for (const code of [secret, '314159']) expect(everything).not.toContain(code)
  // It went to /v1/approve, and only there.
  expect(fake.approvals().map(a => a.body.totp_code)).toEqual(['314159', secret])
  // The store keeps the approver's name, nothing else.
  expect([...fake.store.keys()]).toEqual(['approver'])
})

test('a code typed into the approver name or the deny reason is refused, cleared and never sent', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu30', host: 'h2', cmd: 'id' })
  const ui = await paneReady($, clock)
  // The code lands in the name field (a Tab too many), then Approve.
  await ui.input({ key: 'approver-0', text: 'alice271828', kind: 'change' })
  await ui.input({ key: 'totp-0', text: CODE, kind: 'change' })
  await ui.press({ key: 'approve' })
  expect(await shows(ui, /looks like a TOTP code in the wrong field/)).toBe(true)
  expect(fake.approvals()).toHaveLength(0)
  expect(fake.store.has('approver')).toBe(false)
  expect(JSON.stringify(await ui.drawn())).not.toContain('271828')
  // The same in the deny reason, which the model would read.
  await ui.input({ key: 'reason-1', text: 'code 271828', kind: 'change' })
  await ui.press({ key: 'deny' })
  expect(await shows(ui, /looks like a TOTP code in the wrong field/)).toBe(true)
  // Still waiting: nothing was decided, nothing sent.
  expect(fake.calls()).toHaveLength(0)
  await ui.input({ key: 'reason-2', text: 'not today', kind: 'change' })
  await ui.press({ key: 'deny' })
  const out = await done(clock, call)
  expect(out.deny).toContain('not today')
  expect(out.deny).not.toContain('271828')
})

test('the approver name is remembered only after an approval worked', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.ssh_sudo_exec = ASK
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu31', host: 'h2', cmd: 'id' })
  const ui = await paneReady($, clock)
  await ui.input({ key: 'approver-0', text: 'alcie', kind: 'change' })
  await ui.input({ key: 'totp-0', text: '000000', kind: 'change' })
  await ui.press({ key: 'approve' })
  expect(fake.store.has('approver')).toBe(false)
  await ui.input({ key: 'approver-1', text: 'alice', kind: 'change' })
  await ui.input({ key: 'totp-1', text: CODE })
  expect((await done(clock, call)).deny).toBeUndefined()
  expect(fake.store.get('approver')).toBe('alice')
})

test('precheck unreachable: fail open, prompto decides, the model is told why no ticket came', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  fake.down = ['/v1/precheck']
  fake.results.ssh_sudo_exec = {
    error: { code: -32603, message: '[request_id=X error_class=approval_required] approval_required: rule policy.toml:36 needs a ticket' },
  }
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_sudo_exec', tool_use_id: 'tu15', host: 'h2', cmd: 'id' })
  expect(out.deny).toContain('approval_required')
  expect(out.deny).toContain('/v1/precheck was unavailable')
  // Sent once, without a ticket (none was invented).
  expect(fake.calls()).toHaveLength(1)
  expect(fake.calls()[0]!.body.params.arguments).toEqual({ host: 'h2', cmd: 'id' })
  // A call that needs nothing still works.
  const ok = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu16', host: 'h1', cmd: 'id' })
  expect(ok.deny).toBeUndefined()
})

test('nothing can be sent (no token): refused, never sent without one', async ($, on) => {
  mock.clock(on)
  const fake = install(on, { noToken: true })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu17', host: 'h1', cmd: 'id' })
  expect(out.deny).toContain('no token file')
  expect(fake.seen).toHaveLength(0)
})

test('the hook failing refuses the call (its .catch), it is not sent', async ($, on) => {
  mock.clock(on)
  const fake = install(on, { sessionThrows: true })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu18', host: 'h1', cmd: 'id' })
  expect(out.deny).toContain('prompto plugin')
  expect(out.deny).toContain('not sent')
  expect(fake.calls()).toHaveLength(0)
})

test('Claude Code\'s permission settings still apply to calls the plugin sends', async ($, on) => {
  mock.clock(on)
  // Were the verdict ignored and the person asked, they would allow it.
  const asked: string[] = []
  const fake = install(on, { check: 'deny', answer: 'Allow', asked })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu19', host: 'h1', cmd: 'id' })
  expect(out.deny).toContain('permission settings')
  expect(asked).toHaveLength(0)
  expect(fake.calls()).toHaveLength(0)
})

test('a permission ask is put to the person', async ($, on) => {
  mock.clock(on)
  const asked: string[] = []
  const fake = install(on, { check: 'ask', asked, answer: 'Deny' })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu20', host: 'h1', cmd: 'id' })
  expect(asked[0]).toContain('ssh_exec on h1')
  expect(out.deny).toContain('denied')
  expect(fake.calls()).toHaveLength(0)
})

test('a permission ask answered Allow sends the call', async ($, on) => {
  mock.clock(on)
  const fake = install(on, { check: 'ask', answer: 'Allow' })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu20b', host: 'h1', cmd: 'id' })
  expect(out.deny).toBeUndefined()
  expect(fake.calls()).toHaveLength(1)
})

test('a /prompto that can\'t be registered doesn\'t stop the plugin', async ($, on) => {
  mock.clock(on)
  const fake = install(on, { commandTaken: true })
  await start($)
  expect(fake.logs.join('\n')).toContain('/prompto is unavailable')
  const out = await $.tool.call({ tool: 'mcp__prompto__ssh_exec', tool_use_id: 'tu40', host: 'h1', cmd: 'id' })
  expect(out.deny).toBeUndefined()
  expect(fake.calls()).toHaveLength(1)
})

test('other servers\' tools are not touched', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  let reached = 0
  on('tool.call', { tool: 'mcp__other__ssh_exec' }, () => {
    reached += 1
    return { result: [{ type: 'text', text: 'theirs' }] } as never
  })
  await start($)
  await $.tool.call({ tool: 'mcp__other__ssh_exec', tool_use_id: 'tu21', host: 'h1', cmd: 'id' })
  expect(reached).toBe(1)
  expect(fake.seen).toHaveLength(0)
})

test('file_write: the pane diffs against the current file, read through prompto', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.file_write = { ...ASK, root: false }
  fake.results.file_read = { content: [{ type: 'text', text: JSON.stringify({ content: 'a\nb\nc\n', truncated: false }) }], isError: false }
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__file_write', tool_use_id: 'tu22', host: 'h2', path: '/etc/x.conf', content: 'a\nB\nc\n' })
  const ui = await paneReady($, clock)
  const diff = (await ui.findAll({ type: 'Code' })).find(c => c.props.format === 'diff')
  expect(String(diff?.props.source)).toContain('-b\n+B')
  expect(String(diff?.props.source)).toContain('@@ -1,3 +1,3 @@')
  expect(diff?.props.path).toBe('/etc/x.conf')
  const read = fake.calls().find(c => c.body.params.name === 'file_read')!
  expect(read.body.params.arguments).toEqual({ host: 'h2', path: '/etc/x.conf', max_bytes: 1048576 })
  await ui.press({ key: 'deny' })
  await done(clock, call)
})

test('file_write without a read grant: the pane says so', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { clock })
  fake.precheck.file_write = { ...ASK, root: false }
  fake.precheck.file_read = { decision: 'deny', error_class: 'refused_policy', reason: 'no grant for file_read on h2' }
  await start($)
  const call = $.tool.call({ tool: 'mcp__prompto__file_write', tool_use_id: 'tu23', host: 'h2', path: '/etc/x', content: 'x' })
  const ui = await paneReady($, clock)
  expect(await shows(ui, /no read grant: no grant for file_read on h2/)).toBe(true)
  expect((await ui.findAll({ type: 'Code' })).some(c => c.props.format === 'diff')).toBe(false)
  expect(fake.calls()).toHaveLength(0)
  await ui.press({ key: 'deny' })
  await done(clock, call)
})

test('transport engine: the ticket is added to the call Claude Code sends, no session', { options: { transport: 'engine' } }, async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  fake.precheck.bash_exec = { decision: 'allow', approval: 'ticket', ticket: 'pt1.minted' }
  const seen: Record<string, unknown>[] = []
  on('tool.call', { tool: 'mcp__prompto__bash_exec' }, ($, e) => {
    seen.push({ ...e })
    return { result: [{ type: 'text', text: 'ran' }] } as never
  })
  await start($)
  const out = await $.tool.call({ tool: 'mcp__prompto__bash_exec', tool_use_id: 'tu24', host: 'h1', script: 'id' })
  expect(out.deny).toBeUndefined()
  expect(seen).toHaveLength(1)
  expect(seen[0]!.ticket).toBe('pt1.minted')
  expect(seen[0]!.script).toBe('id')
  expect(fake.calls()).toHaveLength(0)
  expect(fake.seen[0]!.headers['X-Prompto-Session']).toBeUndefined()
})

test('a configured server name is a prompto too', { options: { servers: 'prompto-sbx' } }, async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  await start($)
  await $.tool.call({ tool: 'mcp__prompto-sbx__ssh_exec', tool_use_id: 'tu25', host: 'h1', cmd: 'id' })
  await $.tool.call({ tool: 'mcp__plugin_prompto_prompto__ssh_exec', tool_use_id: 'tu26', host: 'h1', cmd: 'id' })
  expect(fake.calls()).toHaveLength(2)
})

// ---------------------------------------------------------------------------
// /prompto
// ---------------------------------------------------------------------------

test('/prompto whoami, audit and kill', async ($, on) => {
  mock.clock(on)
  const fake = install(on)
  fake.audit = [{ ts: '2026-10-10T12:00:01.000Z', type: 'tool', tool: 'ssh_exec', host: 'h1', ok: true, args: { cmd: 'uptime' } }]
  await start($)
  const who = await $.command.run({ command: 'prompto', args: 'whoami' })
  expect(who.text).toContain('agent:   tester (groups: ops)')
  expect(who.text).toContain('session: sess-test')
  const audit = await $.command.run({ command: 'prompto', args: 'audit 5' })
  expect(audit.text).toContain('ssh_exec h1 ok')
  expect(fake.seen.at(-1)!.url).toContain('/v1/audit?session=sess-test&limit=5')
  const kill = await $.command.run({ command: 'prompto', args: 'kill looping' })
  expect(kill.text).toContain('killed session')
  expect(fake.seen.at(-1)!.body).toEqual({ scope: 'session', reason: 'looping' })
  const help = await $.command.run({ command: 'prompto', args: '' })
  expect(help.text).toContain('/prompto kill global')
})

test('/prompto kill global: only from the pane, with the code', async ($, on) => {
  const clock = mock.clock(on)
  const fake = install(on, { store: { approver: 'alice' }, clock })
  await start($)
  const r = await $.command.run({ command: 'prompto', args: 'kill global incident 7' })
  expect(r.text).toContain('pane')
  // The command itself sent nothing: the code isn't in its arguments.
  expect(fake.seen.filter(s => s.path === '/v1/kill')).toHaveLength(0)
  const ui = await paneReady($, clock)
  await ui.input({ key: 'totp-0', text: CODE, kind: 'change' })
  await ui.press({ key: 'approve' })
  const kills = fake.seen.filter(s => s.path === '/v1/kill')
  expect(kills).toHaveLength(1)
  expect(kills[0]!.body).toEqual({ scope: 'global', approver: 'alice', totp_code: CODE, reason: 'incident 7' })
  expect(await shows(ui, /No prompto approval is waiting/)).toBe(true)
})
