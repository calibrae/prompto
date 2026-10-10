import { test, expect } from 'claude-code/testing'
import { unifiedDiff } from '../hooks/diff'
import { argsOf, auditLine, commandOf, looksLikeCode, rpcMessage, scopeKey, toolPattern } from '../hooks/util'

test('diff: one changed line, with context and line numbers', () => {
  const d = unifiedDiff('a\nb\nc\nd\ne\nf\ng\nh\n', 'a\nb\nc\nd\nE\nf\ng\nh\n', 'x')
  expect(d).toBe('--- a/x\n+++ b/x\n@@ -2,7 +2,7 @@\n b\n c\n d\n-e\n+E\n f\n g\n h\n')
})

test('diff: a new file, an emptied file, no change', () => {
  expect(unifiedDiff('', 'one\ntwo\n', 'n')).toBe('--- a/n\n+++ b/n\n@@ -0,0 +1,2 @@\n+one\n+two\n')
  expect(unifiedDiff('one\n', '', 'n')).toBe('--- a/n\n+++ b/n\n@@ -1,1 +0,0 @@\n-one\n')
  expect(unifiedDiff('same\n', 'same\n', 'n')).toBe('')
})

test('diff: far-apart changes are separate hunks', () => {
  const before = Array.from({ length: 30 }, (_, i) => `l${i}`).join('\n') + '\n'
  const after = before.replace('l2\n', 'L2\n').replace('l25\n', 'L25\n')
  const d = unifiedDiff(before, after, 'f')
  expect(d.match(/^@@/gm)?.length).toBe(2)
  expect(d).toContain('-l2\n+L2\n')
  expect(d).toContain('-l25\n+L25\n')
})

test('diff: only the final newline differs', () => {
  const d = unifiedDiff('x\n', 'x', 'f')
  expect(d).toContain('@@')
  expect(d).toContain('no newline at end of file')
})

test('argsOf drops only the engine\'s keys and copies the rest as JSON', () => {
  const e = { tool: 'mcp__prompto__x', tool_use_id: 't', agentId: 'a', requestMeta: {}, consent: 'c', host: 'h', n: 1, nested: { b: [1, 2] } }
  expect(argsOf(e)).toEqual({ host: 'h', n: 1, nested: { b: [1, 2] } })
})

test('commandOf: the command, the script, the batch, or the arguments without content or ticket', () => {
  expect(commandOf('ssh_exec', { host: 'h', cmd: 'id' })).toBe('id')
  expect(commandOf('bash_exec', { host: 'h', script: 'echo 1' })).toBe('echo 1')
  expect(commandOf('ssh_batch', { host: 'h', commands: ['a', 'b'] })).toBe('a\nb')
  const fw = commandOf('file_write', { host: 'h', path: '/p', content: 'secret-ish body', ticket: 'pt1.x' })
  expect(fw).toContain('"path": "/p"')
  expect(fw).toContain('<15 chars: see the diff>')
  expect(fw).not.toContain('pt1.x')
})

test('toolPattern: this plugin\'s server and the configured ones, nothing else', () => {
  const re = toolPattern('prompto, prompto-sbx')
  expect(re.exec('mcp__prompto__ssh_exec')?.[1]).toBe('ssh_exec')
  expect(re.exec('mcp__prompto-sbx__file_read')?.[1]).toBe('file_read')
  expect(re.exec('mcp__plugin_prompto_prompto__vm_list')?.[1]).toBe('vm_list')
  expect(re.exec('mcp__promptox__ssh_exec')).toBeNull()
  expect(re.exec('mcp__other__ssh_exec')).toBeNull()
  expect(toolPattern('a.b').exec('mcp__aXb__t')).toBeNull()
})

test('scopeKey: session, tool and host(s)', () => {
  expect(scopeKey('s', 'rsync_sync', { source_host: 'a', dest_host: 'b', src: '/x' })).toBe('s|rsync_sync|a|b')
  expect(scopeKey(undefined, 'ssh_exec', { host: 'h', cmd: 'x' })).toBe('|ssh_exec|h|')
})

test('rpcMessage: plain JSON or an SSE data line', () => {
  expect(rpcMessage('{"jsonrpc":"2.0","id":1,"result":{"a":1}}')?.result).toEqual({ a: 1 })
  expect(rpcMessage('event: message\ndata: {"jsonrpc":"2.0","id":1,"error":{"message":"x"}}\n\n')?.error).toEqual({ message: 'x' })
  expect(rpcMessage('not json')).toBeUndefined()
})

test('looksLikeCode: a run of exactly six digits', () => {
  for (const t of ['123456', 'alice123456', 'code: 123456.', '123456 is it']) expect(looksLikeCode(t)).toBe(true)
  for (const t of ['alice', 'sbx-approver', '12345', '1234567', 'policy.toml:36', 'ticket 2026-10-10']) expect(looksLikeCode(t)).toBe(false)
})

test('auditLine: a call shows its outcome, a precheck its decision', () => {
  const base = { ts: '2026-10-10T13:30:54.000Z', tool: 'ssh_sudo_exec', host: 'h2', args: { cmd: 'id -u' } }
  expect(auditLine({ ...base, type: 'tool', ok: true })).toBe('13:30:54 ssh_sudo_exec h2 ok id -u')
  expect(auditLine({ ...base, type: 'tool', ok: false, error_class: 'remote_nonzero' })).toBe('13:30:54 ssh_sudo_exec h2 remote_nonzero id -u')
  expect(auditLine({ ...base, type: 'precheck', ok: true, decision: 'ask' })).toBe('13:30:54 precheck:ssh_sudo_exec h2 ask id -u')
  expect(auditLine({ ...base, type: 'approve', ok: true, decision: 'allow', approved_by: 'alice' })).toBe('13:30:54 approve:ssh_sudo_exec h2 allow by=alice id -u')
})
