import { test, expect } from 'claude-code/testing'
import { unifiedDiff } from '../hooks/diff'
import { SHOW_MAX, argView, argsOf, auditLine, clean, commandOf, cutNote, looksLikeCode, rpcMessage, scopeKey, sha256, toolPattern, utf8 } from '../hooks/util'

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

test('commandOf: the command, the script, the batch, or the other arguments (file_write\'s content aside)', () => {
  expect(commandOf('ssh_exec', { host: 'h', cmd: 'id' })).toBe('id')
  expect(commandOf('bash_exec', { host: 'h', script: 'echo 1' })).toBe('echo 1')
  expect(commandOf('ssh_batch', { host: 'h', commands: ['a', 'b'] })).toBe('a\nb')
  const fw = commandOf('file_write', { host: 'h', path: '/p', content: 'body', ticket: 'pt1.x' })
  expect(fw).toBe('host=h path=/p')
})

test('argView: the main field first, then every other argument but the ticket, in order', () => {
  const v = argView({ host: 'h', timeout_secs: 30, cmd: 'id', env: { A: '1' }, flag: false, ticket: 'pt1.x', list: [1, 'a'] })
  expect(v.main).toEqual({ key: 'cmd', text: 'id', cut: null })
  expect(v.fields.map(f => f.key)).toEqual(['host', 'timeout_secs', 'env', 'flag', 'list'])
  expect(v.fields.map(f => f.text)).toEqual(['h', '30', '{\n  "A": "1"\n}', 'false', '[\n  1,\n  "a"\n]'])
  expect(JSON.stringify(v)).not.toContain('pt1.x')
  // No main field: everything is a field.
  expect(argView({ host: 'h', unit: 'nginx' })).toEqual({
    main: null,
    fields: [
      { key: 'host', text: 'h', cut: null },
      { key: 'unit', text: 'nginx', cut: null },
    ],
  })
})

test('argView: a value too long to draw is its head, its size and its sha256', () => {
  const big = 'é'.repeat(SHOW_MAX + 10)
  const [f] = argView({ content: big }).fields
  expect(f!.text.length).toBe(SHOW_MAX)
  expect(f!.cut).toEqual({ bytes: (SHOW_MAX + 10) * 2, sha256: sha256(utf8(big)) })
  expect(cutNote(f!)).toContain(`you are approving all ${(SHOW_MAX + 10) * 2} bytes, sha256 ${sha256(utf8(big))}`)
  expect(cutNote(argView({ content: 'short' }).fields[0]!)).toBeNull()
})

test('sha256 and utf8: known vectors', () => {
  expect(sha256(utf8(''))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  expect(sha256(utf8('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  expect(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))).toBe(
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  )
  expect(sha256(utf8('a'.repeat(1_000_000)))).toBe('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
  expect([...utf8('é€😀')]).toEqual([0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80])
})

test('clean: controls and bidi/format characters are drawn as escapes; newline and tab stay', () => {
  expect(clean('a\x1b[2Jb\rc\x07d\x9b')).toBe('a\\x1b[2Jb\\x0dc\\x07d\\x9b')
  for (const c of ['\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069', '\u200b', '\u200e', '\u200f', '\ufeff', '\u061c']) {
    const out = clean(`x${c}y`)
    expect(out).not.toContain(c)
    expect(out).toBe(`x\\u{${c.charCodeAt(0).toString(16)}}y`)
  }
  expect(clean('l1\n\tl2 é')).toBe('l1\n\tl2 é')
  expect(argView({ cmd: 'rm -rf /\u202e#' }).main!.text).toBe('rm -rf /\\u{202e}#')
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

test('looksLikeCode: six digits, alone or in small groups split by a space or a hyphen', () => {
  for (const t of ['123456', 'alice123456', 'code: 123456.', '123456 is it', '123 456', '123-456', 'ok 12-34-56', '1 2 3 4 5 6', 'x 12 345 6', '0000 00']) {
    expect([t, looksLikeCode(t)]).toEqual([t, true])
  }
  for (const t of ['alice', 'sbx-approver', '12345', '1234567', 'policy.toml:36', 'ticket 2026-10-10', 'host 10.0.0.1', '12 345', 'ap-1 2']) {
    expect([t, looksLikeCode(t)]).toEqual([t, false])
  }
})

test('auditLine: hazards in a record are escaped', () => {
  const line = auditLine({ ts: '2026-10-10T13:30:54.000Z', type: 'tool', tool: 'ssh_exec', host: 'h\u202e1', ok: true, args: { cmd: 'echo \x1b]0;x\x07' } })
  expect(line).not.toMatch(/[\x00-\x1f\u202e]/)
  expect(line).toContain('h\\u{202e}1')
})

test('auditLine: a call shows its outcome, a precheck its decision', () => {
  const base = { ts: '2026-10-10T13:30:54.000Z', tool: 'ssh_sudo_exec', host: 'h2', args: { cmd: 'id -u' } }
  expect(auditLine({ ...base, type: 'tool', ok: true })).toBe('13:30:54 ssh_sudo_exec h2 ok id -u')
  expect(auditLine({ ...base, type: 'tool', ok: false, error_class: 'remote_nonzero' })).toBe('13:30:54 ssh_sudo_exec h2 remote_nonzero id -u')
  expect(auditLine({ ...base, type: 'precheck', ok: true, decision: 'ask' })).toBe('13:30:54 precheck:ssh_sudo_exec h2 ask id -u')
  expect(auditLine({ ...base, type: 'approve', ok: true, decision: 'allow', approved_by: 'alice' })).toBe('13:30:54 approve:ssh_sudo_exec h2 allow by=alice id -u')
})
