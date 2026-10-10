// A unified diff of two texts, for the approval pane's file_write view.
// Common head and tail are trimmed; the middle is diffed line by line by
// LCS when it is small enough, else shown as removed-then-added.

const CONTEXT = 3
/** Cells of the LCS table at most (rows x columns of the middle). */
const MAX_CELLS = 4_000_000

type Op = { kind: ' ' | '-' | '+'; line: string }

function lines(text: string): string[] {
  if (text === '') return []
  const out = text.split('\n')
  if (out[out.length - 1] === '') out.pop()
  return out
}

function middle(a: string[], b: string[]): Op[] {
  const n = a.length
  const m = b.length
  if (n * m > MAX_CELLS) {
    return [...a.map(line => ({ kind: '-' as const, line })), ...b.map(line => ({ kind: '+' as const, line }))]
  }
  // lcs[i][j]: LCS length of a[i..] and b[j..], one flat array.
  const w = m + 1
  const lcs = new Uint32Array((n + 1) * w)
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i * w + j] = a[i] === b[j] ? lcs[(i + 1) * w + j + 1]! + 1 : Math.max(lcs[(i + 1) * w + j]!, lcs[i * w + j + 1]!)
    }
  }
  const ops: Op[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ kind: ' ', line: a[i]! })
      i++
      j++
    } else if (lcs[(i + 1) * w + j]! >= lcs[i * w + j + 1]!) {
      ops.push({ kind: '-', line: a[i++]! })
    } else {
      ops.push({ kind: '+', line: b[j++]! })
    }
  }
  while (i < n) ops.push({ kind: '-', line: a[i++]! })
  while (j < m) ops.push({ kind: '+', line: b[j++]! })
  return ops
}

/**
 * The unified diff from `before` to `after`, `---`/`+++` headers naming
 * `path`; `''` when they are equal.
 */
export function unifiedDiff(before: string, after: string, path: string): string {
  const a = lines(before)
  const b = lines(after)
  let head = 0
  while (head < a.length && head < b.length && a[head] === b[head]) head++
  let tail = 0
  while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++
  if (head === a.length && head === b.length) return before === after ? '' : noteEol(before, after, path)
  const ops: Op[] = [
    ...a.slice(0, head).map(line => ({ kind: ' ' as const, line })),
    ...middle(a.slice(head, a.length - tail), b.slice(head, b.length - tail)),
    ...a.slice(a.length - tail).map(line => ({ kind: ' ' as const, line })),
  ]
  // Hunks: changed ops with CONTEXT lines around, merged when close.
  const changed = ops.map((o, k) => (o.kind === ' ' ? -1 : k)).filter(k => k >= 0)
  const hunks: Array<[number, number]> = []
  for (const k of changed) {
    const lo = Math.max(0, k - CONTEXT)
    const hi = Math.min(ops.length, k + CONTEXT + 1)
    const last = hunks[hunks.length - 1]
    if (last && lo <= last[1]) last[1] = Math.max(last[1], hi)
    else hunks.push([lo, hi])
  }
  const out = [`--- a/${path}`, `+++ b/${path}`]
  // Line numbers at each op index.
  let oldNo = 1
  let newNo = 1
  const at: Array<[number, number]> = ops.map(o => {
    const here: [number, number] = [oldNo, newNo]
    if (o.kind !== '+') oldNo++
    if (o.kind !== '-') newNo++
    return here
  })
  for (const [lo, hi] of hunks) {
    const slice = ops.slice(lo, hi)
    const oldLen = slice.filter(o => o.kind !== '+').length
    const newLen = slice.filter(o => o.kind !== '-').length
    const [o0, n0] = at[lo]!
    out.push(`@@ -${oldLen === 0 ? o0 - 1 : o0},${oldLen} +${newLen === 0 ? n0 - 1 : n0},${newLen} @@`)
    for (const o of slice) out.push(o.kind + o.line)
  }
  return out.join('\n') + '\n'
}

function noteEol(before: string, after: string, path: string): string {
  // Same lines, different final newline.
  const a = lines(before)
  const last = a[a.length - 1] ?? ''
  const n = a.length
  return [
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -${n},1 +${n},1 @@`,
    `-${last}${before.endsWith('\n') ? '' : ' (no newline at end of file)'}`,
    `+${last}${after.endsWith('\n') ? '' : ' (no newline at end of file)'}`,
  ].join('\n') + '\n'
}
