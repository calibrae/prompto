/**
 * One request waiting for a person in the approval pane: a tool call a
 * policy rule says a human must approve, or a global kill from
 * `/prompto kill global`.
 *
 * Deliberately holds no TOTP code: the code lives in one variable of the
 * module from the keystroke to the /v1/approve request, then is dropped.
 */
export type PromptoPending = {
  /** The tool_use_id of the call, or `kill-<n>`. */
  id: string
  kind: 'call' | 'kill-global'
  /** prompto's tool name (`ssh_sudo_exec`). */
  tool: string
  host: string | null
  /** What will run: the command, the script, or the arguments as JSON. */
  command: string
  /** file_write's path, for the diff's header. */
  path: string | null
  /** The policy rule that asked, and its reason. */
  rule: string | null
  reason: string
  /** Root-capable: "approve for N minutes" needs the root-scope toggle. */
  root: boolean
  /** file_write: the unified diff, or why there is none. */
  diff: string | null
  diffNote: string | null
  /** The agent's recent audit records on that host, one line each. */
  audit: readonly string[]
  auditNote: string | null
  approver: string
  rootScope: boolean
  /** The last outcome to show (wrong code, locked out, ...). */
  message: string | null
  isBusy: boolean
  /** Bumped after every approval attempt: the code field is drawn anew, empty. */
  generation: number
}

declare module 'claude-code' {
  interface PluginState {
    prompto: { pending: PromptoPending[] }
  }
}
