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
  /**
   * Everything the ticket covers, as drawn: `main` (cmd, script, commands
   * or task) first, then every other argument (`ticket` aside). Texts are
   * already safe to draw; a value past the pane's limit is its head, and
   * `cut` says how many bytes are approved in all, and their SHA-256.
   */
  main: PromptoField | null
  fields: PromptoField[]
  /** file_write: `<n> bytes, sha256 <hex>` of the new content. */
  contentSum: string | null
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
  /** The call behind it is gone (the plugin reloaded): nothing to approve. */
  stale: boolean
}

/** One argument as the approval pane draws it. */
export type PromptoField = {
  key: string
  text: string
  cut: { bytes: number; sha256: string } | null
}

declare module 'claude-code' {
  interface PluginState {
    // Shaped: a plugin of another version reads what this one left as absent.
    prompto: { pending: Shaped<PromptoPending[]> }
  }
}
