/**
 * B2 — Dangerous Parameter Types.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/b2-dangerous-parameter-types/data/dangerous-names.ts
 *
 * A schema parameter whose NAME advertises an injection sink (command, sql,
 * path, url…) is evidence — unless the value set is CLOSED by an `enum`/`const`
 * (then it can't be an injection primitive no matter its name). `pattern` /
 * `maxLength` / `format` deliberately do NOT close a value set. See
 * static-flags.ts → detectDangerousParams.
 */

export type DangerousSink =
  | "command-execution"
  | "sql-execution"
  | "code-evaluation"
  | "file-write"
  | "template-render"
  | "network-send";

export const DANGEROUS_PARAM_NAMES: Readonly<Record<string, { sink: DangerousSink; rationale: string }>> = {
  command: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  cmd: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  shell: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  exec: { sink: "command-execution", rationale: "Name advertises exec() call" },
  script: { sink: "command-execution", rationale: "Name advertises script execution" },
  sql: { sink: "sql-execution", rationale: "Name advertises SQL query" },
  query: { sink: "sql-execution", rationale: "Name advertises database query" },
  code: { sink: "code-evaluation", rationale: "Name advertises generic code evaluation" },
  eval: { sink: "code-evaluation", rationale: "Name advertises eval() call" },
  template: { sink: "template-render", rationale: "Name advertises template rendering" },
  path: { sink: "file-write", rationale: "Name advertises filesystem path" },
  file_path: { sink: "file-write", rationale: "Name advertises filesystem path" },
  filepath: { sink: "file-write", rationale: "Name advertises filesystem path" },
  filename: { sink: "file-write", rationale: "Name advertises filesystem path" },
  url: { sink: "network-send", rationale: "Name advertises network endpoint" },
  uri: { sink: "network-send", rationale: "Name advertises network endpoint" },
  endpoint: { sink: "network-send", rationale: "Name advertises network endpoint" },
};

/** Keywords that CLOSE a value set to a finite, author-chosen list. */
export const VALUE_CLOSING_KEYWORDS: Readonly<Record<string, true>> = {
  enum: true,
  const: true,
};
