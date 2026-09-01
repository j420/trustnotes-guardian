/**
 * J6 — Compositional vocabulary for tool-preference manipulation.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/j6-tool-preference-manipulation/data/preference-composition.ts
 *
 * The attack (MPMA, 2025) is a RELATION, not a phrase: the description positions
 * this tool against the rest of the tool surface so the model's selection pass
 * routes traffic here. Guardian ports Sentinel's key insight — detecting it needs
 * TWO co-occurring constituents within a binding window:
 *   1. a PRIORITY / EXCLUSIVITY / REPLACEMENT operator, and
 *   2. a TOOL-SELECTION REFERENT (the tool surface itself — not an arbitrary noun).
 * Plus a DOCUMENTATION-FRAME demotion, so an honest deprecation notice
 * ("supersedes the export_report tool … see the migration guide") is NOT flagged.
 * This is why Guardian passes Sentinel's own hard negatives (the "always returns
 * the first row" data-noun trap; the "alwaysOnCache" substring trap) that a naive
 * keyword matcher fails. See static-flags.ts → detectPreferenceManipulation.
 */

export type OperatorClass = "priority" | "exclusivity" | "replacement";

export interface OperatorSpec {
  kind: OperatorClass;
  weight: number;
  label: string;
}

export const PRIORITY_OPERATORS: Readonly<Record<string, OperatorSpec>> = {
  always: { kind: "priority", weight: 0.5, label: "priority operator — 'always'" },
  first: { kind: "priority", weight: 0.45, label: "priority operator — 'first'" },
  preferred: { kind: "priority", weight: 0.6, label: "priority operator — 'preferred'" },
  prefer: { kind: "priority", weight: 0.6, label: "priority operator — 'prefer'" },
  preferentially: { kind: "priority", weight: 0.65, label: "priority operator — 'preferentially'" },
  primary: { kind: "priority", weight: 0.5, label: "priority operator — 'primary'" },
  priority: { kind: "priority", weight: 0.5, label: "priority operator — 'priority'" },
  foremost: { kind: "priority", weight: 0.55, label: "priority operator — 'foremost'" },
  default: { kind: "priority", weight: 0.4, label: "priority operator — 'default'" },
  best: { kind: "priority", weight: 0.4, label: "priority operator — 'best'" },
  recommended: { kind: "priority", weight: 0.45, label: "priority operator — 'recommended'" },
};

export const EXCLUSIVITY_OPERATORS: Readonly<Record<string, OperatorSpec>> = {
  only: { kind: "exclusivity", weight: 0.6, label: "exclusivity operator — 'only'" },
  never: { kind: "exclusivity", weight: 0.6, label: "exclusivity operator — 'never'" },
  exclusively: { kind: "exclusivity", weight: 0.7, label: "exclusivity operator — 'exclusively'" },
  sole: { kind: "exclusivity", weight: 0.65, label: "exclusivity operator — 'sole'" },
  instead: { kind: "exclusivity", weight: 0.55, label: "exclusivity operator — 'instead'" },
  rather: { kind: "exclusivity", weight: 0.5, label: "exclusivity operator — 'rather than'" },
  avoid: { kind: "exclusivity", weight: 0.6, label: "exclusivity operator — 'avoid'" },
  disregard: { kind: "exclusivity", weight: 0.7, label: "exclusivity operator — 'disregard'" },
  ignore: { kind: "exclusivity", weight: 0.7, label: "exclusivity operator — 'ignore'" },
};

export const REPLACEMENT_OPERATORS: Readonly<Record<string, OperatorSpec>> = {
  replaces: { kind: "replacement", weight: 0.5, label: "replacement operator — 'replaces'" },
  replacing: { kind: "replacement", weight: 0.5, label: "replacement operator — 'replacing'" },
  supersedes: { kind: "replacement", weight: 0.6, label: "replacement operator — 'supersedes'" },
  obsoletes: { kind: "replacement", weight: 0.65, label: "replacement operator — 'obsoletes'" },
  deprecates: { kind: "replacement", weight: 0.5, label: "replacement operator — 'deprecates'" },
  overrides: { kind: "replacement", weight: 0.6, label: "replacement operator — 'overrides'" },
};

/**
 * Referents that make an operator apply to the TOOL SURFACE rather than to data.
 * ("server"/"servers" are deliberately absent — too common in benign prose.)
 */
export const SELECTION_REFERENTS: Readonly<Record<string, string>> = {
  tool: "tool-selection referent — 'tool'",
  tools: "tool-selection referent — 'tools'",
  toolset: "tool-selection referent — 'toolset'",
  function: "tool-selection referent — 'function'",
  functions: "tool-selection referent — 'functions'",
  integration: "tool-selection referent — 'integration'",
  alternative: "tool-selection referent — 'alternative'",
  alternatives: "tool-selection referent — 'alternatives'",
  competitor: "tool-selection referent — 'competitor'",
};

/**
 * OTHERNESS markers — what make a generic tool noun the OBJECT OF A COMPARISON
 * rather than a self-reference. Preference manipulation is inherently
 * comparative: a generic tool noun is only admissible as a referent when one of
 * these scopes it. (This is what rejects "the tool will ignore empty strings".)
 */
export const UNIVERSAL_QUANTIFIERS: Readonly<Record<string, string>> = {
  any: "universal quantifier — 'any'",
  all: "universal quantifier — 'all'",
  every: "universal quantifier — 'every'",
  other: "universal quantifier — 'other'",
  others: "universal quantifier — 'others'",
  another: "universal quantifier — 'another'",
  else: "universal quantifier — 'else'",
  alternative: "universal quantifier — 'alternative'",
  alternatives: "universal quantifier — 'alternatives'",
  competing: "universal quantifier — 'competing'",
};

/**
 * Documentation frames in which a replacement claim is ordinary project hygiene
 * rather than manipulation. Presence demotes the aggregate (a migration note
 * genuinely says "replaces the old export_csv tool").
 */
export const DOCUMENTATION_FRAMES: Readonly<Record<string, string>> = {
  deprecated: "documentation frame — deprecation notice",
  deprecation: "documentation frame — deprecation notice",
  migration: "documentation frame — migration guide",
  migrating: "documentation frame — migration guide",
  changelog: "documentation frame — changelog",
  legacy: "documentation frame — legacy reference",
  since: "documentation frame — version note",
  version: "documentation frame — version note",
  removed: "documentation frame — removal note",
  historical: "documentation frame — historical note",
  example: "documentation frame — example",
  tutorial: "documentation frame — tutorial",
  docs: "documentation frame — documentation reference",
};

/** Verbs that denote invoking a tool (for negated-use exclusivity). */
export const INVOCATION_VERBS: Readonly<Record<string, string>> = {
  use: "invocation verb — 'use'",
  using: "invocation verb — 'using'",
  call: "invocation verb — 'call'",
  calling: "invocation verb — 'calling'",
  invoke: "invocation verb — 'invoke'",
  invoking: "invocation verb — 'invoking'",
  select: "invocation verb — 'select'",
  choose: "invocation verb — 'choose'",
};

/** Negators that scope over a following invocation verb. */
export const NEGATORS: Readonly<Record<string, string>> = {
  not: "negator — 'not'",
  never: "negator — 'never'",
  dont: "negator — \"don't\"",
  avoid: "negator — 'avoid'",
  refrain: "negator — 'refrain from'",
  without: "negator — 'without'",
};

export const NEGATION_SCOPE_TOKENS = 3;
export const NEGATED_USE_WEIGHT = 0.75;

export const J6_COMPOSITION = {
  /** Max token distance between an operator and its referent to be one construction. */
  binding_window_tokens: 6,
  /** Multiplier applied when a documentation frame is present. */
  documentation_frame_multiplier: 0.35,
  /** Multiplier applied when the sentence is third-person rather than directive. */
  descriptive_multiplier: 0.6,
  /** Aggregate below which J6 stays silent. */
  confidence_floor: 0.45,
  /** Aggregate at which J6 reports `high`. */
  high_floor: 0.6,
} as const;
