/**
 * J3 — Full Schema Poisoning.
 *
 * PORTED (config verbatim) from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/j3-full-schema-poisoning/data/config.ts
 *
 * CyberArk's FSP research: LLMs read every JSON-Schema field as authoritative
 * documentation, so `enum` / `const` / `title` / `default` are injection
 * surfaces. J3 is SHAPE-based, not a phrase list — a SENTENCE in an enum slot is
 * structurally anomalous whatever it says (real enum members are short, similar,
 * one-domain: `["asc","desc"]`). Guardian ports the shape thresholds + the
 * addressee markers. See static-flags.ts → detectSchemaPoisoning.
 */

export const J3_CONFIDENCE_CAP = 0.88;

export const J3_SHAPE = {
  /** Word count above which a value in a token-shaped slot (enum/const/title) is prose. */
  prose_word_threshold: 8,
  /** Ratio by which one enum member may exceed the median sibling length before divergence. */
  sibling_divergence_ratio: 4,
  /** Minimum sibling count for the divergence measure to be meaningful. */
  sibling_min_count: 3,
  /** Minimum absolute length for a divergent member (suppresses noise on trivial strings). */
  sibling_min_outlier_chars: 20,
  /** Per-field-kind weight for a shape anomaly. */
  field_weight: {
    enum: 0.7, const: 0.65, title: 0.55, default: 0.5, examples: 0.2,
  } as Readonly<Record<string, number>>,
  /** Weight for a sibling-divergence observation inside an enum. */
  sibling_divergence_weight: 0.75,
  /** Aggregate below which J3 stays silent. */
  confidence_floor: 0.45,
} as const;

/** Second-person / deontic markers whose presence in a value slot states it is addressed to a reader. */
export const SLOT_ADDRESSEE_MARKERS: Readonly<Record<string, string>> = {
  you: "second-person pronoun in a value slot",
  your: "second-person possessive in a value slot",
  assistant: "vocative 'assistant' in a value slot",
  model: "vocative 'model' in a value slot",
  must: "deontic 'must' in a value slot",
  should: "deontic 'should' in a value slot",
  always: "directive adverb 'always' in a value slot",
  never: "directive adverb 'never' in a value slot",
};
