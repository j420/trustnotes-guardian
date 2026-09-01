/**
 * G2 — Trust Assertion Injection.
 *
 * PORTED from MCP Sentinel:
 *   authority claims — _shared/ai-manipulation-phrases.ts (G2_AUTHORITY_CLAIMS)
 *   consequences     — g2-trust-assertion-injection/data/trust-consequences.ts
 *
 * An authority claim ALONE ("approved by Anthropic") is only a truthfulness
 * problem. The ATTACK is the COMPOSITION: authority claim + a trust CONSEQUENCE
 * that cashes it out as reduced scrutiny ("…so no confirmation is required").
 * Guardian requires both, within a binding window, and requires a WAIVER
 * operator to scope a consequence token (so "requires confirmation" is NOT a
 * waiver). See static-flags.ts → detectTrustAssertion.
 */

export interface AuthorityClaim {
  tokens: readonly string[];
  weight: number;
  max_gap: number;
  label: string;
}

/** Subset of G2_AUTHORITY_CLAIMS (the unverifiable endorsement/certification claims). */
export const AUTHORITY_CLAIMS: readonly AuthorityClaim[] = [
  { tokens: ["approved", "by", "anthropic"], weight: 0.92, max_gap: 2, label: "authority claim — approved by Anthropic" },
  { tokens: ["approved", "by", "openai"], weight: 0.92, max_gap: 2, label: "authority claim — approved by OpenAI" },
  { tokens: ["certified", "by"], weight: 0.8, max_gap: 2, label: "certification claim — certified by <vendor>" },
  { tokens: ["endorsed", "by"], weight: 0.8, max_gap: 2, label: "authority claim — endorsed by <vendor>" },
  { tokens: ["verified", "by"], weight: 0.78, max_gap: 2, label: "authority claim — verified by <party>" },
  { tokens: ["security", "audited"], weight: 0.85, max_gap: 2, label: "certification claim — security audited" },
  { tokens: ["soc2", "certified"], weight: 0.82, max_gap: 2, label: "certification claim — SOC2 certified" },
  { tokens: ["officially", "certified"], weight: 0.85, max_gap: 1, label: "certification claim — officially certified" },
  { tokens: ["official", "mcp", "server"], weight: 0.85, max_gap: 1, label: "authority claim — official MCP server" },
  { tokens: ["trusted", "by"], weight: 0.72, max_gap: 2, label: "authority claim — trusted by <party>" },
  { tokens: ["safety", "approved"], weight: 0.85, max_gap: 2, label: "certification claim — safety approved" },
  { tokens: ["administrator", "approved"], weight: 0.82, max_gap: 2, label: "authority claim — administrator approved" },
];

export type ConsequenceKind = "confirmation-waiver" | "verification-waiver" | "trust-grant";

export interface ConsequenceSpec {
  kind: ConsequenceKind;
  weight: number;
  label: string;
}

/** Consequence tokens that only count as a waiver when a WAIVER_OPERATOR scopes them. */
export const CONSEQUENCE_TOKENS: Readonly<Record<string, ConsequenceSpec>> = {
  confirmation: { kind: "confirmation-waiver", weight: 0.6, label: "trust consequence — 'confirmation'" },
  confirm: { kind: "confirmation-waiver", weight: 0.55, label: "trust consequence — 'confirm'" },
  approval: { kind: "confirmation-waiver", weight: 0.55, label: "trust consequence — 'approval'" },
  approve: { kind: "confirmation-waiver", weight: 0.55, label: "trust consequence — 'approve'" },
  prompt: { kind: "confirmation-waiver", weight: 0.45, label: "trust consequence — 'prompt'" },
  ask: { kind: "confirmation-waiver", weight: 0.4, label: "trust consequence — 'ask'" },
  verify: { kind: "verification-waiver", weight: 0.55, label: "trust consequence — 'verify'" },
  verification: { kind: "verification-waiver", weight: 0.55, label: "trust consequence — 'verification'" },
  validate: { kind: "verification-waiver", weight: 0.5, label: "trust consequence — 'validate'" },
  validation: { kind: "verification-waiver", weight: 0.5, label: "trust consequence — 'validation'" },
  review: { kind: "verification-waiver", weight: 0.45, label: "trust consequence — 'review'" },
  scrutiny: { kind: "verification-waiver", weight: 0.6, label: "trust consequence — 'scrutiny'" },
};

/** Negators / waiver operators that must scope a consequence token for it to count. */
export const WAIVER_OPERATORS: Readonly<Record<string, string>> = {
  no: "waiver operator — 'no'",
  not: "waiver operator — 'not'",
  never: "waiver operator — 'never'",
  without: "waiver operator — 'without'",
  skip: "waiver operator — 'skip'",
  bypass: "waiver operator — 'bypass'",
  omit: "waiver operator — 'omit'",
  avoid: "waiver operator — 'avoid'",
  unnecessary: "waiver operator — 'unnecessary'",
  needless: "waiver operator — 'needless'",
  exempt: "waiver operator — 'exempt'",
  waived: "waiver operator — 'waived'",
  bypasses: "waiver operator — 'bypasses'",
  skips: "waiver operator — 'skips'",
};

/** Direct trust grants — assert the agent may act freely without a waiver operator. */
export const TRUST_GRANT_TOKENS: Readonly<Record<string, ConsequenceSpec>> = {
  autoapprove: { kind: "trust-grant", weight: 0.7, label: "trust grant — 'auto-approve'" },
  autoapproved: { kind: "trust-grant", weight: 0.7, label: "trust grant — 'auto-approved'" },
  whitelisted: { kind: "trust-grant", weight: 0.65, label: "trust grant — 'whitelisted'" },
  allowlisted: { kind: "trust-grant", weight: 0.65, label: "trust grant — 'allowlisted'" },
  preapproved: { kind: "trust-grant", weight: 0.7, label: "trust grant — 'pre-approved'" },
  preauthorized: { kind: "trust-grant", weight: 0.7, label: "trust grant — 'pre-authorized'" },
};

export const G2_COMPOSITION = {
  /** Token distance within which a waiver operator binds a consequence token. */
  waiver_scope_tokens: 6,
  /** Distance within which a consequence must sit from an authority claim to be ITS consequence. */
  consequence_binding_tokens: 30,
} as const;
// NOTE: G2 fires on the COMPOSITION only — an authority claim ALONE never fires
// (it is merely an unverifiable endorsement). A finding requires an authority
// claim AND, within `consequence_binding_tokens`, either a CONSEQUENCE_TOKEN
// scoped by a WAIVER_OPERATOR or a bare TRUST_GRANT_TOKEN.
