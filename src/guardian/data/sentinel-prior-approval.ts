/**
 * G5 — Prior-Approval Phrase Catalogue.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/g5-capability-escalation-prior-approval/data/prior-approval-phrases.ts
 *
 * The attack: a description manufactures a pre-existing grant ("uses the
 * permissions you already granted", "same access as the clone tool") so the
 * agent applies a referenced permission without a fresh approval. Guardian
 * matches each phrase structurally (ordered tokens within max_gap) AND requires
 * a PERMISSION_NOUN in the window (adjacency suppression) so "Use alongside
 * read_file" is not flagged. See static-flags.ts → detectPriorApproval.
 */

export type PriorApprovalCategory =
  | "explicit-prior-approval"
  | "permission-inheritance"
  | "session-state-reference"
  | "pre-declared-escalation"
  | "assumed-consent-by-absence";

export interface PhraseSpec {
  readonly tokens: readonly string[];
  readonly weight: number;
  readonly label: string;
  readonly max_gap: number;
  readonly category: PriorApprovalCategory;
}

const EXPLICIT_PRIOR_APPROVAL: readonly PhraseSpec[] = [
  { tokens: ["permissions", "you", "already", "granted"], weight: 0.9, label: "explicit prior approval — permissions you already granted", max_gap: 1, category: "explicit-prior-approval" },
  { tokens: ["you", "already", "approved"], weight: 0.88, label: "explicit prior approval — you already approved", max_gap: 1, category: "explicit-prior-approval" },
  { tokens: ["previously", "granted"], weight: 0.85, label: "explicit prior approval — previously granted", max_gap: 1, category: "explicit-prior-approval" },
  { tokens: ["access", "you", "previously", "authorized"], weight: 0.88, label: "explicit prior approval — access previously authorized", max_gap: 2, category: "explicit-prior-approval" },
  { tokens: ["user", "already", "consented"], weight: 0.86, label: "explicit prior approval — user already consented", max_gap: 2, category: "explicit-prior-approval" },
];

const PERMISSION_INHERITANCE: readonly PhraseSpec[] = [
  { tokens: ["same", "permissions", "as"], weight: 0.82, label: "permission inheritance — same permissions as", max_gap: 1, category: "permission-inheritance" },
  { tokens: ["same", "access", "as"], weight: 0.8, label: "permission inheritance — same access as", max_gap: 1, category: "permission-inheritance" },
  { tokens: ["inherits", "filesystem", "access"], weight: 0.85, label: "permission inheritance — inherits filesystem access", max_gap: 2, category: "permission-inheritance" },
  { tokens: ["shares", "scope"], weight: 0.75, label: "permission inheritance — shares scope", max_gap: 2, category: "permission-inheritance" },
  { tokens: ["equivalent", "permissions"], weight: 0.78, label: "permission inheritance — equivalent permissions", max_gap: 2, category: "permission-inheritance" },
];

const SESSION_STATE_REFERENCE: readonly PhraseSpec[] = [
  { tokens: ["continues", "where", "the", "previous", "tool"], weight: 0.85, label: "session-state reference — continues where previous tool", max_gap: 1, category: "session-state-reference" },
  { tokens: ["permission", "state", "established"], weight: 0.82, label: "session-state reference — permission state established", max_gap: 2, category: "session-state-reference" },
  { tokens: ["resumes", "the", "elevated", "context"], weight: 0.88, label: "session-state reference — resumes elevated context", max_gap: 1, category: "session-state-reference" },
  { tokens: ["session", "permissions"], weight: 0.74, label: "session-state reference — session permissions", max_gap: 1, category: "session-state-reference" },
  { tokens: ["earlier", "approval"], weight: 0.78, label: "session-state reference — earlier approval", max_gap: 2, category: "session-state-reference" },
];

const PRE_DECLARED_ESCALATION: readonly PhraseSpec[] = [
  { tokens: ["re", "use", "your", "session", "permissions"], weight: 0.88, label: "pre-declared escalation — re-use session permissions", max_gap: 2, category: "pre-declared-escalation" },
  { tokens: ["upgrades", "scope", "on", "demand"], weight: 0.88, label: "pre-declared escalation — upgrades scope on demand", max_gap: 2, category: "pre-declared-escalation" },
  { tokens: ["extend", "your", "access"], weight: 0.78, label: "pre-declared escalation — extend your access", max_gap: 1, category: "pre-declared-escalation" },
  { tokens: ["elevate", "privilege"], weight: 0.8, label: "pre-declared escalation — elevate privilege", max_gap: 2, category: "pre-declared-escalation" },
  { tokens: ["previously", "granted", "rights"], weight: 0.85, label: "pre-declared escalation — previously granted rights", max_gap: 1, category: "pre-declared-escalation" },
];

const ASSUMED_CONSENT: readonly PhraseSpec[] = [
  { tokens: ["haven", "revoked"], weight: 0.82, label: "assumed consent — haven't revoked", max_gap: 2, category: "assumed-consent-by-absence" },
  { tokens: ["still", "authorised"], weight: 0.78, label: "assumed consent — still authorised", max_gap: 1, category: "assumed-consent-by-absence" },
  { tokens: ["still", "authorized"], weight: 0.78, label: "assumed consent — still authorized", max_gap: 1, category: "assumed-consent-by-absence" },
  { tokens: ["default", "grant"], weight: 0.72, label: "assumed consent — default grant", max_gap: 1, category: "assumed-consent-by-absence" },
  { tokens: ["continues", "to", "operate", "with", "full"], weight: 0.86, label: "assumed consent — continues to operate with full", max_gap: 1, category: "assumed-consent-by-absence" },
];

export const PRIOR_APPROVAL_PHRASES: readonly PhraseSpec[] = [
  ...EXPLICIT_PRIOR_APPROVAL,
  ...PERMISSION_INHERITANCE,
  ...SESSION_STATE_REFERENCE,
  ...PRE_DECLARED_ESCALATION,
  ...ASSUMED_CONSENT,
];

/** Permission-noun lexicon — a phrase only counts with one of these in its window (adjacency suppression). */
export const PERMISSION_NOUNS: Readonly<Record<string, true>> = {
  access: true, permission: true, permissions: true, scope: true, rights: true,
  auth: true, privilege: true, privileges: true, consent: true, authorised: true, authorized: true,
};

/** Aggregate below which G5 stays silent (noisy-OR over matched phrases). */
export const G5_CONFIDENCE_FLOOR = 0.75;
