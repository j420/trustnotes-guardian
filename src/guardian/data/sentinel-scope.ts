/**
 * A2 — Excessive Scope Claims vocabulary.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/a2-excessive-scope-claims/data/scope-claims.ts
 *
 * A claim (modifier + scope noun co-located within a small token window) is
 * evidence ONLY when the description does not also state its own boundary
 * (BOUNDING_TOKENS) — "full access … within allowed directories" is honest, not
 * an over-claim. Guardian ports both halves (see static-flags.ts → detectScope).
 */

export interface ClaimSpec {
  modifier_tokens: readonly string[];
  noun_tokens: readonly string[];
  weight: number;
  label: string;
  max_gap: number;
}

const UNRESTRICTED_MODIFIERS: readonly string[] = ["full", "complete", "unrestricted", "unlimited", "unfettered"];
const BROAD_MODIFIERS: readonly string[] = ["all", "any", "every", "entire"];
const ACCESS_NOUNS: readonly string[] = ["access", "control", "permission", "privilege", "permissions"];
const DATA_NOUNS: readonly string[] = ["files", "data", "records", "resources"];
const ELEVATED_ROLE_NOUNS: readonly string[] = ["admin", "administrator", "root", "superuser", "god"];
const ELEVATED_ROLE_MODE_NOUNS: readonly string[] = ["mode", "privilege", "access", "role"];
const READ_WRITE_VERBS: readonly string[] = ["read", "write", "modify", "delete"];

export const CLAIM_SPECS: readonly ClaimSpec[] = [
  { modifier_tokens: UNRESTRICTED_MODIFIERS, noun_tokens: ACCESS_NOUNS, weight: 0.85, label: "unrestricted-access", max_gap: 2 },
  { modifier_tokens: BROAD_MODIFIERS, noun_tokens: DATA_NOUNS, weight: 0.75, label: "all-data-scope", max_gap: 2 },
  { modifier_tokens: ELEVATED_ROLE_NOUNS, noun_tokens: ELEVATED_ROLE_MODE_NOUNS, weight: 0.85, label: "elevated-role-claim", max_gap: 1 },
  { modifier_tokens: READ_WRITE_VERBS, noun_tokens: BROAD_MODIFIERS, weight: 0.8, label: "read-write-any", max_gap: 1 },
];

/** Self-bounding containment vocabulary — presence in the same description suppresses the claim. */
const CONTAINMENT_LOCATION: readonly string[] = ["within", "allowed", "allowlist", "whitelist", "specified"];
const CONTAINMENT_QUALIFIER: readonly string[] = ["designated", "configured", "scoped", "sandbox", "sandboxed"];
export const BOUNDING_TOKENS: readonly string[] = [...CONTAINMENT_LOCATION, ...CONTAINMENT_QUALIFIER];
