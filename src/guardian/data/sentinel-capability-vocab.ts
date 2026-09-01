/**
 * A8 — Description-Capability Mismatch vocabulary.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/a8-description-capability-mismatch/data/capability-vocab.ts
 *
 * A8 is the STATIC twin of E5: a description that claims read-only / safe while
 * the input schema carries write-capable or network-send parameters (or a
 * dangerous default) is deceptive labeling — caught before the tool ever runs.
 * (E5 catches the same deception witnessed at runtime.) See static-flags.ts → detectMismatch.
 */

export interface ClaimPhrase {
  tokens: readonly string[];
  weight: number;
  label: string;
  max_gap: number;
}

export const READ_ONLY_CLAIMS: readonly ClaimPhrase[] = [
  { tokens: ["read", "only"], weight: 0.85, label: "read-only claim", max_gap: 1 },
  { tokens: ["readonly"], weight: 0.85, label: "readonly claim", max_gap: 0 },
  { tokens: ["just", "reads"], weight: 0.8, label: "just-reads claim", max_gap: 1 },
  { tokens: ["only", "reads"], weight: 0.8, label: "only-reads claim", max_gap: 1 },
  { tokens: ["safe"], weight: 0.6, label: "safe claim", max_gap: 0 },
  { tokens: ["non", "destructive"], weight: 0.85, label: "non-destructive claim", max_gap: 1 },
  { tokens: ["nondestructive"], weight: 0.85, label: "nondestructive claim", max_gap: 0 },
  { tokens: ["no", "side", "effects"], weight: 0.85, label: "no-side-effects claim", max_gap: 1 },
];

export const WRITE_PARAM_TOKENS: ReadonlySet<string> = new Set([
  "delete", "remove", "write", "create", "update",
  "modify", "overwrite", "drop", "truncate", "kill",
  "terminate", "execute", "run", "send", "post",
  "put", "patch", "destroy", "erase", "reset",
]);

export const NETWORK_PARAM_TOKENS: ReadonlySet<string> = new Set([
  "webhook", "webhook_url", "callback", "endpoint", "url", "notify", "notify_url",
]);

export interface DangerousDefault {
  value_tokens: readonly string[];
  label: string;
}

export const DANGEROUS_DEFAULTS: Readonly<Record<string, DangerousDefault>> = {
  overwrite: { value_tokens: ["true"], label: "overwrite: true" },
  recursive: { value_tokens: ["true"], label: "recursive: true" },
  force: { value_tokens: ["true"], label: "force: true" },
  delete: { value_tokens: ["true"], label: "delete: true" },
};
