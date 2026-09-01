/**
 * A1 — Injection Phrase Catalogue.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/a1-prompt-injection-description/data/injection-phrases.ts
 *
 * The `INJECTION_PHRASES` table below is the *same* catalogue the server-side A1
 * rule iterates — every entry, weight, category, and max_gap. Guardian matches
 * it the same structural way: it tokenises the description and tests for each
 * spec's ordered token sequence within `max_gap` (see static-flags.ts →
 * matchPhrase). This is a subset of Sentinel's full A1 analysis (Guardian ports
 * the phrase catalogue and ordered-token matching; it does NOT port A1's
 * use/mention framing or delimiter-position analysis). Also ported: the
 * literal LLM special-token and JSON role-marker tables.
 */

export type InjectionCategory =
  | "role-override"
  | "role-reassignment"
  | "confirmation-bypass"
  | "mandatory-execution"
  | "privilege-escalation"
  | "hidden-instruction"
  | "exfiltration-directive"
  | "multi-turn-setup"
  | "prior-approval-claim";

export interface PhraseSpec {
  /** Ordered sequence of required content tokens (lowercase). */
  tokens: readonly string[];
  /** Independent probability weight for noisy-OR aggregation. */
  weight: number;
  /** Human-readable label used in the evidence chain. */
  label: string;
  /** Semantic category. */
  category: InjectionCategory;
  /** Maximum token distance between adjacent tokens to allow flexible matching. */
  max_gap: number;
}

const ROLE_OVERRIDE: readonly PhraseSpec[] = [
  { tokens: ["ignore", "previous"], weight: 0.95, label: "role override — ignore previous", category: "role-override", max_gap: 2 },
  { tokens: ["ignore", "prior"], weight: 0.94, label: "role override — ignore prior", category: "role-override", max_gap: 2 },
  { tokens: ["ignore", "above"], weight: 0.9, label: "role override — ignore above", category: "role-override", max_gap: 2 },
  { tokens: ["disregard", "previous"], weight: 0.94, label: "role override — disregard previous", category: "role-override", max_gap: 2 },
  { tokens: ["disregard", "all", "instructions"], weight: 0.94, label: "role override — disregard all instructions", category: "role-override", max_gap: 1 },
  { tokens: ["forget", "previous"], weight: 0.92, label: "role override — forget previous", category: "role-override", max_gap: 2 },
  { tokens: ["forget", "all", "rules"], weight: 0.92, label: "role override — forget rules", category: "role-override", max_gap: 1 },
  { tokens: ["override", "default"], weight: 0.85, label: "role override — override default", category: "role-override", max_gap: 2 },
];

const ROLE_REASSIGNMENT: readonly PhraseSpec[] = [
  { tokens: ["you", "are", "now"], weight: 0.88, label: "role reassignment — you are now", category: "role-reassignment", max_gap: 0 },
  { tokens: ["act", "as"], weight: 0.7, label: "role reassignment — act as", category: "role-reassignment", max_gap: 0 },
  { tokens: ["pretend", "to", "be"], weight: 0.82, label: "role reassignment — pretend to be", category: "role-reassignment", max_gap: 0 },
  { tokens: ["your", "new", "role"], weight: 0.9, label: "role reassignment — your new role", category: "role-reassignment", max_gap: 1 },
  { tokens: ["from", "now", "on"], weight: 0.8, label: "role reassignment — from now on", category: "role-reassignment", max_gap: 0 },
  { tokens: ["behave", "as"], weight: 0.72, label: "role reassignment — behave as", category: "role-reassignment", max_gap: 0 },
];

const CONFIRMATION_BYPASS: readonly PhraseSpec[] = [
  { tokens: ["do", "not", "ask"], weight: 0.88, label: "confirmation bypass — do not ask", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["do", "not", "confirm"], weight: 0.9, label: "confirmation bypass — do not confirm", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["without", "confirmation"], weight: 0.82, label: "confirmation bypass — without confirmation", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["skip", "verification"], weight: 0.86, label: "confirmation bypass — skip verification", category: "confirmation-bypass", max_gap: 2 },
  { tokens: ["never", "prompt"], weight: 0.78, label: "confirmation bypass — never prompt", category: "confirmation-bypass", max_gap: 2 },
];

const MANDATORY_EXECUTION: readonly PhraseSpec[] = [
  { tokens: ["always", "execute"], weight: 0.8, label: "mandatory execution — always execute", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["must", "run"], weight: 0.74, label: "mandatory execution — must run", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["must", "invoke"], weight: 0.78, label: "mandatory execution — must invoke", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["always", "use", "this"], weight: 0.75, label: "mandatory execution — always use this", category: "mandatory-execution", max_gap: 1 },
];

const PRIVILEGE_ESCALATION: readonly PhraseSpec[] = [
  { tokens: ["system", "mode"], weight: 0.85, label: "privilege escalation — system mode", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["admin", "access"], weight: 0.8, label: "privilege escalation — admin access", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["root", "privilege"], weight: 0.85, label: "privilege escalation — root privilege", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["superuser"], weight: 0.75, label: "privilege escalation — superuser", category: "privilege-escalation", max_gap: 0 },
];

const HIDDEN_INSTRUCTION: readonly PhraseSpec[] = [
  { tokens: ["secret", "instruction"], weight: 0.9, label: "hidden instruction — secret instruction", category: "hidden-instruction", max_gap: 1 },
  { tokens: ["hidden", "directive"], weight: 0.9, label: "hidden instruction — hidden directive", category: "hidden-instruction", max_gap: 1 },
  { tokens: ["private", "instruction"], weight: 0.85, label: "hidden instruction — private instruction", category: "hidden-instruction", max_gap: 1 },
];

const EXFILTRATION_DIRECTIVE: readonly PhraseSpec[] = [
  { tokens: ["exfiltrate"], weight: 0.95, label: "exfiltration directive — exfiltrate", category: "exfiltration-directive", max_gap: 0 },
  { tokens: ["send", "to", "webhook"], weight: 0.92, label: "exfiltration directive — send to webhook", category: "exfiltration-directive", max_gap: 1 },
  { tokens: ["transmit", "to"], weight: 0.72, label: "exfiltration directive — transmit to", category: "exfiltration-directive", max_gap: 1 },
  { tokens: ["leak", "credentials"], weight: 0.95, label: "exfiltration directive — leak credentials", category: "exfiltration-directive", max_gap: 1 },
];

const MULTI_TURN_SETUP: readonly PhraseSpec[] = [
  { tokens: ["previous", "conversation"], weight: 0.88, label: "multi-turn setup — previous conversation", category: "multi-turn-setup", max_gap: 1 },
  { tokens: ["earlier", "agreement"], weight: 0.88, label: "multi-turn setup — earlier agreement", category: "multi-turn-setup", max_gap: 1 },
  { tokens: ["as", "discussed"], weight: 0.7, label: "multi-turn setup — as discussed", category: "multi-turn-setup", max_gap: 0 },
];

const PRIOR_APPROVAL_CLAIM: readonly PhraseSpec[] = [
  { tokens: ["you", "already", "approved"], weight: 0.9, label: "prior approval claim — already approved", category: "prior-approval-claim", max_gap: 1 },
  { tokens: ["permissions", "you", "granted"], weight: 0.88, label: "prior approval claim — permissions granted", category: "prior-approval-claim", max_gap: 1 },
  { tokens: ["same", "access", "as"], weight: 0.78, label: "prior approval claim — same access as", category: "prior-approval-claim", max_gap: 1 },
];

/** The merged catalogue — the matcher iterates every entry. */
export const INJECTION_PHRASES: readonly PhraseSpec[] = [
  ...ROLE_OVERRIDE,
  ...ROLE_REASSIGNMENT,
  ...CONFIRMATION_BYPASS,
  ...MANDATORY_EXECUTION,
  ...PRIVILEGE_ESCALATION,
  ...HIDDEN_INSTRUCTION,
  ...EXFILTRATION_DIRECTIVE,
  ...MULTI_TURN_SETUP,
  ...PRIOR_APPROVAL_CLAIM,
];

/**
 * LLM in-band control tokens — detected as exact substrings. A tokeniser
 * shibboleth (`<|im_start|>`, `[INST]`, `<<SYS>>`) is self-delimiting and is not
 * made safe by quotation, so its presence alone is high-signal. (Sentinel's
 * `prose-shaped` markers like `### System` are deliberately omitted here — they
 * need Sentinel's delimiter-position analysis to avoid false positives.)
 */
export const LLM_SPECIAL_TOKENS: readonly string[] = [
  "<|im_start|>",
  "<|im_end|>",
  "<|endoftext|>",
  "<|system|>",
  "<|user|>",
  "<|assistant|>",
  "[INST]",
  "[/INST]",
  "<<SYS>>",
  "<</SYS>>",
];
