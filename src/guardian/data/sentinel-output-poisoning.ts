/**
 * J5 — Tool Output Poisoning (CyberArk ATPA).
 *
 * PORTED from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/j5-tool-output-poisoning/data/config.ts
 *
 * The DIRECTIVE vocabulary is ported (subset). Sentinel's server-side J5 walks
 * the TS AST to find return/throw/response-emitter sites, then runs this matcher
 * on the string content. Guardian is BETTER positioned: it WITNESSES the tool's
 * actual runtime return value in the browser, so it runs the SAME matcher on the
 * real returned text — no AST needed. See static-flags.ts → outputObservations.
 *
 * The FP-control gate is ported faithfully:
 *   "match"         — the phrase itself is an imperative to the AI client, or a
 *                     verb+private-key-path signature. Reports on the phrase alone.
 *   "reader-action" — generic co-occurrence ("read credentials", "please run").
 *                     Reports ONLY when the returned string ALSO carries an
 *                     assistant-directed co-signal (a remediation frame like
 *                     "to fix"/"to resolve", a credential-path token, or a
 *                     second-person address outside the matched span).
 */

export const J5_CONFIDENCE_CAP = 0.82;

export type DirectiveKind = "credential-access" | "exec-directive" | "role-override";
export type DirectiveGate = "match" | "reader-action";

export interface DirectiveSpec {
  readonly tokens: readonly string[];
  readonly max_gap: number;
  readonly kind: DirectiveKind;
  readonly weight: number;
  readonly label: string;
  readonly gate: DirectiveGate;
}

const CREDENTIAL_ACCESS: Readonly<Record<string, DirectiveSpec>> = {
  read_ssh: { tokens: ["read", "ssh"], kind: "credential-access", weight: 0.9, max_gap: 2, label: "credential-access directive — read the .ssh directory", gate: "match" },
  read_id_rsa: { tokens: ["read", "id_rsa"], kind: "credential-access", weight: 0.92, max_gap: 2, label: "credential-access directive — read id_rsa private key", gate: "match" },
  ssh_id_rsa_path: { tokens: ["ssh", "id_rsa"], kind: "credential-access", weight: 0.9, max_gap: 1, label: "credential-access directive — .ssh/id_rsa path", gate: "match" },
  read_credentials: { tokens: ["read", "credentials"], kind: "credential-access", weight: 0.88, max_gap: 2, label: "credential-access directive — read credentials", gate: "reader-action" },
  aws_credentials_file: { tokens: ["aws", "credentials"], kind: "credential-access", weight: 0.85, max_gap: 1, label: "credential-access directive — ~/.aws/credentials", gate: "reader-action" },
  read_private_key: { tokens: ["read", "private", "key"], kind: "credential-access", weight: 0.88, max_gap: 1, label: "credential-access directive — read private key", gate: "reader-action" },
  send_credentials: { tokens: ["send", "credentials"], kind: "credential-access", weight: 0.86, max_gap: 2, label: "credential-access directive — send credentials", gate: "reader-action" },
};

const EXEC_DIRECTIVE: Readonly<Record<string, DirectiveSpec>> = {
  please_execute: { tokens: ["please", "execute"], kind: "exec-directive", weight: 0.82, max_gap: 2, label: "exec directive — please execute", gate: "match" },
  run_the_following: { tokens: ["run", "the", "following"], kind: "exec-directive", weight: 0.8, max_gap: 1, label: "exec directive — run the following", gate: "match" },
  execute_the_command: { tokens: ["execute", "the", "command"], kind: "exec-directive", weight: 0.8, max_gap: 1, label: "exec directive — execute the command", gate: "match" },
  please_run: { tokens: ["please", "run"], kind: "exec-directive", weight: 0.78, max_gap: 2, label: "exec directive — please run", gate: "reader-action" },
  you_should_call: { tokens: ["you", "should", "call"], kind: "exec-directive", weight: 0.85, max_gap: 1, label: "exec directive — you should call", gate: "reader-action" },
  you_must_call: { tokens: ["you", "must", "call"], kind: "exec-directive", weight: 0.85, max_gap: 1, label: "exec directive — you must call", gate: "reader-action" },
};

const ROLE_OVERRIDE: Readonly<Record<string, DirectiveSpec>> = {
  ignore_previous: { tokens: ["ignore", "previous"], kind: "role-override", weight: 0.92, max_gap: 2, label: "role override — ignore previous", gate: "match" },
  ignore_all_previous: { tokens: ["ignore", "all", "previous"], kind: "role-override", weight: 0.93, max_gap: 1, label: "role override — ignore all previous", gate: "match" },
  disregard_previous: { tokens: ["disregard", "previous"], kind: "role-override", weight: 0.9, max_gap: 2, label: "role override — disregard previous", gate: "match" },
  disregard_instructions: { tokens: ["disregard", "all", "instructions"], kind: "role-override", weight: 0.9, max_gap: 1, label: "role override — disregard all instructions", gate: "match" },
  forget_previous: { tokens: ["forget", "previous"], kind: "role-override", weight: 0.88, max_gap: 2, label: "role override — forget previous", gate: "match" },
};

export const J5_DIRECTIVES: Readonly<Record<string, DirectiveSpec>> = { ...CREDENTIAL_ACCESS, ...EXEC_DIRECTIVE, ...ROLE_OVERRIDE };

/** Reader-directed co-signals — a "reader-action" directive fires ONLY with one of these present. */
export const J5_REMEDIATION_FRAMES: readonly (readonly string[])[] = [
  ["to", "fix"], ["to", "resolve"], ["to", "proceed"], ["to", "continue"], ["in", "order", "to"],
];
export const J5_CREDENTIAL_PATH_TOKENS: Readonly<Record<string, true>> = { id_rsa: true, ssh: true };
export const J5_ADDRESS_TOKENS: Readonly<Record<string, true>> = { you: true, please: true };
/** Private-key filename tokens; a following `pub` marks the public (benign) half. */
export const J5_PRIVATE_KEY_FILENAME_TOKENS: Readonly<Record<string, true>> = { id_rsa: true, id_ed25519: true, id_ecdsa: true, id_dsa: true };
export const J5_PUBLIC_KEY_TOKEN = "pub";
