/**
 * Rule metadata — ported VERBATIM from MCP Sentinel's rule registry:
 *   packages/database/src/rule-registry.ts  (RULE_METADATA)
 *
 * These are the exact name / category / severity / OWASP / MITRE / remediation
 * strings Sentinel publishes for each rule. Guardian surfaces them on every
 * finding so a viewer sees the real Sentinel rule behind each observation — the
 * same remediation text a Sentinel scan would print — not a Guardian paraphrase.
 *
 * Only the browser-relevant rules Guardian actually uses are ported (8 of 183).
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export interface SentinelRuleMeta {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  owasp: string;
  mitre: string | null;
  remediation: string;
  /** How Guardian uses this rule in the browser. */
  guardianUse: string;
}

export const SENTINEL_RULES: Readonly<Record<string, SentinelRuleMeta>> = {
  A1: {
    id: "A1",
    name: "Prompt Injection in Tool Description",
    category: "description-analysis",
    severity: "critical",
    owasp: "MCP01-prompt-injection",
    mitre: "AML.T0054",
    remediation:
      "Remove all hidden instructions, role assignments, and directives from tool descriptions. Descriptions must only describe the tool's function. Any attempt to modify AI behavior via description text is a prompt injection attack.",
    guardianUse:
      "Guardian ports A1's injection-phrase catalogue and matches it structurally (ordered tokens within a gap) against each tool's description.",
  },
  A6: {
    id: "A6",
    name: "Unicode Homoglyph Attack in Tool Name or Description",
    category: "description-analysis",
    severity: "critical",
    owasp: "MCP02-tool-poisoning",
    mitre: "AML.T0054",
    remediation:
      "Tool names and descriptions must use only ASCII characters (U+0020–U+007E). Unicode homoglyphs in tool names are a primary vector for tool shadowing attacks where a Cyrillic 'a' is visually indistinguishable from a Latin 'a' but creates a different tool identity.",
    guardianUse:
      "Guardian ports a curated subset of A6's UTS-39 confusables and flags a look-alike letter only in a mixed-script context (a confusable-block letter inside otherwise-ASCII text).",
  },
  A7: {
    id: "A7",
    name: "Zero-Width and Invisible Character Injection",
    category: "description-analysis",
    severity: "critical",
    owasp: "MCP01-prompt-injection",
    mitre: "AML.T0054",
    remediation:
      "Strip all non-printable Unicode characters from tool names and descriptions before storing or serving them. Zero-width characters are used to hide prompt injection payloads that are invisible to humans reviewing the description but processed by LLMs.",
    guardianUse:
      "Guardian ports A7's invisible-codepoint catalogue verbatim and names the exact character class (zero-width, bidi-override, tag-character, …) it found.",
  },
  B6: {
    id: "B6",
    name: "Schema Allows Unconstrained Additional Properties",
    category: "schema-analysis",
    severity: "medium",
    owasp: "MCP07-insecure-config",
    mitre: null,
    remediation:
      "Set 'additionalProperties: false' on all tool input schemas. Allowing additional properties bypasses all parameter validation, enabling clients to pass arbitrary keys that server-side code may process unsafely.",
    guardianUse:
      "Guardian flags a tool whose inputSchema is missing or does not set additionalProperties:false — and its consent gate additionally validates real call args against the schema with Ajv.",
  },
  E5: {
    id: "E5",
    name: "Observed Declared-vs-Observed Behavior Divergence",
    category: "behavioral-analysis",
    severity: "high",
    owasp: "MCP04-data-exfiltration",
    mitre: "AML.T0057",
    remediation:
      "A tool's runtime behavior contradicted what it declared: a tool annotated readOnlyHint:true (or without destructiveHint) was observed to ATTEMPT an off-box send or to write state. Make annotations honest (declare openWorldHint/destructiveHint on any tool that reaches the network or mutates state), remove or gate the undeclared egress/write behind explicit confirmation, and add a destination allowlist to the sending tool.",
    guardianUse:
      "This is Guardian's headline finding, witnessed in the browser: a tool that declared read-only but is OBSERVED attempting external egress. Guardian blocks the egress and records the divergence. (Sentinel witnesses the server-side analogue in its ADR-007 T3 egress-denied sandbox.)",
  },
  J6: {
    id: "J6",
    name: "Tool Preference Manipulation",
    category: "threat-intelligence",
    severity: "high",
    owasp: "MCP02-tool-poisoning",
    mitre: "AML.T0054",
    remediation:
      "Tool descriptions should accurately describe what the tool does without preference manipulation. Remove superlative claims ('fastest', 'most reliable'), deprecation claims about other tools, and urgency signals ('always use this first'). Let the AI choose tools based on actual capability matching, not linguistic manipulation.",
    guardianUse:
      "Guardian ports J6's compositional vocabulary: it flags a preference operator ONLY when it binds to a tool-selection referent within a window, and demotes documentation frames — so honest deprecation notices are not flagged.",
  },
  I1: {
    id: "I1",
    name: "Tool Annotation Deception",
    category: "protocol-surface",
    severity: "critical",
    owasp: "MCP02-tool-poisoning",
    mitre: "AML.T0054",
    remediation:
      "Do not mark destructive tools as readOnlyHint=true. ChatGPT, JetBrains Copilot, and Roo Code skip confirmation dialogs for readOnlyHint tools. Set destructiveHint=true on any tool that modifies state.",
    guardianUse:
      "Guardian reads each tool's DECLARED readOnlyHint and contrasts it with witnessed behavior; a read-only claim paired with an observed write/egress is the divergence it gates on.",
  },
  G6: {
    id: "G6",
    name: "Tool Behavior Drift (Rug Pull Detection)",
    category: "adversarial-ai",
    severity: "critical",
    owasp: "MCP02-tool-poisoning",
    mitre: "AML.T0054",
    remediation:
      "A server exhibited drift from its previously known-good state — a pattern consistent with rug-pull attacks where a server gains trust before introducing malicious changes. Audit any tools added since the last clean state and require re-approval.",
    guardianUse:
      "Guardian's browser analogue is temporal: it flags any tool registered AFTER page load (mid-session injection) and records attempted overwrites of a trusted tool.",
  },
};

/** Convenience: look up a rule's metadata by id (e.g. "A7"), or null. */
export function ruleMeta(id: string): SentinelRuleMeta | null {
  return SENTINEL_RULES[id] ?? null;
}
