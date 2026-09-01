/** Shared Guardian domain types. Guardian judges tools by what they DO, not what they say. */

export type Provenance = "initial" | "mid-session";

/** A witnessed side effect during a tool's execution window. */
export interface SideEffect {
  kind: "network" | "storage" | "clipboard" | "beacon" | "websocket";
  detail: string; // e.g. the URL, or the storage key
  external: boolean; // network egress to a non-same-origin host
  blocked: boolean; // Guardian denied it
  at: number;
}

/** A plain, un-scored static observation about a tool's declared metadata. */
export interface StaticObservation {
  id: string; // e.g. "UNICODE-HOMOGLYPH"
  label: string; // human sentence
  sentinelRule: string; // e.g. "A6"
  evidence: string;
}

/** How a tool's OBSERVED behavior relates to its DECLARED annotations. */
export type DivergenceKind = "none" | "readonly-violation" | "undeclared-egress";

export interface DivergenceFinding {
  kind: DivergenceKind;
  declared: string; // what the tool said
  observed: string; // what Guardian witnessed
  sentinelRule: string; // E5 (declared-vs-observed divergence)
}

/** The full behavioral record Guardian keeps per registered tool. */
export interface ToolRecord {
  name: string;
  description: string;
  declaredReadOnly: boolean;
  inputSchema: unknown;
  provenance: Provenance;
  registeredAt: number;
  observedRuns: number; // real executions witnessed
  probeRuns: number; // deny-all dry-runs witnessed
  sideEffects: SideEffect[]; // witnessed effects (real + probe), newest last
  staticFlags: StaticObservation[];
  divergences: DivergenceFinding[];
  /** "not-yet-observed" until the tool has actually run or been probed. */
  status: "not-yet-observed" | "consistent" | "diverged" | "flagged";
}

export interface TimelineEvent {
  at: number;
  kind: "register" | "attempted-overwrite" | "observe" | "probe" | "block" | "consent";
  tool: string;
  detail: string;
}

/** A minimal structural view of a WebMCP tool descriptor. */
export interface WebMcpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; [k: string]: unknown };
  execute: (args: any) => any;
}
