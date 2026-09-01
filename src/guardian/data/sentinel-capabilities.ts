/**
 * F1 (Lethal Trifecta) + I16 (Consent Fatigue) — a lightweight capability tagger.
 *
 * PORTED / DERIVED from MCP Sentinel:
 *   leg mapping     — f1-lethal-trifecta/data/capability-legs.ts (verbatim)
 *   fatigue tuning  — i16-consent-fatigue-exploitation/data/fatigue-parameters.ts (verbatim)
 *   classifier      — a LIGHTWEIGHT SUBSET of analyzers/capability-graph.ts (~1358 lines).
 *
 * Sentinel's capability graph is a large server-side classifier. Guardian can't
 * ship it in a browser bundle, so this is a compact verb+object / param-name
 * tagger over the SAME signals (description phrasing, parameter names, the
 * destructive annotation) and the SAME capability tags — honestly labeled a
 * subset. It is deliberately conservative: a capability outside these token
 * vocabularies is a Guardian miss that Sentinel's full graph would still catch.
 *
 * These two rules are PAGE-LEVEL (they need the whole tool set), so they are
 * computed by static-flags.ts → pageObservations, not per-tool.
 */

export type Capability =
  | "reads-private-data"
  | "writes-data"
  | "executes-code"
  | "accesses-filesystem"
  | "sends-network"
  | "ingests-untrusted"
  | "manages-credentials"
  | "destructive";

interface CapRule {
  verbs: readonly string[];
  objects: readonly string[];
  cap: Capability;
  weight: number;
}

/** Verb+object co-occurrence rules (mirrors capability-graph's descPatterns, tokenised). */
const CAP_RULES: readonly CapRule[] = [
  { cap: "reads-private-data", weight: 0.6, verbs: ["read", "get", "fetch", "list", "search", "export", "load", "retrieve", "dump", "return", "show"], objects: ["database", "credentials", "credential", "secret", "secrets", "private", "sensitive", "user", "notes", "note", "email", "emails", "contact", "contacts", "calendar", "message", "messages", "document", "documents", "record", "records", "file", "files", "history", "vault"] },
  { cap: "writes-data", weight: 0.6, verbs: ["write", "modify", "delete", "update", "create", "insert", "drop", "truncate", "add", "append", "save", "store", "set", "put", "patch"], objects: ["file", "files", "database", "record", "records", "table", "data", "document", "note", "notes", "entry"] },
  { cap: "executes-code", weight: 0.7, verbs: ["execute", "run", "invoke", "spawn", "eval"], objects: ["command", "script", "shell", "process", "program", "code", "binary"] },
  { cap: "sends-network", weight: 0.6, verbs: ["send", "post", "upload", "push", "notify", "transmit", "sync", "publish", "email", "submit", "forward", "dispatch"], objects: ["to", "via", "through", "external", "remote", "webhook", "http", "https", "url", "server", "endpoint", "api", "board", "community", "cloud", "slack", "discord", "telegram"] },
  { cap: "ingests-untrusted", weight: 0.6, verbs: ["scrape", "crawl", "fetch", "download", "ingest", "parse", "browse", "sync", "pull", "import"], objects: ["web", "external", "untrusted", "url", "remote", "community", "board", "feed", "rss", "comment", "comments", "issue", "issues", "incoming", "public", "internet", "site", "page", "webpage"] },
  { cap: "accesses-filesystem", weight: 0.5, verbs: ["read", "write", "list", "delete", "create", "open"], objects: ["file", "files", "directory", "directories", "folder", "folders", "path"] },
];

/** Param-name → capability signals. */
const PARAM_SIGNALS: Readonly<Record<string, Capability>> = {
  token: "manages-credentials", key: "manages-credentials", secret: "manages-credentials", password: "manages-credentials", credential: "manages-credentials", credentials: "manages-credentials", apikey: "manages-credentials", api_key: "manages-credentials",
  url: "sends-network", uri: "sends-network", endpoint: "sends-network", webhook: "sends-network", callback: "sends-network", notify_url: "sends-network",
  path: "accesses-filesystem", file_path: "accesses-filesystem", filepath: "accesses-filesystem", filename: "accesses-filesystem", dir: "accesses-filesystem", directory: "accesses-filesystem", folder: "accesses-filesystem",
  command: "executes-code", cmd: "executes-code", shell: "executes-code", exec: "executes-code", script: "executes-code",
};

/** Name/description destructive verbs. */
const DESTRUCTIVE_VERBS: ReadonlySet<string> = new Set(["delete", "remove", "drop", "destroy", "erase", "wipe", "truncate", "purge", "kill"]);

function toks(s: string): string[] {
  return (s || "").toLowerCase().split(/[^\p{L}\p{N}_]+/u).filter(Boolean);
}
/** Light stemmer so 'reads'/'fetching'/'parsed' match 'read'/'fetch'/'parse' (mirrors Sentinel's (?:s|ing|ed)? regexes). */
function stem(t: string): string {
  if (t.endsWith("ing") && t.length > 5) return t.slice(0, -3);
  if (t.endsWith("es") && t.length > 4) return t.slice(0, -2);
  if (t.endsWith("ed") && t.length > 4) return t.slice(0, -2);
  if (t.endsWith("s") && t.length > 3) return t.slice(0, -1);
  return t;
}
function inSet(set: Set<string>, t: string): boolean { return set.has(t) || set.has(stem(t)); }
function coOccurs(tokens: string[], verbs: readonly string[], objects: readonly string[], win = 6): boolean {
  const vpos: number[] = [], opos: number[] = [];
  const vs = new Set(verbs), os = new Set(objects);
  tokens.forEach((t, i) => { if (inSet(vs, t)) vpos.push(i); if (inSet(os, t)) opos.push(i); });
  return vpos.some((v) => opos.some((o) => Math.abs(v - o) <= win));
}

export interface CapTag { cap: Capability; confidence: number; detail: string }

/** Classify a tool's capabilities from name+description, param names, and annotations. */
export function classifyCapabilities(tool: { name?: string; description?: string; inputSchema?: unknown; annotations?: { destructiveHint?: boolean } }): CapTag[] {
  const out = new Map<Capability, CapTag>();
  const add = (cap: Capability, confidence: number, detail: string) => {
    const cur = out.get(cap);
    if (!cur || confidence > cur.confidence) out.set(cap, { cap, confidence, detail });
  };
  const tokens = toks(`${tool.name || ""} ${tool.description || ""}`);
  for (const r of CAP_RULES) if (coOccurs(tokens, r.verbs, r.objects)) add(r.cap, r.weight, `description phrasing (${r.cap})`);
  for (const t of tokens) if (DESTRUCTIVE_VERBS.has(t) || DESTRUCTIVE_VERBS.has(stem(t))) add("destructive", 0.6, `destructive verb '${t}'`);

  const schema = tool.inputSchema as any;
  const props = schema && typeof schema === "object" ? schema.properties : undefined;
  if (props && typeof props === "object") {
    for (const p of Object.keys(props)) {
      const cap = PARAM_SIGNALS[p.toLowerCase()];
      if (cap) add(cap, 0.7, `parameter named '${p}'`);
    }
  }
  if (tool.annotations?.destructiveHint === true) add("destructive", 0.9, "destructiveHint: true");
  return [...out.values()];
}

// ── F1 trifecta leg mapping (VERBATIM from capability-legs.ts) ──
export const PRIVATE_DATA_CAPS: readonly Capability[] = ["reads-private-data", "manages-credentials", "accesses-filesystem"];
export const UNTRUSTED_CONTENT_CAPS: readonly Capability[] = ["ingests-untrusted"];
export const EXTERNAL_COMMS_CAPS: readonly Capability[] = ["sends-network"];
export const TRIFECTA_MIN_LEG_CONFIDENCE = 0.5;
export const F1_CONFIDENCE_CAP = 0.9;

// ── I16 consent-fatigue thresholds (VERBATIM) ──
export const DANGEROUS_CAPS: ReadonlySet<Capability> = new Set(["executes-code", "sends-network", "manages-credentials", "writes-data", "destructive"]);
export const FATIGUE_THRESHOLDS = {
  min_total_tools: 10,
  min_benign_tools: 10,
  min_dangerous_tools: 1,
  max_dangerous_tools: 3,
  min_ratio: 5,
  min_capability_confidence: 0.5,
  confidence_cap: 0.7,
} as const;
