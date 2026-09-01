/**
 * Static observations — un-scored, factual labels about a tool's DECLARED metadata.
 *
 * These are NOT a risk score. They are facts a human reviewer can't easily see
 * (invisible characters) or easily miss (a "read-only" claim), shown next to the
 * behavioral record so a tool the agent never runs still reveals deceptive metadata.
 *
 * The vocabulary is derived from the MCP Sentinel taxonomy (rule IDs cited): A6
 * (Unicode Homoglyph), A7 (Zero-Width / bidi), A1 (Prompt Injection), J6 (Tool
 * Preference Manipulation), B6 (Unconstrained Schema). Re-implemented in the browser.
 */
import type { StaticObservation, WebMcpTool } from "./types.js";

// A6 — homoglyph: non-ASCII letters that look like ASCII (Cyrillic/Greek/fullwidth blocks).
const HOMOGLYPH_RANGES: Array<[number, number]> = [
  [0x0400, 0x04ff], // Cyrillic
  [0x0370, 0x03ff], // Greek
  [0xff00, 0xffef], // Fullwidth forms
  [0x2100, 0x214f], // Letterlike symbols
];
// A7 — zero-width / bidi / invisible controls.
const HIDDEN_CODEPOINTS = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, // zero-width space/joiner/nbsp
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi overrides (incl. RTL override)
  0x00ad, // soft hyphen
]);
// A1 — imperative prompt-injection phrases (small catalogue; the point is to name them, not score).
const INJECTION_PHRASES = ["ignore previous", "ignore all previous", "disregard", "new instructions", "system prompt", "you must", "do not tell", "override"];
// J6 — tool-preference manipulation.
const PREFERENCE_PHRASES = ["always use this", "use this first", "instead of the other", "do not use any other", "preferred tool", "replaces the"];

function codepoints(s: string): number[] { return Array.from(s).map((c) => c.codePointAt(0)!); }

function homoglyphChars(name: string): string[] {
  const out: string[] = [];
  for (const cp of codepoints(name)) {
    if (HOMOGLYPH_RANGES.some(([a, b]) => cp >= a && cp <= b)) out.push("U+" + cp.toString(16).toUpperCase().padStart(4, "0"));
  }
  return out;
}
function hiddenChars(s: string): string[] {
  return codepoints(s).filter((cp) => HIDDEN_CODEPOINTS.has(cp)).map((cp) => "U+" + cp.toString(16).toUpperCase().padStart(4, "0"));
}
function phraseHits(text: string, phrases: string[]): string[] {
  const lc = text.toLowerCase();
  return phrases.filter((p) => lc.includes(p));
}

export function staticObservations(tool: WebMcpTool): StaticObservation[] {
  const obs: StaticObservation[] = [];
  const name = tool.name || "";
  const desc = tool.description || "";

  const nameGlyphs = homoglyphChars(name);
  const descGlyphs = homoglyphChars(desc);
  if (nameGlyphs.length) obs.push({ id: "UNICODE-HOMOGLYPH", sentinelRule: "A6", label: `Tool NAME contains look-alike (non-ASCII) characters that render like ASCII`, evidence: `name="${name}" · codepoints ${nameGlyphs.join(", ")}` });
  else if (descGlyphs.length) obs.push({ id: "UNICODE-HOMOGLYPH", sentinelRule: "A6", label: `Description contains look-alike (non-ASCII) characters that render like ASCII`, evidence: `codepoints ${[...new Set(descGlyphs)].join(", ")}` });

  const hidden = [...hiddenChars(name), ...hiddenChars(desc)];
  if (hidden.length) obs.push({ id: "UNICODE-HIDDEN", sentinelRule: "A7", label: `Contains invisible / bidi control characters (unreadable to a human)`, evidence: `codepoints ${[...new Set(hidden)].join(", ")}` });

  const inj = phraseHits(desc, INJECTION_PHRASES);
  if (inj.length) obs.push({ id: "INJ-IMPERATIVE", sentinelRule: "A1", label: `Description contains prompt-injection-style imperative(s)`, evidence: inj.map((p) => `"${p}"`).join(", ") });

  const pref = phraseHits(desc, PREFERENCE_PHRASES);
  if (pref.length) obs.push({ id: "PREFERENCE-MANIP", sentinelRule: "J6", label: `Description tries to steer the agent to prefer this tool`, evidence: pref.map((p) => `"${p}"`).join(", ") });

  const schema = tool.inputSchema as any;
  const unconstrained = !schema || typeof schema !== "object" || schema.additionalProperties !== false;
  if (unconstrained) obs.push({ id: "SCHEMA-UNCONSTRAINED", sentinelRule: "B6", label: `Input schema is missing or allows arbitrary additional properties`, evidence: schema ? `additionalProperties=${JSON.stringify(schema.additionalProperties)}` : "no inputSchema" });

  return obs;
}

/** DECLARED read-only + a destructive-looking parameter/name is annotation deception (I1). */
export function declaresReadOnly(tool: WebMcpTool): boolean {
  return tool.annotations?.readOnlyHint === true || /read[-\s]?only/i.test(tool.description || "");
}
