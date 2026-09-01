/**
 * Static observations — un-scored, factual labels about a tool's DECLARED metadata.
 *
 * These are NOT a risk score. They are facts a human reviewer can't easily see
 * (invisible characters) or easily miss (a "read-only" claim), shown next to the
 * behavioral record so a tool the agent never runs still reveals deceptive metadata.
 *
 * The detection here consumes DATA PORTED FROM MCP SENTINEL (see ./data/sentinel-*):
 *   A6 — ./data/sentinel-confusables.ts   (curated UTS-39 confusables subset)
 *   A7 — ./data/sentinel-invisible.ts     (invisible-codepoint catalogue, verbatim)
 *   A1 — ./data/sentinel-phrases.ts       (injection-phrase catalogue, verbatim)
 *   J6 — ./data/sentinel-preference.ts    (compositional preference vocabulary, verbatim)
 * and it follows Sentinel's matching STRATEGY (mixed-script for A6, class-gated for
 * A7, ordered-token for A1, operator+referent composition for J6) — not a naive
 * keyword scan. This is what lets Guardian pass Sentinel's own hard negatives
 * (the "always returns the first row" data-noun trap, the "alwaysOnCache" substring
 * trap, honest deprecation notices) that a substring matcher false-positives on.
 */
import type { StaticObservation, WebMcpTool } from "./types.js";
import { CONFUSABLES, inConfusableBlock } from "./data/sentinel-confusables.js";
import { classifyInvisible, FLAGGED_CLASSES } from "./data/sentinel-invisible.js";
import { INJECTION_PHRASES, LLM_SPECIAL_TOKENS, type PhraseSpec } from "./data/sentinel-phrases.js";
import {
  PRIORITY_OPERATORS,
  EXCLUSIVITY_OPERATORS,
  REPLACEMENT_OPERATORS,
  SELECTION_REFERENTS,
  UNIVERSAL_QUANTIFIERS,
  DOCUMENTATION_FRAMES,
  INVOCATION_VERBS,
  NEGATORS,
  NEGATION_SCOPE_TOKENS,
  NEGATED_USE_WEIGHT,
  J6_COMPOSITION,
} from "./data/sentinel-preference.js";

// ── shared helpers ─────────────────────────────────────────────────────────
function codepoints(s: string): number[] {
  return Array.from(s).map((c) => c.codePointAt(0)!);
}
function hex(cp: number): string {
  return "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
}
function hasAsciiLetter(s: string): boolean {
  return /[A-Za-z]/.test(s);
}
/** Lowercase word tokens (letters+digits), Unicode-aware split. */
function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}
function noisyOr(a: number, b: number): number {
  return 1 - (1 - a) * (1 - b);
}

// ── A6: homoglyph (mixed-script) ────────────────────────────────────────────
/** Report look-alike letters only in a mixed-script context (Sentinel's core insight). */
function detectHomoglyph(text: string): { codepoints: string[]; mimics: string[] } | null {
  if (!hasAsciiLetter(text)) return null; // wholly-non-Latin (Cyrillic/Greek/Hebrew) is legit single-script
  const cps: string[] = [];
  const mimics: string[] = [];
  for (const cp of codepoints(text)) {
    if (inConfusableBlock(cp)) {
      cps.push(hex(cp));
      const asc = CONFUSABLES[cp];
      if (asc) mimics.push(`${String.fromCodePoint(cp)}→${asc}`);
    }
  }
  return cps.length ? { codepoints: [...new Set(cps)], mimics: [...new Set(mimics)] } : null;
}

// ── A7: invisible / bidi (class-gated) ──────────────────────────────────────
function detectInvisible(text: string): { codepoints: string[]; classes: string[] } | null {
  const cps: string[] = [];
  const classes: string[] = [];
  for (const cp of codepoints(text)) {
    const entry = classifyInvisible(cp);
    if (entry && FLAGGED_CLASSES.has(entry.class)) {
      cps.push(hex(cp));
      classes.push(entry.class);
    }
  }
  return cps.length ? { codepoints: [...new Set(cps)], classes: [...new Set(classes)] } : null;
}

// ── A1: injection phrases (ordered-token match) ─────────────────────────────
/** True if spec.tokens appear in order in `tokens`, each within max_gap of the previous. */
function matchPhrase(tokens: string[], spec: PhraseSpec): boolean {
  let from = 0;
  for (let ti = 0; ti < spec.tokens.length; ti++) {
    const want = spec.tokens[ti];
    let found = -1;
    const limit = ti === 0 ? tokens.length : Math.min(tokens.length, from + spec.max_gap + 1);
    for (let i = from; i < limit; i++) {
      if (tokens[i] === want) { found = i; break; }
    }
    if (found === -1) return false;
    from = found + 1;
  }
  return true;
}
function detectInjection(desc: string): string[] {
  const tokens = tokenize(desc);
  const hits: string[] = [];
  for (const spec of INJECTION_PHRASES) if (matchPhrase(tokens, spec)) hits.push(spec.label);
  const lc = desc.toLowerCase();
  for (const t of LLM_SPECIAL_TOKENS) if (lc.includes(t.toLowerCase())) hits.push(`LLM special token — ${t}`);
  return hits;
}

// ── J6: tool-preference manipulation (compositional) ────────────────────────
/**
 * Faithful browser port of J6's composition. Flags only a valid construction:
 *   (P) a PRIORITY operator binding to an INVOCATION verb ("always use", "use … first")
 *   (E) an EXCLUSIVITY operator (incl. compositional negated-use) with a UNIVERSAL
 *       QUANTIFIER of otherness in the window ("ignore any other", "do not use other")
 *   (R) a REPLACEMENT operator binding to a TOOL-SELECTION referent ("replaces … tool")
 * Then a DOCUMENTATION-FRAME demotion (×0.35) drops honest deprecation notices below
 * the confidence floor. This is a SUBSET of Sentinel's full J6 (named-sibling referents
 * and third-person demotion are not fully modeled), stated honestly.
 */
function detectPreferenceManipulation(desc: string): { label: string; hits: string[] } | null {
  const tokens = tokenize(desc);
  const W = J6_COMPOSITION.binding_window_tokens;
  const at = (i: number) => tokens[i];

  const near = (i: number, pred: (t: string) => boolean): boolean => {
    for (let j = Math.max(0, i - W); j <= Math.min(tokens.length - 1, i + W); j++)
      if (j !== i && pred(at(j))) return true;
    return false;
  };
  const isQuantifier = (t: string) => t in UNIVERSAL_QUANTIFIERS;
  const isReferent = (t: string) => t in SELECTION_REFERENTS;
  const isInvocation = (t: string) => t in INVOCATION_VERBS;

  let opWeight = 0;
  const hits: string[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = at(i);

    // (P) priority + invocation verb
    if (t in PRIORITY_OPERATORS && near(i, isInvocation)) {
      opWeight = Math.max(opWeight, PRIORITY_OPERATORS[t].weight);
      hits.push(PRIORITY_OPERATORS[t].label);
    }
    // (E) explicit exclusivity operator + otherness quantifier
    if (t in EXCLUSIVITY_OPERATORS && near(i, isQuantifier)) {
      opWeight = Math.max(opWeight, EXCLUSIVITY_OPERATORS[t].weight);
      hits.push(EXCLUSIVITY_OPERATORS[t].label);
    }
    // (E') compositional negated-use: NEGATOR within scope, left of an invocation verb, + referent/quantifier
    if (isInvocation(t)) {
      for (let j = Math.max(0, i - NEGATION_SCOPE_TOKENS); j < i; j++) {
        if (at(j) in NEGATORS && (near(i, isQuantifier) || near(i, isReferent))) {
          opWeight = Math.max(opWeight, NEGATED_USE_WEIGHT);
          hits.push(`negated-use exclusivity — "${at(j)} … ${t}"`);
          break;
        }
      }
    }
    // (R) replacement operator + tool-selection referent
    if (t in REPLACEMENT_OPERATORS && near(i, isReferent)) {
      opWeight = Math.max(opWeight, REPLACEMENT_OPERATORS[t].weight);
      hits.push(REPLACEMENT_OPERATORS[t].label);
    }
  }

  if (opWeight === 0) return null;

  let agg = noisyOr(opWeight, 0.3); // +0.3 for the completed construction
  const docFrame = tokens.some((t) => t in DOCUMENTATION_FRAMES);
  if (docFrame) agg *= J6_COMPOSITION.documentation_frame_multiplier;
  if (agg < J6_COMPOSITION.confidence_floor) return null; // honest deprecation / demoted → silent

  const label = docFrame ? " (documentation frame present — demoted, still over floor)" : "";
  return { label, hits: [...new Set(hits)] };
}

// ── the public entry point ──────────────────────────────────────────────────
export function staticObservations(tool: WebMcpTool): StaticObservation[] {
  const obs: StaticObservation[] = [];
  const name = tool.name || "";
  const desc = tool.description || "";

  // A6 — homoglyph (name first, then description)
  const nameGlyph = detectHomoglyph(name);
  const descGlyph = nameGlyph ? null : detectHomoglyph(desc);
  const glyph = nameGlyph || descGlyph;
  if (glyph) {
    const where = nameGlyph ? "Tool NAME" : "Description";
    const mim = glyph.mimics.length ? ` — look-alikes: ${glyph.mimics.join(", ")}` : "";
    obs.push({
      id: "UNICODE-HOMOGLYPH",
      sentinelRule: "A6",
      label: `${where} mixes look-alike (non-ASCII) letters with ASCII — the kind of tool-shadowing disguise A6 catches${mim}`,
      evidence: `${glyph.codepoints.join(", ")}${nameGlyph ? ` in name="${name}"` : ""}`,
    });
  }

  // A7 — invisible / bidi
  const invName = detectInvisible(name);
  const invDesc = detectInvisible(desc);
  const inv = invName && invDesc
    ? { codepoints: [...new Set([...invName.codepoints, ...invDesc.codepoints])], classes: [...new Set([...invName.classes, ...invDesc.classes])] }
    : invName || invDesc;
  if (inv) {
    obs.push({
      id: "UNICODE-HIDDEN",
      sentinelRule: "A7",
      label: `Contains invisible / bidi control characters (unreadable to a human) — class: ${inv.classes.join(", ")}`,
      evidence: inv.codepoints.join(", "),
    });
  }

  // A1 — injection phrases
  const inj = detectInjection(desc);
  if (inj.length)
    obs.push({
      id: "INJ-IMPERATIVE",
      sentinelRule: "A1",
      label: `Description contains prompt-injection phrase(s) from the A1 catalogue`,
      evidence: inj.join("; "),
    });

  // J6 — preference manipulation
  const pref = detectPreferenceManipulation(desc);
  if (pref)
    obs.push({
      id: "PREFERENCE-MANIP",
      sentinelRule: "J6",
      label: `Description steers the agent to prefer this tool over others (compositional match)${pref.label}`,
      evidence: pref.hits.join("; "),
    });

  // B6 — unconstrained schema
  const schema = tool.inputSchema as any;
  const unconstrained = !schema || typeof schema !== "object" || schema.additionalProperties !== false;
  if (unconstrained)
    obs.push({
      id: "SCHEMA-UNCONSTRAINED",
      sentinelRule: "B6",
      label: `Input schema is missing or allows arbitrary additional properties`,
      evidence: schema ? `additionalProperties=${JSON.stringify(schema.additionalProperties)}` : "no inputSchema",
    });

  return obs;
}

/** DECLARED read-only + a destructive-looking parameter/name is annotation deception (I1). */
export function declaresReadOnly(tool: WebMcpTool): boolean {
  return tool.annotations?.readOnlyHint === true || /read[-\s]?only/i.test(tool.description || "");
}
