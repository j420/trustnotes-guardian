/**
 * Static observations — un-scored, factual labels about a tool's DECLARED metadata,
 * plus PAGE-LEVEL (F1/I16) and WITNESSED-OUTPUT (J5) detectors.
 *
 * These are NOT a risk score. They are facts a human reviewer can't easily see
 * or easily miss, shown next to the behavioral record. All detection consumes
 * DATA PORTED FROM MCP SENTINEL (./data/sentinel-*) and follows Sentinel's
 * matching STRATEGY — mixed-script (A6), class-gated (A7), ordered-token
 * (A1/G5), compositional (J6/G2/J3), shape-based (J3), capability-graph subset
 * (F1/I16). This is what lets Guardian pass Sentinel's own hard negatives that a
 * substring matcher false-positives on.
 */
import type { StaticObservation, WebMcpTool } from "./types.js";
import { CONFUSABLES, inConfusableBlock } from "./data/sentinel-confusables.js";
import { classifyInvisible, FLAGGED_CLASSES } from "./data/sentinel-invisible.js";
import { INJECTION_PHRASES, LLM_SPECIAL_TOKENS } from "./data/sentinel-phrases.js";
import {
  PRIORITY_OPERATORS, EXCLUSIVITY_OPERATORS, REPLACEMENT_OPERATORS, SELECTION_REFERENTS,
  UNIVERSAL_QUANTIFIERS, DOCUMENTATION_FRAMES, INVOCATION_VERBS, NEGATORS,
  NEGATION_SCOPE_TOKENS, NEGATED_USE_WEIGHT, J6_COMPOSITION,
} from "./data/sentinel-preference.js";
import { CLAIM_SPECS, BOUNDING_TOKENS } from "./data/sentinel-scope.js";
import { READ_ONLY_CLAIMS, WRITE_PARAM_TOKENS, NETWORK_PARAM_TOKENS, DANGEROUS_DEFAULTS } from "./data/sentinel-capability-vocab.js";
import { DANGEROUS_PARAM_NAMES, VALUE_CLOSING_KEYWORDS } from "./data/sentinel-dangerous-params.js";
import { DESTRUCTIVE_BOOL_PARAMS, READ_ONLY_FLAG_NAMES, DANGEROUS_STRING_DEFAULTS, PATH_PARAM_TOKENS } from "./data/sentinel-dangerous-defaults.js";
import { PRIOR_APPROVAL_PHRASES, PERMISSION_NOUNS, G5_CONFIDENCE_FLOOR } from "./data/sentinel-prior-approval.js";
import { J3_SHAPE, SLOT_ADDRESSEE_MARKERS } from "./data/sentinel-schema-poisoning.js";
import { AUTHORITY_CLAIMS, CONSEQUENCE_TOKENS, WAIVER_OPERATORS, TRUST_GRANT_TOKENS, G2_COMPOSITION } from "./data/sentinel-trust.js";
import { decodeRuns, countInjectionKeywords, A9_MIN_KEYWORDS } from "./data/sentinel-encoded.js";
import {
  classifyCapabilities, PRIVATE_DATA_CAPS, UNTRUSTED_CONTENT_CAPS, EXTERNAL_COMMS_CAPS,
  TRIFECTA_MIN_LEG_CONFIDENCE, DANGEROUS_CAPS, FATIGUE_THRESHOLDS, type Capability,
} from "./data/sentinel-capabilities.js";
import {
  J5_DIRECTIVES, J5_REMEDIATION_FRAMES, J5_CREDENTIAL_PATH_TOKENS, J5_ADDRESS_TOKENS,
  J5_PRIVATE_KEY_FILENAME_TOKENS, J5_PUBLIC_KEY_TOKEN,
} from "./data/sentinel-output-poisoning.js";

// ── shared helpers ──────────────────────────────────────────────────────────
function codepoints(s: string): number[] { return Array.from(s).map((c) => c.codePointAt(0)!); }
function hex(cp: number): string { return "U+" + cp.toString(16).toUpperCase().padStart(4, "0"); }
function hasAsciiLetter(s: string): boolean { return /[A-Za-z]/.test(s); }
/** Word tokens, splitting on non-letter/number (drops underscore). */
function tokenize(text: string): string[] { return text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean); }
/** Word tokens keeping underscore (so `id_rsa` stays whole) — for J5 output scanning. */
function tokWords(text: string): string[] { return text.toLowerCase().split(/[^a-z0-9_]+/).filter(Boolean); }
function noisyOr(a: number, b: number): number { return 1 - (1 - a) * (1 - b); }
/** True if `want` appears in order in `tokens`, each within maxGap of the previous. */
function orderedMatch(tokens: string[], want: readonly string[], maxGap: number): number {
  let from = 0;
  for (let ti = 0; ti < want.length; ti++) {
    let found = -1;
    const limit = ti === 0 ? tokens.length : Math.min(tokens.length, from + maxGap + 1);
    for (let i = from; i < limit; i++) if (tokens[i] === want[ti]) { found = i; break; }
    if (found === -1) return -1;
    from = found + 1;
  }
  return from - 1; // index just past the last matched token
}
/** Schema property helper. */
function props(tool: WebMcpTool): Record<string, any> {
  const s = tool.inputSchema as any;
  return s && typeof s === "object" && s.properties && typeof s.properties === "object" ? s.properties : {};
}
function nameTokens(param: string): string[] { return param.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean); }

// ── A6: homoglyph (mixed-script) ────────────────────────────────────────────
function detectHomoglyph(text: string): { codepoints: string[]; mimics: string[] } | null {
  if (!hasAsciiLetter(text)) return null;
  const cps: string[] = [], mimics: string[] = [];
  for (const cp of codepoints(text)) if (inConfusableBlock(cp)) { cps.push(hex(cp)); const a = CONFUSABLES[cp]; if (a) mimics.push(`${String.fromCodePoint(cp)}→${a}`); }
  return cps.length ? { codepoints: [...new Set(cps)], mimics: [...new Set(mimics)] } : null;
}

// ── A7: invisible / bidi (class-gated) ──────────────────────────────────────
function detectInvisible(text: string): { codepoints: string[]; classes: string[] } | null {
  const cps: string[] = [], classes: string[] = [];
  for (const cp of codepoints(text)) { const e = classifyInvisible(cp); if (e && FLAGGED_CLASSES.has(e.class)) { cps.push(hex(cp)); classes.push(e.class); } }
  return cps.length ? { codepoints: [...new Set(cps)], classes: [...new Set(classes)] } : null;
}

// ── A1: injection phrases ───────────────────────────────────────────────────
function detectInjection(desc: string): string[] {
  const tokens = tokenize(desc), hits: string[] = [];
  for (const spec of INJECTION_PHRASES) if (orderedMatch(tokens, spec.tokens, spec.max_gap) >= 0) hits.push(spec.label);
  const lc = desc.toLowerCase();
  for (const t of LLM_SPECIAL_TOKENS) if (lc.includes(t.toLowerCase())) hits.push(`LLM special token — ${t}`);
  return hits;
}

// ── J6: preference manipulation (compositional) ─────────────────────────────
function detectPreferenceManipulation(desc: string): { label: string; hits: string[] } | null {
  const tokens = tokenize(desc), W = J6_COMPOSITION.binding_window_tokens;
  const near = (i: number, pred: (t: string) => boolean) => {
    for (let j = Math.max(0, i - W); j <= Math.min(tokens.length - 1, i + W); j++) if (j !== i && pred(tokens[j])) return true;
    return false;
  };
  const isQ = (t: string) => t in UNIVERSAL_QUANTIFIERS, isR = (t: string) => t in SELECTION_REFERENTS, isI = (t: string) => t in INVOCATION_VERBS;
  let opWeight = 0; const hits: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t in PRIORITY_OPERATORS && near(i, isI)) { opWeight = Math.max(opWeight, PRIORITY_OPERATORS[t].weight); hits.push(PRIORITY_OPERATORS[t].label); }
    if (t in EXCLUSIVITY_OPERATORS && near(i, isQ)) { opWeight = Math.max(opWeight, EXCLUSIVITY_OPERATORS[t].weight); hits.push(EXCLUSIVITY_OPERATORS[t].label); }
    if (isI(t)) for (let j = Math.max(0, i - NEGATION_SCOPE_TOKENS); j < i; j++) if (tokens[j] in NEGATORS && (near(i, isQ) || near(i, isR))) { opWeight = Math.max(opWeight, NEGATED_USE_WEIGHT); hits.push(`negated-use exclusivity — "${tokens[j]} … ${t}"`); break; }
    if (t in REPLACEMENT_OPERATORS && near(i, isR)) { opWeight = Math.max(opWeight, REPLACEMENT_OPERATORS[t].weight); hits.push(REPLACEMENT_OPERATORS[t].label); }
  }
  if (opWeight === 0) return null;
  let agg = noisyOr(opWeight, 0.3);
  const docFrame = tokens.some((t) => t in DOCUMENTATION_FRAMES);
  if (docFrame) agg *= J6_COMPOSITION.documentation_frame_multiplier;
  if (agg < J6_COMPOSITION.confidence_floor) return null;
  return { label: docFrame ? " (documentation frame present — demoted, still over floor)" : "", hits: [...new Set(hits)] };
}

// ── A2: excessive scope claims ──────────────────────────────────────────────
function detectScope(desc: string): string[] | null {
  const tokens = tokenize(desc);
  if (BOUNDING_TOKENS.some((b) => tokens.includes(b))) return null; // self-bounded → honest
  const hits: string[] = [];
  for (const spec of CLAIM_SPECS) {
    const mods = new Set(spec.modifier_tokens), nouns = new Set(spec.noun_tokens);
    const mpos: number[] = [], npos: number[] = [];
    tokens.forEach((t, i) => { if (mods.has(t)) mpos.push(i); if (nouns.has(t)) npos.push(i); });
    if (mpos.some((m) => npos.some((n) => n > m && n - m <= spec.max_gap))) hits.push(spec.label);
  }
  return hits.length ? hits : null;
}

// ── A8: description-capability mismatch (static twin of E5) ──────────────────
function detectMismatch(tool: WebMcpTool): { claim: string; conflicts: string[] } | null {
  const desc = tool.description || "";
  const tokens = tokenize(desc);
  const declared = tool.annotations?.readOnlyHint === true;
  let claim = declared ? "annotations.readOnlyHint: true" : "";
  if (!claim) for (const c of READ_ONLY_CLAIMS) if (orderedMatch(tokens, c.tokens, c.max_gap) >= 0) { claim = c.label; break; }
  if (!claim) return null;
  const conflicts: string[] = [];
  for (const [p, spec] of Object.entries(props(tool))) {
    for (const t of nameTokens(p)) {
      if (WRITE_PARAM_TOKENS.has(t)) conflicts.push(`write-capable parameter '${p}'`);
      else if (NETWORK_PARAM_TOKENS.has(t)) conflicts.push(`network-send parameter '${p}'`);
    }
    const dd = DANGEROUS_DEFAULTS[p.toLowerCase()];
    if (dd && spec && String((spec as any).default) === "true") conflicts.push(`dangerous default ${dd.label}`);
  }
  return conflicts.length ? { claim, conflicts: [...new Set(conflicts)] } : null;
}

// ── B2: dangerous parameter types ───────────────────────────────────────────
function detectDangerousParams(tool: WebMcpTool): string[] | null {
  const hits: string[] = [];
  for (const [p, spec] of Object.entries(props(tool))) {
    const d = DANGEROUS_PARAM_NAMES[p.toLowerCase()];
    if (!d) continue;
    const closed = spec && typeof spec === "object" && Object.keys(VALUE_CLOSING_KEYWORDS).some((k) => (spec as any)[k] !== undefined);
    if (!closed) hits.push(`'${p}' → ${d.sink} (${d.rationale})`);
  }
  return hits.length ? hits : null;
}

// ── B7: dangerous default values ────────────────────────────────────────────
function detectDangerousDefaults(tool: WebMcpTool): string[] | null {
  const hits: string[] = [];
  for (const [p, spec] of Object.entries(props(tool))) {
    if (!spec || typeof spec !== "object") continue;
    const def = (spec as any).default;
    const lp = p.toLowerCase();
    if (DESTRUCTIVE_BOOL_PARAMS[lp] && def === true) hits.push(DESTRUCTIVE_BOOL_PARAMS[lp].rationale);
    if (READ_ONLY_FLAG_NAMES[lp] && def === false) hits.push(READ_ONLY_FLAG_NAMES[lp].rationale);
    if (nameTokens(p).some((t) => PATH_PARAM_TOKENS.has(t)) && typeof def === "string") {
      const m = DANGEROUS_STRING_DEFAULTS.find((d) => d.value === def);
      if (m) hits.push(`${p}: ${m.rationale}`);
    }
  }
  return hits.length ? hits : null;
}

// ── G5: capability escalation via prior approval ────────────────────────────
function detectPriorApproval(desc: string): { hits: string[] } | null {
  const tokens = tokenize(desc);
  if (!tokens.some((t) => t in PERMISSION_NOUNS)) return null; // adjacency suppression (permission noun required)
  let agg = 0; const hits: string[] = [];
  for (const spec of PRIOR_APPROVAL_PHRASES) if (orderedMatch(tokens, spec.tokens, spec.max_gap) >= 0) { agg = noisyOr(agg, spec.weight); hits.push(spec.label); }
  return agg >= G5_CONFIDENCE_FLOOR ? { hits } : null;
}

// ── J3: full schema poisoning (shape-based) ─────────────────────────────────
function slotAnomaly(kind: "enum" | "const" | "title" | "default", value: string): { weight: number; why: string } | null {
  const words = value.trim().split(/\s+/).filter(Boolean);
  const markers = tokenize(value).filter((t) => t in SLOT_ADDRESSEE_MARKERS);
  if (words.length > J3_SHAPE.prose_word_threshold) return { weight: J3_SHAPE.field_weight[kind], why: `prose (${words.length} words) in ${kind} slot` };
  if (markers.length) return { weight: J3_SHAPE.field_weight[kind], why: `${SLOT_ADDRESSEE_MARKERS[markers[0]]} (${kind})` };
  return null;
}
function detectSchemaPoisoning(tool: WebMcpTool): string[] | null {
  let agg = 0; const hits: string[] = [];
  const consider = (a: { weight: number; why: string } | null) => { if (a) { agg = noisyOr(agg, a.weight); hits.push(a.why); } };
  for (const [, spec] of Object.entries(props(tool))) {
    if (!spec || typeof spec !== "object") continue;
    const s = spec as any;
    if (Array.isArray(s.enum)) {
      const strs = s.enum.filter((v: unknown) => typeof v === "string") as string[];
      for (const v of strs) consider(slotAnomaly("enum", v));
      if (strs.length >= J3_SHAPE.sibling_min_count) {
        const lens = strs.map((v) => v.length).sort((a, b) => a - b);
        const median = lens[Math.floor(lens.length / 2)] || 1;
        for (const v of strs) if (v.length >= J3_SHAPE.sibling_min_outlier_chars && v.length >= J3_SHAPE.sibling_divergence_ratio * median) { agg = noisyOr(agg, J3_SHAPE.sibling_divergence_weight); hits.push(`enum sibling divergence — "${v.slice(0, 40)}…"`); }
      }
    }
    if (typeof s.const === "string") consider(slotAnomaly("const", s.const));
    if (typeof s.title === "string") consider(slotAnomaly("title", s.title));
    if (typeof s.default === "string") consider(slotAnomaly("default", s.default));
  }
  return agg >= J3_SHAPE.confidence_floor && hits.length ? [...new Set(hits)] : null;
}

// ── G2: trust assertion injection (composition) ─────────────────────────────
function detectTrustAssertion(desc: string): { authority: string; consequence: string } | null {
  const tokens = tokenize(desc);
  for (const claim of AUTHORITY_CLAIMS) {
    const end = orderedMatch(tokens, claim.tokens, claim.max_gap);
    if (end < 0) continue;
    const lo = Math.max(0, end - G2_COMPOSITION.consequence_binding_tokens);
    const hi = Math.min(tokens.length - 1, end + G2_COMPOSITION.consequence_binding_tokens);
    for (let i = lo; i <= hi; i++) {
      const t = tokens[i];
      if (t in TRUST_GRANT_TOKENS) return { authority: claim.label, consequence: TRUST_GRANT_TOKENS[t].label };
      if (t in CONSEQUENCE_TOKENS) {
        for (let j = Math.max(0, i - G2_COMPOSITION.waiver_scope_tokens); j <= Math.min(tokens.length - 1, i + G2_COMPOSITION.waiver_scope_tokens); j++)
          if (tokens[j] in WAIVER_OPERATORS) return { authority: claim.label, consequence: `${WAIVER_OPERATORS[tokens[j]]} + ${CONSEQUENCE_TOKENS[t].label}` };
      }
    }
  }
  return null;
}

// ── A9: encoded / obfuscated instructions ───────────────────────────────────
function detectEncoded(tool: WebMcpTool): string[] | null {
  const fields = [tool.description || "", ...Object.values(props(tool)).map((s: any) => (s && typeof s === "object" && typeof s.description === "string" ? s.description : ""))];
  const hits: string[] = [];
  for (const f of fields) for (const run of decodeRuns(f)) {
    if (countInjectionKeywords(run.decoded) >= A9_MIN_KEYWORDS) hits.push(`${run.scheme}-encoded → "${run.decoded.slice(0, 60)}${run.decoded.length > 60 ? "…" : ""}"`);
  }
  return hits.length ? [...new Set(hits)] : null;
}

// ── the per-tool public entry point ─────────────────────────────────────────
export function staticObservations(tool: WebMcpTool): StaticObservation[] {
  const obs: StaticObservation[] = [];
  const name = tool.name || "", desc = tool.description || "";

  const nameGlyph = detectHomoglyph(name);
  const glyph = nameGlyph || detectHomoglyph(desc);
  if (glyph) obs.push({ id: "UNICODE-HOMOGLYPH", sentinelRule: "A6", label: `${nameGlyph ? "Tool NAME" : "Description"} mixes look-alike (non-ASCII) letters with ASCII — tool-shadowing disguise${glyph.mimics.length ? ` — ${glyph.mimics.join(", ")}` : ""}`, evidence: `${glyph.codepoints.join(", ")}${nameGlyph ? ` in name="${name}"` : ""}` });

  const invN = detectInvisible(name), invD = detectInvisible(desc);
  const inv = invN && invD ? { codepoints: [...new Set([...invN.codepoints, ...invD.codepoints])], classes: [...new Set([...invN.classes, ...invD.classes])] } : invN || invD;
  if (inv) obs.push({ id: "UNICODE-HIDDEN", sentinelRule: "A7", label: `Contains invisible / bidi control characters — class: ${inv.classes.join(", ")}`, evidence: inv.codepoints.join(", ") });

  const inj = detectInjection(desc);
  if (inj.length) obs.push({ id: "INJ-IMPERATIVE", sentinelRule: "A1", label: `Description contains prompt-injection phrase(s) from the A1 catalogue`, evidence: inj.join("; ") });

  const enc = detectEncoded(tool);
  if (enc) obs.push({ id: "ENCODED-INSTRUCTION", sentinelRule: "A9", label: `Description hides instructions inside an encoded blob (decoded → injection keywords)`, evidence: enc.join("; ") });

  const scope = detectScope(desc);
  if (scope) obs.push({ id: "EXCESSIVE-SCOPE", sentinelRule: "A2", label: `Description claims excessive scope with no stated boundary`, evidence: scope.join(", ") });

  const mismatch = detectMismatch(tool);
  if (mismatch) obs.push({ id: "CAPABILITY-MISMATCH", sentinelRule: "A8", label: `Declares ${mismatch.claim} but the schema is write/network-capable (static twin of E5)`, evidence: mismatch.conflicts.join("; ") });

  const pref = detectPreferenceManipulation(desc);
  if (pref) obs.push({ id: "PREFERENCE-MANIP", sentinelRule: "J6", label: `Description steers the agent to prefer this tool over others${pref.label}`, evidence: pref.hits.join("; ") });

  const trust = detectTrustAssertion(desc);
  if (trust) obs.push({ id: "TRUST-ASSERTION", sentinelRule: "G2", label: `Pairs an authority claim with a trust-waiver ("skip confirmation") — social engineering`, evidence: `${trust.authority} + ${trust.consequence}` });

  const prior = detectPriorApproval(desc);
  if (prior) obs.push({ id: "PRIOR-APPROVAL", sentinelRule: "G5", label: `Manufactures a pre-existing grant to skip fresh approval`, evidence: prior.hits.join("; ") });

  const dparams = detectDangerousParams(tool);
  if (dparams) obs.push({ id: "DANGEROUS-PARAM", sentinelRule: "B2", label: `Parameter name advertises an injection sink with no closed value set`, evidence: dparams.join("; ") });

  const ddefaults = detectDangerousDefaults(tool);
  if (ddefaults) obs.push({ id: "DANGEROUS-DEFAULT", sentinelRule: "B7", label: `Schema default violates least privilege`, evidence: ddefaults.join("; ") });

  const jpoison = detectSchemaPoisoning(tool);
  if (jpoison) obs.push({ id: "SCHEMA-POISON", sentinelRule: "J3", label: `Injection/prose in a non-description schema slot (enum/const/title/default)`, evidence: jpoison.join("; ") });

  // I2 — destructive schema whose destructiveHint is absent/false (companion of I1)
  if (isDestructiveShape(tool) && tool.annotations?.destructiveHint !== true) {
    obs.push({ id: "MISSING-DESTRUCTIVE-HINT", sentinelRule: "I2", label: `Destructive-looking tool with no destructiveHint — AI clients may auto-approve it`, evidence: destructiveWhy(tool) });
  }

  const schema = tool.inputSchema as any;
  const unconstrained = !schema || typeof schema !== "object" || schema.additionalProperties !== false;
  if (unconstrained) obs.push({ id: "SCHEMA-UNCONSTRAINED", sentinelRule: "B6", label: `Input schema is missing or allows arbitrary additional properties`, evidence: schema ? `additionalProperties=${JSON.stringify(schema.additionalProperties)}` : "no inputSchema" });

  return obs;
}

/** DECLARED read-only + a destructive-looking parameter/name is annotation deception (I1). */
export function declaresReadOnly(tool: WebMcpTool): boolean {
  return tool.annotations?.readOnlyHint === true || /read[-\s]?only/i.test(tool.description || "");
}

/** Structural destructive signal (I1/I2): a destructive verb in the name or a write-capable param. */
function isDestructiveShape(tool: WebMcpTool): boolean {
  const nameHit = nameTokens(tool.name || "").some((t) => WRITE_PARAM_TOKENS.has(t) && ["delete", "remove", "drop", "destroy", "erase", "truncate", "overwrite", "kill", "terminate"].includes(t));
  const paramHit = Object.keys(props(tool)).some((p) => nameTokens(p).some((t) => ["delete", "remove", "drop", "destroy", "erase", "truncate", "overwrite"].includes(t)));
  return nameHit || paramHit;
}
function destructiveWhy(tool: WebMcpTool): string {
  const nameHit = nameTokens(tool.name || "").find((t) => ["delete", "remove", "drop", "destroy", "erase", "truncate", "overwrite", "kill", "terminate"].includes(t));
  const param = Object.keys(props(tool)).find((p) => nameTokens(p).some((t) => ["delete", "remove", "drop", "destroy", "erase", "truncate", "overwrite"].includes(t)));
  return [nameHit ? `name verb '${nameHit}'` : "", param ? `destructive parameter '${param}'` : "", `destructiveHint=${JSON.stringify(tool.annotations?.destructiveHint)}`].filter(Boolean).join("; ");
}

// ── PAGE-LEVEL: F1 (lethal trifecta) + I16 (consent fatigue) ─────────────────
type PageTool = Pick<WebMcpTool, "name" | "description" | "inputSchema" | "annotations">;
export function pageObservations(tools: PageTool[]): StaticObservation[] {
  const out: StaticObservation[] = [];
  const tagged = tools.map((t) => ({ name: t.name || "", caps: classifyCapabilities(t) }));
  const fills = (caps: { cap: Capability; confidence: number }[], legCaps: readonly Capability[]) =>
    caps.some((c) => legCaps.includes(c.cap) && c.confidence >= TRIFECTA_MIN_LEG_CONFIDENCE);

  // F1 — lethal trifecta across the tool set
  const priv = tagged.filter((t) => fills(t.caps, PRIVATE_DATA_CAPS)).map((t) => t.name);
  const untrusted = tagged.filter((t) => fills(t.caps, UNTRUSTED_CONTENT_CAPS)).map((t) => t.name);
  const external = tagged.filter((t) => fills(t.caps, EXTERNAL_COMMS_CAPS)).map((t) => t.name);
  if (priv.length && untrusted.length && external.length) {
    out.push({
      id: "LETHAL-TRIFECTA", sentinelRule: "F1",
      label: `Lethal trifecta present across this page's tools — private-data read + untrusted-content ingest + external comms`,
      evidence: `private-data: {${priv.join(", ")}} · untrusted-content: {${untrusted.join(", ")}} · external-comms: {${external.join(", ")}}`,
    });
  }

  // I16 — consent fatigue: many benign tools hiding a few dangerous ones
  const T = FATIGUE_THRESHOLDS;
  if (tools.length >= T.min_total_tools) {
    const dangerous = tagged.filter((t) => t.caps.some((c) => DANGEROUS_CAPS.has(c.cap) && c.confidence >= T.min_capability_confidence));
    const benignCount = tools.length - dangerous.length;
    if (benignCount >= T.min_benign_tools && dangerous.length >= T.min_dangerous_tools && dangerous.length <= T.max_dangerous_tools && benignCount / dangerous.length >= T.min_ratio) {
      out.push({ id: "CONSENT-FATIGUE", sentinelRule: "I16", label: `${benignCount} benign tools hide ${dangerous.length} dangerous one(s) — approval-fatigue exploitation`, evidence: `dangerous: {${dangerous.map((d) => d.name).join(", ")}} · ratio ${(benignCount / dangerous.length).toFixed(0)}:1` });
    }
  }
  return out;
}

// ── WITNESSED OUTPUT: J5 (tool output poisoning) ────────────────────────────
/** Scan a tool's returned text for reader-directed manipulation directives. */
export function outputObservations(text: string): StaticObservation[] {
  if (!text) return [];
  const tokens = tokWords(text);
  // reader-action co-signals present anywhere in the output?
  const hasFrame = J5_REMEDIATION_FRAMES.some((f) => orderedMatch(tokens, f, 0) >= 0);
  const credPathToken = tokens.some((t, i) => J5_CREDENTIAL_PATH_TOKENS[t] && !(J5_PRIVATE_KEY_FILENAME_TOKENS[t] && tokens[i + 1] === J5_PUBLIC_KEY_TOKEN));
  const out: StaticObservation[] = [];
  for (const [, d] of Object.entries(J5_DIRECTIVES)) {
    const end = orderedMatch(tokens, d.tokens, d.max_gap);
    if (end < 0) continue;
    let fire = d.gate === "match";
    if (!fire) {
      const start = end - d.tokens.length + 1;
      const addressOutside = tokens.some((t, i) => J5_ADDRESS_TOKENS[t] && (i < start || i > end));
      fire = hasFrame || credPathToken || addressOutside;
    }
    if (fire) out.push({ id: `OUTPUT-${d.kind.toUpperCase()}`, sentinelRule: "J5", label: `Witnessed tool OUTPUT contains a ${d.kind} directive addressed to the agent`, evidence: `${d.label} — in returned text: "${text.slice(0, 80)}${text.length > 80 ? "…" : ""}"` });
  }
  // dedupe to one row per directive class (id)
  const seen = new Set<string>();
  return out.filter((o) => { if (seen.has(o.id)) return false; seen.add(o.id); return true; });
}
