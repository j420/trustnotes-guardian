/**
 * A9 — Encoded / Obfuscated Instructions in a tool description.
 *
 * PORTED from MCP Sentinel:
 *   keywords + tokenizer + benign-shape classifier — VERBATIM from
 *     a9-encoded-instructions/data/{injection-keywords.ts, benign-shapes.ts}
 *   decoder — a COMPACT SUBSET of a9-encoded-instructions/decode.ts (base64,
 *     percent-encoding, and hex only; the full rule also handles double-base64,
 *     HTML entities and nested schemes). Honestly labeled as a subset.
 *
 * The attack: instructions hidden from a human reviewer inside an encoded blob
 * that the LLM decodes and follows. Guardian finds candidate encoded runs in the
 * description, decodes them, counts post-decode injection keywords, and suppresses
 * known-benign shapes (SHA/MD5 digests, JWTs, PEM bodies, data: URIs). See
 * static-flags.ts → detectEncoded.
 */

/** Post-decode injection markers (VERBATIM from Sentinel A9). */
export const INJECTION_KEYWORDS: Record<string, true> = {
  ignore: true, disregard: true, override: true, forget: true,
  previous: true, prior: true, earlier: true, instruction: true, instructions: true, system: true, prompt: true,
  exfiltrate: true, "send-to": true, webhook: true,
  assistant: true, developer: true,
  execute: true, eval: true, reveal: true,
  credential: true, credentials: true, secret: true, token: true, password: true,
  ".ssh": true, id_rsa: true, api_key: true,
};

/** Tokenizer that keeps `.`, `_`, `-` so `.ssh` / `id_rsa` / `send-to` stay whole (VERBATIM). */
export function tokenizeDecoded(text: string): string[] {
  const out: string[] = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    const isWord =
      (cp >= 0x30 && cp <= 0x39) || (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) ||
      cp === 0x5f || cp === 0x2e || cp === 0x2d;
    if (isWord) current += String.fromCharCode(cp).toLowerCase();
    else if (current.length) { out.push(current); current = ""; }
  }
  if (current.length) out.push(current);
  return out;
}

export function countInjectionKeywords(decoded: string): number {
  let hits = 0;
  for (const t of tokenizeDecoded(decoded)) if (INJECTION_KEYWORDS[t]) hits++;
  return hits;
}

// ── benign-shape classifier (VERBATIM logic, Buffer→browser base64) ──
function endsWithIgnoringCase(h: string, n: string): boolean {
  return h.length >= n.length && h.slice(h.length - n.length).toLowerCase() === n;
}
function isAllHex(s: string): boolean {
  if (!s.length) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
}
function b64urlDecode(s: string): string {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
}
function lastBoundary(text: string, pos: number): number {
  let i = pos;
  while (i > 0) {
    const c = text.charCodeAt(i - 1);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x28 || c === 0x22) break;
    i--;
  }
  return i;
}

/** Returns a benign-shape label (skip the run) or null. */
export function classifyBenignShape(text: string, start: number, raw: string): string | null {
  const before = text.slice(Math.max(0, start - 24), start);
  const after = text.slice(start + raw.length, start + raw.length + 8);
  if (endsWithIgnoringCase(before, "base64,") || before.toLowerCase().indexOf("data:") >= 0) return "data: URI payload";
  for (const p of ["sha256-", "sha384-", "sha512-", "sha1-", "md5-"]) if (endsWithIgnoringCase(before, p)) return `${p} integrity digest`;
  const armour = text.lastIndexOf("-----BEGIN", start);
  if (armour >= 0 && text.indexOf("-----END", armour) > start) return "PEM key/certificate body";
  if (before.endsWith(".") || after.startsWith(".")) {
    const segStart = lastBoundary(text, start);
    const cand = text.slice(segStart, segStart + 512);
    const d1 = cand.indexOf("."), d2 = d1 >= 0 ? cand.indexOf(".", d1 + 1) : -1;
    if (d1 > 0 && d2 > d1) { try { if (b64urlDecode(cand.slice(0, d1)).indexOf('"alg"') >= 0) return "JWT segment"; } catch { /* not b64url */ } }
  }
  if (isAllHex(raw) && (raw.length === 32 || raw.length === 40 || raw.length === 64)) return `${raw.length}-char hex digest`;
  return null;
}

// ── compact decoder: find candidate runs, decode, return decoded text or null ──
export interface DecodedRun {
  scheme: "base64" | "percent" | "hex";
  raw: string;
  start: number;
  decoded: string;
}

function tryB64(s: string): string | null { try { const d = atob(s.replace(/=+$/, "")); return /[\x00-\x08\x0e-\x1f]/.test(d) ? null : d; } catch { return null; } }
function tryHex(s: string): string | null {
  if (s.length % 2 !== 0) return null;
  let out = "";
  for (let i = 0; i < s.length; i += 2) { const b = parseInt(s.slice(i, i + 2), 16); if (b >= 0x20 && b < 0x7f) out += String.fromCharCode(b); else if (b !== 0x0a && b !== 0x09) return null; }
  return out;
}

/** Extract & decode candidate encoded runs from a field. Skips benign shapes. */
export function decodeRuns(text: string): DecodedRun[] {
  const runs: DecodedRun[] = [];
  // percent-encoding: a stretch with ≥3 %XX triplets
  for (const m of text.matchAll(/(?:%[0-9a-fA-F]{2}){3,}/g)) {
    if (classifyBenignShape(text, m.index!, m[0])) continue;
    try { runs.push({ scheme: "percent", raw: m[0], start: m.index!, decoded: decodeURIComponent(m[0]) }); } catch { /* malformed */ }
  }
  // base64: contiguous base64 charset, length ≥ 16
  for (const m of text.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    if (classifyBenignShape(text, m.index!, m[0])) continue;
    const d = tryB64(m[0]); if (d) runs.push({ scheme: "base64", raw: m[0], start: m.index!, decoded: d });
  }
  // hex: 0x-PREFIXED contiguous hex, length ≥ 16 and even. Sentinel's A9 only scans
  // 0x-prefixed hex strings (scanHexString), so we match that — a bare hex run is not
  // an "encoded instruction" candidate, and this also avoids double-decoding it as base64.
  for (const m of text.matchAll(/0x([0-9a-fA-F]{16,})/g)) {
    const hexStr = m[1];
    if (hexStr.length % 2 !== 0 || classifyBenignShape(text, m.index! + 2, hexStr)) continue;
    const d = tryHex(hexStr); if (d) runs.push({ scheme: "hex", raw: m[0], start: m.index!, decoded: d });
  }
  return runs;
}

/** Minimum post-decode injection-keyword hits before A9 reports. */
export const A9_MIN_KEYWORDS = 2;
