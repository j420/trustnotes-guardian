/**
 * A6 — homoglyph (look-alike) confusables.
 *
 * Sentinel's server-side A6 rule uses the FULL vendored Unicode 16.0.0 UTS-39
 * confusables table (`a6-unicode-homoglyph/data/uts39-tables.generated.ts`,
 * ~97k tokens) plus mixed-script skeleton analysis. That table is far too large
 * to ship in a browser bundle, so Guardian ports a **curated subset** — the
 * highest-frequency Latin look-alikes from the Cyrillic, Greek, and Fullwidth
 * blocks — mapped to the ASCII letter each one mimics.
 *
 * Guardian's A6 check follows Sentinel's core insight: a look-alike is evidence
 * only in a MIXED-SCRIPT context — a confusable-block letter sitting inside an
 * otherwise-ASCII token (or ASCII-bearing description). A wholly-Cyrillic or
 * wholly-Greek name is legitimate single-script text and is NOT flagged; genuine
 * right-to-left (Hebrew/Arabic) prose is not in the confusable set at all. This
 * is why Guardian matches Sentinel on its own A6 negatives (ascii-only,
 * single-script-non-Latin, RTL prose) — see static-flags.ts → detectHomoglyph.
 *
 * This is a curated subset, honestly labeled: it is NOT the complete UTS-39
 * table, so a look-alike outside this curated set is a false negative for
 * Guardian while Sentinel's server-side rule would still catch it.
 */

/** Codepoint → the ASCII character it visually mimics. Curated, not exhaustive. */
export const CONFUSABLES: Readonly<Record<number, string>> = {
  // ── Cyrillic → Latin (the most common homoglyph source) ──
  0x0430: "a", // а CYRILLIC SMALL LETTER A
  0x0435: "e", // е CYRILLIC SMALL LETTER IE
  0x043e: "o", // о CYRILLIC SMALL LETTER O
  0x0440: "p", // р CYRILLIC SMALL LETTER ER
  0x0441: "c", // с CYRILLIC SMALL LETTER ES
  0x0443: "y", // у CYRILLIC SMALL LETTER U
  0x0445: "x", // х CYRILLIC SMALL LETTER HA
  0x0455: "s", // ѕ CYRILLIC SMALL LETTER DZE
  0x0456: "i", // і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
  0x0458: "j", // ј CYRILLIC SMALL LETTER JE
  0x043d: "h", // н (visually near) — kept conservative
  0x0410: "A", // А CYRILLIC CAPITAL LETTER A
  0x0412: "B", // В CYRILLIC CAPITAL LETTER VE
  0x0415: "E", // Е CYRILLIC CAPITAL LETTER IE
  0x041a: "K", // К CYRILLIC CAPITAL LETTER KA
  0x041c: "M", // М CYRILLIC CAPITAL LETTER EM
  0x041d: "H", // Н CYRILLIC CAPITAL LETTER EN
  0x041e: "O", // О CYRILLIC CAPITAL LETTER O
  0x0420: "P", // Р CYRILLIC CAPITAL LETTER ER
  0x0421: "C", // С CYRILLIC CAPITAL LETTER ES
  0x0422: "T", // Т CYRILLIC CAPITAL LETTER TE
  0x0425: "X", // Х CYRILLIC CAPITAL LETTER HA

  // ── Greek → Latin ──
  0x03b1: "a", // α GREEK SMALL LETTER ALPHA
  0x03bf: "o", // ο GREEK SMALL LETTER OMICRON
  0x03c1: "p", // ρ GREEK SMALL LETTER RHO
  0x03c5: "u", // υ GREEK SMALL LETTER UPSILON
  0x03bd: "v", // ν GREEK SMALL LETTER NU
  0x0391: "A", // Α GREEK CAPITAL LETTER ALPHA
  0x0392: "B", // Β GREEK CAPITAL LETTER BETA
  0x0395: "E", // Ε GREEK CAPITAL LETTER EPSILON
  0x0397: "H", // Η GREEK CAPITAL LETTER ETA
  0x0399: "I", // Ι GREEK CAPITAL LETTER IOTA
  0x039a: "K", // Κ GREEK CAPITAL LETTER KAPPA
  0x039c: "M", // Μ GREEK CAPITAL LETTER MU
  0x039d: "N", // Ν GREEK CAPITAL LETTER NU
  0x039f: "O", // Ο GREEK CAPITAL LETTER OMICRON
  0x03a1: "P", // Ρ GREEK CAPITAL LETTER RHO
  0x03a4: "T", // Τ GREEK CAPITAL LETTER TAU
  0x03a7: "X", // Χ GREEK CAPITAL LETTER CHI
};

/**
 * Confusable-block ranges: a codepoint here is treated as "from a look-alike
 * block" even when it is not in the curated CONFUSABLES map above (so the
 * mixed-script signal still fires; the specific ASCII target is just unnamed).
 * Covers Cyrillic, Greek/Coptic, Fullwidth forms, and Letterlike symbols.
 */
export const CONFUSABLE_BLOCKS: ReadonlyArray<readonly [number, number]> = [
  [0x0400, 0x04ff], // Cyrillic
  [0x0500, 0x052f], // Cyrillic Supplement
  [0x0370, 0x03ff], // Greek and Coptic
  [0x1f00, 0x1fff], // Greek Extended
  [0xff00, 0xffef], // Halfwidth and Fullwidth Forms
  [0x2100, 0x214f], // Letterlike Symbols
];

export function inConfusableBlock(cp: number): boolean {
  return CONFUSABLE_BLOCKS.some(([a, b]) => cp >= a && cp <= b);
}
