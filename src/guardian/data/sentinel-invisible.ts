/**
 * A7 — invisible / format / bidirectional codepoint catalogue.
 *
 * PORTED VERBATIM from MCP Sentinel:
 *   packages/analyzer/src/rules/implementations/a7-zero-width-injection/data/invisible-codepoints.ts
 *
 * This is the *same data table* the server-side A7 rule uses — every entry, its
 * class, and its human description. It is copied (not re-authored) so Guardian's
 * A7 observation names the exact same character classes Sentinel does. What
 * Guardian does NOT port is Sentinel's `bidi.ts` termination/nesting analysis;
 * so Guardian only auto-flags the classes in `FLAGGED_CLASSES` below — the ones
 * that are evidence on presence alone — and deliberately does not flag bidi
 * MARKS (routine in genuine Arabic/Hebrew prose) or unbalanced ISOLATES (which
 * need the structural analysis Guardian doesn't run in the browser).
 */

/** High-level class of invisible character. Drives the label and whether we flag. */
export type InvisibleClass =
  | "private-use"
  | "zero-width"
  | "bidi-mark"
  | "bidi-embedding"
  | "bidi-override"
  | "bidi-isolate"
  | "bidi-terminator"
  | "tag-character"
  | "variation-selector"
  | "invisible-space";

/** One named range of invisible codepoints. */
export interface InvisibleRange {
  start: number;
  end: number;
  name: string;
  class: InvisibleClass;
  description: string;
}

export const INVISIBLE_RANGES: Record<string, InvisibleRange> = {
  // ─── zero-width characters ───
  zwsp: { start: 0x200b, end: 0x200b, name: "Zero Width Space (ZWSP)", class: "zero-width", description: "U+200B splits a word at no visible location — it changes tokenisation and defeats exact-match comparison while leaving the rendered string unchanged." },
  zwnj: { start: 0x200c, end: 0x200c, name: "Zero Width Non-Joiner (ZWNJ)", class: "zero-width", description: "U+200C prevents glyph joining in scripts where joining applies (Arabic, Devanagari); in Latin text it is a pure invisible insertion." },
  zwj: { start: 0x200d, end: 0x200d, name: "Zero Width Joiner (ZWJ)", class: "zero-width", description: "U+200D — legitimate inside emoji sequences; an invisible insertion when it appears inside Latin text." },
  word_joiner: { start: 0x2060, end: 0x2060, name: "Word Joiner", class: "zero-width", description: "U+2060 is an invisible zero-width non-breaking glue character." },
  invisible_operators: { start: 0x2061, end: 0x2064, name: "Invisible Mathematical Operators", class: "zero-width", description: "U+2061–U+2064 carry mathematical semantics and render as nothing." },
  bom: { start: 0xfeff, end: 0xfeff, name: "Zero Width No-Break Space / BOM", class: "zero-width", description: "U+FEFF is legitimate as a byte-order mark AT THE START of a stream; anywhere else it is an invisible insertion." },

  // ─── bidirectional: marks (direction hints, no reordering of strong text) ───
  lrm: { start: 0x200e, end: 0x200e, name: "Left-To-Right Mark (LRM)", class: "bidi-mark", description: "U+200E sets the direction of adjacent neutral characters. Routine in genuine bidirectional text; meaningless in pure-Latin text." },
  rlm: { start: 0x200f, end: 0x200f, name: "Right-To-Left Mark (RLM)", class: "bidi-mark", description: "U+200F sets the direction of adjacent neutral characters. Routine in genuine Arabic/Hebrew text; meaningless in pure-Latin text." },
  alm: { start: 0x061c, end: 0x061c, name: "Arabic Letter Mark (ALM)", class: "bidi-mark", description: "U+061C is the Arabic-script counterpart of RLM. Routine in genuine Arabic text." },

  // ─── bidirectional: embeddings (deprecated since Unicode 6.3) ───
  lre: { start: 0x202a, end: 0x202a, name: "Left-To-Right Embedding (LRE)", class: "bidi-embedding", description: "U+202A opens a left-to-right embedding that must be closed by U+202C. Deprecated in favour of isolates." },
  rle: { start: 0x202b, end: 0x202b, name: "Right-To-Left Embedding (RLE)", class: "bidi-embedding", description: "U+202B opens a right-to-left embedding that must be closed by U+202C. Deprecated in favour of isolates." },
  pdf: { start: 0x202c, end: 0x202c, name: "Pop Directional Formatting (PDF)", class: "bidi-terminator", description: "U+202C closes the innermost open embedding or override." },

  // ─── bidirectional: overrides (the Trojan Source primitive) ───
  lro: { start: 0x202d, end: 0x202d, name: "Left-To-Right Override (LRO)", class: "bidi-override", description: "U+202D forces left-to-right direction on STRONG characters — it changes rendered order for text that would otherwise render unambiguously." },
  rlo: { start: 0x202e, end: 0x202e, name: "Right-To-Left Override (RLO)", class: "bidi-override", description: "U+202E forces right-to-left direction on STRONG characters: the Latin text after it renders reversed. This is the primitive behind Trojan Source (CVE-2021-42574)." },

  // ─── bidirectional: isolates (modern, leak when unbalanced) ───
  lri: { start: 0x2066, end: 0x2066, name: "Left-To-Right Isolate (LRI)", class: "bidi-isolate", description: "U+2066 opens a left-to-right isolate that must be closed by U+2069." },
  rli: { start: 0x2067, end: 0x2067, name: "Right-To-Left Isolate (RLI)", class: "bidi-isolate", description: "U+2067 opens a right-to-left isolate that must be closed by U+2069." },
  fsi: { start: 0x2068, end: 0x2068, name: "First Strong Isolate (FSI)", class: "bidi-isolate", description: "U+2068 opens an isolate whose direction is taken from its first strong character." },
  pdi: { start: 0x2069, end: 0x2069, name: "Pop Directional Isolate (PDI)", class: "bidi-terminator", description: "U+2069 closes the innermost open isolate." },

  // ─── tag characters (U+E0000 block) ───
  tag_block: { start: 0xe0000, end: 0xe007f, name: "Tag Character", class: "tag-character", description: "U+E0020–U+E007E map 1:1 onto ASCII 0x20–0x7E, letting an attacker carry a complete ASCII message inside codepoints no renderer displays." },

  // ─── variation selectors ───
  vs_basic: { start: 0xfe00, end: 0xfe0f, name: "Variation Selector", class: "variation-selector", description: "U+FE00–U+FE0F select a glyph variant. Legitimate after an emoji base; unexplained in a plain Latin identifier." },
  vs_supplementary: { start: 0xe0100, end: 0xe01ef, name: "Supplementary Variation Selector", class: "variation-selector", description: "U+E0100–U+E01EF — used mainly in CJK Ideographic Variation Sequences." },

  // ─── Private Use Area ───
  private_use_bmp: { start: 0xe000, end: 0xf8ff, name: "Private Use Area (BMP)", class: "private-use", description: "U+E000–U+F8FF have no assigned meaning; rendering is font-dependent." },
  private_use_plane15: { start: 0xf0000, end: 0xffffd, name: "Supplementary Private Use Area-A", class: "private-use", description: "U+F0000–U+FFFFD — plane 15 private use; no assigned meaning." },
  private_use_plane16: { start: 0x100000, end: 0x10fffd, name: "Supplementary Private Use Area-B", class: "private-use", description: "U+100000–U+10FFFD — plane 16 private use; no assigned meaning." },

  // ─── invisible formatters / width spaces ───
  soft_hyphen: { start: 0x00ad, end: 0x00ad, name: "Soft Hyphen", class: "invisible-space", description: "U+00AD — rendered only when a line break falls at that point; otherwise invisible." },
  combining_grapheme_joiner: { start: 0x034f, end: 0x034f, name: "Combining Grapheme Joiner", class: "invisible-space", description: "U+034F — affects grapheme clustering; invisible in plain text." },
  hangul_filler: { start: 0x115f, end: 0x1160, name: "Hangul Filler", class: "invisible-space", description: "U+115F / U+1160 — invisible placeholder codepoints." },
  khmer_inherent_vowel: { start: 0x17b4, end: 0x17b5, name: "Khmer Inherent Vowel", class: "invisible-space", description: "U+17B4 / U+17B5 — deprecated invisible Khmer vowels." },
  mongolian_separator: { start: 0x180e, end: 0x180e, name: "Mongolian Vowel Separator", class: "invisible-space", description: "U+180E — historic invisible separator." },
  width_spaces: { start: 0x2000, end: 0x200a, name: "Width Spaces (EN QUAD … HAIR SPACE)", class: "invisible-space", description: "U+2000–U+200A — width-varying whitespace that substitutes silently for an ordinary ASCII space and defeats exact-match comparison." },
};

/**
 * Classes Guardian auto-flags on presence alone. Deliberately excludes:
 *   - "bidi-mark"  — routine in genuine Arabic/Hebrew prose (the single largest
 *                    false-positive source; Sentinel demotes them too);
 *   - "bidi-isolate" / "bidi-terminator" — only evidence when UNBALANCED, which
 *                    needs the structural analysis Guardian doesn't run in-browser;
 *   - "variation-selector" — legitimate after an emoji base;
 *   - "private-use" — icon fonts (Nerd/Powerline) legitimately use single PUA glyphs.
 * This mirrors Sentinel's own design intent for those classes.
 */
export const FLAGGED_CLASSES: ReadonlySet<InvisibleClass> = new Set<InvisibleClass>([
  "zero-width",
  "bidi-override",
  "bidi-embedding",
  "tag-character",
  "invisible-space",
]);

/** Lookup: codepoint → its InvisibleRange entry (or null). */
export function classifyInvisible(cp: number): InvisibleRange | null {
  for (const r of Object.values(INVISIBLE_RANGES)) {
    if (cp >= r.start && cp <= r.end) return r;
  }
  return null;
}
