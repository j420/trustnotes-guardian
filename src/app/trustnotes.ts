/**
 * TrustNotes — a real notes app a human AND their agent can both drive over WebMCP.
 * It registers four honest tools; Guardian (installed first) witnesses them.
 */
export interface Note { id: number; text: string; done: boolean; at: number }

const KEY = "trustnotes.notes";
let notes: Note[] = load();
let seq = notes.reduce((m, n) => Math.max(m, n.id), 0) + 1;
const listeners: Array<() => void> = [];
export function onNotesChange(fn: () => void) { listeners.push(fn); }
function changed() { save(); for (const l of listeners) l(); }
export function getNotes() { return notes.slice(); }

function load(): Note[] {
  try { const raw = localStorage.getItem(KEY); if (raw) return JSON.parse(raw); } catch { /* ignore */ }
  return [
    { id: 1, text: "Buy oat milk", done: false, at: Date.now() },
    { id: 2, text: "Reply to Dana about the trip", done: false, at: Date.now() },
    { id: 3, text: "Renew library card", done: true, at: Date.now() },
  ];
}
function save() { try { localStorage.setItem(KEY, JSON.stringify(notes)); } catch { /* ignore */ } }

const text = (o: unknown) => ({ content: [{ type: "text", text: typeof o === "string" ? o : JSON.stringify(o) }] });

/** Register the four honest TrustNotes tools on the (already-guarded) modelContext. */
export async function registerTrustNotesTools(mc: any) {
  await mc.registerTool({
    name: "add_note",
    description: "Add a note to the user's list.",
    annotations: { readOnlyHint: false },
    inputSchema: { type: "object", properties: { text: { type: "string", minLength: 1, maxLength: 500 } }, required: ["text"], additionalProperties: false },
    execute: async (a: any) => { const n: Note = { id: seq++, text: String(a.text), done: false, at: Date.now() }; notes.push(n); changed(); return text(`Added note #${n.id}: ${n.text}`); },
  });

  await mc.registerTool({
    name: "search_notes",
    description: "Search the user's notes for a query string. Read-only.",
    annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"], additionalProperties: false },
    execute: async (a: any) => { const q = String(a.query || "").toLowerCase(); const hits = notes.filter((n) => n.text.toLowerCase().includes(q)); return text({ count: hits.length, notes: hits }); },
  });

  await mc.registerTool({
    name: "delete_note",
    description: "Delete a note by id. This permanently removes it.",
    annotations: { readOnlyHint: false, destructiveHint: true },
    inputSchema: { type: "object", properties: { id: { type: "number" } }, required: ["id"], additionalProperties: false },
    execute: async (a: any) => { const before = notes.length; notes = notes.filter((n) => n.id !== Number(a.id)); changed(); return text(before === notes.length ? `No note #${a.id}` : `Deleted note #${a.id}`); },
  });

  await mc.registerTool({
    name: "export_notes",
    description: "Return all notes as JSON so the user can copy or back them up. Read-only.",
    annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    execute: async () => text({ notes }),
  });
}
