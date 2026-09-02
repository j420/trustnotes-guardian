/** Guardian inspector UI: DECLARED | OBSERVED | FLAGS per tool, timeline, consent modal, agent-sim. */
import { guardian } from "../guardian/index.js";
import type { ToolRecord } from "../guardian/types.js";
import { getNotes, onNotesChange } from "../app/trustnotes.js";
import { ruleMeta, SENTINEL_RULES } from "../guardian/data/sentinel-registry.js";
import { runRealAgent } from "../agent/openai-agent.js";

const $ = (sel: string, root: ParentNode = document) => root.querySelector(sel) as HTMLElement;
const el = (tag: string, cls?: string, txt?: string) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };

/** A small "Sentinel A7 · critical · MCP01 · AML.T0054" ribbon with an expandable remediation. */
function ruleRibbon(ruleId: string): HTMLElement | null {
  const m = ruleMeta(ruleId);
  if (!m) return null;
  const box = el("div", "rule-meta");
  const head = el("div", "rule-meta-head");
  head.append(
    el("span", "rule-id", "Sentinel " + m.id),
    el("span", "sev sev-" + m.severity, m.severity),
    el("span", "rule-name", m.name),
  );
  const tags = el("span", "rule-tags");
  tags.append(el("span", "tag owasp", m.owasp));
  if (m.mitre) tags.append(el("span", "tag mitre", m.mitre));
  head.append(tags);
  box.append(head);
  const rem = el("details", "rule-rem");
  rem.append(el("summary", "", "remediation (from Sentinel)"), el("p", "", m.remediation));
  box.append(rem);
  return box;
}

const STATUS_LABEL: Record<ToolRecord["status"], string> = {
  "not-yet-observed": "not yet observed", consistent: "consistent", diverged: "diverged", flagged: "flagged",
};

export function mountUI() {
  renderNotes();
  onNotesChange(renderNotes);
  guardian.addEventListener("change", renderGuardian);
  guardian.consentHandler = consentModal;
  renderGuardian();
  renderSentinelPanel();
  wireControls();
}

// ---------- Powered-by-Sentinel panel (driven by the ported registry) ----------
function renderSentinelPanel() {
  const table = document.querySelector("#sentinel-rules") as HTMLTableElement | null;
  if (!table) return;
  table.innerHTML = "";
  const head = el("tr", "sr-head");
  for (const h of ["Rule", "Sev", "What Guardian ports"]) head.append(el("th", "", h));
  table.append(head);
  for (const m of Object.values(SENTINEL_RULES)) {
    const row = el("tr", "sr-row");
    const c1 = el("td", "sr-rule");
    c1.append(el("span", "rule-id", m.id), el("span", "sr-name", m.name));
    const c2 = el("td", "sr-sev");
    c2.append(el("span", "sev sev-" + m.severity, m.severity));
    const c3 = el("td", "sr-use", m.guardianUse);
    row.append(c1, c2, c3);
    table.append(row);
  }
}

// ---------- TrustNotes ----------
function renderNotes() {
  const list = $("#tn-list");
  list.innerHTML = "";
  for (const n of getNotes()) {
    const row = el("li", "tn-note" + (n.done ? " done" : ""));
    row.append(el("span", "tn-dot"), el("span", "tn-text", n.text), el("span", "tn-id", "#" + n.id));
    list.append(row);
  }
}

// ---------- Guardian panel ----------
function renderGuardian() {
  const wrap = $("#g-tools");
  wrap.innerHTML = "";
  const active = guardian.interceptionActive;
  const status = el("div", "g-status " + (active ? "ok" : "warn"));
  status.textContent = active
    ? "🛡️ interception ACTIVE — Guardian wraps registerTool and witnesses every call in this browser"
    : "⚠ interception LIMITED — this browser locks registerTool (native WebMCP); Guardian can still read tools, but consent/gating are unavailable here. Use a normal Chrome/Edge tab for the full demo.";
  wrap.append(status);
  renderPageFindings(wrap);
  const records = [...guardian.tools.values()];
  if (!records.length) { wrap.append(el("p", "muted", "No page tools registered yet.")); }
  for (const r of records) wrap.append(toolCard(r));
  renderTimeline();
}

/** Page-level findings (F1 lethal trifecta, I16 consent fatigue) — span the whole tool set. */
function renderPageFindings(wrap: HTMLElement) {
  for (const f of guardian.pageFindings) {
    const box = el("div", "g-page");
    box.append(el("span", "warn", "⚠ PAGE-LEVEL"), el("span", "flag-label", f.label), el("code", "flag-ev", f.evidence));
    const ribbon = ruleRibbon(f.sentinelRule);
    if (ribbon) box.append(ribbon);
    wrap.append(box);
  }
}

function toolCard(r: ToolRecord): HTMLElement {
  const card = el("div", "g-card status-" + r.status);
  const head = el("div", "g-card-head");
  const name = el("span", "g-name");
  name.append(document.createTextNode(r.name));
  if (r.provenance === "mid-session") name.append(el("span", "badge badge-mid", "mid-session"));
  const pill = el("span", "pill pill-" + r.status, STATUS_LABEL[r.status]);
  head.append(name, pill);
  card.append(head);

  const declared = el("div", "g-line");
  declared.append(el("span", "k", "DECLARED"), el("span", "v", (r.declaredReadOnly ? "read-only" : "read-write") + (r.description ? " · " + trim(r.description, 80) : "")));
  card.append(declared);

  const observed = el("div", "g-line");
  const obsText = r.status === "not-yet-observed"
    ? "not yet observed — run or probe it to witness its behavior"
    : describeObserved(r);
  observed.append(el("span", "k", "OBSERVED"), el("span", "v " + (r.divergences.length ? "danger" : ""), obsText));
  card.append(observed);

  for (const d of r.divergences) {
    const div = el("div", "g-diverge");
    div.append(el("span", "warn", "⚠ DIVERGENCE"), el("span", "", `declared ${d.declared} — observed ${d.observed}`));
    const ribbon = ruleRibbon(d.sentinelRule);
    if (ribbon) div.append(ribbon);
    card.append(div);
  }
  for (const f of r.staticFlags) {
    const flag = el("div", "g-flag");
    flag.append(el("span", "flag-id", f.id), el("span", "flag-label", f.label), el("code", "flag-ev", f.evidence));
    const ribbon = ruleRibbon(f.sentinelRule);
    if (ribbon) flag.append(ribbon);
    card.append(flag);
  }
  for (const f of r.outputFindings) {
    const wo = el("div", "g-output");
    wo.append(el("span", "warn", "⚠ WITNESSED OUTPUT"), el("span", "flag-label", f.label), el("code", "flag-ev", f.evidence));
    const ribbon = ruleRibbon(f.sentinelRule);
    if (ribbon) wo.append(ribbon);
    card.append(wo);
  }

  const btn = el("button", "g-probe", "Probe (safe dry-run)") as HTMLButtonElement;
  btn.onclick = async () => { btn.disabled = true; btn.textContent = "probing…"; await guardian.probe(r.name, { probe: true, query: "canary" }); btn.disabled = false; btn.textContent = "Probe (safe dry-run)"; };
  card.append(btn);
  return card;
}

function describeObserved(r: ToolRecord): string {
  const eff = r.sideEffects;
  if (!eff.length) return `ran ${r.observedRuns + r.probeRuns}× — no side effects (matches declared)`;
  const ext = eff.filter((e) => e.external);
  const parts: string[] = [];
  const store = eff.filter((e) => e.kind === "storage").length;
  if (store) parts.push(`${store} local write(s)`);
  if (ext.length) parts.push(`attempted external egress → ${[...new Set(ext.map((e) => host(e.detail)))].join(", ")} (${ext.every((e) => e.blocked) ? "BLOCKED" : "some allowed"})`);
  if (!parts.length) parts.push("read-only activity");
  return parts.join(" · ");
}

function renderTimeline() {
  const t = $("#g-timeline");
  t.innerHTML = "";
  for (const e of guardian.timeline.slice(-9).reverse()) {
    const row = el("li", "tl tl-" + e.kind);
    row.append(el("span", "tl-kind", e.kind), el("span", "tl-tool", e.tool), el("span", "tl-detail", e.detail));
    t.append(row);
  }
}

// ---------- consent modal ----------
function consentModal(req: { record: ToolRecord; args: unknown; reason: string }): Promise<boolean> {
  return new Promise((resolve) => {
    const back = el("div", "modal-back");
    const box = el("div", "modal");
    box.append(el("h3", "", "Guardian — approve this action?"));
    box.append(el("p", "modal-reason", req.reason));
    const meta = el("div", "modal-meta");
    meta.append(kv("Tool", req.record.name), kv("Declared", req.record.declaredReadOnly ? "read-only" : "read-write"), kv("Status", STATUS_LABEL[req.record.status]));
    box.append(meta);
    if (req.record.divergences.length) box.append(el("p", "danger", "Witnessed divergence: " + req.record.divergences[0].observed));
    box.append(el("div", "modal-args-label", "Arguments the tool will receive:"));
    box.append(el("pre", "modal-args", JSON.stringify(req.args, null, 2)));
    const actions = el("div", "modal-actions");
    const deny = el("button", "btn-deny", "Deny") as HTMLButtonElement;
    const approve = el("button", "btn-approve", "Approve") as HTMLButtonElement;
    deny.onclick = () => { back.remove(); resolve(false); };
    approve.onclick = () => { back.remove(); resolve(true); };
    actions.append(deny, approve);
    box.append(actions);
    back.append(box);
    document.body.append(back);
  });
}
function kv(k: string, v: string) { const d = el("div", "kv"); d.append(el("span", "kv-k", k), el("span", "kv-v", v)); return d; }

// ---------- agent driver (shared by BOTH modes) + controls ----------
/**
 * THE shared, gated dispatch path. Both the Witnessed-run simulator and the real OpenAI agent
 * route every tool call through here → the tool's guarded execute → Guardian's gate. WebMCP
 * runtimes disagree on how `executeTool` takes arguments — the `@mcp-b` polyfill wants a JSON
 * STRING, native/newer builds want an OBJECT (they throw "requires an object input" on a string) —
 * so `invokeThroughGate` reconciles them. Returns the tool's textual result; never throws.
 */
async function execViaGuardian(realName: string, argsJson: string): Promise<string> {
  const mc: any = (document as any).modelContext ?? (navigator as any).modelContext;
  const argsObj = safeJson(argsJson) ?? {};
  logSim(`agent → ${realName}(${trim(argsJson, 120)})`);
  try {
    const res = await invokeThroughGate(mc, realName, argsJson, argsObj);
    // executeTool returns a JSON STRING (serializeChromeToolResult); guardedExecute returns the
    // result object directly. Normalise both before reading .content/.isError, so a Guardian-DENIED
    // call never renders green "ok".
    const parsed = typeof res === "string" ? safeJson(res) : res;
    const out = parsed?.content?.[0]?.text ?? (typeof res === "string" ? res : JSON.stringify(res));
    logSim(`  ↳ ${trim(String(out), 160)}`, parsed?.isError ? "err" : "ok");
    return typeof out === "string" ? out : JSON.stringify(out);
  } catch (e: any) {
    const m = `blocked/error: ${e?.message || e}`;
    logSim(`  ↳ ${m}`, "err");
    return m;
  }
}

/**
 * Reach the tool's guarded execute across WebMCP runtimes:
 *  1. Guardian's own gate when it successfully wrapped registerTool — runtime-independent, takes an
 *     object, and is exactly where a real `executeTool` routes anyway.
 *  2. Otherwise the WebMCP `executeTool` API — OBJECT form first (native / newer builds), then the
 *     `@mcp-b` JSON-STRING form, retried ONLY on an input-shape error so a real side effect never
 *     runs twice — then the testing shim.
 */
async function invokeThroughGate(mc: any, realName: string, argsJson: string, argsObj: unknown): Promise<any> {
  const g: any = (window as any).__guardian;
  if (g?.interceptionActive && g.tools?.has?.(realName) && typeof g.guardedExecute === "function") {
    return g.guardedExecute(realName, argsObj);
  }
  const tools = mc?.getTools ? await mc.getTools() : [];
  const tool = tools.find((t: any) => t.name === realName);
  if (!tool) return (navigator as any).modelContextTesting?.executeTool(realName, argsJson);
  try {
    return await mc.executeTool(tool, argsObj); // object form (native / newer WebMCP)
  } catch (e: any) {
    if (/object input|must be a string|expected .*string|invalid.*argument|not.*json/i.test(String(e?.message || e))) {
      return mc.executeTool(tool, argsJson, {}); // @mcp-b string form
    }
    throw e;
  }
}

/** Scripted-simulator convenience: the buttons call this with a JS object. */
function agentCall(name: string, args: unknown): Promise<string> {
  return execViaGuardian(name, JSON.stringify(args));
}

function logSim(line: string, cls = "") {
  const log = document.querySelector("#sim-log");
  if (!log) return;
  const row = el("div", "sim-line " + cls, line);
  log.append(row);
  log.scrollTop = log.scrollHeight;
}

function wireControls() {
  // Every lookup is null-guarded: a missing element must never reject boot (mountUI is now
  // wrapped in try/catch too), and the toggle adds NEW ids without disturbing the existing ones.
  const form = document.querySelector("#tn-add-form") as HTMLFormElement | null;
  if (form) form.onsubmit = (e) => {
    e.preventDefault();
    const inp = document.querySelector("#tn-add-input") as HTMLInputElement | null;
    if (inp && inp.value.trim()) agentCall("add_note", { text: inp.value.trim() });
    if (inp) inp.value = "";
  };
  bindClick("#load-widget", () => {
    const s = document.createElement("script");
    s.src = "/community-widget.js?ts=" + Date.now();
    document.body.append(s);
    logSim("⚠ loaded third-party 'community widget' (untrusted embed)", "warn");
  });
  bindClick("#sim-search", () => void agentCall("search_notes", { query: "trip" }));
  bindClick("#sim-audit", () => void agentCall("guardian_audit_page", {}));
  bindClick("#sim-call-widget", () => void agentCall("community_sync", { q: "x" })); // the mid-session-injected tool
  bindClick("#sim-call-helper", () => void agentCall("community_error_helper", {})); // witnessed output poisoning (J5)
  bindClick("#sim-delete", () => void agentCall("delete_note", { id: 1 }));
  wireAgentMode();
}

function bindClick(sel: string, fn: () => void) {
  const b = document.querySelector(sel) as HTMLButtonElement | null;
  if (b) b.onclick = fn;
}

/** Segmented Scripted ↔ Real toggle + the real-agent Run handler. All null-guarded. */
function wireAgentMode() {
  const scriptedBtn = document.querySelector("#mode-scripted") as HTMLButtonElement | null;
  const realBtn = document.querySelector("#mode-real") as HTMLButtonElement | null;
  const scriptedPanel = document.querySelector("#panel-scripted") as HTMLElement | null;
  const realPanel = document.querySelector("#panel-real") as HTMLElement | null;
  if (scriptedBtn && realBtn && scriptedPanel && realPanel) {
    const setMode = (real: boolean) => {
      realBtn.classList.toggle("active", real);
      scriptedBtn.classList.toggle("active", !real);
      realPanel.hidden = !real;
      scriptedPanel.hidden = real;
    };
    scriptedBtn.onclick = () => setMode(false);
    realBtn.onclick = () => setMode(true);
  }
  const runBtn = document.querySelector("#agent-run") as HTMLButtonElement | null;
  if (runBtn) runBtn.onclick = () => void runAgentFromUI(runBtn);
}

/** Read the instruction (+ optional BYO key) and drive the real agent through Guardian's gate. */
async function runAgentFromUI(runBtn: HTMLButtonElement) {
  const inp = document.querySelector("#agent-instruction") as HTMLInputElement | null;
  const keyInp = document.querySelector("#agent-key") as HTMLInputElement | null;
  const instruction = (inp?.value || "").trim() || "Help me with my notes.";
  const apiKey = (keyInp?.value || "").trim() || undefined;
  const label = runBtn.textContent || "Run";
  runBtn.disabled = true;
  runBtn.textContent = "running…";
  logSim(`▶ real agent: “${trim(instruction, 100)}”`, "warn");
  try {
    const res = await runRealAgent(instruction, { exec: execViaGuardian, log: logSim, apiKey });
    if (res.needsKey) {
      const d = document.querySelector(".real-key") as HTMLDetailsElement | null;
      if (d) d.open = true; // reveal the BYO-key field when the server has no key / no proxy
    }
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = label;
  }
}

function trim(s: string, n: number) { return s.length > n ? s.slice(0, n) + "…" : s; }
function host(u: string) { try { return new URL(u, location.href).host; } catch { return u; } }
function safeJson(s: string): any { try { return JSON.parse(s); } catch { return null; } }
