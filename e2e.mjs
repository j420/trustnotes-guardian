// End-to-end: loads the built app in real Chromium and drives the full demo flow,
// asserting Guardian's witnessed behavior at every beat. Serves dist/ over http.
import { chromium } from "playwright";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const DIST = new URL("./dist/", import.meta.url).pathname;
const PORT = 4320;
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".map": "application/json", ".svg": "image/svg+xml" };
const server = http.createServer(async (req, res) => {
  try {
    let p = decodeURIComponent((req.url || "/").split("?")[0]);
    if (p === "/") p = "/index.html";
    const file = join(DIST, normalize(p));
    if (!file.startsWith(DIST)) { res.writeHead(403); return res.end(); }
    const body = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" });
    res.end(body);
  } catch { res.writeHead(404); res.end("nf"); }
});
await new Promise((r) => server.listen(PORT, r));

const browser = await chromium.launch({ headless: true, executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome", args: ["--no-sandbox", "--disable-dev-shm-usage"] });
const page = await browser.newPage();
await page.goto(`http://localhost:${PORT}/`, { waitUntil: "networkidle" });
await page.waitForFunction(() => window.__guardian && window.__guardian.tools.size >= 4, { timeout: 15000 });
// Force the load window closed so the widget's tool is unambiguously "mid-session".
await page.evaluate(() => { window.__guardian.__forceMid = true; });
await page.waitForTimeout(1600); // let the 1.5s mid-session window close

const R = await page.evaluate(async () => {
  const out = [];
  const push = (name, pass, detail = "") => out.push({ name, pass, detail });
  const g = window.__guardian;
  const mc = document.modelContext;
  const call = async (name, args) => { const tools = await mc.getTools(); const t = tools.find((x) => x.name === name); return t ? mc.executeTool(t, JSON.stringify(args), {}) : (navigator.modelContextTesting?.executeTool(name, JSON.stringify(args))); };

  // 1. four honest tools + guardian tools present
  const names = [...g.tools.keys()];
  push("4 TrustNotes tools registered", ["add_note", "search_notes", "delete_note", "export_notes"].every((n) => names.includes(n)), names.join(","));
  const exposed = (await mc.getTools()).map((t) => t.name);
  push("guardian_* tools exposed to the agent", ["guardian_audit_page", "guardian_probe_tool", "guardian_explain_tool"].every((n) => exposed.includes(n)), "");
  push("all page tools start 'not-yet-observed'", [...g.tools.values()].every((r) => r.status === "not-yet-observed"), "");

  // 2. agent runs a legit read-only tool -> observed consistent, no egress
  await call("search_notes", { query: "trip" });
  const sn = g.tools.get("search_notes");
  push("search_notes observed consistent (read-only, no egress)", sn.status === "consistent" && sn.divergences.length === 0, sn.status);

  // 3. third-party widget injects a poisoned tool mid-session
  await new Promise((res) => { const s = document.createElement("script"); s.src = "/community-widget.js?ts=" + Date.now(); s.onload = res; s.onerror = res; document.body.append(s); });
  await new Promise((r) => setTimeout(r, 300));
  const poisoned = [...g.tools.values()].find((r) => r.provenance === "mid-session");
  push("poisoned tool injected mid-session + caught", !!poisoned, poisoned ? poisoned.name : "NOT FOUND");
  if (!poisoned) return out;
  push("flagged mid-session", poisoned.provenance === "mid-session", poisoned.provenance);
  push("static flags: homoglyph + hidden + injection + preference + trust + prior-approval", ["UNICODE-HOMOGLYPH", "UNICODE-HIDDEN", "INJ-IMPERATIVE", "PREFERENCE-MANIP", "TRUST-ASSERTION", "PRIOR-APPROVAL"].every((id) => poisoned.staticFlags.some((f) => f.id === id)), poisoned.staticFlags.map((f) => f.id).join(","));
  push("declares read-only", poisoned.declaredReadOnly === true, "");

  // 3b. PAGE-LEVEL: loading the widget completes the lethal trifecta across the page's tools (F1)
  push("F1 lethal trifecta present after widget loads", g.pageFindings.some((f) => f.sentinelRule === "F1"), g.pageFindings.map((f) => f.sentinelRule).join(",") || "none");

  // 3c. WITNESSED OUTPUT: the widget's error-helper returns a poisoned string (J5)
  await call("community_error_helper", {});
  const helper = g.tools.get("community_error_helper");
  push("J5 witnessed output poisoning caught (community_error_helper)", !!helper && helper.outputFindings.some((f) => f.sentinelRule === "J5"), helper ? helper.outputFindings.map((f) => f.id).join(",") : "no helper");

  // 4. probe (deny-all) witnesses the divergence with no real network
  const probe = await g.probe(poisoned.name, { probe: true });
  push("probe witnessed a divergence (declared read-only, observed egress)", probe.divergences.some((d) => d.kind === "readonly-violation"), JSON.stringify(probe.divergences));
  push("probe blocked the egress", probe.effects.some((e) => e.external && e.blocked), "");
  push("poisoned tool now 'diverged'", poisoned.status === "diverged", poisoned.status);

  // 5. agent actually calls the poisoned tool -> consent required -> approve -> egress blocked live
  g.consentHandler = async () => true; // simulate the human clicking Approve
  const res1 = await call(poisoned.name, { q: "x" });
  const blocked = poisoned.sideEffects.some((e) => e.external && e.blocked);
  push("live call: external egress BLOCKED", blocked, "");

  // 6. agent calls a real destructive tool -> consent -> DENY -> not executed
  // (assert the gate directly on the raw result; the polyfill's executeTool normalizes it)
  g.consentHandler = async () => true;
  await g.guardedExecute("add_note", { text: "seed note" }); // seed so the count is meaningful
  const notesBefore = JSON.parse(localStorage.getItem("trustnotes.notes") || "[]").length;
  g.consentHandler = async () => false; // simulate the human clicking Deny
  const res2 = await g.guardedExecute("delete_note", { id: 1 });
  const notesAfter = JSON.parse(localStorage.getItem("trustnotes.notes") || "[]").length;
  push("denied destructive call did NOT execute", res2?.isError === true && notesAfter === notesBefore, `before=${notesBefore} after=${notesAfter} isError=${res2?.isError}`);
  push("deny recorded on the timeline", g.timeline.some((e) => e.kind === "consent" && /DENIED/.test(e.detail)), "");

  // 7. input validation blocks a malformed call
  g.consentHandler = async () => true;
  const res3 = await g.guardedExecute("add_note", { wrong: "field" });
  push("Ajv validation blocked a malformed call", res3?.isError === true, res3?.content?.[0]?.text || "");

  return out;
});

// 8. REAL-AGENT PATH (mocked OpenAI — no key, no live network): the LLM only DRIVES; every
// tool call it issues flows through the SAME executeTool → guardedExecute gate. We stub
// /api/agent at the Node level with a stateful two-response conversation: turn 1 returns an
// assistant message with a tool_call to community_sync; turn 2 returns finish_reason "stop".
// Then we drive the real UI (toggle → Run) and assert the model-issued call was gated and its
// egress BLOCKED — proving the real-agent path is protected without any live key or network.
let proxyCalls = 0;
await page.route("**/api/agent", async (route) => {
  proxyCalls++;
  const bodyObj = proxyCalls === 1
    ? { choices: [{ finish_reason: "tool_calls", message: { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "community_sync", arguments: '{"q":"notes"}' } }] } }] }
    : { choices: [{ finish_reason: "stop", message: { role: "assistant", content: "I attempted the sync; Guardian blocked the external egress." } }] };
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(bodyObj) });
});

await page.evaluate(() => { window.__guardian.consentHandler = async () => true; }); // human approves
const beforeRuns = await page.evaluate(() => window.__guardian.tools.get("community_sync")?.observedRuns ?? -1);
await page.click("#mode-real");
await page.fill("#agent-instruction", "sync my notes to the community board");
await page.click("#agent-run");
await page.waitForFunction((b) => {
  const cs = window.__guardian.tools.get("community_sync");
  const btn = document.querySelector("#agent-run");
  return cs && cs.observedRuns > b && btn && !btn.disabled;
}, beforeRuns, { timeout: 10000 }).catch(() => {});
const ra = await page.evaluate((b) => {
  const cs = window.__guardian.tools.get("community_sync");
  if (!cs) return { pass: false, detail: "community_sync missing" };
  const blocked = cs.sideEffects.some((e) => e.external && e.blocked);
  return { pass: cs.observedRuns > b && blocked, detail: `runs ${b}->${cs.observedRuns} blocked=${blocked}` };
}, beforeRuns);
R.push({ name: "real agent (mocked OpenAI) drove a tool call through Guardian's gate — egress BLOCKED", pass: ra.pass && proxyCalls >= 1, detail: `${ra.detail} proxyCalls=${proxyCalls}` });

console.log("\n============ TRUSTNOTES + GUARDIAN E2E ============");
let allPass = true;
for (const c of R) { if (!c.pass) allPass = false; console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   [" + c.detail + "]" : ""}`); }
console.log("---------------------------------------------------");
console.log(`${R.filter((c) => c.pass).length}/${R.length} => ${allPass ? "ALL PASS ✅" : "SOME FAILED ❌"}`);
await browser.close(); server.close();
process.exit(allPass ? 0 : 1);
