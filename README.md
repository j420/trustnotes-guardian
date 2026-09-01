# 🛡️ WebMCP Guardian — *watches what tools do, not what they say*

**A drop‑in, client‑side trust layer for [WebMCP](https://github.com/webmachinelearning/webmcp).**
It witnesses what every agent‑callable tool on a page actually *does*, catches tools injected
mid‑session by third‑party scripts, and gates risky calls behind human consent — and it exposes all of
that as agent‑callable WebMCP tools. Demonstrated inside **TrustNotes**, a real notes app a human and
their agent both drive.

Open source (MIT).

---

## The problem

WebMCP lets a web page hand *tools* to an in‑browser AI agent (`navigator.modelContext.registerTool`).
But the page writes each tool's **name and description** — the exact text the agent reads to decide what
to do — and WebMCP gives every script on the page (analytics, chat widgets, ads, A/B tools) the **same
`document.modelContext`**. So any third‑party embed can **register or mutate an agent‑callable tool
mid‑session**. This is *Mid‑Session Tool Injection* — the threat described in **arXiv 2606.06387,
“WebMCP Tool Surface Poisoning: Runtime Manipulation Attacks on LLM Agents.”** WebMCP today ships **no
built‑in defense, and its consent primitive (`requestUserInteraction()`) is still an unfinished TODO in
the draft spec.**

## What Guardian does — **observe · catch · gate** (no risk score)

Guardian doesn't guess a tool's risk from its description. It **witnesses behavior** and reports
**DECLARED vs OBSERVED**.

- **Observe** — wraps each tool's `execute` and instruments the page's side‑effect surface
  (`fetch` / `XHR` / `sendBeacon` / WebSocket / `localStorage` / clipboard), attributing every effect to
  the tool that caused it. The headline finding is a **declared‑vs‑observed divergence**: a tool that
  declared `readOnlyHint: true` but is *observed* attempting to send your data to an external origin —
  and Guardian **blocks that egress live**. (This maps to MCP Sentinel's **E5**, declared‑vs‑observed
  behavior divergence.)
- **Catch** — flags tools **registered after the page loaded** (mid‑session injection) and **attempted
  overwrites** of a trusted tool (the platform rejects duplicate names; Guardian records the attempt).
- **Gate** — a **human‑consent** prompt before a risky call (showing the *exact arguments*) plus
  **JSON‑Schema input validation** (the polyfill does none) — the safety WebMCP itself doesn't provide
  yet. Plus a **Probe** button: run a tool once in a **deny‑all witnessing harness** (canary inputs,
  egress denied, local writes shadowed) to see what it *would* do **before** you ever let it run.

Guardian also registers its own agent‑callable tools — `guardian_audit_page`, `guardian_probe_tool`,
`guardian_explain_tool` — so an agent can ask *"is this page safe?"*. **No tool can disable Guardian.**

### Honest by design
- Every claim is labeled **DECLARED** (the tool's own words) vs **OBSERVED** (what Guardian witnessed)
  vs a **static** metadata fact.
- A tool the agent hasn't run is **“not yet observed” — never “safe.”**
- The **Agent Simulator** in the UI is clearly labeled **“scripted calls, not a live LLM.”** It issues
  the exact `executeTool` calls a real agent would; Guardian's gate sits on `execute`, so it fires
  identically for a real agent, the simulator, or a malicious script. **Verdicts are computed live,
  never scripted.**

## Powered by the MCP Sentinel taxonomy — concretely

Guardian reuses **real detection data ported from [MCP Sentinel](https://github.com/j420/mcpsentinal)**,
a 183‑rule MCP‑security registry — **20 rules** re‑implemented for the browser. Sentinel's engine is
server‑side (Node + Postgres) and can't run in a browser, so Guardian ports the tables and, crucially,
Sentinel's *matching strategy* — not a naive keyword scan. The ported data lives in
[`src/guardian/data/sentinel-*.ts`](src/guardian/data); some catalogues are **verbatim**, the two biggest
classifiers are honestly‑labeled **curated subsets**:

| File | Ported from Sentinel | Fidelity |
|---|---|---|
| `sentinel-invisible.ts` (A7) | `a7-zero-width-injection/data/invisible-codepoints.ts` | **verbatim** (class‑gated) |
| `sentinel-phrases.ts` (A1) | `a1-.../data/injection-phrases.ts` | **verbatim** (ordered‑token) |
| `sentinel-preference.ts` (J6) | `j6-.../data/preference-composition.ts` | **verbatim** (compositional) |
| `sentinel-prior-approval.ts` (G5) | `g5-.../data/prior-approval-phrases.ts` | **verbatim** (ordered‑token + adjacency) |
| `sentinel-trust.ts` (G2) | `g2-.../trust-consequences.ts` + `_shared/ai-manipulation-phrases.ts` | **curated subset** (12 of 16 authority claims) + composition |
| `sentinel-scope.ts` / `-capability-vocab.ts` / `-dangerous-params.ts` / `-dangerous-defaults.ts` / `-schema-poisoning.ts` | A2 / A8 / B2 / B7 / J3 data | **verbatim** typed tables |
| `sentinel-output-poisoning.ts` (J5) | `j5-.../data/config.ts` | **curated subset** (18 of 20 directives) + verbatim gate |
| `sentinel-encoded.ts` (A9) | `a9-.../{decode.ts, data/*}` | **curated subset** decoder (base64/percent/hex) |
| `sentinel-confusables.ts` (A6) | `a6-...` UTS‑39 table (~97k tokens) | **curated subset** (mixed‑script gate) |
| `sentinel-capabilities.ts` (F1/I16) | `analyzers/capability-graph.ts` (~1358 lines) | **curated subset** tagger |
| `sentinel-registry.ts` | `packages/database/src/rule-registry.ts` | **verbatim** severity/OWASP/MITRE; names & remediation condensed |

The 20 rules span **three surfaces**, and every finding cites the rule + surfaces its real Sentinel metadata:

| Surface | Sentinel rules |
|---|---|
| **DECLARED metadata** (name/description/schema/annotations) | A1, A2, A6, A7, A8, A9, B2, B6, B7, G2, G5, I2, J3, J6 |
| **Whole tool set** (page‑level) | F1 lethal trifecta · I16 consent fatigue |
| **WITNESSED behavior** (runtime) | E5 declared‑vs‑observed · J5 tool‑output poisoning · G6 / I1 realized here |

All 20 are in the registry and cited on findings. **18 emit a standalone finding**; the other two are
realized behaviorally — **I1** (annotation deception) drives **E5**'s declared‑vs‑observed divergence
rather than a separate detector, and **G6** (rug‑pull) surfaces as the mid‑session‑injection badge.

**Validated against Sentinel's own red‑team fixtures.** `npm run validate` runs Guardian's ported
detectors against the *actual* true‑positive / true‑negative strings from Sentinel's fixture suite —
**61/61** (37 rule cases + 6 widget + 4 page‑level + 6 witnessed‑output + 8 false‑positive regression
guards), including Sentinel's *hard negatives* that a substring matcher false‑positives on: the
`always returns the first row` data‑noun trap, the `alwaysOnCache` substring trap, an honest deprecation
notice, a certification that *requires* confirmation (G2 waiver‑inverted), a legitimate percent‑encoding
doc (A9), an `id_rsa.pub` rotation note (J5), and bidi marks in genuine RTL prose.

Guardian uses the *same severity vocabulary* as Sentinel, but it does **not** produce a risk score — the
verdict comes from **witnessed behavior**, not a points total. A curated subset means a look‑alike outside
the ported set is a Guardian miss that Sentinel's full server‑side rule would still catch (stated in the
app's "Powered by MCP Sentinel" panel).

## Run it

```bash
npm install
npm run dev        # open the printed localhost URL
npm run build      # static production build → dist/
npm run typecheck  # tsc --noEmit
npm run spike      # Phase-0 mechanics proof (headless Chromium) — 12/12
npm run e2e        # full demo flow proof (headless Chromium) — 17/17
npm run validate   # ported detectors vs Sentinel's own red-team fixtures — 61/61
```

Runs in any modern browser via the **`@mcp-b/global`** WebMCP polyfill; also runs under native WebMCP
in Chrome (behind the WebMCP flag) and ChatGPT's in‑app browser.

### Add Guardian to your own WebMCP page
```ts
import "@mcp-b/global";                 // installs document.modelContext (or use native)
import { guardian } from "trustnotes-guardian/guardian";
guardian.install(document.modelContext); // BEFORE you register your own tools
```

## Verified vs assumed (scope, honestly)
- **Verified** (in real headless Chromium, against the real `@mcp-b` polyfill): interception on the
  `executeTool` + testing‑shim paths; a `fetch` inside `execute` attributed to its tool and blocked;
  duplicate‑name `InvalidStateError`; the probe witnessing a blocked egress with no real network; Ajv
  validation in the production build. (`npm run spike` = 12/12, `npm run e2e` = 17/17.)
- **Assumed, not verified**: behavior on a *native* flag‑gated browser build (property writability,
  agent access) — we demonstrate on the polyfill path, which is today's real target. Side‑effect
  attribution is within a tool's execution window; an effect a tool defers past its own return is
  best‑effort.
- **Scope**: Guardian protects a page where it loads first from third‑party scripts injecting tools
  mid‑session; it does **not** retro‑wrap a hostile page that loaded before it. The platform enforces a
  tool‑*name* charset, so a homoglyph rides in the (unrestricted) *description* — but the behavioral
  divergence Guardian catches is **name‑independent**.

## Not a “security theater” claim
We're **not aware of** another client‑side security layer for WebMCP (the official *Model Context Tool
Inspector* lists and executes tools and has Gemini testing, but does no security witnessing, mid‑session
detection, or consent gating). Guardian's difference is **active enforcement + behavioral witnessing +
agent‑callable**, spined by a real MCP‑security taxonomy.

## License
MIT.
