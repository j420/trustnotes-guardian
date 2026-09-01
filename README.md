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

Guardian's static observations reuse **real detection data ported from [MCP Sentinel](https://github.com/j420/mcpsentinal)**,
a 183‑rule MCP‑security registry. Sentinel's engine is server‑side (Node + Postgres) and can't run in a
browser, so Guardian ports the browser‑relevant tables and, crucially, Sentinel's *matching strategy* —
not a naive keyword scan. The ported data lives in [`src/guardian/data/sentinel-*.ts`](src/guardian/data):

| File | Ported from Sentinel | Fidelity |
|---|---|---|
| `sentinel-invisible.ts` | `a7-zero-width-injection/data/invisible-codepoints.ts` | **verbatim** catalogue (class‑gated) |
| `sentinel-phrases.ts` | `a1-prompt-injection-description/data/injection-phrases.ts` | **verbatim** catalogue (ordered‑token match) |
| `sentinel-preference.ts` | `j6-tool-preference-manipulation/data/preference-composition.ts` | **verbatim** operator/referent vocabulary (compositional) |
| `sentinel-confusables.ts` | `a6-unicode-homoglyph` UTS‑39 table (~97k tokens) | **curated subset** (mixed‑script gate), honestly labeled |
| `sentinel-registry.ts` | `packages/database/src/rule-registry.ts` | **verbatim** rule name / severity / OWASP / MITRE / remediation |

Each finding cites the rule it maps to, and the app surfaces the **real Sentinel metadata** for it:

| Observation | Sentinel rule |
|---|---|
| Declared‑vs‑observed behavior divergence (witnessed) | **E5** |
| Look‑alike / homoglyph characters | **A6** |
| Invisible / bidi control characters | **A7** |
| Prompt‑injection imperative in the description | **A1** |
| Tool‑preference manipulation | **J6** |
| Unconstrained input schema | **B6** |
| Mid‑session injection / attempted overwrite | **G6 / E5** |

**Validated against Sentinel's own red‑team fixtures.** `npm run validate` runs Guardian's ported
detectors against the *actual* true‑positive / true‑negative strings from Sentinel's A6/A7/A1/J6 fixture
suite — **22/22**, including Sentinel's *hard negatives* that a substring matcher false‑positives on: the
`always returns the first row` data‑noun trap, the `alwaysOnCache` substring trap, an honest deprecation
notice (`supersedes … tool … see the migration guide`), and bidi marks in genuine RTL prose.

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
npm run e2e        # full demo flow proof (headless Chromium) — 15/15
npm run validate   # ported detectors vs Sentinel's own red-team fixtures — 22/22
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
  validation in the production build. (`npm run spike` = 12/12, `npm run e2e` = 15/15.)
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
