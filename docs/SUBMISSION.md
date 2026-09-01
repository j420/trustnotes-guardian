# WebMCP Guardian — project summary

_Project summary and pitch. Keep the honesty framing — it is the point._

## Elevator pitch (one line)
A drop‑in client‑side trust layer for WebMCP that **watches what tools do, not what they say** — it
witnesses each tool's real behavior, catches tools injected mid‑session by third‑party scripts, and
gates risky calls behind human consent, all exposed as agent‑callable WebMCP tools.

## Inspiration
WebMCP turns every website into a set of tools an AI agent can call. But the page writes each tool's
name and description — the exact text the agent trusts — and every third‑party script on the page gets
the same `document.modelContext`. A published attack paper (arXiv 2606.06387, *WebMCP Tool Surface
Poisoning*) shows any embedded analytics/chat/ad widget can register or mutate an agent‑callable tool
**mid‑session**. WebMCP ships no defense yet, and its consent primitive is still an unfinished TODO. We
build MCP security tooling, so we built the missing seatbelt.

## What it does
**TrustNotes** is a real notes app you and your agent both drive over WebMCP. **Guardian** is its
built‑in trust layer — **observe · catch · gate**:
- **Observe:** wraps every tool's `execute` and instruments the page's side‑effect surface
  (fetch/XHR/beacon/WebSocket/storage/clipboard), attributing each effect to the tool that caused it. It
  reports **DECLARED vs OBSERVED** and flags a **witnessed divergence** — e.g. a tool that declared
  read‑only but is observed trying to POST your notes to an external server — and **blocks that egress
  live.**
- **Catch:** flags tools registered **after page load** (mid‑session injection) and **attempted
  overwrites** of a trusted tool.
- **Gate:** a human‑consent prompt (showing the exact arguments) + JSON‑Schema input validation before
  risky calls, plus a **Probe** that dry‑runs a tool in a deny‑all harness so you can see what it *would*
  do before ever letting it run.
Guardian registers its own agent‑callable tools (`guardian_audit_page`, `guardian_probe_tool`,
`guardian_explain_tool`) so the agent can ask "is this page safe?". No tool can disable Guardian.

## How we built it
Vite + TypeScript, the `@mcp-b/global` WebMCP polyfill, and `ajv` for validation — a pure client‑side
build, no backend. The core is a `registerTool` wrapper that swaps each tool's `execute` for a guarded
one (proven to intercept every execution path against the real polyfill source), plus global
instrumentation that attributes side effects to the currently‑executing tool. Guardian reuses **real
detection data ported from our MCP Sentinel 183‑rule security registry — 20 rules re‑implemented for the
browser** across three surfaces: DECLARED metadata (A1/A2/A6/A7/A8/A9/B2/B6/B7/G2/G5/I1/I2/J3/J6), the
whole tool set (F1 lethal trifecta, I16 consent fatigue), and WITNESSED behavior (E5 declared‑vs‑observed,
J5 tool‑output poisoning, G6 mid‑session). Several catalogues are *verbatim*; the UTS‑39 confusables (A6), the G2 authority claims and J5 directive vocab,
the A9 decoder, and the capability graph (F1/I16) are honestly‑labeled curated subsets. It's not a keyword
scan — Guardian ports Sentinel's *matching strategy* (mixed‑script, class‑gated, ordered‑token,
operator+referent composition, schema‑shape, capability tagging) — and `npm run validate` proves it
against Sentinel's own red‑team fixtures: **61/61** (incl. 8 false‑positive regression guards), including the hard negatives (the "always returns the
first row" data‑noun trap, the "alwaysOnCache" substring trap, an honest deprecation notice, a
certification that *requires* confirmation, a legit percent‑encoding doc, an `id_rsa.pub` rotation note).
The strongest of the 20 is **J5**: Guardian is uniquely positioned to WITNESS a tool's returned text, so
it catches an "error" that tells the agent to read `~/.ssh/id_rsa` — something no scanner limited to a
tool's *declared metadata* can see (the agent only reads name/description/schema until the tool runs).
The deployed portal has a "Powered by MCP Sentinel" panel and cites the real rule behind each finding.
Everything is proven in real headless Chromium: a mechanics spike (12/12) and a full‑flow E2E (17/17).

## How this maps to the judging criteria
- **WebMCP Leverage:** deep, non‑trivial use — Guardian both *wraps* `document.modelContext` (observing
  and gating `registerTool`/`executeTool`) **and** *registers* its own agent‑callable tools; TrustNotes
  registers four real tools an agent drives.
- **Execution:** a complete, coherent product — a usable notes app + a live inspector + consent modal +
  probe + agent simulator, deployed and demoable, with automated proofs (spike 12/12, e2e 17/17, validate 61/61).
- **Potential Impact:** a concrete audience (developers shipping WebMCP tools who also load third‑party
  scripts) and a documented, current threat (arXiv 2606.06387) that WebMCP has no built‑in defense for —
  the safety layer for the human+agent web as WebMCP rolls out via OpenAI and Chrome.
- **Creativity & Ambition:** judges tools by **witnessed behavior**, not their self‑description — the
  first client‑side security/consent layer we're aware of for WebMCP (the official inspector only lists
  and runs tools; it does no witnessing, mid‑session detection, or gating).

## Challenges
The polyfill enforces a tool‑*name* charset, so a homoglyph can't hide in the name — we moved the
deception into the (unrestricted) description and leaned on the name‑independent behavioral divergence
as the headline. Attributing an async side effect to the right tool needed a careful active‑tool window.

## Honesty (what we did NOT claim)
"Not yet observed" is never "safe." The Agent Simulator is labeled "scripted calls, not a live LLM"
(verdicts are computed live). We say data is **ported from** Sentinel and label each table verbatim vs.
curated‑subset — not "runs 183 rules"; a look‑alike outside the curated confusables is a miss Sentinel's
full server‑side rule would still catch, and the app says so. We demonstrate on the polyfill path and
label native‑browser behavior as assumed‑not‑verified.

## What's next
Native‑browser verification on the Chrome WebMCP flag; cross‑tool toxic‑flow witnessing (Sentinel E6);
more side‑effect sinks; and an npm‑published `@guardian/webmcp` drop‑in.

## Links
- Repo: https://github.com/j420/trustnotes-guardian
- Live demo: <your Vercel URL>
- Video: <your YouTube URL>
