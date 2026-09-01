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
instrumentation that attributes side effects to the currently‑executing tool. The static observations
reuse **real detection data ported from our MCP Sentinel 183‑rule security registry** — the
invisible‑codepoint catalogue (A7) and injection‑phrase catalogue (A1) *verbatim*, the compositional
tool‑preference vocabulary (J6), a curated subset of the UTS‑39 confusables (A6), and the rule metadata
(name / severity / OWASP / MITRE / remediation) surfaced on every finding in the app. It's not a
keyword scan: Guardian ports Sentinel's *matching strategy* (mixed‑script for A6, class‑gated for A7,
ordered‑token for A1, operator+referent composition for J6), and `npm run validate` proves it against
Sentinel's own red‑team fixtures — **22/22**, including Sentinel's hard negatives (the "always returns
the first row" data‑noun trap, the "alwaysOnCache" substring trap, an honest deprecation notice). The
deployed portal has a "Powered by MCP Sentinel" panel and cites the real rule behind each finding.
Everything is proven in real headless Chromium: a mechanics spike (12/12) and a full‑flow E2E (15/15).

## How this maps to the judging criteria
- **WebMCP Leverage:** deep, non‑trivial use — Guardian both *wraps* `document.modelContext` (observing
  and gating `registerTool`/`executeTool`) **and** *registers* its own agent‑callable tools; TrustNotes
  registers four real tools an agent drives.
- **Execution:** a complete, coherent product — a usable notes app + a live inspector + consent modal +
  probe + agent simulator, deployed and demoable, with automated proofs (spike 12/12, e2e 15/15).
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
