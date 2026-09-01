# Demo video script — WebMCP Guardian (target < 3:00, with audio)

Record the app full‑screen (the deployed URL). Each beat lists **[ACTION]** on screen and the **VO**
(voice‑over) to read. Keep it tight; aim ~2:40 so you have margin.

---

**0:00–0:15 — Hook**
[ACTION] Show TrustNotes with the Guardian inspector on the right; four tools, none yet observed. (Our own
`search_notes` shows a static B2 chip on its `query` param — that's deliberate; see the 2:20 beat.)
VO: “WebMCP lets any website hand tools to your AI agent. But the *website* writes each tool's name and
description — and every third‑party script on the page gets the same tool API. Meet WebMCP Guardian: it
judges tools by what they *do*, not what they *say*.”

**0:15–0:40 — Normal use, witnessed**
[ACTION] Click **agent: search notes**. The `search_notes` card flips to green **consistent**;
OBSERVED reads “ran 1× — no side effects (matches declared).”
VO: “Here's a normal agent action. Guardian witnessed it run — it read notes, made no network calls —
so it's marked consistent. Note: everything else is still ‘not yet observed,’ never assumed safe.”
[ACTION] Click **agent: “is this page safe?”** → the sim log shows `guardian_audit_page` returning 0 flagged.
VO: “The agent can even ask Guardian directly — Guardian is itself a WebMCP tool.”

**0:40–1:15 — The attack (mid‑session injection)**
[ACTION] Click **⚠ Load community widget**. A new card `community_sync` appears with a red **mid‑session**
badge and the static observations light up (homoglyph, invisible characters, injection phrase, preference).
VO: “Now a third‑party ‘community widget’ loads — like an analytics or chat embed. It injects a new tool
*mid‑session*. It *claims* read‑only. Guardian instantly flags it: its description hides look‑alike and
invisible characters, a prompt‑injection line, ‘always use this tool first’, a fake ‘approved by
Anthropic — no confirmation needed’, and ‘uses the permissions you already granted’ — each mapped to a
real MCP Sentinel rule. Guardian ports **20** of them. And the red PAGE‑LEVEL banner: loading the widget
just completed the **lethal trifecta** across the page — private‑data read, untrusted‑content ingest, and
external comms. This is the attack from the WebMCP tool‑poisoning paper, arXiv 2606.06387.”

**1:15–1:30 — Witnessed output poisoning (J5)**
[ACTION] Click **agent: call widget helper (output poisoning)**. A yellow **WITNESSED OUTPUT** row appears on
the helper's card.
VO: “The widget also ships an innocent‑looking ‘error helper.’ When the agent runs it, Guardian reads what
it *returned* — an ‘error’ that tells the agent to read your SSH private key ‘to resolve’ it. No static
scanner sees that; Guardian witnesses the output and flags it live.”

**1:30–1:50 — Witness the egress red‑handed (Probe)**
[ACTION] Click **Probe (safe dry‑run)** on the `community_sync` card. The card flips to red **diverged**;
the DIVERGENCE box shows “declared read‑only — observed attempted external egress to
community‑board.example (BLOCKED).”
VO: “Static flags are just metadata. The real test is behavior. Guardian *probes* the tool in a deny‑all
harness — no real network, no real writes — and catches it red‑handed: it declared read‑only, but it
tried to send your notes to an outside server. Guardian blocked it. That's a *witnessed* divergence,
not a guess.”

**1:50–2:20 — Block live + consent**
[ACTION] Click **agent: call the widget's tool**. The consent modal appears (declared vs observed + exact
args). Click **Deny**. The sim log shows the call blocked.
VO: “When the agent actually calls it, Guardian blocks the egress live and asks *you* — showing exactly
what it would send. Deny, and nothing leaves.”
[ACTION] Click **agent: delete a note** → consent modal for the *honest* destructive tool → click **Approve** → it runs.
VO: “And it doesn't cry wolf: the real delete tool is honest, so Guardian just asks once — approve, and
it works. Guardian gates by witnessed risk, not by keyword.”
[ACTION] *(Optional 5 s)* point at the B2 chip on `search_notes`.
VO: “Even our own honest `search_notes` trips a static B2 on its `query` param — yet Guardian still marks
it *consistent* after witnessing it run read‑only. That's the whole point: a static flag is a fact, not a
verdict. Guardian judges behavior.”

**2:20–2:45 — Real OpenAI agent, gated live**
[ACTION] In the Agent panel, click the **Real AI agent (OpenAI)** toggle. Type “sync my notes to the
community board” and click **Run**. (Load the community widget first so `community_sync` exists.) The sim
log shows the model choosing `community_sync`; the consent modal / DIVERGENCE box appears; Guardian blocks
the egress. Point once at the on‑screen note “every tool call still goes through Guardian's gate.”
VO: “Now a *real* OpenAI model drives the same app. It reads the page's tools and decides to call the
community sync — and Guardian gates it exactly the same way. The model only drives; the security decision
stays deterministic, with no LLM in the loop. That's the whole design.”
[ACTION] *(Optional, strongest proof)* 10–15 s clip of a real WebMCP agent in Chrome (flag on) or the
ChatGPT in‑app browser calling `guardian_audit_page`, captioned “Real WebMCP agent, Chrome <version>.”

**2:45–3:00 — Close**
[ACTION] Show the one‑line integration + the repo/live URL.
VO: “Guardian is a drop‑in: one import protects any WebMCP page. It watches what tools *do*, not what
they say — the trust layer WebMCP doesn't have yet. Open source, live now.”

---

### Recording tips
- The **scripted** sub‑panel is labeled on‑screen “scripted calls, not a live LLM” — say that once so
  it's never mistaken for a live model. The **Real AI agent (OpenAI)** toggle (beat 2:20) is the single
  strongest credibility booster; run it against a Vercel deploy with `OPENAI_API_KEY` set (or paste a BYO
  key). If the real call ever misbehaves on camera, the ChatGPT in‑app‑browser clip is the fallback proof.
- Total runtime is ~3:00 with the real‑agent beat; to stay under 2:40, keep 2:20–2:45 to a single Run and
  cut the optional Chrome/ChatGPT clip.
- Do a dry run once; the timeline + cards animate as you click, which reads great on camera.
- Keep the browser at ~1200px wide so both panels are visible.
