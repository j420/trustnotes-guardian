/**
 * Real OpenAI agent driver — the "Real AI agent" mode of the Agent panel.
 *
 * IMPORTANT INVARIANT: the LLM is the party being PROTECTED, never part of Guardian's gate.
 * This loop only DRIVES the page's tools; every tool call is dispatched through `exec`
 * (execViaGuardian in the UI), which routes to `document.modelContext.executeTool` →
 * Guardian's `guardedExecute`. So consent, input validation, witnessed divergence, and
 * live egress-blocking fire identically whether the caller is this LLM, the scripted
 * simulator, or a malicious script. There is NO LLM in `needsConsent`, no LLM risk score.
 *
 * OpenAI's chat-completions API is CORS-blocked from the browser and needs a server-side
 * key, so the actual HTTP call goes through the same-origin serverless proxy at /api/agent
 * (see api/agent.js). This module never sees the key on the server path; a user-pasted
 * BYO key is forwarded once via a header and never stored.
 *
 * Typed loosely on purpose: OpenAI's JSON is `any`, and `document.modelContext` is reached
 * as `(document as any).modelContext` elsewhere. The loop itself is strict-clean.
 */

export interface RealAgentDeps {
  /** Dispatch one tool call through Guardian's gate. `realName` is the WebMCP tool name,
   *  `argsJson` a JSON string. Returns the tool's textual result (already gate-processed). */
  exec: (realName: string, argsJson: string) => Promise<string>;
  /** Append a line to the shared #sim-log. `cls` is "", "ok", "err", or "warn". */
  log: (line: string, cls?: string) => void;
  /** Optional BYO key (sk-…). When present it is forwarded to the proxy and a client model is allowed. */
  apiKey?: string;
  /** Only honored by the proxy alongside a BYO key. */
  model?: string;
  /** Override the proxy endpoint (default "/api/agent"). */
  endpoint?: string;
}

export interface RealAgentResult {
  ok: boolean;
  /** true when the failure is "no server key" or "no proxy here" — the UI reveals the BYO-key field. */
  needsKey?: boolean;
}

/** Distinguishes expected degradation (no proxy / no key) from an unexpected error. */
type AgentErrorKind = "no-proxy" | "no-key" | "network" | "proxy" | "non-json";
class AgentError extends Error {
  kind: AgentErrorKind;
  constructor(kind: AgentErrorKind, message: string) {
    super(message);
    this.kind = kind;
    this.name = "AgentError";
  }
}

const MAX_TURNS = 6;
const OPENAI_NAME_RE = /[^a-zA-Z0-9_-]/g;

const SYSTEM_PROMPT =
  "You are an AI assistant embedded in the TrustNotes web app. You help the user by calling the " +
  "page's WebMCP tools. Prefer a tool when one fits the request; otherwise answer briefly. When a " +
  "tool call is blocked or returns an error, tell the user plainly what happened — do not retry it.";

/** Sanitize a WebMCP tool name (`[A-Za-z0-9_.-]{1,128}`) to OpenAI's `^[a-zA-Z0-9_-]{1,64}$`,
 *  de-colliding against names already issued. */
function sanitizeName(name: string, used: Set<string>): string {
  let base = (name || "tool").replace(OPENAI_NAME_RE, "_").slice(0, 64);
  if (!base) base = "tool";
  let candidate = base;
  let i = 1;
  while (used.has(candidate)) {
    const suffix = "_" + i++;
    candidate = base.slice(0, 64 - suffix.length) + suffix;
  }
  used.add(candidate);
  return candidate;
}

/** Build the OpenAI `tools` array from the live WebMCP tool descriptors, plus a sanitized→real map. */
function buildToolset(webmcpTools: any[]): { tools: any[]; toRealName: Map<string, string> } {
  const used = new Set<string>();
  const toRealName = new Map<string, string>();
  const tools = (webmcpTools || []).map((t) => {
    const sanitized = sanitizeName(t?.name || "tool", used);
    toRealName.set(sanitized, t?.name);
    const schema = t?.inputSchema;
    const parameters = schema && typeof schema === "object" ? schema : { type: "object", properties: {} };
    return {
      type: "function",
      function: { name: sanitized, description: String(t?.description || ""), parameters },
    };
  });
  return { tools, toRealName };
}

/** One POST to the serverless proxy → the raw OpenAI completion JSON. Throws AgentError on any failure. */
async function postChat(messages: any[], tools: any[], deps: RealAgentDeps): Promise<any> {
  const endpoint = deps.endpoint || "/api/agent";
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (deps.apiKey) headers["x-openai-key"] = deps.apiKey;
  const body: any = { messages, tools };
  if (deps.apiKey && deps.model) body.model = deps.model;

  let res: Response;
  try {
    res = await fetch(endpoint, { method: "POST", headers, body: JSON.stringify(body) });
  } catch {
    throw new AgentError("network", `could not reach the agent proxy at ${endpoint}.`);
  }

  const ct = res.headers.get("content-type") || "";
  if (!res.ok) {
    // A dev server (vite) with no /api serves a 404 HTML page — never JSON.parse it blindly.
    if (res.status === 404) {
      throw new AgentError("no-proxy", "/api/agent isn't served here. Real-agent mode needs the Vercel deploy or `vercel dev`; or paste your own key below. Scripted mode works offline.");
    }
    let errCode = "", msg = "";
    if (ct.includes("application/json")) {
      const j = await res.json().catch(() => null);
      errCode = j?.error || "";
      msg = j?.message || "";
    }
    if (errCode === "no_openai_key") {
      throw new AgentError("no-key", "the server has no OPENAI_API_KEY configured. Paste your own key below to try it, or deploy with the env var set.");
    }
    throw new AgentError("proxy", `proxy error ${res.status}${errCode ? ` (${errCode})` : ""}${msg ? `: ${msg}` : ""}`);
  }

  if (!ct.includes("application/json")) throw new AgentError("non-json", "the agent proxy returned a non-JSON response.");
  return res.json().catch(() => { throw new AgentError("non-json", "the agent proxy returned malformed JSON."); });
}

/**
 * Run a real OpenAI agent that drives the page's WebMCP tools. Call ONLY on a user action
 * (the Run button), never at boot. Resolves after the model stops (or the turn cap is hit),
 * logging every model message and tool result to the shared log. Never throws — degradation
 * is reported through `log` and the returned result.
 */
export async function runRealAgent(instruction: string, deps: RealAgentDeps): Promise<RealAgentResult> {
  const { exec, log } = deps;
  const mc: any = (document as any).modelContext ?? (navigator as any).modelContext;
  if (!mc?.getTools) {
    log("real-agent: no WebMCP modelContext on this page.", "err");
    return { ok: false };
  }

  try {
    const webmcpTools = await mc.getTools();
    const { tools, toRealName } = buildToolset(webmcpTools);

    const messages: any[] = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: instruction },
    ];

    for (let turn = 0; turn < MAX_TURNS; turn++) {
      const data = await postChat(messages, tools, deps);
      const choice = data?.choices?.[0];
      if (!choice) { log("real-agent: model returned no choices.", "err"); break; }

      const msg = choice.message ?? { role: "assistant", content: "" };
      messages.push(msg); // push the assistant message VERBATIM (with its tool_calls + ids)
      if (typeof msg.content === "string" && msg.content.trim()) log("model: " + msg.content.trim());

      const calls = Array.isArray(msg.tool_calls) ? msg.tool_calls : [];
      if (choice.finish_reason !== "tool_calls" || calls.length === 0) break; // model is done

      for (const call of calls) {
        const sanitized: string = call?.function?.name || "";
        const realName = toRealName.get(sanitized) ?? sanitized;
        let argsJson: string = typeof call?.function?.arguments === "string" ? call.function.arguments : "";
        if (!argsJson.trim()) argsJson = "{}";
        try { JSON.parse(argsJson); } catch { argsJson = "{}"; } // default invalid args → {}

        // The one line that matters: dispatch through Guardian's gate. Reply to EVERY tool_call
        // with exactly one tool message keyed by its id (OpenAI rejects the next turn otherwise).
        const result = await exec(realName, argsJson);
        messages.push({ role: "tool", tool_call_id: call?.id, content: typeof result === "string" ? result : JSON.stringify(result) });
      }
    }
    return { ok: true };
  } catch (e: any) {
    if (e instanceof AgentError) {
      log("real-agent: " + e.message, "err");
      return { ok: false, needsKey: e.kind === "no-key" || e.kind === "no-proxy" };
    }
    log("real-agent error: " + (e?.message || e), "err");
    return { ok: false };
  }
}
