/**
 * Vercel serverless proxy for the "Real AI agent (OpenAI)" mode.
 *
 * Plain JS on purpose: it lives outside `tsconfig` (include: ["src"]) and is never imported by the
 * app, so it doesn't touch `tsc --noEmit` or the Vite bundle. Vercel auto-detects a top-level /api dir.
 *
 * It is a THIN, STATELESS relay of ONE Chat Completions call. The agent LOOP stays in the browser so
 * every tool call goes through Guardian's gate. Two reasons this exists at all:
 *   1. OpenAI's API is CORS-blocked from the browser, so the page can't call it directly.
 *   2. The API key must stay server-side.
 *
 * Hardened against denial-of-wallet, because on a public URL this can run on the owner's key:
 *   - server-key path: pinned model allowlist, forced max_tokens, same-site Origin/Referer check,
 *     request-size cap, and a tiny in-memory per-IP rate limit. A client-chosen model is honored ONLY
 *     when the caller supplies their own key (x-openai-key).
 *   - never logs headers/body, never echoes the key, sanitizes upstream errors, sends no-store.
 */

const OPENAI_URL = "https://api.openai.com/v1/chat/completions";
const DEFAULT_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
// Small, cheap, tool-calling-capable models only. Keeps a public server key from being pointed at a
// pricey model. Add ids here if you deploy with a different default.
const MODEL_ALLOWLIST = new Set([DEFAULT_MODEL, "gpt-4o-mini", "gpt-4.1-mini", "gpt-4o"]);
const MAX_TOKENS = 700;              // server cap; ignore any client value
const MAX_BODY_BYTES = 64 * 1024;    // reject oversized prompts
const MAX_MESSAGES = 40;
const MAX_TOOLS = 40;
const RATE_LIMIT = { windowMs: 60_000, max: 20 }; // per-IP, best-effort (per warm lambda instance)

const hits = new Map(); // ip -> { count, resetAt }
function rateLimited(ip) {
  const now = Date.now();
  const rec = hits.get(ip);
  if (!rec || now > rec.resetAt) { hits.set(ip, { count: 1, resetAt: now + RATE_LIMIT.windowMs }); return false; }
  rec.count++;
  return rec.count > RATE_LIMIT.max;
}

function sameSite(req) {
  const host = req.headers["host"] || "";
  const from = req.headers["origin"] || req.headers["referer"] || "";
  if (!from) return true; // same-origin fetch may omit Origin; don't hard-fail
  try { return new URL(from).host === host; } catch { return false; }
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  if (!sameSite(req)) return res.status(403).json({ error: "forbidden_origin" });

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
  if (rateLimited(ip)) return res.status(429).json({ error: "rate_limited" });

  // Body may already be parsed by Vercel; otherwise read+cap it ourselves.
  let body = req.body;
  if (body === undefined) {
    try { body = await readJson(req, MAX_BODY_BYTES); } catch (e) { return res.status(413).json({ error: "payload_too_large" }); }
  }
  if (!body || typeof body !== "object") return res.status(400).json({ error: "bad_request" });
  const rawBytes = Buffer.byteLength(JSON.stringify(body));
  if (rawBytes > MAX_BODY_BYTES) return res.status(413).json({ error: "payload_too_large" });

  const messages = Array.isArray(body.messages) ? body.messages : null;
  const tools = Array.isArray(body.tools) ? body.tools : undefined;
  if (!messages || messages.length === 0 || messages.length > MAX_MESSAGES) return res.status(400).json({ error: "bad_messages" });
  if (tools && tools.length > MAX_TOOLS) return res.status(400).json({ error: "too_many_tools" });

  const byoKey = req.headers["x-openai-key"];
  const key = (typeof byoKey === "string" && byoKey.startsWith("sk-")) ? byoKey : process.env.OPENAI_API_KEY;
  if (!key) return res.status(400).json({ error: "no_openai_key" });

  // A client-chosen model is honored only with a BYO key; a server key is pinned to the allowlist.
  let model = DEFAULT_MODEL;
  if (byoKey && typeof body.model === "string") model = body.model;
  else if (!byoKey && typeof body.model === "string" && MODEL_ALLOWLIST.has(body.model)) model = body.model;

  const payload = { model, messages, tool_choice: tools ? "auto" : undefined, max_tokens: MAX_TOKENS };
  if (tools) payload.tools = tools;

  try {
    const upstream = await fetch(OPENAI_URL, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
      body: JSON.stringify(payload),
    });
    const text = await upstream.text();
    if (!upstream.ok) {
      // Sanitize: surface the status + a short message, never the key or full upstream body.
      let msg = "";
      try { msg = (JSON.parse(text)?.error?.message || "").slice(0, 200); } catch { /* ignore */ }
      return res.status(upstream.status === 401 ? 400 : 502).json({ error: "openai_error", status: upstream.status, message: msg });
    }
    res.setHeader("content-type", "application/json");
    return res.status(200).send(text); // pass the successful completion through verbatim
  } catch {
    return res.status(502).json({ error: "upstream_unreachable" });
  }
}

function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > limit) { reject(new Error("too_large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}
