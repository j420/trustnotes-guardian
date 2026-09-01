/**
 * Behavioral instrumentation — the Guardian core.
 *
 * Guardian installs monitored wrappers on the page's side-effect surface (fetch,
 * XHR, sendBeacon, WebSocket, localStorage/sessionStorage, clipboard) and attributes
 * every effect to the tool whose `execute` is currently running (the "active tool").
 * A tool that egresses externally while a policy forbids it is DENIED — real
 * prevention, not a warning. This is what lets Guardian witness "declared read-only
 * but observed a network POST" and block it.
 *
 * Honest scope: effects are attributed within a tool's execution window (from the
 * moment guardedExecute enters until its promise settles). A side effect a tool
 * defers past its own return (e.g. via setTimeout) is best-effort and may be
 * unattributed — stated in the README.
 */
import type { SideEffect } from "./types.js";

// monitor: observe only · deny-external: block egress to other origins ·
// deny-all: block egress AND shadow local writes (the probe's witnessing harness)
export type Mode = "monitor" | "deny-external" | "deny-all";

interface ActiveFrame {
  tool: string;
  mode: Mode;
  effects: SideEffect[]; // collected for this frame
}

let active: ActiveFrame | null = null;
let installed = false;
export type EffectListener = (tool: string, e: SideEffect) => void;
const listeners: EffectListener[] = [];
export function onEffect(fn: EffectListener) { listeners.push(fn); }

function isExternal(url: string): boolean {
  try {
    const u = new URL(url, location.href);
    return (u.protocol === "http:" || u.protocol === "https:") && u.origin !== location.origin;
  } catch {
    return false;
  }
}

/** True when the active frame shadows local (non-egress) writes — the probe harness. */
export function shadowingLocal(): boolean { return active?.mode === "deny-all"; }

function record(kind: SideEffect["kind"], detail: string, external: boolean): boolean {
  const block = !!active && external && active.mode !== "monitor";
  const e: SideEffect = { kind, detail, external, blocked: block, at: Date.now() };
  if (active) {
    active.effects.push(e);
    for (const l of listeners) l(active.tool, e);
  }
  return block; // true => caller must not perform the real effect
}

/** Run `fn` as `tool`, attributing every side effect to it; returns the effects seen. */
export async function withActiveTool<T>(tool: string, mode: Mode, fn: () => Promise<T> | T): Promise<{ result: T | undefined; effects: SideEffect[]; error?: unknown }> {
  const prev = active;
  const frame: ActiveFrame = { tool, mode, effects: [] };
  active = frame;
  try {
    const result = await fn();
    return { result, effects: frame.effects };
  } catch (error) {
    return { result: undefined, effects: frame.effects, error };
  } finally {
    active = prev;
  }
}

class GuardianBlockedError extends Error {
  constructor(what: string) { super(`Guardian blocked ${what} (declared behavior did not permit external egress)`); this.name = "GuardianBlockedError"; }
}

export function installInstrumentation() {
  if (installed) return;
  installed = true;

  // fetch
  const realFetch = window.fetch.bind(window);
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    const ext = isExternal(url);
    if (record("network", url, ext)) return Promise.reject(new GuardianBlockedError("network request to " + url));
    return realFetch(input as any, init);
  }) as typeof fetch;

  // sendBeacon
  const realBeacon = navigator.sendBeacon?.bind(navigator);
  if (realBeacon) {
    navigator.sendBeacon = ((url: string | URL, data?: BodyInit | null) => {
      const s = typeof url === "string" ? url : url.href;
      if (record("beacon", s, isExternal(s))) return false;
      return realBeacon(url as any, data as any);
    }) as typeof navigator.sendBeacon;
  }

  // XHR
  const realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...rest: any[]) {
    const s = typeof url === "string" ? url : url.href;
    (this as any).__g_url = s;
    (this as any).__g_ext = isExternal(s);
    return (realOpen as any).call(this, method, url, ...rest);
  } as any;
  const realSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (this: XMLHttpRequest, body?: Document | XMLHttpRequestBodyInit | null) {
    const s = (this as any).__g_url || "(xhr)";
    if (record("network", s, !!(this as any).__g_ext)) throw new GuardianBlockedError("XHR to " + s);
    return realSend.call(this, body as any);
  } as any;

  // WebSocket (block external during deny-external)
  const RealWS = window.WebSocket;
  window.WebSocket = function (this: any, url: string | URL, protocols?: string | string[]) {
    const s = typeof url === "string" ? url : url.href;
    if (record("websocket", s, isExternal(s))) throw new GuardianBlockedError("WebSocket to " + s);
    return new (RealWS as any)(url, protocols);
  } as any;
  (window.WebSocket as any).prototype = RealWS.prototype;

  // storage writes (observed, not blocked — they're local, not egress)
  for (const store of [window.localStorage, window.sessionStorage]) {
    try {
      const proto = Object.getPrototypeOf(store);
      const realSet = proto.setItem;
      proto.setItem = function (this: Storage, k: string, v: string) {
        record("storage", (this === window.sessionStorage ? "session:" : "local:") + k, false);
        if (shadowingLocal()) return; // probe: witness the write, don't apply it
        return realSet.call(this, k, v);
      };
    } catch { /* storage may be unavailable */ }
  }

  // clipboard writes (observed)
  const realWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
  if (realWriteText) {
    navigator.clipboard.writeText = ((text: string) => { record("clipboard", `${text.length} chars`, false); return realWriteText(text); }) as any;
  }
}
