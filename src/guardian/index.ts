/**
 * Guardian engine — installs on WebMCP, witnesses tool behavior, and gates risky calls.
 *
 * Guardian judges tools by what they DO, not what they say:
 *  - wraps registerTool -> guardedExecute (fires on every execution path)
 *  - instruments the page's side-effect surface and attributes effects to the active tool
 *  - records DECLARED vs OBSERVED, and flags a witnessed divergence (Sentinel E5)
 *  - catches mid-session injection + attempted-overwrite of a trusted tool
 *  - a "probe" runs a tool in a deny-all witnessing harness (canary inputs, no real effect)
 *  - a consent + input-validation gate stands before risky calls
 *  - registers its OWN agent-callable tools (guardian_audit_page / probe_tool / explain_tool)
 */
import Ajv2020 from "ajv/dist/2020";
import type { DivergenceFinding, SideEffect, TimelineEvent, ToolRecord, WebMcpTool } from "./types.js";
import { installInstrumentation, withActiveTool } from "./observe.js";
import { declaresReadOnly, staticObservations } from "./static-flags.js";

const ajv = new (Ajv2020 as any)({ strict: false, allErrors: true });

export type ConsentRequest = { record: ToolRecord; args: unknown; reason: string };
export type ConsentHandler = (req: ConsentRequest) => Promise<boolean>;

export class Guardian extends EventTarget {
  readonly tools = new Map<string, ToolRecord>();
  readonly timeline: TimelineEvent[] = [];
  private origExecute = new Map<string, (a: any) => any>();
  private validators = new Map<string, (a: any) => boolean>();
  private loadWindowClosed = false;
  /** false only if a native browser locked registerTool so Guardian couldn't wrap it. */
  interceptionActive = true;
  consentHandler: ConsentHandler | null = null;

  private emit() { this.dispatchEvent(new Event("change")); }
  private log(e: Omit<TimelineEvent, "at">) { this.timeline.push({ ...e, at: Date.now() }); this.emit(); }

  /** Mid-session = registered after the initial load window closed. */
  private provenance(): "initial" | "mid-session" { return this.loadWindowClosed ? "mid-session" : "initial"; }

  install(mc: any) {
    installInstrumentation();
    // Close the "initial load" window shortly after boot; anything after is mid-session.
    setTimeout(() => { this.loadWindowClosed = true; }, 1500);

    const origRegister = mc.registerTool.bind(mc);
    const self = this;
    const guardedRegister = async function (tool: WebMcpTool, options?: any) {
      // Attempted-overwrite: a name we already trust is being re-registered.
      if (self.tools.has(tool.name)) {
        try {
          return await origRegister(tool, options); // platform throws InvalidStateError
        } catch (err) {
          self.log({ kind: "attempted-overwrite", tool: tool.name, detail: "a script tried to re-register a trusted tool — blocked by the platform, flagged by Guardian" });
          const rec = self.tools.get(tool.name)!;
          rec.status = "flagged";
          rec.staticFlags.push({ id: "ATTEMPTED-OVERWRITE", sentinelRule: "E5/G6", label: "A script attempted to overwrite this trusted tool mid-session", evidence: String((err as any)?.name || err) });
          self.emit();
          throw err;
        }
      }
      const orig = tool.execute;
      const guarded = (args: any) => self.guardedExecute(tool.name, args);
      const res = await origRegister({ ...tool, execute: guarded }, options); // register FIRST
      self.origExecute.set(tool.name, orig); // record only after the platform accepts it
      self.ingest(tool);
      return res;
    };

    // Install the wrapper robustly. A NATIVE (flag-enabled) browser may expose
    // modelContext with a non-writable registerTool; a bare assignment would THROW
    // in module strict mode and white-screen the app. Fall back to defineProperty on
    // the instance, then the prototype, and never let a failure crash boot.
    this.interceptionActive = installMethod(mc, "registerTool", guardedRegister);
    if (!this.interceptionActive) {
      cfgWarn("Guardian could not wrap registerTool (native property is locked on this browser build) — running in observation-limited mode. The polyfill path is fully supported.");
    }

    // Guardian's own agent-callable tools go through the ORIGINAL register (unguarded,
    // never self-audited, and an injected tool can never disable them).
    this.registerGuardianTools(mc, origRegister);
  }

  private ingest(tool: WebMcpTool) {
    const flags = staticObservations(tool);
    const rec: ToolRecord = {
      name: tool.name,
      description: tool.description || "",
      declaredReadOnly: declaresReadOnly(tool),
      inputSchema: tool.inputSchema ?? null,
      provenance: this.provenance(),
      registeredAt: Date.now(),
      observedRuns: 0,
      probeRuns: 0,
      sideEffects: [],
      staticFlags: flags,
      divergences: [],
      status: "not-yet-observed",
    };
    this.tools.set(tool.name, rec);
    if (tool.inputSchema && typeof tool.inputSchema === "object") {
      try { this.validators.set(tool.name, ajv.compile(tool.inputSchema)); } catch { /* tolerate odd schemas */ }
    }
    this.log({ kind: "register", tool: tool.name, detail: `${rec.provenance} registration${flags.length ? " · static flags: " + flags.map((f) => f.id).join(", ") : ""}` });
  }

  /** DECLARED vs OBSERVED: derive divergences from the effects seen in a run/probe. */
  private diverge(rec: ToolRecord, effects: SideEffect[]): DivergenceFinding[] {
    const egress = effects.filter((e) => e.external);
    const found: DivergenceFinding[] = [];
    if (egress.length) {
      if (rec.declaredReadOnly) {
        found.push({ kind: "readonly-violation", declared: "readOnlyHint: true (declared read-only)", observed: `attempted external egress to ${egress.map((e) => shortHost(e.detail)).join(", ")}`, sentinelRule: "E5" });
      } else {
        found.push({ kind: "undeclared-egress", declared: "no network egress declared", observed: `attempted external egress to ${egress.map((e) => shortHost(e.detail)).join(", ")}`, sentinelRule: "E5" });
      }
    }
    return found;
  }

  private mergeDivergences(rec: ToolRecord, found: DivergenceFinding[]) {
    for (const d of found) if (!rec.divergences.some((x) => x.kind === d.kind && x.observed === d.observed)) rec.divergences.push(d);
    if (rec.divergences.length) rec.status = "diverged";
    else if (rec.status === "not-yet-observed") rec.status = "consistent";
  }

  validate(name: string, args: unknown): { ok: boolean; errors: string } {
    const v = this.validators.get(name);
    if (!v) return { ok: true, errors: "" };
    const ok = v(args);
    return { ok, errors: ok ? "" : ((v as any).errors || []).map((e: any) => `${e.instancePath || "(root)"} ${e.message}`).join("; ") };
  }

  private needsConsent(rec: ToolRecord): string | null {
    if (rec.status === "diverged" || rec.status === "flagged") return "this tool has a witnessed divergence or was flagged";
    if (rec.staticFlags.some((f) => ["UNICODE-HOMOGLYPH", "UNICODE-HIDDEN", "INJ-IMPERATIVE"].includes(f.id))) return "this tool's metadata contains deceptive signals";
    if (!rec.declaredReadOnly && /delete|remove|drop|overwrite|purge|wipe/i.test(rec.name + " " + rec.description)) return "this tool declares a destructive action";
    return null;
  }

  /** The wrapped execute: validate -> (consent if risky) -> run under instrumentation -> record. */
  async guardedExecute(name: string, rawArgs: any): Promise<any> {
    const rec = this.tools.get(name)!;
    const orig = this.origExecute.get(name)!;
    const args = typeof rawArgs === "string" ? safeParse(rawArgs) : rawArgs;

    const val = this.validate(name, args);
    if (!val.ok) { this.log({ kind: "block", tool: name, detail: "input validation failed: " + val.errors }); return errorResult(`Guardian blocked ${name}: input validation failed (${val.errors})`); }

    const reason = this.needsConsent(rec);
    if (reason && this.consentHandler) {
      const approved = await this.consentHandler({ record: rec, args, reason });
      this.log({ kind: "consent", tool: name, detail: approved ? "user APPROVED" : "user DENIED — " + reason });
      if (!approved) return errorResult(`Guardian: user denied execution of ${name}`);
    }

    const { result, effects, error } = await withActiveTool(name, "deny-external", () => orig(args));
    rec.observedRuns++;
    rec.sideEffects.push(...effects);
    this.mergeDivergences(rec, this.diverge(rec, effects));
    const blocked = effects.filter((e) => e.blocked);
    if (blocked.length) this.log({ kind: "block", tool: name, detail: `blocked external egress: ${blocked.map((e) => shortHost(e.detail)).join(", ")}` });
    this.log({ kind: "observe", tool: name, detail: describeEffects(effects) });
    this.emit();
    if (error) return errorResult(`Guardian blocked an action during ${name}: ${(error as any)?.message || error}`);
    return result;
  }

  /** Probe: witness what a tool WOULD do, under deny-all, with no real effect. */
  async probe(name: string, canaryArgs: unknown = {}): Promise<{ effects: SideEffect[]; divergences: DivergenceFinding[] }> {
    const rec = this.tools.get(name);
    const orig = this.origExecute.get(name);
    if (!rec || !orig) return { effects: [], divergences: [] };
    const { effects } = await withActiveTool(name, "deny-all", () => orig(canaryArgs));
    rec.probeRuns++;
    rec.sideEffects.push(...effects);
    const div = this.diverge(rec, effects);
    this.mergeDivergences(rec, div);
    this.log({ kind: "probe", tool: name, detail: describeEffects(effects) + (div.length ? " · DIVERGENCE: " + div[0].observed : "") });
    this.emit();
    return { effects, divergences: div };
  }

  /** Register Guardian's own agent-callable tools via the ORIGINAL registerTool (unguarded). */
  registerGuardianTools(mc: any, origRegister: (t: WebMcpTool, o?: any) => any) {
    const text = (o: unknown) => ({ content: [{ type: "text", text: JSON.stringify(o, null, 2) }] });
    origRegister({
      name: "guardian_audit_page",
      description: "Guardian: report every tool on this page — DECLARED vs OBSERVED behavior, static observations, and when each was registered. Use this to decide if the page's tools are safe.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => text({ tools: [...this.tools.values()].map(summary), timeline: this.timeline.slice(-12) }),
    });
    origRegister({
      name: "guardian_probe_tool",
      description: "Guardian: safely witness what a specific tool WOULD do by running it once in a deny-all harness (no real network, no real writes). Returns the observed attempted behavior.",
      inputSchema: { type: "object", properties: { toolName: { type: "string" } }, required: ["toolName"], additionalProperties: false },
      execute: async (a: any) => text(await this.probe(a?.toolName, { probe: true })),
    });
    origRegister({
      name: "guardian_explain_tool",
      description: "Guardian: explain one tool in full — its declared metadata, everything Guardian has observed it do, static observations, and any divergences.",
      inputSchema: { type: "object", properties: { toolName: { type: "string" } }, required: ["toolName"], additionalProperties: false },
      execute: async (a: any) => text(this.tools.get(a?.toolName) ?? { error: "unknown tool" }),
    });
    void mc;
  }
}

function summary(r: ToolRecord) {
  return { name: r.name, declaredReadOnly: r.declaredReadOnly, provenance: r.provenance, status: r.status, observedRuns: r.observedRuns, staticFlags: r.staticFlags.map((f) => f.id), divergences: r.divergences.map((d) => d.observed) };
}
function describeEffects(effects: SideEffect[]): string {
  if (!effects.length) return "no side effects observed";
  const ext = effects.filter((e) => e.external);
  const parts = [`${effects.length} effect(s)`];
  if (ext.length) parts.push(`${ext.length} external egress (${ext.every((e) => e.blocked) ? "blocked" : "some allowed"})`);
  return parts.join(" · ");
}
function shortHost(url: string) { try { return new URL(url, location.href).host; } catch { return url; } }
function cfgWarn(msg: string) { try { console.warn("[Guardian] " + msg); } catch { /* noop */ } }

/**
 * Install `fn` as `obj[name]`, tolerating a non-writable native property. Tries a
 * direct assignment, then defineProperty on the instance, then on the prototype;
 * never throws. Returns whether the method now IS `fn` (i.e. interception took).
 */
function installMethod(obj: any, name: string, fn: any): boolean {
  try { obj[name] = fn; if (obj[name] === fn) return true; } catch { /* non-writable */ }
  try { Object.defineProperty(obj, name, { value: fn, writable: true, configurable: true }); if (obj[name] === fn) return true; } catch { /* non-configurable */ }
  try {
    const proto = Object.getPrototypeOf(obj);
    if (proto) { Object.defineProperty(proto, name, { value: fn, writable: true, configurable: true }); if (obj[name] === fn) return true; }
  } catch { /* frozen prototype */ }
  return false;
}
function safeParse(s: string) { try { return JSON.parse(s); } catch { return {}; } }
function errorResult(text: string) { return { content: [{ type: "text", text }], isError: true }; }

export const guardian = new Guardian();
