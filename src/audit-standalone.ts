/**
 * Standalone Guardian auditor — bundled to a single IIFE and injected into ANY WebMCP page
 * (a bookmarklet, DevTools paste, or the Playwright CLI at scripts/guardian-audit.mjs).
 *
 * It performs READ-ONLY enumeration only: it reads `document.modelContext.getTools()` and runs
 * Guardian's ported Sentinel declared-metadata detectors + page-level checks over the real tool
 * descriptors. It NEVER invokes a tool — that is Guardian's T1 ethic for a live third-party page
 * (you cannot tell from a schema whether calling a tool has side effects, so you don't).
 */
import { staticObservations, declaresReadOnly, pageObservations } from "./guardian/static-flags.js";
import { ruleMeta } from "./guardian/data/sentinel-registry.js";

type AnyTool = { name: string; description: string; inputSchema: unknown; annotations?: unknown };

function citeRule(id: string) {
  const m = ruleMeta(id);
  return m ? { id: m.id, name: m.name, severity: m.severity, owasp: m.owasp, mitre: m.mitre } : { id };
}

async function audit() {
  const mc: any = (document as any).modelContext ?? (navigator as any).modelContext;
  if (!mc?.getTools) return { url: location.href, error: "no WebMCP modelContext on this page (nothing to audit)" };
  const raw = await mc.getTools();
  const tools: AnyTool[] = (raw || []).map((t: any) => ({ name: t.name, description: t.description || "", inputSchema: t.inputSchema ?? null, annotations: t.annotations }));

  const perTool = tools.map((t) => {
    const flags = staticObservations(t as any).map((f) => ({ id: f.id, label: f.label, evidence: f.evidence, rule: citeRule(f.sentinelRule) }));
    return { name: t.name, declaredReadOnly: declaresReadOnly(t as any), description: t.description, flagCount: flags.length, flags };
  });
  const pageFindings = pageObservations(tools as any).map((f) => ({ id: f.id, label: f.label, evidence: f.evidence, rule: citeRule(f.sentinelRule) }));

  return {
    url: location.href,
    scannedAt: new Date().toISOString(),
    toolCount: tools.length,
    flaggedTools: perTool.filter((t) => t.flagCount > 0).length,
    pageFindings,
    tools: perTool,
    method: "read-only enumeration (document.modelContext.getTools) — no tool was invoked",
    note: "Declared-metadata surface only. Witnessed-behavior rules (E5/J5) need Guardian installed before the page's tools register, and invoking a live third party's tools would violate Guardian's T1 read-only ethic.",
  };
}

(window as any).__guardianAudit = audit;
export {};
