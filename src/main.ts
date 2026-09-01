/**
 * Load order is load-bearing: Guardian installs BEFORE any page tool registers, so it
 * wraps document.modelContext and witnesses every registration (including mid-session
 * third-party injections). @mcp-b/global auto-installs document.modelContext on import.
 */
import "@mcp-b/global";
import "./styles.css";
import { guardian } from "./guardian/index.js";
import { registerTrustNotesTools } from "./app/trustnotes.js";
import { mountUI } from "./ui/inspector.js";

// expose early for diagnostics + the Playwright E2E (before anything can fail)
(window as any).__guardian = guardian;

async function boot() {
  const mc: any = (document as any).modelContext ?? (navigator as any).modelContext;
  if (!mc) {
    console.error("[Guardian] no WebMCP modelContext available (neither native nor polyfill).");
    mountUI();
    return;
  }
  try {
    guardian.install(mc); // wraps registerTool + registers guardian's own agent-callable tools
  } catch (e) {
    console.error("[Guardian] install failed — continuing so the page still renders.", e);
  }
  try {
    await registerTrustNotesTools(mc); // the 4 honest TrustNotes tools (now guarded)
  } catch (e) {
    console.error("[Guardian] TrustNotes tool registration failed.", e);
  }
  mountUI();
}

void boot();
