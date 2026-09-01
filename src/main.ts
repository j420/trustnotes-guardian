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

const mc: any = (document as any).modelContext;
guardian.install(mc); // wraps registerTool + registers guardian's own agent-callable tools
await registerTrustNotesTools(mc); // the 4 honest TrustNotes tools (now guarded)
mountUI();

// expose for the Playwright E2E + debugging
(window as any).__guardian = guardian;
