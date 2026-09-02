import { defineConfig } from "vite";

// Bundles the standalone Guardian auditor to a single IIFE that runs on ANY WebMCP page.
// `npm run build:audit` → dist-audit/guardian-audit.iife.js  (used by the CLI + the bookmarklet).
export default defineConfig({
  build: {
    outDir: "dist-audit",
    emptyOutDir: true,
    target: "es2022",
    lib: {
      entry: "src/audit-standalone.ts",
      name: "GuardianAudit",
      formats: ["iife"],
      fileName: () => "guardian-audit.iife.js",
    },
  },
});
