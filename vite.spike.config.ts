import { defineConfig } from "vite";
// Dedicated build for the Phase-0 mechanics spike (kept reproducible: `npm run spike`).
export default defineConfig({ root: "spike", build: { outDir: "../dist-spike", emptyOutDir: true, target: "es2022" } });
