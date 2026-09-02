#!/usr/bin/env node
/**
 * Guardian WebMCP URL auditor — point it at any real WebMCP page and read its tools' DECLARED
 * surface against the ported Sentinel detectors. READ-ONLY: it never invokes a tool.
 *
 *   node scripts/guardian-audit.mjs <url> [--json out.json] [--shot out.png]
 *
 * Requires the bundle: `npm run build:audit` first (produces dist-audit/guardian-audit.iife.js).
 * Chromium: set GUARDIAN_CHROMIUM=/path/to/chrome, or `npx playwright install chromium` and omit it.
 */
import { chromium } from "playwright";
import { readFile, writeFile } from "node:fs/promises";

const args = process.argv.slice(2);
const url = args.find((a) => !a.startsWith("--"));
const jsonOut = valOf("--json");
const shotOut = valOf("--shot");
const clickSel = valOf("--click"); // optional: click a selector before auditing (e.g. to reveal a lazily-injected tool)
const waitMs = Number(valOf("--wait") || 1200);
function valOf(flag) { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : null; }
if (!url) { console.error("usage: node scripts/guardian-audit.mjs <webmcp-url> [--json out.json] [--shot out.png]"); process.exit(2); }

const bundle = await readFile(new URL("../dist-audit/guardian-audit.iife.js", import.meta.url), "utf8").catch(() => {
  console.error("missing bundle — run `npm run build:audit` first."); process.exit(2);
});

const PROXY = process.env.HTTPS_PROXY || process.env.https_proxy;
// Never route localhost through a proxy (breaks a locally-served target). External URLs use the
// proxy when one is configured; on a normal machine none is set and the browser connects directly.
let isLocal = false;
try { isLocal = /^(localhost|127\.|0\.0\.0\.0|\[?::1)/.test(new URL(url).host); } catch { /* keep false */ }
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.GUARDIAN_CHROMIUM || undefined,
  // --no-proxy-server for local targets: Chromium otherwise inherits HTTPS_PROXY from env and mangles localhost.
  args: ["--no-sandbox", "--disable-dev-shm-usage", ...(isLocal ? ["--no-proxy-server"] : [])],
  proxy: PROXY && !isLocal ? { server: PROXY, bypass: "localhost,127.0.0.1" } : undefined,
});
const page = await (await browser.newContext()).newPage();

const C = { d: "\x1b[2m", r: "\x1b[0m", b: "\x1b[1m", red: "\x1b[31m", yel: "\x1b[33m", grn: "\x1b[32m", cyan: "\x1b[36m" };
const sevColor = { critical: C.red, high: C.red, medium: C.yel, low: C.grn, informational: C.cyan };

try {
  process.stdout.write(`\nLoading ${C.b}${url}${C.r} …\n`);
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForFunction(() => !!(document.modelContext || navigator.modelContext), null, { timeout: 12000 })
    .catch(() => {}); // best-effort: some pages register lazily; the audit reports honestly if absent
  await page.waitForTimeout(waitMs); // give the page's scripts time to register their tools
  if (clickSel) { await page.click(clickSel, { timeout: 5000 }).catch(() => console.error(`  (couldn't click ${clickSel})`)); await page.waitForTimeout(waitMs); }
  await page.addScriptTag({ content: bundle });
  const rep = await page.evaluate(() => window.__guardianAudit());
  if (shotOut) await page.screenshot({ path: shotOut, fullPage: true });
  if (jsonOut) await writeFile(jsonOut, JSON.stringify(rep, null, 2));

  if (rep.error) { console.error(`\n${C.red}✗ ${rep.error}${C.r}\n`); process.exitCode = 1; }
  else {
    console.log(`\n${C.b}🛡️  Guardian WebMCP audit${C.r}  ${C.d}(read-only enumeration — no tool invoked)${C.r}`);
    console.log(`${C.d}${rep.url}${C.r}`);
    console.log(`tools: ${C.b}${rep.toolCount}${C.r}   flagged: ${rep.flaggedTools ? C.red + rep.flaggedTools + C.r : C.grn + "0" + C.r}\n`);
    for (const f of rep.pageFindings) console.log(`  ${C.red}⚑ PAGE ${f.rule.id || f.rule}${C.r} ${f.label}  ${C.d}${f.evidence}${C.r}`);
    if (rep.pageFindings.length) console.log("");
    for (const t of rep.tools) {
      const head = t.flagCount ? `${C.red}●${C.r}` : `${C.grn}○${C.r}`;
      console.log(`  ${head} ${C.b}${t.name}${C.r} ${C.d}${t.declaredReadOnly ? "[declared read-only]" : "[read-write]"}${C.r}`);
      for (const fl of t.flags) {
        const sc = sevColor[fl.rule.severity] || C.d;
        console.log(`      ${sc}${(fl.rule.severity || "?").toUpperCase().padEnd(8)}${C.r} ${C.cyan}${fl.rule.id}${C.r} ${fl.label}  ${C.d}${String(fl.evidence).slice(0, 70)}${C.r}`);
      }
    }
    console.log(`\n${C.d}${rep.note}${C.r}`);
    if (jsonOut) console.log(`${C.d}JSON → ${jsonOut}${C.r}`);
  }
} catch (e) {
  console.error(`\n${C.red}✗ could not audit ${url}${C.r}\n  ${String(e).split("\n")[0]}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
