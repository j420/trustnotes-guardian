// Builds are done by the caller (vite build). This serves dist/ and runs the spike in Chromium.
import { chromium } from "playwright";
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const DIST = new URL("./dist-spike/", import.meta.url).pathname;
const PORT = 4319;
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".map": "application/json", ".svg": "image/svg+xml", ".json": "application/json" };

const server = http.createServer(async (req, res) => {
  try {
    let p = decodeURIComponent((req.url || "/").split("?")[0]);
    if (p === "/") p = "/index.html";
    const file = join(DIST, normalize(p));
    if (!file.startsWith(DIST)) { res.writeHead(403); return res.end("no"); }
    const body = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404); res.end("not found");
  }
});
await new Promise((r) => server.listen(PORT, r));

const browser = await chromium.launch({
  headless: true,
  executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const page = await browser.newPage();
const consoleErrors = [];
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
page.on("pageerror", (e) => consoleErrors.push("pageerror: " + e.message));

await page.goto(`http://localhost:${PORT}/`, { waitUntil: "networkidle" }).catch(() => {});
await page.waitForFunction(() => !!window.__SPIKE__, { timeout: 15000 }).catch(() => {});
const result = await page.evaluate(() => window.__SPIKE__ || { error: "no result", checks: [] });

console.log("\n================ PHASE-0 SPIKE RESULTS ================");
for (const c of result.checks || []) console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "   [" + c.detail + "]" : ""}`);
console.log(`------------------------------------------------------`);
console.log(`${result.passed}/${result.total} checks passed  =>  ${result.allPass ? "ALL PASS ✅" : "SOME FAILED ❌"}`);
if (consoleErrors.length) { console.log("console/page errors:"); consoleErrors.forEach((e) => console.log("  " + e)); }

await browser.close();
server.close();
process.exit(result.allPass ? 0 : 1);
