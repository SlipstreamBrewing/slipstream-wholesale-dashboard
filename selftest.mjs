// Self-test: catches truncation / sync corruption and syntax errors before a
// push. A truncated file still "looks" fine but deploys to a blank page or a
// dead Worker — this fails loudly instead. Run: node selftest.mjs
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { execSync } from "node:child_process";

let fail = 0;
const ok = (m) => console.log("  ok  " + m);
const bad = (m) => { console.log(" FAIL " + m); fail++; };

function balanced(s, open, close) {
  let n = 0;
  for (const ch of s) { if (ch === open) n++; else if (ch === close) n--; }
  return n === 0;
}
function noTruncation(name, s) {
  if (s.includes(String.fromCharCode(0))) return bad(`${name}: contains null bytes (sync corruption)`);
  if (s.trim().length < 200) return bad(`${name}: suspiciously short`);
  ok(`${name}: ${s.length} bytes, no null padding`);
}

// --- worker.js ---
const worker = readFileSync(new URL("./worker.js", import.meta.url), "utf8");
noTruncation("worker.js", worker);
if (!worker.trimEnd().endsWith("}")) bad("worker.js: does not end cleanly with }");
if (!balanced(worker, "{", "}")) bad("worker.js: unbalanced { }");
["export default", "async fetch(", "/api/metrics", "getValidXeroToken",
 "revenue", "cogs", "directCosts", "channels", "litres"]
  .forEach((t) => worker.includes(t) ? ok(`worker.js has "${t}"`) : bad(`worker.js missing "${t}"`));

// syntax-check worker.js as a module (stub the html import)
try {
  const stub = worker.replace(/^import PAGE from .*$/m, 'const PAGE = "";');
  writeFileSync("._wt.mjs", stub);
  execSync("node --check ._wt.mjs", { stdio: "pipe" });
  ok("worker.js: syntax valid");
} catch (e) { bad("worker.js: syntax error\n" + (e.stderr || e).toString()); }
finally { try { unlinkSync("._wt.mjs"); } catch {} }

// --- dashboard.html ---
const page = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8");
noTruncation("dashboard.html", page);
if (!/<\/html>\s*$/.test(page)) bad("dashboard.html: does not end with </html>");
["id=\"app\"", "id=\"gate\"", "/api/metrics", "/auth/xero/begin", "computeSet(",
 "Sales by channel", "Check your numbers"]
  .forEach((t) => page.includes(t) ? ok(`dashboard.html has ${t}`) : bad(`dashboard.html missing ${t}`));

// syntax-check the inline script
try {
  const m = page.match(/<script>([\s\S]*?)<\/script>\s*<\/body>/);
  if (!m) bad("dashboard.html: could not locate main <script> block");
  else {
    writeFileSync("._pt.mjs", m[1]);
    execSync("node --check ._pt.mjs", { stdio: "pipe" });
    ok("dashboard.html: inline script syntax valid");
  }
} catch (e) { bad("dashboard.html: script syntax error\n" + (e.stderr || e).toString()); }
finally { try { unlinkSync("._pt.mjs"); } catch {} }

console.log("");
if (fail) { console.log(`SELFTEST: ${fail} problem(s) — do not push.`); process.exit(1); }
console.log("SELFTEST: green — safe to push.");
