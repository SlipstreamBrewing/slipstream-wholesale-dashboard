// Slipstream Brewing Wholesale dashboard — Cloudflare Worker (backend shell).
// Read-only. Money from Xero (ex-GST); litres from Beer30. Secrets live in
// Cloudflare, never in this repo. Tokens + password + data live in KV (TOKENS).
//
// The page (dashboard.html) computes all the KPI definitions; this Worker only
// serves raw source data on the agreed contract. See wholesale-kpi-spec.md.

import PAGE from "./dashboard.html";

// ---------------------------------------------------------------------------
// Wholesale account mapping (from the real Xero chart of accounts, 14 Jul 2026).
// Money scope is LOCKED to these three income accounts. The COGS + direct-cost
// lists are the fine-grain sets confirmed at reconciliation — edit here only.
// ---------------------------------------------------------------------------
const WHOLESALE_INCOME = {
  keg:     ["sales - wholesale kegs"],
  package: ["sales - wholesale package"],
  general: ["sales - wholesale"],
};
const WHOLESALE_COGS = [
  "brewery - ingredients", "packaging", "excise tax",
  "opening stock - brewery", "closing stock - brewery", "stock movement - brewery",
  "cost of goods sold:finished goods:packaged kegs sold",
  "cost of goods sold:finished goods:package sold",
  "cost of goods sold:package supply losses, packages",
  "cost of goods sold:finished goods losses:package losses",
  "cost of goods sold:raw material losses",
  "rebates - wholesale sales", "cds scheme", "freight - inwards",
  "quality control, laboratory & testing",
];
const WHOLESALE_DIRECT_COSTS = [
  "freight", "freight & courier",
  "warehousing - qld", "warehousing - nsw", "warehousing- vic", "warehousing - wa",
  "trade marketing", "sales commission", "selling expenses", "debt collection",
  "co2",
];

// Granular scopes only (apps created on/after 2 Mar 2026). The P&L report is all
// the money metrics need; the channel split, volume and counts come from Beer30.
const XERO_SCOPES = "offline_access accounting.reports.profitandloss.read";

// Beer30 Company_Category -> dashboard channel (owner model, 15 Jul 2026).
const CHANNEL_MAP = {
  "on-premise": "On-Premise",
  "off-premise": "Off-Premise",
  "national retailer": "National Retailer",
  "distributor": "Distributor",
  "slipstream": "In-House",
};
// Ranked external channels; In-House and Direct / Online are shown but not ranked.
const RANKED_CHANNELS = ["On-Premise", "Off-Premise", "National Retailer", "Distributor"];
const UNRANKED_CHANNELS = ["In-House", "Direct / Online"];
function channelOf(cat) {
  return CHANNEL_MAP[(cat || "").trim().toLowerCase()] || "Direct / Online";
}
function money(s) {
  const n = parseFloat(String(s == null ? "" : s).replace(/[$,]/g, "").trim());
  return isNaN(n) ? 0 : n;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (err) {
      return json({ error: { plain: "Something went wrong on the dashboard server." } }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    // Rung 2 hook: pull Beer30's own export on a schedule when a stable URL is
    // wired. Left inert until then.
    return;
  },
};

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;

  // Ingest keeps its own bearer-token auth (Beer30 export drops / bridges).
  if (p === "/api/ingest" && request.method === "POST") return handleIngest(request, env);

  // Password lifecycle
  const hasPw = !!(await env.TOKENS.get("config:password"));
  if (p === "/api/set-password" && request.method === "POST") return setPassword(request, env, hasPw);
  if (p === "/api/login" && request.method === "POST") return login(request, env);
  if (p === "/api/logout" && request.method === "POST") return logout(env);

  // Before a password exists, everything shows the set-password screen.
  if (!hasPw) {
    if (p === "/" ) return html(PAGE);
    return json({ error: { plain: "Set your dashboard password first." }, needsPassword: true }, 401);
  }

  // Everything below needs a valid session.
  const authed = await checkSession(request, env);
  if (!authed) {
    if (p === "/") return html(PAGE);
    return json({ error: { plain: "Please log in." }, needsLogin: true }, 401);
  }

  if (p === "/") return html(PAGE);
  if (p === "/api/metrics") return metrics(request, env);
  if (p === "/api/status") return status(env);
  if (p === "/api/beer30/test") return beer30Test(env);
  if (p === "/report") return weeklyReport(request, env);
  if (p === "/auth/xero/begin") return xeroBegin(request, env);
  if (p === "/auth/xero/callback") return xeroCallback(request, env);
  if (p === "/api/disconnect" && request.method === "POST") return disconnect(request, env);

  return new Response("Not found", { status: 404 });
}

// ---------------------------------------------------------------------------
// Crypto helpers (Web Crypto only)
// ---------------------------------------------------------------------------
const enc = new TextEncoder();
function b64url(bytes) {
  let s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function pbkdf2(password, saltHex, iterations = 100000) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return hex(bits);
}
async function getSessionSecret(env) {
  let s = await env.TOKENS.get("config:session_secret");
  if (!s) {
    s = hex(crypto.getRandomValues(new Uint8Array(32)));
    await env.TOKENS.put("config:session_secret", s);
  }
  return s;
}
async function hmac(secretHex, msg) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secretHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}

// ---------------------------------------------------------------------------
// Password + session
// ---------------------------------------------------------------------------
async function setPassword(request, env, hasPw) {
  if (hasPw) return json({ error: { plain: "A password is already set." } }, 400);
  const { password } = await request.json().catch(() => ({}));
  if (!password || password.length < 6)
    return json({ error: { plain: "Choose a password of at least 6 characters." } }, 400);
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await pbkdf2(password, salt);
  await env.TOKENS.put("config:password", JSON.stringify({ salt, hash, iterations: 100000 }));
  return await issueSession(env, { ok: true });
}
async function login(request, env) {
  const { password } = await request.json().catch(() => ({}));
  const rec = await env.TOKENS.get("config:password", "json");
  if (!rec) return json({ error: { plain: "No password set yet." }, needsPassword: true }, 401);
  const hash = await pbkdf2(password || "", rec.salt, rec.iterations || 100000);
  if (hash !== rec.hash) return json({ error: { plain: "That password didn't match." } }, 401);
  return await issueSession(env, { ok: true });
}
async function issueSession(env, body) {
  const secret = await getSessionSecret(env);
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  const payload = `s.${exp}`;
  const sig = await hmac(secret, payload);
  const cookie = `sid=${payload}.${sig}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 3600}`;
  return json(body, 200, { "Set-Cookie": cookie });
}
function logout(env) {
  return json({ ok: true }, 200, {
    "Set-Cookie": "sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
  });
}
async function checkSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return false;
  const parts = m[1].split(".");
  if (parts.length !== 3) return false;
  const [pre, exp, sig] = parts;
  const payload = `${pre}.${exp}`;
  const secret = await getSessionSecret(env);
  if ((await hmac(secret, payload)) !== sig) return false;
  return Date.now() < Number(exp);
}

// ---------------------------------------------------------------------------
// Xero OAuth + token store (rotating refresh persisted on every refresh)
// ---------------------------------------------------------------------------
function xeroRedirectUri(url) {
  return `${new URL(url).origin}/auth/xero/callback`;
}
async function xeroBegin(request, env) {
  if (!env.XERO_CLIENT_ID) return json({ error: { plain: "Xero isn't set up yet." } }, 400);
  const state = hex(crypto.getRandomValues(new Uint8Array(16)));
  await env.TOKENS.put(`oauth:state:${state}`, "1", { expirationTtl: 600 });
  const u = new URL("https://login.xero.com/identity/connect/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", env.XERO_CLIENT_ID);
  u.searchParams.set("redirect_uri", xeroRedirectUri(request.url));
  u.searchParams.set("scope", XERO_SCOPES);
  u.searchParams.set("state", state);
  return Response.redirect(u.toString(), 302);
}
async function xeroCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || !(await env.TOKENS.get(`oauth:state:${state}`)))
    return html("<p>Connection failed. Please try connecting Xero again.</p>");
  await env.TOKENS.delete(`oauth:state:${state}`);

  const basic = btoa(`${env.XERO_CLIENT_ID}:${env.XERO_CLIENT_SECRET}`);
  const tok = await fetch("https://identity.xero.com/connect/token", {
    method: "POST",
    headers: { "Authorization": `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: xeroRedirectUri(request.url),
    }),
  }).then((r) => r.json());
  if (!tok.access_token) return html("<p>Connection failed at the token step. Please try again.</p>");

  // Which organisation did they connect?
  const conns = await fetch("https://api.xero.com/connections", {
    headers: { "Authorization": `Bearer ${tok.access_token}`, "Accept": "application/json" },
  }).then((r) => r.json()).catch(() => []);
  const org = Array.isArray(conns) && conns[0] ? conns[0] : {};

  await saveXeroTokens(env, {
    access_token: tok.access_token,
    refresh_token: tok.refresh_token,
    expires_at: Date.now() + (tok.expires_in - 60) * 1000,
    tenant_id: org.tenantId || "",
    tenant_name: org.tenantName || "",
  });
  // Bounce back to the dashboard's connections screen.
  return Response.redirect(`${url.origin}/?connected=xero`, 302);
}
async function saveXeroTokens(env, t) {
  await env.TOKENS.put("xero:tokens", JSON.stringify(t));
}
async function getValidXeroToken(env) {
  const t = await env.TOKENS.get("xero:tokens", "json");
  if (!t) return null;
  if (Date.now() < t.expires_at) return t;
  // Refresh (Xero rotates the refresh token every time — persist the new one).
  const basic = btoa(`${env.XERO_CLIENT_ID}:${env.XERO_CLIENT_SECRET}`);
  const r = await fetch("https://identity.xero.com/connect/token", {
    method: "POST",
    headers: { "Authorization": `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: t.refresh_token }),
  }).then((x) => x.json());
  if (!r.access_token) return null;
  const nt = {
    ...t,
    access_token: r.access_token,
    refresh_token: r.refresh_token || t.refresh_token,
    expires_at: Date.now() + (r.expires_in - 60) * 1000,
  };
  await saveXeroTokens(env, nt);
  return nt;
}
async function disconnect(request, env) {
  const { source } = await request.json().catch(() => ({}));
  if (source === "xero") await env.TOKENS.delete("xero:tokens");
  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// Xero P&L pull + wholesale extraction
// ---------------------------------------------------------------------------
function labelOf(row) { return (row.Cells?.[0]?.Value || "").trim().toLowerCase(); }
function amountOf(row) {
  const v = row.Cells?.[row.Cells.length - 1]?.Value;
  const n = parseFloat(v);
  return isNaN(n) ? 0 : n;
}
function walkRows(rows, out) {
  for (const r of rows || []) {
    if (r.Rows) walkRows(r.Rows, out);
    else if (r.RowType === "Row") out.push(r);
  }
}
function sumMatching(rows, names) {
  let total = 0;
  for (const r of rows) if (names.includes(labelOf(r))) total += amountOf(r);
  return total;
}
async function xeroPnl(env, token, from, to) {
  const u = new URL("https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss");
  u.searchParams.set("fromDate", from);
  u.searchParams.set("toDate", to);
  const rep = await fetch(u.toString(), {
    headers: {
      "Authorization": `Bearer ${token.access_token}`,
      "Xero-Tenant-Id": token.tenant_id,
      "Accept": "application/json",
    },
  }).then((r) => r.json());
  const rows = [];
  walkRows(rep?.Reports?.[0]?.Rows || [], rows);
  const channels = {
    keg: sumMatching(rows, WHOLESALE_INCOME.keg),
    package: sumMatching(rows, WHOLESALE_INCOME.package),
    general: sumMatching(rows, WHOLESALE_INCOME.general),
  };
  const revenue = channels.keg + channels.package + channels.general;
  const cogs = sumMatching(rows, WHOLESALE_COGS);
  const directCosts = sumMatching(rows, WHOLESALE_DIRECT_COSTS);
  return { revenue, channels, cogs, directCosts, accounts: null, orders: null };
}

// ---------------------------------------------------------------------------
// Beer30 sales export -> per-channel aggregates (export/ingest; live API later)
// Stored per day: data:sales:<YYYY-MM-DD> =
//   { "<channel>": { netInv, kegL, packL, companies:[...], invoices:[...] } }
// ---------------------------------------------------------------------------
async function salesForRange(env, from, to) {
  const list = await env.TOKENS.list({ prefix: "data:sales:" });
  const acc = {};
  let any = false;
  for (const k of list.keys) {
    const day = k.name.slice("data:sales:".length);
    if (day === "lastSync" || day < from || day > to) continue;
    const row = await env.TOKENS.get(k.name, "json");
    if (!row) continue;
    any = true;
    for (const [ch, v] of Object.entries(row)) {
      const a = acc[ch] || (acc[ch] = { netInv: 0, kegL: 0, packL: 0, companies: new Set(), invoices: new Set() });
      a.netInv += v.netInv || 0; a.kegL += v.kegL || 0; a.packL += v.packL || 0;
      (v.companies || []).forEach((c) => a.companies.add(c));
      (v.invoices || []).forEach((i) => a.invoices.add(i));
    }
  }
  if (!any) return null;
  const channels = {};
  for (const [ch, a] of Object.entries(acc)) {
    channels[ch] = {
      netInv: a.netInv, litres: a.kegL + a.packL, kegL: a.kegL, packL: a.packL,
      customers: a.companies.size, orders: a.invoices.size,
    };
  }
  return { channels };
}
async function handleIngest(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!env.INGEST_TOKEN || auth !== `Bearer ${env.INGEST_TOKEN}`)
    return json({ error: { plain: "Upload code missing or wrong." } }, 401);
  const text = await request.text();
  const days = parseSalesExport(text);
  const dayCount = Object.keys(days).length;
  if (!dayCount) return json({ error: { plain: "No rows found - is this the Beer30 sales export?" } }, 400);
  for (const [date, chans] of Object.entries(days)) {
    await env.TOKENS.put(`data:sales:${date}`, JSON.stringify(chans));
  }
  await env.TOKENS.put("data:sales:lastSync", new Date().toISOString());
  return json({ ok: true, days: dayCount });
}
function parseSalesExport(text) {
  const recs = parseCSV(text);
  const out = {};
  for (const r of recs) {
    const date = normDate((r["Delivery"] || "").trim());
    if (!date) continue;
    const ch = channelOf(r["Company_Category"]);
    const isKeg = (r["Package"] || "").trim().toLowerCase() === "keg";
    const litres = money(r["Vol. (L)"]);
    const day = out[date] || (out[date] = {});
    const a = day[ch] || (day[ch] = { netInv: 0, kegL: 0, packL: 0, companies: [], invoices: [] });
    a.netInv += money(r["Subtotal"]);
    if (isKeg) a.kegL += litres; else a.packL += litres;
    const co = (r["Company"] || "").trim(); if (co && !a.companies.includes(co)) a.companies.push(co);
    const inv = (r["Invoice #"] || "").trim(); if (inv && !a.invoices.includes(inv)) a.invoices.push(inv);
  }
  return out;
}
function parseCSV(text) {
  const s = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const rows = []; let field = "", row = [], inQ = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQ) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim());
  const out = [];
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].length === 1 && rows[i][0] === "") continue;
    const obj = {}; head.forEach((h, j) => { obj[h] = rows[i][j]; });
    out.push(obj);
  }
  return out;
}
function normDate(s) {
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/); // dd/mm/yyyy
  if (m) return `${m[3]}-${m[2].padStart(2, "0")}-${m[1].padStart(2, "0")}`;
  return null;
}

// ---------------------------------------------------------------------------
// Beer30 live API adapter (channels from /companies + /distribution/orders)
// ---------------------------------------------------------------------------
async function b30Get(env, path) {
  const key = (env.BEER30_KEY || "").trim();
  const base = (env.BEER30_BASE || "https://api.b30.app").trim().replace(/\/+$/, "");
  const sep = path.includes("?") ? "&" : "?";
  const r = await fetch(`${base}${path}${sep}format=json&key=${encodeURIComponent(key)}`, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`Beer30 ${path} -> ${r.status}`);
  return r.json();
}
function litresPerUnit(pkg) {
  const p = (pkg || "").toLowerCase();
  const mml = p.match(/(\d+(?:\.\d+)?)\s*-?\s*ml/);
  if (mml) {
    const ml = parseFloat(mml[1]);
    let mult = 1;
    const br = p.match(/\[([^\]]+)\]/);
    if (br) { const nums = br[1].match(/\d+/g) || []; mult = nums.reduce((a, n) => a * parseInt(n, 10), 1) || 1; }
    else { const xs = p.match(/(\d+)\s*x\s*(\d+)/); if (xs) mult = parseInt(xs[1], 10) * parseInt(xs[2], 10); }
    return (ml * mult) / 1000;
  }
  const m = p.match(/(\d+(?:\.\d+)?)\s*-?\s*l\b/);
  if (m && !p.includes("ml")) return parseFloat(m[1]);
  return 0;
}
function isKegPkg(pkg) {
  const p = (pkg || "").toLowerCase();
  return p.includes("keg") || (/(\d+(?:\.\d+)?)\s*-?\s*l\b/.test(p) && !p.includes("ml"));
}
async function fetchBeer30Companies(env) {
  const cj = await b30Get(env, "/companies");
  const arr = (cj && cj.companies && (cj.companies.Company || cj.companies)) || [];
  const catOf = {}, nameOf = {};
  for (const c of arr) { catOf[c["company-id"]] = c.category; nameOf[c["company-id"]] = c.name; }
  return { catOf, nameOf };
}
// Page through published, non-voided orders in a delivery-date range.
async function iterB30Orders(env, from, to, cb) {
  const limit = 1000;
  let offset = 0;
  for (let page = 0; page < 100; page++) {
    const oj = await b30Get(env, `/distribution/orders?type=PUBLISHED&delivery-date-start=${from}&delivery-date-end=${to}&limit=${limit}&offset=${offset}`);
    const orders = (oj && oj.orders) || [];
    for (const o of orders) {
      const st = (o.status || "").toUpperCase();
      if (st === "VOIDED" || st === "DECLINED") continue;
      cb(o);
    }
    if (orders.length < limit) break;
    offset += limit;
  }
}
// Distinct company-ids that ordered in a range (used to detect first-ever orders).
async function b30CompanySet(env, from, to) {
  const s = new Set();
  await iterB30Orders(env, from, to, (o) => s.add(o["company-id"]));
  return s;
}
async function fetchBeer30Orders(env, from, to, catOf) {
  const acc = {};
  const cust = {};
  await iterB30Orders(env, from, to, (o) => {
    const cid = o["company-id"];
    const ch = channelOf(catOf[cid]);
    const a = acc[ch] || (acc[ch] = { netInv: 0, kegL: 0, packL: 0, companies: new Set(), invoices: new Set() });
    a.companies.add(cid); a.invoices.add(o["order-id"]);
    const c = cust[cid] || (cust[cid] = { channel: ch, netInv: 0, litres: 0, orders: new Set() });
    c.orders.add(o["order-id"]);
    for (const it of (o.items || [])) {
      const qty = parseFloat(it.quantity) || 0;
      const price = parseFloat(it.price) || 0;
      const line = qty * price;
      const litres = litresPerUnit(it.package) * qty;
      a.netInv += line;
      if (isKegPkg(it.package)) a.kegL += litres; else a.packL += litres;
      c.netInv += line; c.litres += litres;
    }
  });
  if (!Object.keys(acc).length) return null;
  const channels = {};
  for (const [ch, a] of Object.entries(acc)) {
    channels[ch] = { netInv: a.netInv, litres: a.kegL + a.packL, kegL: a.kegL, packL: a.packL, customers: a.companies.size, orders: a.invoices.size };
  }
  const customers = {};
  for (const [cid, c] of Object.entries(cust)) {
    customers[cid] = { channel: c.channel, netInv: c.netInv, litres: c.litres, orders: c.orders.size };
  }
  return { channels, customers };
}

// ---------------------------------------------------------------------------
// Weekly wholesale sales report (self-contained HTML, safe to email)
// ---------------------------------------------------------------------------
function bneDay() { // "today" in Brisbane (UTC+10, no DST) as a UTC-midnight Date
  const n = new Date(Date.now() + 10 * 3600 * 1000);
  return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate()));
}
function ymdU(d) { return d.toISOString().slice(0, 10); }
function addD(d, n) { return new Date(d.getTime() + n * 86400000); }
function reportPeriods() {
  const today = bneDay();
  const dow = today.getUTCDay();            // 0=Sun
  const sinceMon = (dow + 6) % 7;           // Mon=0
  const thisMon = addD(today, -sinceMon);
  const lastMon = addD(thisMon, -7), lastSun = addD(thisMon, -1);
  const prevMon = addD(lastMon, -7), prevSun = addD(lastMon, -1);
  const mStart = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1));
  const fyY = today.getUTCMonth() >= 6 ? today.getUTCFullYear() : today.getUTCFullYear() - 1;
  const fyStart = new Date(Date.UTC(fyY, 6, 1));
  return {
    today: ymdU(today),
    week: { from: ymdU(lastMon), to: ymdU(lastSun) },
    prevWeek: { from: ymdU(prevMon), to: ymdU(prevSun) },
    mtd: { from: ymdU(mStart), to: ymdU(today) },
    ytd: { from: ymdU(fyStart), to: ymdU(today) },
  };
}
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtMoney = (n) => n == null ? "—" : "$" + Math.round(n).toLocaleString("en-AU");
const fmtL = (n) => n == null ? "—" : Math.round(n).toLocaleString("en-AU") + " L";
const fmtN = (n) => n == null ? "—" : Number(n).toLocaleString("en-AU");
function rollup(agg) {
  if (!agg) return { netInv: 0, litres: 0, orders: 0, accounts: 0 };
  let netInv = 0, litres = 0, orders = 0, accounts = 0;
  for (const [name, c] of Object.entries(agg.channels)) {
    litres += c.litres || 0;
    if (RANKED_CHANNELS.includes(name)) { netInv += c.netInv || 0; orders += c.orders || 0; accounts += c.customers || 0; }
  }
  return { netInv, litres, orders, accounts };
}
function deltaPct(cur, prev) {
  if (!prev) return null;
  return ((cur - prev) / Math.abs(prev)) * 100;
}
function deltaHtml(cur, prev) {
  const d = deltaPct(cur, prev);
  if (d == null) return '<span style="color:#6b7480">—</span>';
  const up = d >= 0;
  return `<span style="color:${up ? "#1f9d6b" : "#d1495b"};font-weight:600">${up ? "▲" : "▼"} ${Math.abs(d).toFixed(1)}%</span>`;
}
async function weeklyReport(request, env) {
  const P = reportPeriods();
  const demo = /integration-demo/i.test((env.BEER30_BASE || ""));
  const cm = await fetchBeer30Companies(env);
  const catOf = cm.catOf, nameOf = cm.nameOf;
  const [week, prevWeek, mtd, ytd] = await Promise.all([
    fetchBeer30Orders(env, P.week.from, P.week.to, catOf),
    fetchBeer30Orders(env, P.prevWeek.from, P.prevWeek.to, catOf),
    fetchBeer30Orders(env, P.mtd.from, P.mtd.to, catOf),
    fetchBeer30Orders(env, P.ytd.from, P.ytd.to, catOf),
  ]);
  // New customers: ordered in MTD but never in the prior 24 months.
  const priorFrom = ymdU(addD(new Date(P.mtd.from + "T00:00:00Z"), -730));
  const priorTo = ymdU(addD(new Date(P.mtd.from + "T00:00:00Z"), -1));
  let priorSet = new Set();
  try { priorSet = await b30CompanySet(env, priorFrom, priorTo); } catch (e) {}
  const mtdCust = (mtd && mtd.customers) || {};
  const newCust = Object.entries(mtdCust)
    .filter(([cid]) => !priorSet.has(cid))
    .map(([cid, c]) => ({ cid, name: nameOf[cid] || cid, ...c }))
    .sort((a, b) => b.netInv - a.netInv);
  // Top 15 by MTD net revenue (with last-week revenue alongside)
  const weekCust = (week && week.customers) || {};
  const top = Object.entries(mtdCust)
    .map(([cid, c]) => ({ cid, name: nameOf[cid] || cid, ...c, weekNet: (weekCust[cid] || {}).netInv || 0 }))
    .sort((a, b) => b.netInv - a.netInv).slice(0, 15);

  const rw = rollup(week), rp = rollup(prevWeek), rm = rollup(mtd), ry = rollup(ytd);
  const chanRows = (agg) => {
    if (!agg) return '<tr><td colspan="5" style="color:#6b7480">No data</td></tr>';
    const ext = RANKED_CHANNELS.filter((n) => agg.channels[n]).map((n) => [n, agg.channels[n]]).sort((a, b) => b[1].netInv - a[1].netInv);
    const tot = ext.reduce((s, [, c]) => s + c.netInv, 0);
    let rows = ext.map(([n, c], i) => `<tr><td>${i + 1}. ${esc(n)}</td><td class="r">${fmtMoney(c.netInv)}</td><td class="r">${tot ? ((c.netInv / tot) * 100).toFixed(0) : 0}%</td><td class="r">${fmtL(c.litres)}</td><td class="r">${fmtN(c.orders)}</td></tr>`).join("");
    const un = UNRANKED_CHANNELS.filter((n) => agg.channels[n]);
    if (un.length) {
      rows += `<tr><td colspan="5" style="padding-top:8px;color:#6b7480;font-size:11px">Shown, not ranked</td></tr>`;
      rows += un.map((n) => { const c = agg.channels[n]; return `<tr style="color:#6b7480"><td>${esc(n)}</td><td class="r">${fmtMoney(c.netInv)}</td><td class="r">—</td><td class="r">${fmtL(c.litres)}</td><td class="r">${fmtN(c.orders)}</td></tr>`; }).join("");
    }
    return rows;
  };
  const gen = new Date(Date.now() + 10 * 3600 * 1000).toISOString().replace("T", " ").slice(0, 16);
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Slipstream Wholesale — Weekly Sales Report (${esc(P.week.from)} to ${esc(P.week.to)})</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1a1f26;background:#f6f7f9;margin:0;padding:24px;font-size:14px;line-height:1.45}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:21px;margin:0 0 2px}h2{font-size:15px;margin:26px 0 8px}
.sub{color:#6b7480;font-size:12.5px}
.demo{background:#fff7e6;border:1px solid #f2d999;color:#7a5a00;padding:10px 12px;border-radius:8px;margin:14px 0;font-size:12.5px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.tile{flex:1 1 160px;background:#fff;border:1px solid #e6e9ee;border-radius:10px;padding:14px}
.tile .l{color:#6b7480;font-size:12px}.tile .v{font-size:24px;font-weight:700;letter-spacing:-.4px;margin-top:2px}
.tile .d{font-size:11.5px;margin-top:4px;color:#6b7480}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e6e9ee;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-top:1px solid #eef0f3;font-size:13px}
th{background:#fafbfc;color:#6b7480;font-weight:600;border-top:none}
td.r,th.r{text-align:right}
footer{margin-top:22px;color:#6b7480;font-size:11.5px}
@media print{body{background:#fff;padding:0}.tile,table{break-inside:avoid}}
</style></head><body><div class="wrap">
<h1>Slipstream Brewing — Wholesale Weekly Sales Report</h1>
<div class="sub">Week of <b>${esc(P.week.from)}</b> to <b>${esc(P.week.to)}</b> · generated ${esc(gen)} (Brisbane) · source: Beer30</div>
${demo ? '<div class="demo"><b>Demo data.</b> This report is running against the Beer30 integration-demo environment, not live trading figures.</div>' : ""}

<h2>Last completed week</h2>
<div class="tiles">
  <div class="tile"><div class="l">Net revenue</div><div class="v">${fmtMoney(rw.netInv)}</div><div class="d">vs prev week ${deltaHtml(rw.netInv, rp.netInv)}</div></div>
  <div class="tile"><div class="l">Orders</div><div class="v">${fmtN(rw.orders)}</div><div class="d">vs prev week ${deltaHtml(rw.orders, rp.orders)}</div></div>
  <div class="tile"><div class="l">Volume</div><div class="v">${fmtL(rw.litres)}</div><div class="d">vs prev week ${deltaHtml(rw.litres, rp.litres)}</div></div>
  <div class="tile"><div class="l">Active accounts</div><div class="v">${fmtN(rw.accounts)}</div><div class="d">vs prev week ${deltaHtml(rw.accounts, rp.accounts)}</div></div>
</div>

<h2>Period summary</h2>
<table><tr><th>Period</th><th class="r">Net revenue</th><th class="r">Orders</th><th class="r">Volume</th><th class="r">Accounts</th></tr>
<tr><td>Last week (${esc(P.week.from)} – ${esc(P.week.to)})</td><td class="r">${fmtMoney(rw.netInv)}</td><td class="r">${fmtN(rw.orders)}</td><td class="r">${fmtL(rw.litres)}</td><td class="r">${fmtN(rw.accounts)}</td></tr>
<tr><td>Month to date (${esc(P.mtd.from)} – ${esc(P.mtd.to)})</td><td class="r">${fmtMoney(rm.netInv)}</td><td class="r">${fmtN(rm.orders)}</td><td class="r">${fmtL(rm.litres)}</td><td class="r">${fmtN(rm.accounts)}</td></tr>
<tr><td>Financial YTD (${esc(P.ytd.from)} – ${esc(P.ytd.to)})</td><td class="r">${fmtMoney(ry.netInv)}</td><td class="r">${fmtN(ry.orders)}</td><td class="r">${fmtL(ry.litres)}</td><td class="r">${fmtN(ry.accounts)}</td></tr>
</table>
<div class="sub" style="margin-top:6px">Revenue, orders and accounts cover the four external channels. Volume includes all channels.</div>

<h2>Sales by channel — last week</h2>
<table><tr><th>Channel</th><th class="r">Net revenue</th><th class="r">Share</th><th class="r">Volume</th><th class="r">Orders</th></tr>${chanRows(week)}</table>

<h2>Sales by channel — month to date</h2>
<table><tr><th>Channel</th><th class="r">Net revenue</th><th class="r">Share</th><th class="r">Volume</th><th class="r">Orders</th></tr>${chanRows(mtd)}</table>

<h2>Top 15 customers — month to date</h2>
<table><tr><th>#</th><th>Customer</th><th>Channel</th><th class="r">MTD revenue</th><th class="r">MTD volume</th><th class="r">Orders</th><th class="r">Last week</th></tr>
${top.length ? top.map((c, i) => `<tr><td>${i + 1}</td><td>${esc(c.name)}</td><td>${esc(c.channel)}</td><td class="r">${fmtMoney(c.netInv)}</td><td class="r">${fmtL(c.litres)}</td><td class="r">${fmtN(c.orders)}</td><td class="r">${c.weekNet ? fmtMoney(c.weekNet) : "—"}</td></tr>`).join("") : '<tr><td colspan="7" style="color:#6b7480">No customer activity this month</td></tr>'}
</table>

<h2>New customers — month to date</h2>
<div class="sub" style="margin-bottom:6px">Accounts with their first order in this month (no orders in the previous 24 months).</div>
<table><tr><th>Customer</th><th>Channel</th><th class="r">Revenue</th><th class="r">Volume</th><th class="r">Orders</th></tr>
${newCust.length ? newCust.map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.channel)}</td><td class="r">${fmtMoney(c.netInv)}</td><td class="r">${fmtL(c.litres)}</td><td class="r">${fmtN(c.orders)}</td></tr>`).join("") : '<tr><td colspan="5" style="color:#6b7480">No new accounts this month</td></tr>'}
</table>

<footer>Slipstream Brewing Company Pty Ltd · Wholesale sales report · figures ex-GST, from Beer30 order data.<br>
Channels: On-Premise, Off-Premise, National Retailer, Distributor (ranked); In-House and Direct / Online shown separately.</footer>
</div></body></html>`;
  const url = new URL(request.url);
  const headers = { "Content-Type": "text/html; charset=utf-8" };
  if (url.searchParams.get("download") === "1")
    headers["Content-Disposition"] = `attachment; filename="slipstream-wholesale-week-${P.week.to}.html"`;
  return new Response(html, { headers });
}

// ---------------------------------------------------------------------------
// Status + metrics API (the agreed contract)
// ---------------------------------------------------------------------------
async function status(env) {
  const xt = await env.TOKENS.get("xero:tokens", "json");
  const bSync = await env.TOKENS.get("data:sales:lastSync");
  const apiOn = !!(env.BEER30_KEY && ("" + env.BEER30_KEY).trim());
  return json({
    sources: {
      accounting: {
        configured: !!env.XERO_CLIENT_ID,
        connected: !!xt,
        org: xt?.tenant_name || null,
        sandbox: /demo company/i.test(xt?.tenant_name || ""),
      },
      beer30: { configured: true, connected: apiOn || !!bSync, mode: apiOn ? "api" : (bSync ? "upload" : null), source: "Beer30", lastSync: apiOn ? new Date().toISOString() : (bSync || null) },
    },
  });
}
function parseRange(s) {
  const [from, to] = (s || "").split(":");
  return from && to ? { from, to } : null;
}
async function metrics(request, env) {
  const url = new URL(request.url);
  const want = {
    cur: parseRange(url.searchParams.get("cur")),
    prev: parseRange(url.searchParams.get("prev")),
    yoy: parseRange(url.searchParams.get("yoy")),
  };
  const out = { sources: {}, periods: {}, trend: null };

  // Accounting source
  const token = await getValidXeroToken(env);
  const xt = await env.TOKENS.get("xero:tokens", "json");
  out.sources.accounting = {
    configured: !!env.XERO_CLIENT_ID,
    connected: !!xt,
    org: xt?.tenant_name || null,
    sandbox: /demo company/i.test(xt?.tenant_name || ""),
    lastSync: xt ? new Date().toISOString() : null,
    error: null,
  };
  const bSync = await env.TOKENS.get("data:sales:lastSync");
  const apiOn = !!(env.BEER30_KEY && ("" + env.BEER30_KEY).trim());
  out.sources.beer30 = {
    configured: true, connected: apiOn || !!bSync, source: "Beer30",
    mode: apiOn ? "api" : (bSync ? "upload" : null),
    lastSync: apiOn ? new Date().toISOString() : (bSync || null), error: null,
    ranked: RANKED_CHANNELS, unranked: UNRANKED_CHANNELS,
  };

  // Live API: fetch the company->channel map once, reuse across periods.
  let catOf = null;
  if (apiOn) {
    try { catOf = (await fetchBeer30Companies(env)).catOf; }
    catch (e) { out.sources.beer30.error = { plain: "Couldn't reach Beer30 for the account list; showing last upload." }; }
  }

  for (const key of ["cur", "prev", "yoy"]) {
    const r = want[key];
    if (!r) continue;
    out.periods[key] = { accounting: null, beer30: null };
    if (token) {
      try {
        out.periods[key].accounting = await xeroPnl(env, token, r.from, r.to);
      } catch (e) {
        out.sources.accounting.error = { plain: "Couldn't read the Xero P&L for this period." };
      }
    }
    try {
      let live = null;
      if (catOf) {
        try { live = await fetchBeer30Orders(env, r.from, r.to, catOf); }
        catch (e) { out.sources.beer30.error = { plain: "Live Beer30 pull failed for a period; showing last upload where available." }; }
      }
      out.periods[key].beer30 = live || await salesForRange(env, r.from, r.to);
    } catch (e) {
      out.sources.beer30.error = { plain: "Couldn't read the Beer30 sales for this period." };
    }
  }
  return json(out);
}

// ---------------------------------------------------------------------------
// Beer30 API connection test (live-API feasibility; key stays a Worker secret)
// ---------------------------------------------------------------------------
async function beer30Test(env) {
  const key = (env.BEER30_KEY || "").trim();
  if (!key)
    return json({ ok: false, error: { plain: "No Beer30 API key set yet. Add BEER30_KEY in Cloudflare > Settings > Variables and Secrets." } });
  const base = (env.BEER30_BASE || "https://api.b30.app").trim().replace(/\/+$/, "");
  try {
    const url = `${base}/base?format=json&key=${encodeURIComponent(key)}`;
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    const txt = await r.text();
    let data = null; try { data = JSON.parse(txt); } catch {}
    if (!r.ok) {
      const msg = data?.response?.message || data?.message || (txt || "").replace(/\s+/g, " ").trim().slice(0, 160);
      return json({ ok: false, status: r.status,
        error: { plain: `Beer30 replied ${r.status}. ${msg || "no message body"} [key length ${key.length}, host ${base}]` } });
    }
    const endpoints = data && Array.isArray(data.api) ? data.api.length : null;
    return json({ ok: true, status: r.status, endpoints, message: data?.response?.message || "success" });
  } catch (e) {
    return json({ ok: false, error: { plain: "Couldn't reach Beer30 (" + (e.message || "network error") + ")." } });
  }
}

// ---------------------------------------------------------------------------
// tiny response helpers
// ---------------------------------------------------------------------------
function json(obj, statusCode = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status: statusCode,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}
function html(body) {
  return new Response(body, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
