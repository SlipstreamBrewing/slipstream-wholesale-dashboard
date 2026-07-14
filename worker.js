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
// the implemented money metrics need. Invoice-count metrics (active accounts,
// AOV) will add the granular invoices read scope when that pull is wired.
const XERO_SCOPES = "offline_access accounting.reports.profitandloss.read";

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
// Beer30 volume (export/ingest mode; live API pull slots in the same shape)
// ---------------------------------------------------------------------------
async function volumeForRange(env, from, to) {
  // Reads day rows written by /api/ingest: data:volume:<YYYY-MM-DD> = {litresKeg,litresPackage}
  const list = await env.TOKENS.list({ prefix: "data:volume:" });
  let litres = 0, keg = 0, pkg = 0, any = false;
  for (const k of list.keys) {
    const day = k.name.slice("data:volume:".length);
    if (day >= from && day <= to) {
      const row = await env.TOKENS.get(k.name, "json");
      if (row) { any = true; keg += row.litresKeg || 0; pkg += row.litresPackage || 0; }
    }
  }
  litres = keg + pkg;
  return any ? { litres, channels: { keg, package: pkg } } : null;
}
async function handleIngest(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!env.INGEST_TOKEN || auth !== `Bearer ${env.INGEST_TOKEN}`)
    return json({ error: { plain: "Upload code missing or wrong." } }, 401);
  const url = new URL(request.url);
  const source = url.searchParams.get("source") || "volume";
  const text = await request.text();
  if (source !== "volume") return json({ error: { plain: "Unknown upload type." } }, 400);
  const rows = parseVolumeExport(text);
  for (const r of rows) {
    await env.TOKENS.put(`data:volume:${r.date}`,
      JSON.stringify({ litresKeg: r.litresKeg, litresPackage: r.litresPackage }));
  }
  await env.TOKENS.put("data:volume:lastSync", new Date().toISOString());
  return json({ ok: true, days: rows.length });
}
// Beer30 CSV export → day rows. Expected headers (case-insensitive):
// date, keg_litres, package_litres  (adjust to the real export at wiring time).
function parseVolumeExport(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const head = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const di = head.findIndex((h) => h.includes("date"));
  const ki = head.findIndex((h) => h.includes("keg"));
  const pi = head.findIndex((h) => h.includes("package") || h.includes("packaged") || h.includes("can"));
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const c = lines[i].split(",");
    if (!c[di]) continue;
    const date = normDate(c[di].trim());
    if (!date) continue;
    out.push({
      date,
      litresKeg: parseFloat(c[ki]) || 0,
      litresPackage: parseFloat(c[pi]) || 0,
    });
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
// Status + metrics API (the agreed contract)
// ---------------------------------------------------------------------------
async function status(env) {
  const xt = await env.TOKENS.get("xero:tokens", "json");
  const vSync = await env.TOKENS.get("data:volume:lastSync");
  return json({
    sources: {
      accounting: {
        configured: !!env.XERO_CLIENT_ID,
        connected: !!xt,
        org: xt?.tenant_name || null,
        sandbox: /demo company/i.test(xt?.tenant_name || ""),
      },
      volume: { configured: true, connected: !!vSync, source: "Beer30", lastSync: vSync || null },
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
  const vSync = await env.TOKENS.get("data:volume:lastSync");
  out.sources.volume = {
    configured: true, connected: !!vSync, source: "Beer30",
    lastSync: vSync || null, error: null,
  };

  for (const key of ["cur", "prev", "yoy"]) {
    const r = want[key];
    if (!r) continue;
    out.periods[key] = { accounting: null, volume: null };
    if (token) {
      try {
        out.periods[key].accounting = await xeroPnl(env, token, r.from, r.to);
      } catch (e) {
        out.sources.accounting.error = { plain: "Couldn't read the Xero P&L for this period." };
      }
    }
    try {
      out.periods[key].volume = await volumeForRange(env, r.from, r.to);
    } catch (e) {
      out.sources.volume.error = { plain: "Couldn't read the Beer30 volume for this period." };
    }
  }
  return json(out);
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
