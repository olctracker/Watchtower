/* =========================================================
   Watchtower — login traffic monitor
   ========================================================= */
(() => {
"use strict";

const CFG = window.WATCH_CONFIG;
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }
};

const SITE = CFG.sites.find((s) => s.id === store.get("watch-site")) || CFG.sites[0];
const sb = window.supabase.createClient(SITE.supabaseUrl, SITE.supabaseKey, {
  // own storage key so this site's sign-in is separate from the main app's
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false, storageKey: `olc-watch-${SITE.id}` }
});

const KEEP_DAYS = 90;
const isAdmin = () => S.profile && S.profile.role === "admin";
const S = {
  profile: null,
  rows: [],
  newIds: new Set(),
  range: store.get("watch-range", "24h"),
  filter: "all",
  live: false,
  ipSel: null,
  channel: null,
  sessions: [],
  pending: 0,
  timer: null
};

/* ---------------- helpers ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const errMsg = (e) => (e && (e.message || e.error_description)) || "Something went wrong";
const key = (u) => String(u || "").toLowerCase();
const RANGES = { "24h": 864e5, "7d": 7 * 864e5, "30d": 30 * 864e5, "90d": 90 * 864e5 };
const RANGE_LABEL = { "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days", "90d": "last 90 days" };

const RESULT = {
  ok:           { cls: "ok",   label: "Signed in" },
  wrong_pin:    { cls: "warn", label: "Wrong PIN" },
  locked:       { cls: "bad",  label: "Locked out" },
  unknown_user: { cls: "bad",  label: "Unknown user" }
};

function ago(d) {
  const s = Math.floor((Date.now() - new Date(d)) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  if (s < 7 * 86400) return `${Math.round(s / 86400)}d ago`;
  return fmtDT(d);
}
const fmtDate = (d) => new Date(d).toLocaleDateString([], { month: "short", day: "numeric" });
const fmtDT = (d) => new Date(d).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

function device(ua) {
  if (!ua) return "";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
    : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "";
  const br = /Edg\//.test(ua) ? "Edge" : /SamsungBrowser/.test(ua) ? "Samsung" : /OPR\//.test(ua) ? "Opera"
    : /CriOS|Chrome\//.test(ua) ? "Chrome" : /FxiOS|Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "";
  return [os, br].filter(Boolean).join(" · ");
}

function toast(msg, bad = false) {
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : "");
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

const inRange = (r) => Date.now() - new Date(r.at) <= RANGES[S.range];
const isFail = (r) => r.result !== "ok";

/* ---------------- IP geolocation ---------------- */
const GEO_KEY = "watch-geo-v1";
const GEO_TTL = 14 * 864e5;
const geoCache = store.get(GEO_KEY, {});
const geoPending = {};
const geoTried = new Set();

function isPrivateIp(ip) {
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(::1|f[cd]|fe80)/i.test(ip);
}
const validIp = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-f:]+$/i.test(s) && s.includes(":");

async function fetchJson(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try { const r = await fetch(url, { signal: ctl.signal }); return r.ok ? await r.json() : null; }
  finally { clearTimeout(t); }
}

async function lookupGeo(ip) {
  if (!ip) return null;
  const c = geoCache[ip];
  if (c && Date.now() - c.t < GEO_TTL) return c.g;
  if (isPrivateIp(ip)) return { private: true };
  if (geoPending[ip]) return geoPending[ip];
  geoPending[ip] = (async () => {
    let g = null;
    try {
      const a = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
      if (a && a.success) g = {
        city: a.city, region: a.region, country: a.country, cc: a.country_code,
        flag: a.flag && a.flag.emoji, isp: a.connection && (a.connection.isp || a.connection.org),
        asn: a.connection && a.connection.asn, tz: a.timezone && a.timezone.id, src: "ipwho.is"
      };
    } catch {}
    if (!g) {
      try {
        const b = await fetchJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
        if (b && !b.error) g = {
          city: b.city, region: b.region, country: b.country_name, cc: b.country_code,
          flag: flagEmoji(b.country_code), isp: b.org, asn: b.asn, tz: b.timezone, src: "ipapi.co"
        };
      } catch {}
    }
    if (g) { geoCache[ip] = { t: Date.now(), g }; store.set(GEO_KEY, geoCache); }
    delete geoPending[ip];
    return g;
  })();
  return geoPending[ip];
}
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}
function geoShort(ip) {
  const c = geoCache[ip];
  if (!c) return "";
  const g = c.g;
  return [g.flag, [g.city, g.cc].filter(Boolean).join(", ")].filter(Boolean).join(" ");
}

/* ---------------- data ---------------- */
async function loadRows() {
  const since = new Date(Date.now() - KEEP_DAYS * 864e5).toISOString();
  const [{ data, error }, sess] = await Promise.all([
    sb.from("login_log").select("*").eq("site", SITE.id).gte("at", since).order("at", { ascending: false }).limit(10000),
    sb.rpc("watch_sessions")
  ]);
  if (error) throw error;
  S.rows = data || [];
  S.sessions = (sess && !sess.error && sess.data) || [];
}

/* ---------------- active devices (Supabase session records) ---------------- */
function deviceRow(d, { showUser = true } = {}) {
  const geo = d.ip ? geoShort(d.ip) : "";
  const sub = [d.ip ? `<span class="mono">${esc(d.ip)}</span>` : "no IP", geo && esc(geo), esc(device(d.user_agent))].filter(Boolean).join(" · ");
  const attrs = showUser ? `data-go="#/u/${esc(encodeURIComponent(d.username))}"` : `data-ip="${esc(d.ip || "")}"`;
  const sel = !showUser && d.ip && d.ip === S.ipSel ? "sel" : "";
  return `<button class="row ${sel}" ${attrs}>
    <div class="main">
      <div class="t1">${showUser ? `<span class="who">${esc(d.username)}</span>` : ""}<span class="tag info">Signed in ${esc(fmtDate(d.signed_in))}</span></div>
      <div class="t2">${sub}</div>
    </div>
    <div class="when" title="Last active ${esc(new Date(d.last_active).toLocaleString())}">${ago(d.last_active)}</div>
  </button>`;
}

/* ---------------- danger zone (Admin) ---------------- */
function dangerZone(buttons) {
  if (!isAdmin()) return "";
  return `<section class="card danger-zone" style="margin-top:16px">
    <div class="card-h"><h3>Clean up logs</h3></div>
    <div class="dz-b">${buttons}</div>
  </section>`;
}
async function purge(opts, confirmText, typeDelete = false) {
  if (typeDelete) {
    const t = prompt(`${confirmText}\n\nType DELETE to confirm.`);
    if ((t || "").trim().toUpperCase() !== "DELETE") { if (t !== null) toast("Nothing deleted", true); return; }
  } else if (!confirm(confirmText)) return;
  const { data, error } = await sb.rpc("watch_purge_log", opts);
  if (error) return toast(errMsg(error), true);
  toast(`Deleted ${data} log ${data === 1 ? "entry" : "entries"}`);
  try { await loadRows(); } catch {}
  render();
}

function startLive() {
  if (S.channel) return;
  S.channel = sb.channel("login_log_live")
    .on("postgres_changes", { event: "INSERT", schema: "public", table: "login_log" }, (p) => {
      const r = p.new;
      if (r && r.site === "watch" && route().view === "accounts") { renderAccounts(); return; }
      if (!r || r.site !== SITE.id || S.rows.some((x) => x.id === r.id)) return;
      S.rows.unshift(r);
      S.newIds.add(r.id);
      if (isFail(r)) toast(`${RESULT[r.result].label}: ${r.username}`, r.result !== "wrong_pin");
      render();
      if (r.ip) lookupGeo(r.ip).then(() => {
        const before = ALERTS_NOW.length;
        render();
        const a = ALERTS_NOW.find((x) => key(x.user) === key(r.username) && x.ip === r.ip);
        if (a && ALERTS_NOW.length > before) toast(`⚠ ${r.username}: new country, ${countryName(a.to)}`, true);
      });
    })
    .on("postgres_changes", { event: "*", schema: "public", table: "watch_users" }, () => {
      refreshPending();
      if (route().view === "accounts") renderAccounts();
    })
    .subscribe((status) => {
      S.live = status === "SUBSCRIBED";
      const d = $(".brand .dot");
      if (d) d.classList.toggle("live", S.live);
    });
}

function summarizeUsers(rows) {
  const m = new Map();
  for (const r of rows) {
    const k = key(r.username);
    let u = m.get(k);
    if (!u) m.set(k, u = { name: r.username, ok: 0, fail: 0, last: r.at, lastOk: null, ips: new Set(), known: r.result !== "unknown_user" });
    r.result === "ok" ? u.ok++ : u.fail++;
    if (r.result === "ok" && !u.lastOk) u.lastOk = r.at;
    if (r.ip) u.ips.add(r.ip);
    if (r.result !== "unknown_user") u.known = true;
  }
  return [...m.values()];
}

function summarizeIps(rows) {
  const m = new Map();
  for (const r of rows) {
    if (!r.ip) continue;
    let x = m.get(r.ip);
    if (!x) m.set(r.ip, x = { ip: r.ip, ok: 0, fail: 0, first: r.at, last: r.at, users: new Set(), ua: r.user_agent });
    r.result === "ok" ? x.ok++ : x.fail++;
    if (r.at < x.first) x.first = r.at;
    if (r.at > x.last) x.last = r.at;
    x.users.add(r.username);
  }
  return [...m.values()].sort((a, b) => (a.last < b.last ? 1 : -1));
}

/* ---------------- routing ---------------- */
function route() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [view, ...rest] = h.split("/");
  const arg = rest.join("/");
  if (view === "u" && arg) return { view: "user", name: arg };
  if (view === "ip" && arg) return { view: "ip", ip: arg };
  if (view === "accounts") return { view: "accounts" };
  return { view: "home" };
}
const go = (h) => { location.hash = h; };
window.addEventListener("hashchange", () => { S.ipSel = null; render(); window.scrollTo(0, 0); });

/* ---------------- shell ---------------- */
function shell(inner) {
  const sites = CFG.sites.length > 1
    ? `<select class="icon-btn" id="siteSel">${CFG.sites.map((s) =>
        `<option value="${esc(s.id)}" ${s.id === SITE.id ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select>`
    : "";
  return `
  <header class="top">
    <div class="brand"><span class="dot ${S.live ? "live" : ""}" title="Live updates"></span>Watchtower <small>· ${esc(SITE.name)}</small></div>
    <div class="sp"></div>
    ${sites}
    ${isAdmin() ? `<button class="icon-btn" data-go="#/accounts" style="position:relative">Accounts<span id="acctBadge" class="badge-n" style="${S.pending ? "" : "display:none"}">${S.pending || ""}</span></button>` : ""}
    <button class="icon-btn" id="refreshBtn" title="Refresh">⟳</button>
    <button class="icon-btn" id="outBtn">Sign out</button>
  </header>
  <main>${inner}</main>`;
}

function bindShell() {
  $("#refreshBtn").onclick = async () => {
    try { await loadRows(); render(); toast("Updated"); } catch (e) { toast(errMsg(e), true); }
  };
  $("#outBtn").onclick = async () => { await sb.auth.signOut(); location.hash = ""; renderAuth(); };
  const sel = $("#siteSel");
  if (sel) sel.onchange = () => { store.set("watch-site", sel.value); location.reload(); };
}

function render() {
  if (!S.profile) return;
  ALERTS_NOW = computeAlerts();
  const r = route();
  if (r.view === "accounts") { renderAccounts(); return; }
  if (r.view === "user") renderUser(r.name);
  else if (r.view === "ip") renderIp(r.ip);
  else renderHome();
  S.newIds.clear();
}

/* ---------------- shared pieces ---------------- */
let ALERTS_NOW = [];
function eventRow(r, { showUser = true, noLink = false } = {}) {
  const t = RESULT[r.result] || { cls: "info", label: r.result };
  const newC = r.ip && isAlertEvent(ALERTS_NOW, r.username, r.ip);
  const geo = r.ip ? geoShort(r.ip) : "";
  const sub = [r.ip ? `<span class="mono">${esc(r.ip)}</span>` : "no IP", geo && esc(geo), esc(device(r.user_agent))].filter(Boolean).join(" · ");
  const target = noLink ? "" : showUser ? `#/u/${encodeURIComponent(r.username)}` : (r.ip ? `#/ip/${encodeURIComponent(r.ip)}` : "");
  return `<button class="row ${t.cls} ${S.newIds.has(r.id) ? "new" : ""}" data-go="${esc(target)}">
    <div class="main">
      <div class="t1">${showUser ? `<span class="who">${esc(r.username)}</span>` : ""}<span class="tag ${t.cls}">${t.label}</span>${newC ? `<span class="tag bad">New country</span>` : ""}</div>
      <div class="t2">${sub}</div>
    </div>
    <div class="when" title="${esc(new Date(r.at).toLocaleString())}">${ago(r.at)}</div>
  </button>`;
}

function bindGo(root = document) {
  $$("[data-go]", root).forEach((el) => {
    el.onclick = (e) => { e.stopPropagation(); if (el.dataset.go) go(el.dataset.go); };
  });
}

function stat(n, l, cls = "") { return `<div class="stat ${cls}"><div class="n">${n}</div><div class="l">${l}</div></div>`; }

let geoBusy = false;
function warmGeo(ips) {
  // look up locations in the background (5 at a time), then refresh the view once
  if (geoBusy) return;
  const need = [...new Set(ips)].filter((ip) => ip && !geoCache[ip] && !geoTried.has(ip) && !isPrivateIp(ip));
  const budget = Math.max(0, 400 - geoTried.size);   // stay well inside the free lookup limits
  const batch = need.slice(0, budget);
  if (!batch.length) return;
  geoBusy = true;
  batch.forEach((ip) => geoTried.add(ip));
  (async () => {
    for (let i = 0; i < batch.length; i += 5) await Promise.all(batch.slice(i, i + 5).map((ip) => lookupGeo(ip)));
    geoBusy = false;
    render();
  })();
}
const allKnownIps = () => S.rows.map((r) => r.ip).concat(S.sessions.map((d) => d.ip)).filter(Boolean);

/* ---------------- country-change alerts ---------------- */
const REVIEWED_KEY = "watch-reviewed-v1";
const reviewed = new Set(store.get(REVIEWED_KEY, []));
const KIND_LABEL = { ok: "Signed in", wrong_pin: "Wrong PIN", locked: "Locked out", device: "Device active" };
const countryName = (g) => `${g.flag ? g.flag + " " : ""}${g.country || g.cc}`;

function computeAlerts() {
  // a member's "usual" countries are the ones seen before; anything new after that is an alert
  const ev = [];
  for (const r of S.rows) if (r.ip && r.result !== "unknown_user") ev.push({ u: key(r.username), name: r.username, ip: r.ip, at: r.at, kind: r.result });
  for (const d of S.sessions) if (d.ip) ev.push({ u: key(d.username), name: d.username, ip: d.ip, at: d.last_active, kind: "device" });
  ev.sort((a, b) => (a.at < b.at ? -1 : 1));
  const seen = new Map(), out = new Map();
  for (const e of ev) {
    const c = geoCache[e.ip]; const g = c && c.g;
    if (!g || g.private || !g.cc) continue;
    let st = seen.get(e.u);
    if (!st) { seen.set(e.u, st = { set: new Set(), last: null }); }
    if (st.set.size && !st.set.has(g.cc)) {
      const id = `${e.u}|${g.cc}`;
      if (!out.has(id)) out.set(id, { id, user: e.name, ip: e.ip, at: e.at, kind: e.kind, to: g, from: st.last, usual: [...st.set] });
    }
    st.set.add(g.cc); st.last = g;
  }
  return [...out.values()].sort((a, b) => (a.at < b.at ? 1 : -1));
}
const isAlertEvent = (alerts, user, ip) => alerts.some((a) => key(a.user) === key(user) && a.ip === ip);

function alertsCard(alerts, { title = "Location alerts" } = {}) {
  const open = alerts.filter((a) => !reviewed.has(a.id));
  if (!open.length) return "";
  return `<section class="card alert-card" style="margin-bottom:16px">
    <div class="card-h"><h3>⚠ ${title}</h3><div class="sp"></div><span class="tag bad">${open.length}</span></div>
    <div class="card-b">${open.map((a) => `
      <div class="row bad" style="cursor:default">
        <div class="main">
          <div class="t1"><span class="who">${esc(a.user)}</span><span class="tag bad">New country</span></div>
          <div class="t2" style="white-space:normal">${esc(countryName(a.to))}${a.from ? ` · usually ${esc(countryName(a.from))}` : ""}</div>
          <div class="t2"><span class="mono">${esc(a.ip)}</span> · ${KIND_LABEL[a.kind] || esc(a.kind)} · ${esc(fmtDT(a.at))}</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:6px">
          <button class="icon-btn" data-go="#/u/${esc(encodeURIComponent(a.user))}">Review</button>
          <button class="icon-btn" data-ok="${esc(a.id)}" title="Mark as reviewed">✓ OK</button>
        </div>
      </div>`).join("")}</div>
    <div class="note" style="padding:0 14px 12px">VPNs, travel and some mobile carriers can also cause this. "OK" hides an alert on this device.</div>
  </section>`;
}
function bindAlerts() {
  $$("[data-ok]").forEach((b) => b.onclick = () => {
    reviewed.add(b.dataset.ok); store.set(REVIEWED_KEY, [...reviewed]); render();
  });
}

/* ---------------- home ---------------- */
function renderHome() {
  const rows = S.rows.filter(inRange);
  const okRows = rows.filter((r) => r.result === "ok");
  const failRows = rows.filter(isFail);
  const users = summarizeUsers(rows).filter((u) => u.ok > 0)
    .sort((a, b) => (a.lastOk < b.lastOk ? 1 : -1));
  const feed = (S.filter === "ok" ? okRows : S.filter === "fail" ? failRows : rows).slice(0, 200);
  const ips = new Set(rows.map((r) => r.ip).filter(Boolean));
  const devices = S.sessions.filter((d) => Date.now() - new Date(d.last_active) <= RANGES[S.range]);

  const alerts = computeAlerts();
  $("#app").innerHTML = shell(`
    ${alertsCard(alerts)}
    <div class="crumb" style="justify-content:space-between">
      <span>Showing the ${RANGE_LABEL[S.range]}</span>
      <div class="seg" id="rangeSeg">${Object.keys(RANGES).map((k) =>
        `<button data-r="${k}" class="${S.range === k ? "on" : ""}">${k}</button>`).join("")}</div>
    </div>
    <div class="stats">
      ${stat(users.length, "Members signed in", "good")}
      ${stat(okRows.length, "Sign-ins")}
      ${stat(failRows.length, "Failed attempts", failRows.length ? "warn" : "")}
      ${stat(ips.size, "Different IPs")}
    </div>
    <div class="grid2">
      <section class="card">
        <div class="card-h"><h3>Traffic</h3><div class="sp"></div>
          <div class="seg" id="filterSeg">
            <button data-f="all" class="${S.filter === "all" ? "on" : ""}">All</button>
            <button data-f="ok" class="${S.filter === "ok" ? "on" : ""}">Sign-ins</button>
            <button data-f="fail" class="${S.filter === "fail" ? "on" : ""}">Warnings</button>
          </div>
        </div>
        <div class="card-b">${feed.length ? feed.map((r) => eventRow(r)).join("") : `<div class="empty">Nothing here yet</div>`}</div>
      </section>
      <section class="card first-sm">
        <div class="card-h"><h3>Signed in</h3><div class="sp"></div><span class="faint">${users.length}</span></div>
        <div class="card-b">${users.length ? users.map((u) => `
          <button class="row" data-go="#/u/${esc(encodeURIComponent(u.name))}">
            <div class="avatar">${esc(u.name.slice(0, 2).toUpperCase())}</div>
            <div class="main">
              <div class="t1"><span class="who">${esc(u.name)}</span>${u.fail ? `<span class="tag warn">${u.fail} failed</span>` : ""}</div>
              <div class="t2">${u.ok} sign-in${u.ok === 1 ? "" : "s"} · ${u.ips.size} IP${u.ips.size === 1 ? "" : "s"}</div>
            </div>
            <div class="when">${ago(u.lastOk)}</div>
          </button>`).join("") : `<div class="empty">No one has signed in during this time</div>`}</div>
      </section>
    </div>
    <section class="card" style="margin-top:16px">
      <div class="card-h"><h3>Failed logins</h3><div class="sp"></div><span class="faint">${failRows.length}</span></div>
      ${failRows.length ? `<div class="tbl-wrap"><table>
        <thead><tr><th>When</th><th>Username tried</th><th>Result</th><th>IP</th><th class="hide-sm">Location</th><th class="hide-sm">Device</th></tr></thead>
        <tbody>${failRows.slice(0, 300).map((r) => `
          <tr data-go="${r.ip ? `#/ip/${esc(encodeURIComponent(r.ip))}` : `#/u/${esc(encodeURIComponent(r.username))}`}">
            <td>${esc(fmtDT(r.at))}</td>
            <td><b>${esc(r.username)}</b></td>
            <td><span class="tag ${RESULT[r.result].cls}">${RESULT[r.result].label}</span></td>
            <td class="mono">${esc(r.ip || "—")}</td>
            <td class="hide-sm">${esc(r.ip ? geoShort(r.ip) : "")}</td>
            <td class="hide-sm dim">${esc(device(r.user_agent))}</td>
          </tr>`).join("")}</tbody></table></div>` : `<div class="empty">No failed logins 👍</div>`}
    </section>
    <section class="card" style="margin-top:16px">
      <div class="card-h"><h3>Active devices</h3><div class="sp"></div><span class="faint">${devices.length}</span></div>
      <div class="note" style="padding:0 14px;margin-top:10px">Devices still signed in, including installed apps. "Last active" updates when the app is opened, about once an hour at most.</div>
      <div class="card-b">${devices.length ? devices.slice(0, 150).map((d) => deviceRow(d)).join("") : `<div class="empty">No devices active in this time</div>`}</div>
    </section>
    ${dangerZone(`
      <button class="dz-btn" id="purgeOld">Delete logs older than 90 days</button>
      <button class="dz-btn bad" id="purgeAll">Delete all logs</button>`)}`);

  bindShell();
  bindGo();
  $$("#rangeSeg button").forEach((b) => b.onclick = () => { S.range = b.dataset.r; store.set("watch-range", S.range); render(); });
  $$("#filterSeg button").forEach((b) => b.onclick = () => { S.filter = b.dataset.f; render(); });
  const po = $("#purgeOld"), pa = $("#purgeAll");
  if (po) po.onclick = () => purge({ p_older_than_days: 90 }, "Delete every log entry older than 90 days? This can't be undone.");
  if (pa) pa.onclick = () => purge({}, "Delete ALL login logs for every member? This can't be undone.", true);
  bindAlerts();
  warmGeo(allKnownIps());
}

/* ---------------- user ---------------- */
function renderUser(name) {
  const rows = S.rows.filter((r) => key(r.username) === key(name));
  const ips = summarizeIps(rows);
  const okN = rows.filter((r) => r.result === "ok").length;
  const failN = rows.length - okN;
  const lastOk = rows.find((r) => r.result === "ok");
  const devs = S.sessions.filter((d) => key(d.username) === key(name));
  const display = rows[0] ? rows[0].username : devs[0] ? devs[0].username : name;
  const allIps = ips.map((x) => x.ip).concat(devs.map((d) => d.ip)).filter(Boolean);
  if (!S.ipSel || !allIps.includes(S.ipSel)) S.ipSel = (devs[0] && devs[0].ip) || (ips[0] && ips[0].ip) || null;

  $("#app").innerHTML = shell(`
    <div class="crumb"><button data-go="#/">← Traffic</button></div>
    ${alertsCard(ALERTS_NOW.filter((a) => key(a.user) === key(name)), { title: "Location alerts for this member" })}
    <h2>${esc(display)}</h2>
    <p class="dim" style="margin:0 0 14px">${lastOk ? `Last signed in ${ago(lastOk.at)}` : "No successful sign-ins recorded"} · last ${KEEP_DAYS} days</p>
    <div class="stats">
      ${stat(okN, "Sign-ins", "good")}
      ${stat(failN, "Failed attempts", failN ? "warn" : "")}
      ${stat(ips.length, "IPs used")}
      ${stat(new Set(ips.map((x) => (geoCache[x.ip] && geoCache[x.ip].g.cc) || null).filter(Boolean)).size || "—", "Countries")}
    </div>
    <div class="grid2">
      <div>
        <section class="card" style="margin-bottom:16px">
          <div class="card-h"><h3>Devices signed in</h3><div class="sp"></div><span class="faint">${devs.length}</span></div>
          <div class="card-b">${devs.length ? devs.map((d) => deviceRow(d, { showUser: false })).join("") : `<div class="empty">Not signed in on any device</div>`}</div>
        </section>
        <section class="card">
          <div class="card-h"><h3>Stored IPs</h3><div class="sp"></div><span class="faint">${ips.length}</span></div>
          <div class="card-b">${ips.length ? ips.map((x) => `
            <button class="row ${x.ip === S.ipSel ? "sel" : ""}" data-ip="${esc(x.ip)}">
              <div class="main">
                <div class="t1"><span class="who mono">${esc(x.ip)}</span>${x.fail ? `<span class="tag warn">${x.fail} failed</span>` : ""}${x.users.size > 1 ? `<span class="tag info">shared</span>` : ""}</div>
                <div class="t2">${esc(geoShort(x.ip) || "…")} · ${x.ok} sign-in${x.ok === 1 ? "" : "s"} · first ${esc(fmtDT(x.first))}</div>
              </div>
              <div class="when">${ago(x.last)}</div>
            </button>`).join("") : `<div class="empty">No IPs recorded</div>`}</div>
        </section>
        <section class="card" style="margin-top:16px">
          <div class="card-h"><h3>Activity</h3></div>
          <div class="card-b">${rows.length ? rows.slice(0, 100).map((r) => eventRow(r, { showUser: false })).join("") : `<div class="empty">No activity</div>`}</div>
        </section>
      </div>
      <div class="sticky">${ipPanelShell(S.ipSel)}</div>
    </div>
    ${dangerZone(`<button class="dz-btn bad" id="purgeUser">Delete all of ${esc(display)}'s logs</button>`)}`);

  bindShell();
  bindGo();
  bindAlerts();
  const pu = $("#purgeUser");
  if (pu) pu.onclick = () => purge({ p_username: display }, `Delete all of ${display}'s login logs? This can't be undone. (Their account isn't affected.)`);
  $$("[data-ip]").forEach((b) => b.onclick = () => {
    S.ipSel = b.dataset.ip;
    $$("[data-ip]").forEach((x) => x.classList.toggle("sel", x === b));
    showIp(S.ipSel);
    if (window.innerWidth <= 820) $("#ipPanel").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  bindIpSearch();
  showIp(S.ipSel);
  warmGeo(allKnownIps());
}

/* ---------------- IP page ---------------- */
function renderIp(ip) {
  const rows = S.rows.filter((r) => r.ip === ip);
  $("#app").innerHTML = shell(`
    <div class="crumb"><button data-go="#/">← Traffic</button></div>
    <h2 class="mono">${esc(ip)}</h2>
    <p class="dim" style="margin:0 0 14px">${rows.length} attempt${rows.length === 1 ? "" : "s"} from this IP · last ${KEEP_DAYS} days</p>
    <div class="grid2">
      <section class="card">
        <div class="card-h"><h3>Activity from this IP</h3></div>
        <div class="card-b">${rows.length ? rows.slice(0, 200).map((r) => eventRow(r)).join("") : `<div class="empty">No logins recorded from this IP</div>`}</div>
      </section>
      <div class="sticky">${ipPanelShell(ip)}</div>
    </div>`);
  bindShell();
  bindGo();
  bindIpSearch();
  showIp(ip);
}

/* ---------------- IP lookup panel ---------------- */
function ipPanelShell(ip) {
  return `<section class="card" id="ipPanel">
    <div class="card-h"><h3>IP lookup</h3></div>
    <form class="search" id="ipForm">
      <input class="input mono" name="ip" placeholder="Search any IP" value="${esc(ip || "")}" autocomplete="off" inputmode="decimal">
      <button class="btn" type="submit">Look up</button>
    </form>
    <div id="geoBox"><div class="empty">Pick an IP to see where it is</div></div>
  </section>`;
}

function bindIpSearch() {
  const f = $("#ipForm");
  if (!f) return;
  f.onsubmit = (e) => {
    e.preventDefault();
    const ip = f.ip.value.trim();
    if (!validIp(ip)) return toast("That doesn't look like an IP address", true);
    S.ipSel = ip;
    $$("[data-ip]").forEach((x) => x.classList.toggle("sel", x.dataset.ip === ip));
    showIp(ip);
  };
}

async function showIp(ip) {
  const box = $("#geoBox");
  if (!box) return;
  if (!ip) { box.innerHTML = `<div class="empty">Pick an IP to see where it is</div>`; return; }
  const input = $("#ipForm input");
  if (input) input.value = ip;
  box.innerHTML = `<div class="loading">Looking up ${esc(ip)}…</div>`;
  const g = await lookupGeo(ip);
  if (S.ipSel !== ip && route().view !== "ip") return; // user picked another IP meanwhile
  const here = S.rows.filter((r) => r.ip === ip);
  const users = [...new Set(here.map((r) => r.username).concat(S.sessions.filter((d) => d.ip === ip).map((d) => d.username)))];
  const okN = here.filter((r) => r.result === "ok").length;

  let geoHtml;
  if (!g) geoHtml = `<div class="place dim">Location unavailable</div><div class="note">The lookup service didn't answer. Try again in a bit.</div>`;
  else if (g.private) geoHtml = `<div class="place dim">Private / local network address</div>`;
  else geoHtml = `
    <div class="place">${g.flag ? `<span class="flag">${g.flag}</span>` : ""}${esc([g.city, g.region].filter(Boolean).join(", ") || "Unknown city")}</div>
    <dl class="kv">
      <dt>Country</dt><dd>${esc(g.country || "—")}</dd>
      <dt>ISP</dt><dd>${esc(g.isp || "—")}</dd>
      ${g.asn ? `<dt>ASN</dt><dd>${esc(g.asn)}</dd>` : ""}
      ${g.tz ? `<dt>Time zone</dt><dd>${esc(g.tz)}</dd>` : ""}
    </dl>`;

  box.innerHTML = `<div class="geo">
    <div class="ip">${esc(ip)}</div>
    ${geoHtml}
    ${here.length || users.length ? `
      <dl class="kv" style="margin-top:12px">
        <dt>Attempts</dt><dd>${here.length} (${okN} ok, ${here.length - okN} failed)</dd>
        ${here.length ? `<dt>First seen</dt><dd>${esc(fmtDT(here[here.length - 1].at))}</dd>
        <dt>Last seen</dt><dd>${esc(fmtDT(here[0].at))}</dd>` : ""}
      </dl>
      <div class="users-on-ip">${users.map((u) => `<button class="chip" data-go="#/u/${esc(encodeURIComponent(u))}">${esc(u)}</button>`).join("")}</div>
      ${users.length > 1 ? `<div class="note">More than one account has used this IP. That can be normal (same house, school or mobile carrier) or a sign of alt accounts.</div>` : ""}
      ${route().view !== "ip" ? `<div class="note"><a href="#/ip/${esc(encodeURIComponent(ip))}">See all activity from this IP →</a></div>` : ""}`
    : `<div class="note">No logins recorded from this IP.</div>`}
    <div class="note">Locations are approximate. The country is usually right; the city is often a nearby hub, and VPNs or mobile data can show somewhere else entirely.${g && g.src ? ` Source: ${esc(g.src)}.` : ""}</div>
  </div>`;
  bindGo(box);
}

/* ---------------- accounts (admin) ---------------- */
async function renderAccounts() {
  if (!isAdmin()) return go("#/");
  $("#app").innerHTML = shell(`<div class="loading">Loading accounts…</div>`);
  bindShell();
  const since = new Date(Date.now() - 30 * 864e5).toISOString();
  const [{ data: users, error }, { data: wlog }] = await Promise.all([
    sb.from("watch_users").select("*").order("created_at"),
    sb.from("login_log").select("*").eq("site", "watch").gte("at", since).order("at", { ascending: false }).limit(200)
  ]);
  if (route().view !== "accounts") return;
  if (error) { $("main").innerHTML = `<div class="card"><div class="empty">${esc(errMsg(error))}</div></div>`; return; }
  S.pending = users.filter((u) => !u.approved).length;
  const pending = users.filter((u) => !u.approved);
  const active = users.filter((u) => u.approved);
  const acctRow = (u) => `
    <div class="row" style="cursor:default">
      <div class="avatar">${esc(u.username.slice(0, 2).toUpperCase())}</div>
      <div class="main">
        <div class="t1"><span class="who">${esc(u.username)}</span>${u.role === "admin" ? `<span class="tag info">Admin</span>` : ""}${!u.approved ? `<span class="tag warn">Pending</span>` : ""}</div>
        <div class="t2">Created ${esc(fmtDT(u.created_at))}</div>
      </div>
      ${u.id === S.profile.id ? `<span class="faint" style="font-size:12px">You</span>` : `
        ${!u.approved ? `<button class="btn" data-approve="${esc(u.id)}" style="padding:6px 12px">Approve</button>` : ""}
        <button class="icon-btn" data-del="${esc(u.id)}" data-name="${esc(u.username)}" data-pending="${u.approved ? "" : "1"}" style="color:var(--danger)">${u.approved ? "Delete" : "Reject"}</button>`}
    </div>`;

  $("main").innerHTML = `
    <div class="crumb"><button data-go="#/">← Traffic</button></div>
    <h2>Accounts</h2>
    <p class="dim" style="margin:0 0 14px">New accounts can't see anything until you approve them.</p>
    <div class="grid2">
      <div>
        <section class="card">
          <div class="card-h"><h3>Waiting for approval</h3><div class="sp"></div><span class="faint">${pending.length}</span></div>
          <div class="card-b">${pending.length ? pending.map(acctRow).join("") : `<div class="empty">No one is waiting</div>`}</div>
        </section>
        <section class="card" style="margin-top:16px">
          <div class="card-h"><h3>Approved</h3><div class="sp"></div><span class="faint">${active.length}</span></div>
          <div class="card-b">${active.map(acctRow).join("")}</div>
        </section>
      </div>
      <section class="card">
        <div class="card-h"><h3>Sign-ins to Watchtower</h3><div class="sp"></div><span class="faint">30 days</span></div>
        <div class="card-b">${(wlog || []).length ? wlog.map((r) => eventRow(r, { showUser: true, noLink: true })).join("") : `<div class="empty">None yet</div>`}</div>
      </section>
    </div>`;
  bindGo();
  updateAcctBadge();
  $$("[data-approve]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    const { error } = await sb.rpc("watch_approve", { p_id: b.dataset.approve });
    if (error) { toast(errMsg(error), true); b.disabled = false; return; }
    toast("Approved");
    renderAccounts();
  });
  $$("[data-del]").forEach((b) => b.onclick = async () => {
    const pend = !!b.dataset.pending;
    if (!confirm(pend ? `Reject ${b.dataset.name}'s sign-up?` : `Delete ${b.dataset.name}'s account? They will lose access right away. This can't be undone.`)) return;
    b.disabled = true;
    const { error } = await sb.rpc("watch_delete", { p_id: b.dataset.del });
    if (error) { toast(errMsg(error), true); b.disabled = false; return; }
    toast(pend ? "Sign-up rejected" : "Account deleted");
    renderAccounts();
  });
}

async function refreshPending() {
  if (!isAdmin()) return;
  const { count } = await sb.from("watch_users").select("id", { count: "exact", head: true }).eq("approved", false);
  S.pending = count || 0;
  updateAcctBadge();
}
function updateAcctBadge() {
  const b = $("#acctBadge");
  if (b) { b.textContent = S.pending || ""; b.style.display = S.pending ? "" : "none"; }
}

/* ---------------- sign in / create account ---------------- */
const PIN_LEN = 10;
const pinInput = (name, ac) => `<input class="input mono" name="${name}" type="password" inputmode="numeric" pattern="[0-9]*"
  maxlength="${PIN_LEN}" autocomplete="${ac}" placeholder="${"•".repeat(PIN_LEN)}" required>`;

function renderAuth(msg = "", mode = "login") {
  $("#app").innerHTML = `
    <div class="auth"><div class="card">
      <h1>Watchtower</h1>
      <p>${mode === "login" ? "Sign in to your Watch account" : "New accounts need the admin's approval"}</p>
      <div class="seg" style="margin-bottom:16px;display:flex">
        <button data-mode="login" class="${mode === "login" ? "on" : ""}" style="flex:1">Sign in</button>
        <button data-mode="signup" class="${mode === "signup" ? "on" : ""}" style="flex:1">Create account</button>
      </div>
      <form id="authForm">
        <label class="f"><span>Username</span>
          <input class="input" name="u" autocomplete="username" autocapitalize="off" spellcheck="false" maxlength="20" required></label>
        <label class="f"><span>${PIN_LEN}-digit PIN</span>${pinInput("p", mode === "login" ? "current-password" : "new-password")}</label>
        ${mode === "signup" ? `<label class="f"><span>Confirm PIN</span>${pinInput("p2", "new-password")}</label>` : ""}
        <div class="err" id="authErr">${esc(msg)}</div>
        <button class="btn block" type="submit">${mode === "login" ? "Sign in" : "Create account"}</button>
      </form>
    </div></div>`;
  $$("[data-mode]").forEach((b) => b.onclick = () => renderAuth("", b.dataset.mode));
  const pinRe = new RegExp(`^\\d{${PIN_LEN}}$`);
  $("#authForm").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target, err = $("#authErr"), btn = $("button[type=submit]", f);
    const u = f.u.value.trim(), p = f.p.value;
    err.textContent = "";
    if (!pinRe.test(p)) return (err.textContent = `PIN must be ${PIN_LEN} digits`);
    if (mode === "signup" && p !== f.p2.value) return (err.textContent = "PINs don't match");
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = "One moment…";
    try {
      if (mode === "signup") {
        const { error } = await sb.rpc("watch_signup", { p_username: u, p_pin: p });
        if (error) { err.textContent = errMsg(error); return; }
      } else {
        const { data: locked } = await sb.rpc("watch_login_check", { p_username: u });
        if (locked > 0) { err.textContent = `Too many wrong PINs. Try again in ${Math.ceil(locked / 60)} min.`; return; }
      }
      const { error } = await sb.auth.signInWithPassword({ email: SITE.emailFor(u), password: SITE.pwFor(p) });
      if (error) {
        if (mode === "signup") { renderAuth("Account created. Sign in to continue."); return; }
        const { data: left } = await sb.rpc("watch_login_failed", { p_username: u });
        err.textContent = left > 0 ? `Wrong username or PIN. ${left} ${left === 1 ? "try" : "tries"} left.` : "Too many wrong PINs. Locked for 15 minutes.";
        return;
      }
      await sb.rpc("watch_login_ok");
      await enter();
    } catch (ex) { err.textContent = errMsg(ex); }
    finally { btn.disabled = false; btn.textContent = label; }
  };
}

function renderPending(name) {
  $("#app").innerHTML = `
    <div class="auth"><div class="card">
      <h1>Waiting for approval</h1>
      <p>Hi ${esc(name)}, your account was created. The admin needs to approve it before you can see anything. Check back later.</p>
      <button class="btn block" id="chkBtn">Check again</button>
      <button class="icon-btn" id="outBtn" style="width:100%;margin-top:10px">Sign out</button>
    </div></div>`;
  $("#chkBtn").onclick = () => enter();
  $("#outBtn").onclick = async () => { await sb.auth.signOut(); renderAuth(); };
}

async function enter() {
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return renderAuth();
  const { data: me } = await sb.from("watch_users").select("id, username, role, approved").eq("id", user.id).maybeSingle();
  if (!me) {
    await sb.auth.signOut();
    return renderAuth("That isn't a Watch account.");
  }
  if (!me.approved) return renderPending(me.username);
  S.profile = me;
  $("#app").innerHTML = `<div class="loading">Loading traffic…</div>`;
  try { await loadRows(); }
  catch (e) {
    $("#app").innerHTML = shell(`<div class="card"><div class="empty">Couldn't load the login log: ${esc(errMsg(e))}</div></div>`);
    bindShell();
    return;
  }
  render();
  startLive();
  refreshPending();
  if (S.timer) clearInterval(S.timer);
  // keep "x min ago" fresh and catch anything realtime missed
  S.timer = setInterval(async () => {
    if (document.hidden || route().view === "accounts") return;
    try { await loadRows(); render(); refreshPending(); } catch {}
  }, 120000);
}

/* ---------------- boot ---------------- */
(async () => {
  const { data } = await sb.auth.getSession();
  data.session ? enter() : renderAuth();
})();

})();
