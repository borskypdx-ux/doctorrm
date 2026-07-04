/* DoctorRM — hlavní aplikace */
"use strict";

const VPL = "všeobecné praktické lékařství";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const nowYear = new Date().getFullYear();

let DATA = null;          // dešifrovaný payload
let GP_KMEN_SORTED = [];  // pro percentil
let OLD_GPS = [];         // lékaři 63+ se souřadnicemi (pro shlukový bonus)
let EDITS = loadJSON("drm_edits_v1", {});
let WEIGHTS = loadJSON("drm_weights_v1", { age: 50, kmen: 30, lf: 10, vp: 10 });
let FILTER = { text: "", obory: new Set([VPL]), kraj: "", okres: "", obec: "", vekMin: null, vekMax: null, vekUnknown: true };
let SORT = { key: "score", dir: -1 };
let filtered = [];
let map, clusterLayer, obceLayer, vpLayer, lfLayer;
let mapDirty = true;

function loadJSON(k, dflt) { try { return JSON.parse(localStorage.getItem(k)) ?? dflt; } catch { return dflt; } }
function saveJSON(k, v) { localStorage.setItem(k, JSON.stringify(v)); }
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function norm(s) { return String(s ?? "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, ""); }
function distKm(la1, lo1, la2, lo2) {
  const dy = (la2 - la1) * 111.32, dx = (lo2 - lo1) * 111.32 * Math.cos((la1 + la2) / 2 * Math.PI / 180);
  return Math.sqrt(dx * dx + dy * dy);
}

/* ================= AUTH / DEŠIFROVÁNÍ ================= */
async function decryptPayload(password, buf) {
  const b = new Uint8Array(buf);
  if (String.fromCharCode(...b.slice(0, 4)) !== "DRM1") throw new Error("Neplatný datový soubor");
  const salt = b.slice(4, 20), iv = b.slice(20, 32), ct = b.slice(32);
  const keyMat = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    keyMat, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const gz = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([gz]).stream().pipeThrough(ds);
  const text = await new Response(stream).text();
  return JSON.parse(text);
}

async function tryUnlock(password, silent) {
  const prog = $("#pwProgress"), err = $("#pwErr");
  err.textContent = "";
  prog.textContent = "Stahuji data…";
  try {
    if (!window.__encBuf) {
      const resp = await fetch("data/data.enc", { cache: "no-cache" });
      if (!resp.ok) throw new Error("Nelze stáhnout data (" + resp.status + ")");
      window.__encBuf = await resp.arrayBuffer();
    }
    prog.textContent = "Dešifruji…";
    DATA = await decryptPayload(password, window.__encBuf);
    if ($("#pwRemember").checked) localStorage.setItem("drm_pw", password);
    sessionStorage.setItem("drm_pw", password);
    prog.textContent = "";
    initApp();
  } catch (e) {
    prog.textContent = "";
    if (!silent) err.textContent = e.name === "OperationError" ? "Špatné heslo." : ("Chyba: " + e.message);
    console.warn(e);
  }
}

/* ================= ODVOZENÉ HODNOTY ================= */
function recEdit(r) { return EDITS[r.id] || {}; }
function recPromoce(r) { const e = recEdit(r); return e.promoce ?? r.promoce ?? null; }
// zdroj věku podle priority: ruční > ARES (skutečný rok narození) > odhad z promoce
function recNarozeni(r) {
  const e = recEdit(r);
  if (e.vek != null) return nowYear - e.vek;
  if (e.promoce != null) return e.promoce - DATA.meta.promoceAge;
  if (r.birth != null) return r.birth;                 // ARES — skutečný rok narození
  const p = r.promoce; return p ? p - DATA.meta.promoceAge : null;
}
function recVek(r) { const n = recNarozeni(r); return n != null ? nowYear - n : null; }
function vekSrc(r) {
  const e = recEdit(r);
  if (e.vek != null || e.promoce != null) return "ručně";
  if (r.birth != null) return "ARES (rok narození)";
  if (r.promoce != null) return "odhad z promoce ČLK";
  return null;
}
function kmenPercentile(k) {
  if (k == null || !GP_KMEN_SORTED.length) return 0;
  let lo = 0, hi = GP_KMEN_SORTED.length;
  while (lo < hi) { const m = (lo + hi) >> 1; if (GP_KMEN_SORTED[m] <= k) lo = m + 1; else hi = m; }
  return lo / GP_KMEN_SORTED.length;
}
function minDist(r, pts) {
  if (r.lat == null) return null;
  let best = 1e9;
  for (const p of pts) { const d = distKm(r.lat, r.lon, p.lat, p.lon); if (d < best) best = d; }
  return best;
}
function neighbours63(r) {
  if (r.lat == null) return 0;
  let n = 0;
  for (const o of OLD_GPS) {
    if (o.id === r.id) continue;
    if (Math.abs(o.lat - r.lat) > 0.04 || Math.abs(o.lon - r.lon) > 0.06) continue;
    if (distKm(r.lat, r.lon, o.lat, o.lon) <= 3) n++;
  }
  return n;
}
function scoreComponents(r) {
  if (!r.gp) return null;
  const vek = recVek(r);
  let age;
  if (vek == null) age = 0.35;
  else if (vek >= 63) age = Math.min(0.75 + 0.125 * neighbours63(r), 1);
  else age = Math.max(0, Math.min((vek - 50) / 13, 1)) * 0.6;
  const kmen = kmenPercentile(r.kmen);
  const dLf = minDist(r, DATA.lf), dVp = minDist(r, DATA.vp);
  const lf = dLf == null ? 0 : Math.exp(-dLf / 40);
  const vp = dVp == null ? 0 : Math.exp(-dVp / 30);
  const W = WEIGHTS, tot = (W.age + W.kmen + W.lf + W.vp) || 1;
  const score = 100 * (W.age * age + W.kmen * kmen + W.lf * lf + W.vp * vp) / tot;
  return { score, age, kmen, lf, vp, vek };
}
const scoreCache = new Map();
function recScore(r) {
  if (!r.gp) return null;
  let c = scoreCache.get(r.id);
  if (!c) { c = scoreComponents(r); scoreCache.set(r.id, c); }
  return c;
}
function invalidateScores() { scoreCache.clear(); rebuildOldGps(); }
function rebuildOldGps() {
  OLD_GPS = DATA.records.filter((r) => r.gp && r.lat != null && recVek(r) != null && recVek(r) >= 63)
    .map((r) => ({ id: r.id, lat: r.lat, lon: r.lon }));
}

/* ================= SLOUPCE ================= */
const COLUMNS = [
  { key: "score",   label: "Score",       on: 1, get: (r) => { const s = recScore(r); return s ? Math.round(s.score) : null; },
    fmt: (v) => v == null ? "" : `<span class="score-badge" style="background:${scoreColor(v)}">${v}</span>` },
  { key: "nazev",   label: "Název",       on: 1, get: (r) => r.nazev },
  { key: "doctor",  label: "Lékař / odb. zástupce", on: 1, get: (r) => r.doctor || r.oz || "" },
  { key: "vek",     label: "Věk",         on: 1, get: (r) => recVek(r),
    fmt: (v) => v == null ? '<span class="muted">?</span>' : `<span class="${v >= 63 ? "age-red" : v >= 55 ? "age-orange" : ""}">${v}</span>` },
  { key: "narozeni",label: "Rok narození",on: 0, get: (r) => recNarozeni(r) },
  { key: "promoce", label: "Promoce",     on: 1, get: (r) => recPromoce(r) },
  { key: "kmen",    label: "Potenc. kmen",on: 1, get: (r) => r.kmen, fmt: (v) => v == null ? "" : v.toLocaleString("cs") },
  { key: "stav",    label: "Stav",        on: 1, get: (r) => recEdit(r).stav || "" },
  { key: "obec",    label: "Město/obec",  on: 1, get: (r) => r.obec },
  { key: "okres",   label: "Okres",       on: 1, get: (r) => r.okres },
  { key: "kraj",    label: "Kraj",        on: 0, get: (r) => r.kraj },
  { key: "ulice",   label: "Adresa",      on: 1, get: (r) => r.ulice },
  { key: "psc",     label: "PSČ",         on: 0, get: (r) => r.psc },
  { key: "obory",   label: "Obory",       on: 0, get: (r) => r.obory.join(", ") },
  { key: "druh",    label: "Druh zařízení", on: 0, get: (r) => r.druh },
  { key: "typ",     label: "FO/PO",       on: 0, get: (r) => r.typ },
  { key: "ico",     label: "IČO",         on: 0, get: (r) => r.ico },
  { key: "tel",     label: "Telefon",     on: 1, get: (r) => r.tel },
  { key: "email",   label: "E-mail",      on: 0, get: (r) => r.email },
  { key: "web",     label: "Web",         on: 0, get: (r) => r.web },
  { key: "zahajeni",label: "Zahájení činnosti", on: 0, get: (r) => r.zahajeni },
  { key: "pozn",    label: "Poznámka",    on: 1, get: (r) => recEdit(r).pozn || "" },
];
let visibleCols = loadJSON("drm_cols_v1", null) || COLUMNS.filter((c) => c.on).map((c) => c.key);
function scoreColor(v) { return v >= 70 ? "#c0392b" : v >= 50 ? "#d97e12" : v >= 30 ? "#2a9d8f" : "#8a949e"; }

/* ================= FILTRY ================= */
function applyFilters() {
  const t = norm(FILTER.text);
  filtered = DATA.records.filter((r) => {
    if (FILTER.obory.size && !r.obory.some((o) => FILTER.obory.has(o))) return false;
    if (FILTER.kraj && r.kraj !== FILTER.kraj) return false;
    if (FILTER.okres && r.okres !== FILTER.okres) return false;
    if (FILTER.obec && norm(r.obec) !== norm(FILTER.obec) && !norm(r.obec).startsWith(norm(FILTER.obec))) return false;
    if (FILTER.vekMin != null || FILTER.vekMax != null) {
      const v = recVek(r);
      if (v == null) { if (!FILTER.vekUnknown) return false; }
      else if ((FILTER.vekMin != null && v < FILTER.vekMin) || (FILTER.vekMax != null && v > FILTER.vekMax)) return false;
    }
    if (t) {
      const hay = norm(r.nazev + " " + (r.doctor || "") + " " + (r.oz || "") + " " + r.obec + " " + r.ico + " " + (recEdit(r).pozn || ""));
      if (!hay.includes(t)) return false;
    }
    return true;
  });
  sortFiltered();
  $("#countInfo").textContent = filtered.length.toLocaleString("cs") + " záznamů";
  renderTable();
  mapDirty = true;
  if (!$("#tab-map").classList.contains("hidden")) renderMap();
  renderScoreTab();
}
function sortFiltered() {
  const col = COLUMNS.find((c) => c.key === SORT.key);
  if (!col) return;
  filtered.sort((a, b) => {
    const va = col.get(a), vb = col.get(b);
    if (va == null && vb == null) return 0;
    if (va == null) return 1;
    if (vb == null) return -1;
    return (typeof va === "number" ? va - vb : String(va).localeCompare(String(vb), "cs")) * SORT.dir;
  });
}

/* ================= TABULKA (virtuální scroll) ================= */
const ROW_H = 31;
function renderTable() {
  const cols = COLUMNS.filter((c) => visibleCols.includes(c.key));
  $("#grid thead").innerHTML = "<tr>" + cols.map((c) =>
    `<th data-k="${c.key}">${c.label}${SORT.key === c.key ? (SORT.dir > 0 ? " ▲" : " ▼") : ""}</th>`).join("") + "</tr>";
  renderRows();
}
function renderRows() {
  const wrap = $("#tableWrap");
  const cols = COLUMNS.filter((c) => visibleCols.includes(c.key));
  const start = Math.max(0, Math.floor(wrap.scrollTop / ROW_H) - 10);
  const end = Math.min(filtered.length, start + Math.ceil(wrap.clientHeight / ROW_H) + 20);
  const tbody = $("#grid tbody");
  tbody.innerHTML = filtered.slice(start, end).map((r, i) =>
    `<tr data-i="${start + i}">` + cols.map((c) => {
      const v = c.get(r);
      return `<td>${c.fmt ? c.fmt(v) : esc(v ?? "")}</td>`;
    }).join("") + "</tr>").join("");
  tbody.style.transform = `translateY(${start * ROW_H}px)`;
  $("#gridSpacer").style.height = filtered.length * ROW_H + 60 + "px";
}

/* ================= MAPA ================= */
function initMap() {
  map = L.map("map").setView([49.82, 15.47], 8);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    { maxZoom: 19, attribution: "© OpenStreetMap" }).addTo(map);
  clusterLayer = L.markerClusterGroup({ disableClusteringAtZoom: 12, chunkedLoading: true, maxClusterRadius: 46 });
  obceLayer = L.layerGroup();
  vpLayer = L.layerGroup();
  lfLayer = L.layerGroup();
  map.addLayer(clusterLayer); map.addLayer(vpLayer); map.addLayer(lfLayer);

  for (const c of DATA.lf) {
    L.circleMarker([c.lat, c.lon], { radius: 10, color: "#1d6fd6", fillColor: "#1d6fd6", fillOpacity: .85 })
      .bindPopup(`<b>${esc(c.name)}</b><br>lékařská fakulta`).addTo(lfLayer);
  }
  for (const c of DATA.vp) {
    L.circleMarker([c.lat, c.lon], { radius: 8, color: "#7b2cbf", fillColor: "#7b2cbf", fillOpacity: .9 })
      .bindPopup(`<b>${esc(c.name)}</b><br>${esc(c.obec)} · naše ordinace`).addTo(vpLayer);
  }
  const maxExp = Math.max(...DATA.obce.map((o) => o.expKmen));
  for (const o of DATA.obce) {
    const ratio = Math.min(o.expKmen / 5000, 1);   // 5000+ pacientů na praktika = tmavě červená
    const col = `hsl(${120 - 120 * ratio},72%,${45 - ratio * 8}%)`;
    L.circleMarker([o.lat, o.lon], { radius: Math.max(4, Math.min(Math.sqrt(o.pop) / 14, 26)), color: col, fillColor: col, fillOpacity: .5, weight: 1 })
      .bindPopup(`<b>${esc(o.name)}</b><br>obyvatel: ${o.pop.toLocaleString("cs")}<br>` +
        `očekávaný kmen praktika zde: <b>${o.expKmen.toLocaleString("cs")}</b><br>` +
        `nejbližší praktik: ${o.nearestGpKm} km · praktiků do 10 km: ${o.gps10km}`)
      .addTo(obceLayer);
  }
}
function renderMap() {
  if (!mapDirty) return;
  mapDirty = false;
  clusterLayer.clearLayers();
  const ms = [];
  for (const r of filtered) {
    if (r.lat == null) continue;
    const v = recVek(r);
    const col = v == null ? "#999" : v >= 63 ? "#d33" : v >= 55 ? "#e8a33d" : "#2a9d8f";
    const s = recScore(r);
    const m = L.circleMarker([r.lat, r.lon], { radius: r.gp ? 7 : 5, color: col, fillColor: col, fillOpacity: .85, weight: 1 });
    m.bindPopup(
      `<b>${esc(r.nazev)}</b><br>${esc(r.doctor || r.oz || "")}` +
      (v != null ? ` · <b>${v} let</b>` : " · věk ?") +
      `<br>${esc(r.ulice)}, ${esc(r.obec)}` +
      (r.kmen != null ? `<br>potenc. kmen: <b>${r.kmen.toLocaleString("cs")}</b>` : "") +
      (s ? `<br>score: <b>${Math.round(s.score)}</b>` : "") +
      `<br><a href="#" onclick="openDetail('${r.id}');return false;">detail →</a>`);
    ms.push(m);
  }
  clusterLayer.addLayers(ms);
}

/* ================= SCORING TAB ================= */
function renderScoreTab() {
  if ($("#tab-score").classList.contains("hidden")) return;
  const gp = filtered.filter((r) => r.gp && r.lat != null);
  $("#scoreScope").textContent = `(z ${gp.length.toLocaleString("cs")} praktiků dle aktivních filtrů)`;
  const scored = gp.map((r) => ({ r, s: recScore(r) })).filter((x) => x.s)
    .sort((a, b) => b.s.score - a.s.score).slice(0, 100);
  const W = WEIGHTS, tot = (W.age + W.kmen + W.lf + W.vp) || 1;
  $("#scoreList").innerHTML = scored.map((x, i) => {
    const { r, s } = x;
    const bw = (v, w) => Math.round(220 * (v * w / tot));
    return `<div class="score-row" onclick="openDetail('${r.id}')">
      <span class="rank">${i + 1}.</span>
      <span class="score-badge" style="background:${scoreColor(s.score)}">${Math.round(s.score)}</span>
      <div class="who"><div class="nm">${esc(r.nazev)}</div>
        <div class="muted small">${esc(r.doctor || r.oz || "?")} · ${esc(r.obec)} (${esc(r.okres)})
        ${s.vek != null ? "· <b>" + s.vek + " let</b>" : "· věk ?"} · kmen ${r.kmen?.toLocaleString("cs") ?? "?"}</div></div>
      <div class="score-bars" title="věk ${(s.age * 100).toFixed(0)} % · kmen ${(s.kmen * 100).toFixed(0)} % · LF ${(s.lf * 100).toFixed(0)} % · VP ${(s.vp * 100).toFixed(0)} %">
        <i class="sb-age" style="width:${bw(s.age, W.age)}px"></i><i class="sb-kmen" style="width:${bw(s.kmen, W.kmen)}px"></i>
        <i class="sb-lf" style="width:${bw(s.lf, W.lf)}px"></i><i class="sb-vp" style="width:${bw(s.vp, W.vp)}px"></i>
      </div></div>`;
  }).join("") || '<p class="muted">Žádní praktici v aktuálním filtru.</p>';

  const areas = [...DATA.obce].filter((o) => o.pop > 1500).sort((a, b) => b.expKmen - a.expKmen).slice(0, 40);
  $("#areaList").innerHTML = areas.map((o) =>
    `<div class="area-row"><b style="min-width:200px">${esc(o.name)}</b>
     <span>očekávaný kmen: <b>${o.expKmen.toLocaleString("cs")}</b></span>
     <span class="muted">obyvatel: ${o.pop.toLocaleString("cs")}</span>
     <span class="muted">nejbližší praktik: ${o.nearestGpKm} km</span>
     <span class="muted">praktiků do 10 km: ${o.gps10km}</span></div>`).join("");
}

/* ================= DETAIL ================= */
window.openDetail = function (id) {
  const r = DATA.records.find((x) => x.id === id);
  if (!r) return;
  const e = recEdit(r), s = recScore(r), v = recVek(r);
  $("#dTitle").textContent = r.nazev;
  const rows = [
    ["Lékař / zástupce", r.doctor || r.oz || "—"],
    ["Věk", v != null ? `${v} let (nar. ${recNarozeni(r)}) · zdroj: ${vekSrc(r)}` : "neznámý"],
    ["Promoce", recPromoce(r) ? recPromoce(r) + (r.promoceSrc === "lkcr" ? " (ČLK)" : e.promoce ? " (ručně)" : "") : "—"],
    ["Obory", r.obory.join(", ")],
    ["Druh zařízení", r.druh],
    ["Typ", r.typ === "PO" ? "právnická osoba" : "fyzická osoba"],
    ["IČO", r.ico],
    ["Adresa", `${r.ulice}, ${r.psc} ${r.obec}`],
    ["Okres / kraj", `${r.okres} / ${r.kraj}`],
    ["Telefon", r.tel || "—"],
    ["E-mail", r.email || "—"],
    ["Web", r.web ? `<a href="${esc(/^https?:/.test(r.web) ? r.web : "http://" + r.web)}" target="_blank">${esc(r.web)}</a>` : "—"],
    ["Zahájení činnosti", r.zahajeni || "—"],
    ["Potenc. kmen", r.kmen != null ? r.kmen.toLocaleString("cs") + " pacientů (gravitační model)" : "—"],
  ];
  if (s) rows.push(["Score", `<b>${Math.round(s.score)}</b> — věk ${(s.age * 100).toFixed(0)} %, kmen ${(s.kmen * 100).toFixed(0)} %, LF ${(s.lf * 100).toFixed(0)} %, VP ${(s.vp * 100).toFixed(0)} % · lékařů 63+ do 3 km: ${neighbours63(r)}`]);
  if (r.lat != null) rows.push(["Mapa", `<a href="https://mapy.cz/turisticka?q=${r.lat},${r.lon}" target="_blank">mapy.cz</a> · <a href="https://www.google.com/maps?q=${r.lat},${r.lon}" target="_blank">Google</a>`]);
  rows.push(["ČLK", `<a href="https://www.lkcr.cz/seznam-lekaru" target="_blank">ověřit v seznamu lékařů →</a>`]);

  $("#dBody").innerHTML =
    `<dl>${rows.map(([k, vv]) => `<dt>${k}</dt><dd>${vv}</dd>`).join("")}</dl>
     <h4>Moje údaje</h4>
     <div class="editrow">
       <select id="eStav">
         ${["", "Nekontaktováno", "Osloveno", "Jedná se", "Due diligence", "Koupeno", "Nezájem", "Nerelevantní"]
           .map((o) => `<option ${o === (e.stav || "") ? "selected" : ""}>${o}</option>`).join("")}
       </select>
       <input id="ePromoce" type="number" placeholder="rok promoce" value="${e.promoce ?? ""}" style="width:110px">
       <input id="eVek" type="number" placeholder="věk (přepíše)" value="${e.vek ?? ""}" style="width:110px">
     </div>
     <textarea id="ePozn" placeholder="poznámka…">${esc(e.pozn || "")}</textarea>
     <div class="editrow"><button class="chip" id="eSave">💾 uložit</button><span class="muted small" id="eMsg"></span></div>`;
  $("#eSave").onclick = () => {
    const ed = {};
    if ($("#eStav").value) ed.stav = $("#eStav").value;
    if ($("#ePromoce").value) ed.promoce = +$("#ePromoce").value;
    if ($("#eVek").value) ed.vek = +$("#eVek").value;
    if ($("#ePozn").value.trim()) ed.pozn = $("#ePozn").value.trim();
    if (Object.keys(ed).length) EDITS[r.id] = ed; else delete EDITS[r.id];
    saveJSON("drm_edits_v1", EDITS);
    invalidateScores(); applyFilters();
    $("#eMsg").textContent = "uloženo ✓";
    setTimeout(() => $("#eMsg").textContent = "", 1500);
  };
  $("#drawer").classList.remove("hidden");
};

/* ================= UI WIRING ================= */
function initApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  GP_KMEN_SORTED = DATA.records.filter((r) => r.kmen != null).map((r) => r.kmen).sort((a, b) => a - b);
  rebuildOldGps();

  $("#metaInfo").textContent = `· ${DATA.meta.counts.records.toLocaleString("cs")} zařízení · ${DATA.meta.counts.gp.toLocaleString("cs")} praktiků · data ${DATA.meta.builtAt}`;

  // obory dropdown
  const oborList = $("#oborList");
  oborList.innerHTML = DATA.meta.obory.map((o) =>
    `<label><input type="checkbox" value="${esc(o)}" ${FILTER.obory.has(o) ? "checked" : ""}> ${esc(o)}</label>`).join("");
  const syncOborCount = () => {
    $("#oborCount").textContent = FILTER.obory.size ? `(${FILTER.obory.size})` : "(vše)";
  };
  syncOborCount();
  oborList.onchange = (ev) => {
    const cb = ev.target;
    if (cb.checked) FILTER.obory.add(cb.value); else FILTER.obory.delete(cb.value);
    syncOborCount(); applyFilters();
  };
  $("#oborSearch").oninput = () => {
    const q = norm($("#oborSearch").value);
    $$("#oborList label").forEach((l) => l.style.display = norm(l.textContent).includes(q) ? "" : "none");
  };
  $("#oborAll").onclick = (e) => { e.preventDefault(); FILTER.obory = new Set(); $$("#oborList input").forEach((i) => i.checked = false); syncOborCount(); applyFilters(); };
  $("#oborNone").onclick = (e) => { e.preventDefault(); FILTER.obory = new Set(["—nic—"]); $$("#oborList input").forEach((i) => i.checked = false); syncOborCount(); applyFilters(); };
  $("#oborVpl").onclick = (e) => { e.preventDefault(); FILTER.obory = new Set([VPL]); $$("#oborList input").forEach((i) => i.checked = i.value === VPL); syncOborCount(); applyFilters(); };

  // kraje/okresy/obce
  const kraje = [...new Set(DATA.records.map((r) => r.kraj).filter(Boolean))].sort((a, b) => a.localeCompare(b, "cs"));
  $("#fKraj").innerHTML += kraje.map((k) => `<option>${esc(k)}</option>`).join("");
  const syncOkres = () => {
    const oks = [...new Set(DATA.records.filter((r) => !FILTER.kraj || r.kraj === FILTER.kraj).map((r) => r.okres).filter(Boolean))].sort((a, b) => a.localeCompare(b, "cs"));
    $("#fOkres").innerHTML = '<option value="">— okres —</option>' + oks.map((o) => `<option ${o === FILTER.okres ? "selected" : ""}>${esc(o)}</option>`).join("");
  };
  syncOkres();
  const syncObce = () => {
    const obce = [...new Set(DATA.records.filter((r) => (!FILTER.kraj || r.kraj === FILTER.kraj) && (!FILTER.okres || r.okres === FILTER.okres)).map((r) => r.obec).filter(Boolean))].sort((a, b) => a.localeCompare(b, "cs"));
    $("#obecList").innerHTML = obce.slice(0, 3000).map((o) => `<option value="${esc(o)}">`).join("");
  };
  syncObce();
  $("#fKraj").onchange = () => { FILTER.kraj = $("#fKraj").value; FILTER.okres = ""; syncOkres(); syncObce(); applyFilters(); };
  $("#fOkres").onchange = () => { FILTER.okres = $("#fOkres").value; syncObce(); applyFilters(); };
  $("#fObec").oninput = debounce(() => { FILTER.obec = $("#fObec").value; applyFilters(); }, 300);
  $("#fText").oninput = debounce(() => { FILTER.text = $("#fText").value; applyFilters(); }, 250);
  $("#fVekMin").oninput = debounce(() => { FILTER.vekMin = $("#fVekMin").value ? +$("#fVekMin").value : null; applyFilters(); }, 300);
  $("#fVekMax").oninput = debounce(() => { FILTER.vekMax = $("#fVekMax").value ? +$("#fVekMax").value : null; applyFilters(); }, 300);
  $("#fVekUnknown").onchange = () => { FILTER.vekUnknown = $("#fVekUnknown").checked; applyFilters(); };
  $("#f63").onclick = () => {
    const on = $("#f63").classList.toggle("on");
    FILTER.vekMin = on ? 63 : null; $("#fVekMin").value = on ? 63 : "";
    if (on) { FILTER.vekUnknown = false; $("#fVekUnknown").checked = false; }
    applyFilters();
  };
  $("#fReset").onclick = () => {
    FILTER = { text: "", obory: new Set([VPL]), kraj: "", okres: "", obec: "", vekMin: null, vekMax: null, vekUnknown: true };
    $("#fText").value = ""; $("#fKraj").value = ""; $("#fObec").value = ""; $("#fVekMin").value = ""; $("#fVekMax").value = "";
    $("#fVekUnknown").checked = true; $("#f63").classList.remove("on");
    $$("#oborList input").forEach((i) => i.checked = i.value === VPL);
    syncOkres(); syncObce(); syncOborCount(); applyFilters();
  };

  // dropdowny otvírání
  for (const [btn, panel] of [["#oborBtn", "#oborPanel"], ["#colsDrop .drop-btn", "#colsPanel"]]) {
    $(btn).onclick = (e) => { e.stopPropagation(); $(panel).classList.toggle("hidden"); };
  }
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".drop-panel") && !e.target.closest(".drop-btn"))
      $$(".drop-panel").forEach((p) => p.classList.add("hidden"));
  });

  // sloupce
  $("#colsPanel").innerHTML = COLUMNS.map((c) =>
    `<label><input type="checkbox" value="${c.key}" ${visibleCols.includes(c.key) ? "checked" : ""}> ${c.label}</label>`).join("");
  $("#colsPanel").onchange = () => {
    visibleCols = $$("#colsPanel input:checked").map((i) => i.value);
    saveJSON("drm_cols_v1", visibleCols);
    renderTable();
  };

  // tabulka
  $("#grid thead").addEventListener("click", (e) => {
    const th = e.target.closest("th"); if (!th) return;
    const k = th.dataset.k;
    if (SORT.key === k) SORT.dir *= -1; else { SORT.key = k; SORT.dir = k === "score" || k === "kmen" || k === "vek" ? -1 : 1; }
    sortFiltered(); renderTable();
  });
  $("#grid tbody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr"); if (!tr) return;
    openDetail(filtered[+tr.dataset.i].id);
  });
  $("#tableWrap").addEventListener("scroll", () => requestAnimationFrame(renderRows));
  $("#dClose").onclick = () => $("#drawer").classList.add("hidden");

  // taby
  $$("nav .tab").forEach((b) => b.onclick = () => {
    $$("nav .tab").forEach((x) => x.classList.toggle("active", x === b));
    $$(".tabpane").forEach((p) => p.classList.add("hidden"));
    $("#tab-" + b.dataset.tab).classList.remove("hidden");
    if (b.dataset.tab === "map") { if (!map) initMap(); renderMap(); setTimeout(() => map.invalidateSize(), 60); }
    if (b.dataset.tab === "score") renderScoreTab();
  });

  // mapa vrstvy
  $("#layerDoctors").onchange = (e) => e.target.checked ? map.addLayer(clusterLayer) : map.removeLayer(clusterLayer);
  $("#layerObce").onchange = (e) => e.target.checked ? map.addLayer(obceLayer) : map.removeLayer(obceLayer);
  $("#layerVp").onchange = (e) => e.target.checked ? map.addLayer(vpLayer) : map.removeLayer(vpLayer);
  $("#layerLf").onchange = (e) => e.target.checked ? map.addLayer(lfLayer) : map.removeLayer(lfLayer);

  // scoring váhy
  for (const k of ["age", "kmen", "lf", "vp"]) {
    const el = $("#w" + k[0].toUpperCase() + k.slice(1));
    el.value = WEIGHTS[k];
    $("#w" + k[0].toUpperCase() + k.slice(1) + "V").textContent = WEIGHTS[k] + " %";
    el.oninput = debounce(() => {
      WEIGHTS[k] = +el.value;
      $("#w" + k[0].toUpperCase() + k.slice(1) + "V").textContent = el.value + " %";
      saveJSON("drm_weights_v1", WEIGHTS);
      invalidateScores(); applyFilters();
    }, 250);
  }

  // nastavení
  $("#sourceInfo").innerHTML = [
    `Registr zařízení: ${esc(DATA.meta.sourceNrpzs)}`,
    `Populace: ${esc(DATA.meta.sourcePop)}`,
    `Věk lékaře: skutečný rok narození z ARES (veřejný rejstřík) u ${DATA.meta.aresHits ?? 0} ordinací s.r.o.; jinak odhad z roku promoce ČLK (věk = ${nowYear} − (rok promoce − ${DATA.meta.promoceAge})); ručně lze kdykoli přepsat`,
    `Roky promoce ČLK: seznam je chráněný reCAPTCHA — doplňuje se ručně (detail lékaře / import)`,
    `Sestaveno: ${DATA.meta.builtAt}`,
  ].map((x) => `<li>${x}</li>`).join("");
  $("#exportEdits").onclick = () => download("doctorrm-upravy.json", JSON.stringify(EDITS, null, 1));
  $("#importEditsBtn").onclick = () => $("#importEdits").click();
  $("#importEdits").onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const imp = JSON.parse(await f.text());
      EDITS = { ...EDITS, ...imp };
      saveJSON("drm_edits_v1", EDITS);
      invalidateScores(); applyFilters();
      alert("Importováno " + Object.keys(imp).length + " záznamů.");
    } catch (err) { alert("Chyba importu: " + err.message); }
  };
  $("#resetEdits").onclick = () => {
    if (confirm("Opravdu smazat všechny lokální poznámky a úpravy?")) {
      EDITS = {}; saveJSON("drm_edits_v1", EDITS); invalidateScores(); applyFilters();
    }
  };
  $("#logout").onclick = () => { sessionStorage.removeItem("drm_pw"); localStorage.removeItem("drm_pw"); location.reload(); };

  $("#exportCsv").onclick = () => {
    const cols = COLUMNS.filter((c) => visibleCols.includes(c.key));
    const lines = [cols.map((c) => c.label).join(";")];
    for (const r of filtered) lines.push(cols.map((c) => String(c.get(r) ?? "").replace(/;/g, ",").replace(/\n/g, " ")).join(";"));
    download("doctorrm-export.csv", "﻿" + lines.join("\n"));
  };

  applyFilters();
}
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
  a.download = name; a.click();
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

/* ================= START ================= */
$("#pwBtn").onclick = () => tryUnlock($("#pw").value, false);
$("#pw").addEventListener("keydown", (e) => { if (e.key === "Enter") tryUnlock($("#pw").value, false); });
const saved = sessionStorage.getItem("drm_pw") || localStorage.getItem("drm_pw");
if (saved) tryUnlock(saved, true);
