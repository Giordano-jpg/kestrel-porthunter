"use strict";

/* Kestrel PortHunter · interfaz. Todo texto que viene de la red (nombres DNS, NetBIOS,
   banners...) pasa por esc() antes de entrar en el HTML. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

const VIEWS = ["panel", "hosts", "scan", "jobs", "monitor", "settings"];
const STATUS_LABEL = { up: "Activo", down: "No responde", unknown: "Sin comprobar" };
const JOB_STATUS = {
  queued: "En cola", running: "En curso", done: "Terminada", error: "Error",
  cancelled: "Cancelada", interrupted: "Interrumpida",
};
const EVENT_ICON = { new: "✚", ip_change: "⇄", name_change: "✎", up: "▲", down: "▼", port_open: "◉", port_closed: "○" };
const SOURCE_LABEL = { list: "DNS (-sL)", ping: "descubrimiento", ports: "escaneo de puertos" };
const INTERVALS = [[0, "Manual"], [15, "15 min"], [30, "30 min"], [60, "1 h"], [240, "4 h"], [1440, "1 día"]];
const MON_FIELDS = ["window_seconds", "tcp_ports_threshold", "udp_ports_threshold", "stealth_threshold",
  "sweep_hosts_threshold", "alert_cooldown_seconds"];

const state = {
  view: "panel",
  meta: null,
  diag: null,
  networks: [],
  selected: new Set(),
  hostsItems: [],
  openJob: null,
  jobDetailKey: "",
  openDevice: null,
  jobsActive: 0,
  monitor: null,
  monitorFormLoaded: false,
  settingsLoaded: false,
  finderItems: [],
  finderIndex: -1,
};

// ---------------------------------------------------------------------------
// utilidades
// ---------------------------------------------------------------------------

// En la ventana de escritorio no hay servidor HTTP: se llama a Python con el puente de pywebview.
const DESKTOP = !!window.PH_DESKTOP;

async function api(path, { method = "GET", body, form } = {}) {
  if (DESKTOP) {
    const r = form ? await desktopUpload(form) : await window.pywebview.api.request(method, path, body ?? null);
    if (r.status >= 400) throw new Error((r.data && r.data.error) || `Error ${r.status}`);
    return r.data;
  }
  const opts = { method, headers: {} };
  if (method !== "GET") opts.headers["X-PortHunter"] = "1";
  if (form) opts.body = form;
  else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  let data = null;
  try { data = await resp.json(); } catch { /* respuesta vacía */ }
  if (!resp.ok) throw new Error((data && data.error) || `Error ${resp.status}`);
  return data;
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

async function desktopUpload(form) {
  const files = [];
  for (const f of form.getAll("file")) files.push({ name: f.name, data: await fileToBase64(f) });
  return window.pywebview.api.upload(files);
}

async function desktopDownload(href) {
  const r = await window.pywebview.api.download(href);
  if (r.saved) toast(`Guardado en ${r.saved}`, "ok", 7000);
  else if (r.error) toast(r.error, "error");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

function toast(message, kind = "info", ms = 4500) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), ms);
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

const rtf = new Intl.RelativeTimeFormat("es", { numeric: "auto" });
function ago(iso) {
  if (!iso) return "—";
  const s = Math.min(0, (new Date(iso) - Date.now()) / 1000);  // relojes desfasados: nunca "dentro de"
  const abs = Math.abs(s);
  if (abs < 45) return "ahora";
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}
function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "medium" }) : "—";
}
function duration(a, b) {
  if (!a) return "—";
  const s = Math.max(0, ((b ? new Date(b) : new Date()) - new Date(a)) / 1000);
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}
const truncate = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s || "");
const kindLabel = (k) => (state.meta && state.meta.kinds[k]) || k;

function statusHtml(st) {
  return `<span class="status"><span class="dot st-${esc(st)}"></span>${esc(STATUS_LABEL[st] || st)}</span>`;
}
function jobPill(st) {
  return `<span class="pill ${esc(st)}">${esc(JOB_STATUS[st] || st)}</span>`;
}
function progressHtml(job) {
  const pct = Math.round((job.progress || 0) * 100);
  const indet = job.status === "running" && pct === 0;
  return `<div class="progress ${indet ? "indeterminate" : ""}"><div style="width:${pct}%"></div></div>`;
}
function profileOptions(selected = "rapido") {
  const profiles = (state.meta && state.meta.profiles) || {};
  return Object.entries(profiles)
    .map(([k, v]) => `<option value="${esc(k)}" ${k === selected ? "selected" : ""}>${esc(v)}</option>`).join("");
}

function summaryText(job) {
  const phases = job.summary || [];
  if (!phases.length) return job.error ? `<span class="bad">${esc(truncate(job.error, 140))}</span>` : "";
  const parts = [];
  for (const p of phases) {
    parts.push(p.source === "list" ? `${p.named} nombres` : `${p.up} activos`);
    if (p.new) parts.push(`${p.new} nuevos`);
    if (p.ip_changes) parts.push(`${p.ip_changes} cambios de IP`);
    if (p.source === "ports") parts.push(`${p.open_ports} puertos abiertos`);
    if (p.went_down) parts.push(`${p.went_down} ya no responden`);
  }
  const text = esc(parts.join(" · "));
  return job.error ? `${text}<div class="bad">${esc(truncate(job.error, 140))}</div>` : text;
}

function eventsHtml(list) {
  if (!list.length) return `<p class="muted">Sin novedades todavía.</p>`;
  return list.map((e) => `
    <div class="event ${e.device_id ? "clickable" : ""}" ${e.device_id ? `data-device="${e.device_id}"` : ""}>
      <span>${EVENT_ICON[e.kind] || "•"}</span><span>${esc(e.message)}</span>
      <time title="${esc(fmtDate(e.ts))}">${esc(ago(e.ts))}</time>
    </div>`).join("");
}

function rememberTarget(t) {
  try {
    const list = JSON.parse(localStorage.getItem("ph.targets") || "[]").filter((x) => x !== t);
    list.unshift(t);
    localStorage.setItem("ph.targets", JSON.stringify(list.slice(0, 8)));
  } catch { /* almacenamiento no disponible */ }
  updateSuggestions();
}
function recentTargets() {
  try { return JSON.parse(localStorage.getItem("ph.targets") || "[]"); } catch { return []; }
}

// ---------------------------------------------------------------------------
// navegación y refresco
// ---------------------------------------------------------------------------

function route() {
  const [view, sub] = location.hash.slice(1).split("/");
  state.view = VIEWS.includes(view) ? view : "panel";
  if (state.view === "jobs" && sub) { state.openJob = Number(sub); state.jobDetailKey = ""; }
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === state.view));
  $$(".view").forEach((s) => s.classList.toggle("active", s.id === `view-${state.view}`));
  if (state.view !== "settings") state.settingsLoaded = false;
  refreshView(false);
}

const loaders = {
  panel: loadPanel, hosts: loadHosts, scan: loadScan, jobs: loadJobs, monitor: loadMonitor, settings: loadSettings,
};
async function refreshView(silent = true) {
  try { await loaders[state.view](silent); } catch (e) { if (!silent) toast(e.message, "error"); }
}

let tick = 0;
setInterval(async () => {
  if (document.hidden || !state.ready) return;
  tick += 1;
  try { applyCounts(await api("/api/summary")); } catch { return; }
  const v = state.view;
  if (v === "panel" || v === "jobs" || v === "monitor") refreshView(true);
  else if (v === "hosts" && state.jobsActive && tick % 4 === 0) refreshView(true);
  if (state.openDevice && state.jobsActive && tick % 3 === 0) refreshDrawer(false);
}, 2500);

function applyCounts(c) {
  state.jobsActive = (c.running || 0) + (c.queued || 0);
  $("#badge-jobs").textContent = state.jobsActive || "";
  $("#badge-alerts").textContent = c.alerts || "";
  const mon = $("#side-monitor");
  if (mon) mon.innerHTML = c.monitor_running ? `<span class="live">Monitor activo</span>` : "Monitor parado";
}

function renderSideStatus() {
  const d = state.diag;
  if (!d) return;
  $("#side-status").innerHTML = `
    <div>${d.nmap_version ? `<span class="good">●</span> nmap ${esc(d.nmap_version)}` : `<span class="bad">●</span> nmap no encontrado`}</div>
    <div>${d.admin ? `<span class="good">●</span> Administrador` : `<span class="muted">●</span> Sin privilegios`}</div>
    <div id="side-monitor">Monitor parado</div>`;
}

function updateSuggestions() {
  const values = new Map();
  for (const n of (state.diag && state.diag.networks) || []) values.set(n.cidr, `Red de ${n.iface}`);
  for (const n of state.networks) values.set(n.targets, n.name);
  for (const t of recentTargets()) if (!values.has(t)) values.set(t, "Usado recientemente");
  $("#target-suggestions").innerHTML = [...values]
    .map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("");

  const chips = [];
  for (const n of (state.diag && state.diag.networks) || []) {
    chips.push(`<button type="button" class="chip" data-target="${esc(n.cidr)}" title="Tu IP ${esc(n.ip)} en ${esc(n.iface)}">${esc(n.cidr)} · ${esc(n.iface)}</button>`);
  }
  for (const n of state.networks) {
    chips.push(`<button type="button" class="chip" data-target="${esc(n.targets)}">${esc(n.name)}</button>`);
  }
  $("#quick-chips").innerHTML = chips.join("");
  $("#scan-chips").innerHTML = chips.join("");
}

// ---------------------------------------------------------------------------
// panel
// ---------------------------------------------------------------------------

async function loadPanel() {
  const d = await api("/api/dashboard");
  applyCounts({ ...d.counts, monitor_running: d.monitor_running });
  const c = d.counts;
  const stats = [
    [c.total, "equipos en el inventario"],
    [c.up, "activos en la última comprobación"],
    [c.watched, "vigilados"],
    [c.ports, "puertos abiertos conocidos"],
    [c.alerts, "alertas sin revisar", c.alerts ? "alert" : ""],
  ];
  $("#stats").innerHTML = stats
    .map(([n, label, cls]) => `<div class="stat ${cls || ""}"><b>${esc(n)}</b><span>${esc(label)}</span></div>`).join("");

  $("#watched").innerHTML = d.watched.length ? `
    <table class="table"><thead><tr><th>Equipo</th><th>IP actual</th><th>Estado</th><th>Visto</th><th>Puertos</th></tr></thead>
    <tbody>${d.watched.map((w) => `
      <tr class="clickable" data-device="${w.id}">
        <td><b>${esc(w.name)}</b>${w.alias && w.hostname ? `<div class="sub">${esc(w.hostname)}</div>` : ""}</td>
        <td class="ip">${esc(w.current_ip || "—")}</td>
        <td>${statusHtml(w.status)}</td>
        <td title="${esc(fmtDate(w.last_seen))}">${esc(ago(w.last_seen))}</td>
        <td class="ports">${esc(w.port_list || "")}</td>
      </tr>`).join("")}</tbody></table>`
    : `<p class="muted">Todavía no vigilas ningún equipo. En «Equipos», marca con ☆ los que conoces (los que antes
       buscabas con Ctrl+F en el .txt) y aquí verás siempre su IP actual y si responden.</p>`;

  const jobs = [...d.active_jobs, ...d.recent_jobs];
  $("#panel-jobs").innerHTML = jobs.length ? jobs.map((j) => `
    <div class="job-mini clickable" data-job="${j.id}">
      <div class="row"><b class="grow">#${j.id} ${esc(j.label)}</b>${jobPill(j.status)}</div>
      <div class="sub mono">${esc(truncate(j.targets, 70))}</div>
      ${j.status === "running"
        ? `${progressHtml(j)}<div class="sub">${Math.round(j.progress * 100)}% · ${esc(j.phase || "")}</div>`
        : `<div class="sub">${summaryText(j)}</div>`}
    </div>`).join("")
    : `<p class="muted">Sin tareas todavía. Usa la acción rápida de arriba o la sección «Escanear».</p>`;

  $("#events").innerHTML = eventsHtml(d.events);

  $("#panel-alerts").innerHTML = d.alerts.length ? d.alerts.map((a) => `
    <div class="event">
      <span><span class="pill sev-${esc(a.severity)}">!</span></span>
      <span>${esc(alertLabel(a.kind))} desde <span class="ip">${esc(a.src)}</span>${a.src_name ? ` (${esc(a.src_name)})` : ""}</span>
      <time title="${esc(fmtDate(a.last_seen))}">${esc(ago(a.last_seen))}</time>
    </div>`).join("")
    : `<p class="muted">${d.monitor_running ? "Sin alertas: nadie te ha escaneado desde que arrancó el monitor."
      : "Inicia el monitor para detectar escaneos contra este equipo."}</p>`;
}

const alertLabel = (k) => (state.meta && state.meta.alert_kinds[k]) || k;

// Buscador del panel
const finderSearch = debounce(async () => {
  const q = $("#finder").value.trim();
  const box = $("#finder-results");
  if (!q) { box.innerHTML = ""; return; }
  const r = await api(`/api/devices?q=${encodeURIComponent(q)}&limit=8`);
  state.finderItems = r.items;
  state.finderIndex = -1;
  if (!r.items.length) {
    box.innerHTML = `<div class="finder-item muted">Nada coincide con «${esc(q)}». Si es un equipo nuevo, lanza un descubrimiento de la red.</div>`;
    return;
  }
  box.innerHTML = r.items.map((d) => {
    const extra = [d.hostname && d.hostname !== d.name ? d.hostname : "", d.vendor, d.mac].filter(Boolean).join(" · ");
    return `<div class="finder-item" data-device="${d.id}">
      <div><b>${esc(d.name)}</b>${d.watched ? " ★" : ""}<div class="sub">${esc(extra)}</div></div>
      <span class="ip">${esc(d.current_ip || "—")}</span>
      <span>${statusHtml(d.status)} <span class="sub">${esc(ago(d.last_seen))}</span></span>
    </div>`;
  }).join("") + (r.total > r.items.length
    ? `<div class="finder-item" data-more="${esc(q)}"><span>Ver los ${r.total} resultados en «Equipos» →</span></div>` : "");
}, 180);

function finderKeys(ev) {
  const items = $$("#finder-results .finder-item[data-device]");
  if (ev.key === "Escape") { ev.target.value = ""; $("#finder-results").innerHTML = ""; return; }
  if (!items.length) return;
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    state.finderIndex = (state.finderIndex + (ev.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
    items.forEach((el, i) => el.classList.toggle("active", i === state.finderIndex));
  } else if (ev.key === "Enter") {
    const el = items[Math.max(0, state.finderIndex)];
    openDevice(Number(el.dataset.device));
  }
}

async function quickAction(kind) {
  const targets = $("#quick-target").value.trim();
  if (!targets) { toast("Escribe la red o el rango (o pulsa una de las sugerencias).", "error"); return; }
  const options = { timing: "T4", reinforced: true, profile: "rapido" };
  const r = await api("/api/jobs", { method: "POST", body: { kind, targets, options } });
  rememberTarget(targets);
  toast(`Tarea #${r.job_id} en marcha: ${kindLabel(kind)}`, "ok");
  loadPanel();
}

// ---------------------------------------------------------------------------
// equipos
// ---------------------------------------------------------------------------

function hostFilters() {
  const p = new URLSearchParams();
  const q = $("#hosts-q").value.trim();
  if (q) p.set("q", q);
  if ($("#hosts-status").value) p.set("status", $("#hosts-status").value);
  if ($("#hosts-watched").checked) p.set("watched", "1");
  if ($("#hosts-ports").checked) p.set("ports", "1");
  return p;
}

async function loadHosts() {
  const params = hostFilters();
  for (const [id, fmt] of [["#export-txt", "txt"], ["#export-csv", "csv"], ["#export-targets", "targets"]]) {
    $(id).href = `/api/export/${fmt}?${params}`;
  }
  const r = await api(`/api/devices?${params}&limit=5000`);
  state.hostsItems = r.items;
  $("#hosts-count").textContent = r.total > r.items.length
    ? `${r.items.length} de ${r.total} equipos` : `${r.total} equipo${r.total === 1 ? "" : "s"}`;
  $("#hosts-table tbody").innerHTML = r.items.map(hostRow).join("");
  $("#hosts-empty").classList.toggle("hidden", r.items.length > 0 || params.toString() !== "");
  updateSelectionBar();
}

function hostRow(d) {
  const sel = state.selected.has(d.id);
  const others = [d.hostname, d.netbios].filter((x) => x && x.toLowerCase() !== d.name.toLowerCase());
  return `<tr class="clickable ${sel ? "selected" : ""}" data-device="${d.id}">
    <td><input type="checkbox" data-select="${d.id}" ${sel ? "checked" : ""} aria-label="Seleccionar"></td>
    <td><button class="star ${d.watched ? "on" : ""}" data-star="${d.id}" title="${d.watched ? "Dejar de vigilar" : "Vigilar"}">${d.watched ? "★" : "☆"}</button></td>
    <td><b>${esc(d.name)}</b>${others.length ? `<div class="sub">${esc(others.join(" · "))}</div>` : ""}</td>
    <td class="ip">${esc(d.current_ip || "—")}</td>
    <td>${statusHtml(d.status)}</td>
    <td>${d.mac ? `<span class="mono small">${esc(d.mac)}</span><div class="sub">${esc(d.vendor || "")}</div>` : `<span class="muted">—</span>`}</td>
    <td>${d.distance == null ? "—" : esc(d.distance)}</td>
    <td>${esc(truncate(d.os_guess || d.ttl_hint || "—", 40))}${d.ttl ? `<div class="sub">TTL ${esc(d.ttl)}</div>` : ""}</td>
    <td class="ports">${esc(d.port_list || "")}${d.port_count > 10 ? ` +${d.port_count - 10}` : ""}</td>
    <td title="${esc(fmtDate(d.last_seen))}">${esc(ago(d.last_seen))}</td>
  </tr>`;
}

function updateSelectionBar() {
  const n = state.selected.size;
  $("#selection-bar").classList.toggle("hidden", n === 0);
  $("#sel-count").textContent = `${n} seleccionado${n === 1 ? "" : "s"}`;
  const visible = state.hostsItems.map((d) => d.id);
  $("#sel-all").checked = visible.length > 0 && visible.every((id) => state.selected.has(id));
}

async function scanDevices(ids, kind, options, label) {
  const r = await api("/api/devices/scan", { method: "POST", body: { ids, kind, options, label } });
  toast(`Tarea #${r.job_id} en marcha`, "ok");
  return r.job_id;
}

async function setWatched(ids, watched) {
  await api("/api/devices/watch", { method: "POST", body: { ids, watched } });
}

async function importFiles(files) {
  if (!files.length) return;
  const form = new FormData();
  for (const f of files) form.append("file", f);
  toast(`Importando ${files.length} fichero(s)…`);
  const r = await api("/api/import", { method: "POST", form });
  for (const res of r.results) {
    if (res.error) toast(`${res.file}: ${res.error}`, "error", 8000);
    else {
      const what = res.source === "list" ? `${res.named} nombres` : `${res.hosts} equipos`;
      toast(`${res.file}: ${what}, ${res.new} nuevos, ${res.ip_changes} cambios de IP`, "ok", 7000);
    }
  }
  refreshView(false);
}

// ---------------------------------------------------------------------------
// escanear
// ---------------------------------------------------------------------------

async function loadScan() {
  await loadNetworks();
  updateModeOptions();
  updatePreview();
}

function scanFormData() {
  const f = $("#scan-form");
  const visible = (el) => !el.closest("[data-for]") || !el.closest("[data-for]").classList.contains("hidden");
  const kind = f.querySelector("input[name=kind]:checked").value;
  const options = {};
  if (visible(f.profile)) options.profile = f.profile.value;
  if (visible(f.timing)) options.timing = f.timing.value;
  for (const name of ["reinforced", "no_ping", "traceroute"]) if (visible(f[name])) options[name] = f[name].checked;
  if (visible(f.extra_args) && f.extra_args.value.trim()) options.extra_args = f.extra_args.value.trim();
  return { kind, targets: f.targets.value.trim(), options, label: f.label.value.trim() };
}

function updateModeOptions() {
  const kind = $("#scan-form input[name=kind]:checked").value;
  $$("#scan-form [data-for]").forEach((el) => el.classList.toggle("hidden", !el.dataset.for.split(" ").includes(kind)));
  $("[data-extra-label]").textContent = kind === "custom" ? "Argumentos de nmap" : "Argumentos extra (opcional)";
}

const updatePreview = debounce(async () => {
  const d = scanFormData();
  const pre = $("#cmd-preview");
  if (!d.targets) {
    pre.textContent = "Escribe un objetivo para ver el comando.";
    pre.classList.remove("error");
    return;
  }
  try {
    const r = await api("/api/jobs/preview", { method: "POST", body: d });
    pre.textContent = r.commands.map((c, i) => (r.commands.length > 1 ? `# Fase ${i + 1}\n${c}` : c)).join("\n\n");
    pre.classList.remove("error");
  } catch (e) {
    pre.textContent = e.message;
    pre.classList.add("error");
  }
}, 300);

async function submitScan(ev) {
  ev.preventDefault();
  const d = scanFormData();
  const r = await api("/api/jobs", { method: "POST", body: d });
  rememberTarget(d.targets);
  toast(`Tarea #${r.job_id} en marcha`, "ok");
  location.hash = `#jobs/${r.job_id}`;
}

async function saveNetwork() {
  const d = scanFormData();
  const name = $("#net-name").value.trim();
  if (!name) { toast("Ponle un nombre a la red.", "error"); return; }
  await api("/api/networks", {
    method: "POST",
    body: { name, targets: d.targets, kind: d.kind, options: d.options, interval_min: Number($("#net-interval").value) },
  });
  toast(`Red «${name}» guardada`, "ok");
  $("#net-name").value = "";
  loadNetworks();
}

async function loadNetworks() {
  state.networks = await api("/api/networks");
  updateSuggestions();
  const nets = state.networks;
  $("#networks").innerHTML = nets.length ? `<table class="table"><tbody>${nets.map((n) => `
    <tr>
      <td><b>${esc(n.name)}</b><div class="sub mono">${esc(truncate(n.targets, 60))}</div>
        <div class="sub">${esc(kindLabel(n.kind))}</div></td>
      <td><select data-net-interval="${n.id}" title="Repetir automáticamente">
          ${INTERVALS.map(([v, l]) => `<option value="${v}" ${v === n.interval_min ? "selected" : ""}>${l}</option>`).join("")}
        </select>
        <div class="sub">${n.last_run ? `Última: ${esc(ago(n.last_run))}` : "Nunca ejecutada"}</div></td>
      <td><div class="row">
        <button class="icon" data-net-run="${n.id}" title="Ejecutar ahora">▶</button>
        <button class="icon" data-net-load="${n.id}" title="Cargar en el formulario">✎</button>
        <button class="icon danger" data-net-del="${n.id}" title="Borrar">✕</button></div></td>
    </tr>`).join("")}</tbody></table>`
    : `<p class="muted">Guarda aquí tus redes habituales (p. ej. 10.10.0.0/17) para lanzarlas con un clic o programarlas.</p>`;
}

function loadNetworkIntoForm(net) {
  const f = $("#scan-form");
  f.targets.value = net.targets;
  const radio = f.querySelector(`input[name=kind][value="${net.kind}"]`);
  if (radio) radio.checked = true;
  const o = net.options || {};
  if (o.profile) f.profile.value = o.profile;
  if (o.timing) f.timing.value = o.timing;
  for (const k of ["reinforced", "no_ping", "traceroute"]) if (k in o) f[k].checked = !!o[k];
  f.extra_args.value = o.extra_args || "";
  f.label.value = net.name;
  updateModeOptions();
  updatePreview();
}

// ---------------------------------------------------------------------------
// tareas
// ---------------------------------------------------------------------------

async function loadJobs() {
  const jobs = await api("/api/jobs?limit=150");
  $("#jobs-table tbody").innerHTML = jobs.length ? jobs.map((j) => `
    <tr class="clickable ${state.openJob === j.id ? "selected" : ""}" data-job="${j.id}">
      <td>${j.id}</td>
      <td><b>${esc(j.label)}</b>${j.label !== j.kind_label ? `<div class="sub">${esc(j.kind_label)}</div>` : ""}</td>
      <td class="mono small">${esc(truncate(j.targets, 50))}</td>
      <td>${jobPill(j.status)}</td>
      <td>${j.status === "running"
        ? `${progressHtml(j)}<div class="sub">${Math.round(j.progress * 100)}% · ${esc(j.phase || "")}</div>` : ""}</td>
      <td title="${esc(fmtDate(j.started || j.created))}">${esc(ago(j.started || j.created))}</td>
      <td>${j.status === "queued" ? "—" : duration(j.started, j.finished)}</td>
      <td class="small">${summaryText(j)}</td>
    </tr>`).join("")
    : `<tr><td colspan="8" class="empty">Sin tareas. Lanza una desde «Escanear».</td></tr>`;
  if (state.openJob) await loadJobDetail(state.openJob);
}

function summaryGrid(summary) {
  return (summary || []).map((p) => {
    const cells = p.source === "list"
      ? [[p.named, "nombres en DNS"], [p.new, "nuevos"], [p.ip_changes, "cambios de IP"]]
      : [[p.up, "activos"], [p.new, "nuevos"], [p.ip_changes, "cambios de IP"]];
    if (p.source === "ping") cells.push([p.went_down, "ya no responden"]);
    if (p.source === "ports") cells.push([p.open_ports, "puertos abiertos"]);
    return `<div class="muted small">${esc(p.phase || "")}${p.complete === false ? " · resultado parcial" : ""}</div>
      <div class="summary-grid">${cells.map(([n, l]) => `<div><b>${esc(n ?? 0)}</b><span>${esc(l)}</span></div>`).join("")}</div>`;
  }).join("");
}

async function loadJobDetail(id) {
  const box = $("#job-detail");
  const prevLog = $("#job-log");
  const keep = prevLog ? { top: prevLog.scrollTop, bottom: prevLog.scrollTop + prevLog.clientHeight >= prevLog.scrollHeight - 30 } : { bottom: true };
  const j = await api(`/api/jobs/${id}?lines=400`);
  const key = `${j.id}:${j.status}`;
  if (key === state.jobDetailKey && !["running", "queued"].includes(j.status)) return;
  state.jobDetailKey = key;
  box.classList.remove("hidden");
  const files = (j.xml_files || []).map((f) =>
    `<a class="btn" href="/api/jobs/${j.id}/files/${encodeURIComponent(f)}?dl=1" title="Resultado XML de nmap (se abre con Zenmap)">${esc(f)}</a>`).join("");
  box.innerHTML = `
    <div class="card-head">
      <h2>#${j.id} · ${esc(j.label)} ${jobPill(j.status)}</h2>
      <div class="row wrap">
        ${["queued", "running"].includes(j.status) ? `<button class="danger" data-cancel="${j.id}">Cancelar</button>` : ""}
        ${files}
        ${j.kind !== "import" ? `<a class="btn" href="/api/jobs/${j.id}/files/job_${j.id}.log?dl=1">Log</a>` : ""}
        <button class="ghost" data-close-job>Cerrar</button>
      </div>
    </div>
    ${j.error ? `<div class="notice warn">${esc(j.error)}</div>` : ""}
    ${j.status === "running" ? `${progressHtml(j)}<p class="sub">${Math.round(j.progress * 100)}% · ${esc(j.phase || "")} · ${duration(j.started)}</p>` : ""}
    <div class="commands"><div class="muted small">Comando${j.commands.length > 1 ? "s" : ""}</div>
      ${j.commands.map((c) => `<pre>${esc(c)}</pre>`).join("")}</div>
    ${summaryGrid(j.summary)}
    ${j.events.length ? `<div class="muted small">Novedades de esta tarea</div><div class="event-list">${eventsHtml(j.events)}</div>` : ""}
    ${j.kind !== "import" ? `<div class="muted small">Salida de nmap</div><pre class="log" id="job-log">${esc(j.log.join("\n"))}</pre>` : ""}`;
  const log = $("#job-log");
  if (log) log.scrollTop = keep.bottom ? log.scrollHeight : keep.top;
}

// ---------------------------------------------------------------------------
// monitor
// ---------------------------------------------------------------------------

async function loadMonitor(silent) {
  if (!state.monitorFormLoaded) {
    const ifaces = await api("/api/monitor/interfaces");
    const st = await api("/api/monitor");
    const cfg = st.config;
    $("#mon-iface").innerHTML = ifaces.map((i) => `
      <option value="${esc(i.id)}" ${(cfg.iface ? cfg.iface === i.id : i.default) ? "selected" : ""}>
        ${esc(i.name)} — ${esc(i.ips.join(", ") || "sin IP")}${i.default ? " (predeterminada)" : ""}</option>`).join("");
    $("#mon-watch-all").checked = cfg.watch_all;
    $("#mon-save_pcap").checked = cfg.save_pcap;
    for (const f of MON_FIELDS) $(`#mon-${f}`).value = cfg[f];
    $("#mon-whitelist").value = (cfg.whitelist || []).join(", ");
    state.monitorFormLoaded = true;
  }
  const [st, alerts] = await Promise.all([api("/api/monitor"), api("/api/alerts?limit=300")]);
  state.monitor = st;

  const notice = $("#monitor-unavailable");
  notice.classList.toggle("hidden", st.available);
  if (!st.available) notice.textContent = st.reason;

  const btn = $("#mon-toggle");
  if (!btn.disabled) {
    btn.textContent = st.running ? "Detener monitor" : "Iniciar monitor";
    btn.className = st.running ? "danger" : "primary";
  }
  const s = st.stats || {};
  $("#mon-status").innerHTML = st.running ? `
      <span class="live">Escuchando</span>
      <span>en <b>${esc(st.iface)}</b> desde ${esc(ago(st.started))}</span>
      <span><b>${esc(s.packets || 0)}</b> paquetes</span>
      <span>TCP <b>${esc(s.tcp || 0)}</b> · UDP <b>${esc(s.udp || 0)}</b> · ICMP <b>${esc(s.icmp || 0)}</b> · ARP <b>${esc(s.arp || 0)}</b></span>
      <span><b>${esc(st.active_alerts)}</b> alertas en curso</span>`
    : st.error ? `<span class="bad">${esc(st.error)}</span>` : `<span>Detenido.</span>`;

  $("#alerts-table tbody").innerHTML = alerts.map(alertRow).join("");
  $("#alerts-empty").classList.toggle("hidden", alerts.length > 0);

  $("#inbound-table tbody").innerHTML = st.inbound.map((e) => `
    <tr>
      <td class="ip">${esc(e.src)}</td>
      <td>${e.device ? `<a href="#" data-device="${e.device.id}">${esc(e.device.name)}</a>` : `<span class="muted">desconocido</span>`}</td>
      <td>${esc(e.count)}</td>
      <td>${esc(e.distinct)}</td>
      <td class="ports">${esc(e.top.join(", "))}</td>
      <td title="${esc(fmtDate(e.last))}">${esc(ago(e.last))}</td>
    </tr>`).join("");
  $("#inbound-empty").classList.toggle("hidden", st.inbound.length > 0);
  $("#inbound-empty").textContent = st.running
    ? "Nadie ha intentado conectarse a este equipo desde que arrancó el monitor."
    : "Inicia el monitor para ver quién intenta conectarse a este equipo.";
}

function alertRow(a) {
  const ports = a.ports ? a.ports.split(",") : [];
  const hosts = a.hosts ? a.hosts.split(",") : [];
  const scope = ports.length
    ? `<b>${ports.length}</b> puerto${ports.length === 1 ? "" : "s"}<div class="ports">${esc(truncate(ports.join(", "), 80))}</div>`
    : `<b>${hosts.length}</b> equipos<div class="ports">${esc(truncate(hosts.join(", "), 80))}</div>`;
  return `<tr class="${a.acknowledged ? "acked" : ""}">
    <td><span class="pill sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
    <td>${esc(alertLabel(a.kind))}</td>
    <td><span class="ip">${esc(a.src)}</span>${a.src_name ? `<div class="sub">${esc(a.src_name)}</div>` : ""}</td>
    <td class="ip">${esc(a.dst || "red local")}</td>
    <td>${scope}</td>
    <td>${esc(a.count)}</td>
    <td class="small">${esc(a.note || "")}</td>
    <td class="small">${esc(fmtDate(a.first_seen))}<div class="sub">última ${esc(ago(a.last_seen))}</div></td>
    <td><div class="row">
      ${a.pcap ? `<a class="btn icon" href="/api/alerts/${a.id}/pcap" title="Descargar .pcap para abrir en Wireshark">pcap</a>` : ""}
      ${a.acknowledged ? "" : `<button class="icon" data-ack="${a.id}" title="Marcar como revisada">✓</button>`}
    </div></td>
  </tr>`;
}

async function toggleMonitor() {
  const btn = $("#mon-toggle");
  btn.disabled = true;
  try {
    if (state.monitor && state.monitor.running) {
      btn.textContent = "Deteniendo…";
      await api("/api/monitor/stop", { method: "POST", body: {} });
      toast("Monitor detenido");
    } else {
      btn.textContent = "Iniciando…";
      const body = {
        iface: $("#mon-iface").value,
        watch_all: $("#mon-watch-all").checked,
        save_pcap: $("#mon-save_pcap").checked,
        whitelist: $("#mon-whitelist").value,
      };
      for (const f of MON_FIELDS) body[f] = $(`#mon-${f}`).value;
      await api("/api/monitor/start", { method: "POST", body });
      toast("Monitor iniciado", "ok");
    }
  } catch (e) {
    toast(e.message, "error", 9000);
  } finally {
    btn.disabled = false;
    loadMonitor();
  }
}

// ---------------------------------------------------------------------------
// ajustes
// ---------------------------------------------------------------------------

async function loadSettings(silent) {
  if (silent && state.settingsLoaded) return;
  const [s, d] = await Promise.all([api("/api/settings"), api("/api/diagnostics")]);
  const f = $("#settings-form");
  f.nmap_path.value = s.nmap_path;
  f.max_parallel_jobs.value = s.max_parallel_jobs;
  f.dns_servers.value = s.dns_servers;
  f.system_dns.checked = s.system_dns;
  f.unprivileged.checked = s.unprivileged;
  state.settingsLoaded = true;
  renderDiag(d);
}

function renderDiag(d) {
  state.diag = d;
  renderSideStatus();
  updateSuggestions();
  const yes = (ok, text) => `<span class="${ok ? "good" : "bad"}">${esc(text)}</span>`;
  $("#diag").innerHTML = `
    ${d.tips.length ? `<div class="notice warn"><b>Recomendaciones</b><ul>${d.tips.map((t) => `<li>${esc(t)}</li>`).join("")}</ul></div>` : ""}
    <dl class="kv">
      <dt>nmap</dt><dd>${d.nmap_path ? yes(true, `${d.nmap_version || "?"} · ${d.nmap_path}`) : yes(false, "no encontrado")}</dd>
      <dt>Administrador</dt><dd>${d.admin ? yes(true, "sí") : esc("no")}</dd>
      ${d.npcap_admin_only === null ? "" : `<dt>Npcap sólo-admin</dt><dd>${d.npcap_admin_only ? "sí (pide UAC si no eres admin)" : "no"}</dd>`}
      <dt>Captura (monitor)</dt><dd>${yes(d.scapy_ok, d.scapy)}</dd>
      <dt>WSL</dt><dd>${d.wsl ? yes(false, "sí") : "no"}</dd>
      <dt>Equipo</dt><dd>${esc(d.hostname)}</dd>
      <dt>Redes locales</dt><dd>${d.networks.map((n) => `${esc(n.ip)} → <code>${esc(n.cidr)}</code> (${esc(n.iface)})`).join("<br>") || "—"}</dd>
      <dt>Sistema</dt><dd>${esc(d.platform)} · Python ${esc(d.python)}</dd>
      <dt>Versión</dt><dd>${esc(d.app_version)}</dd>
    </dl>`;
}

async function saveSettings(ev) {
  ev.preventDefault();
  const f = ev.target;
  await api("/api/settings", {
    method: "PATCH",
    body: {
      nmap_path: f.nmap_path.value.trim(),
      max_parallel_jobs: Number(f.max_parallel_jobs.value || 2),
      dns_servers: f.dns_servers.value.trim(),
      system_dns: f.system_dns.checked,
      unprivileged: f.unprivileged.checked,
    },
  });
  toast("Ajustes guardados", "ok");
  renderDiag(await api("/api/diagnostics"));
}

// ---------------------------------------------------------------------------
// ficha de equipo
// ---------------------------------------------------------------------------

async function openDevice(id) {
  state.openDevice = id;
  $("#finder-results").innerHTML = "";
  await refreshDrawer(true);
  $("#drawer").classList.remove("hidden");
  $("#drawer-backdrop").classList.remove("hidden");
}

function closeDrawer() {
  state.openDevice = null;
  $("#drawer").classList.add("hidden");
  $("#drawer-backdrop").classList.add("hidden");
}

async function refreshDrawer(force) {
  const id = state.openDevice;
  if (!id) return;
  const active = document.activeElement;
  if (!force && $("#drawer").contains(active) && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName)) return;
  let d;
  try { d = await api(`/api/devices/${id}`); } catch (e) { toast(e.message, "error"); closeDrawer(); return; }
  const profile = $("#dev-profile") ? $("#dev-profile").value : "rapido";
  $("#drawer").innerHTML = drawerHtml(d, profile);
}

function info(label, value, cls = "") {
  return `<div><span>${esc(label)}</span><b class="${cls}">${value}</b></div>`;
}

function distanceText(n) {
  if (n == null) return "—";
  if (n === 0) return "este mismo equipo";
  if (n === 1) return "1 salto · misma red local";
  return `${n} saltos`;
}

function drawerHtml(d, profile) {
  const short = (d.hostname || "").split(".")[0].toLowerCase();
  const names = [d.hostname, d.netbios && d.netbios.toLowerCase() !== short ? `NetBIOS ${d.netbios}` : ""].filter(Boolean);
  const sys = d.os_guess || (d.ttl_hint ? `${d.ttl_hint} (por TTL ${d.ttl})` : "—");
  const ports = d.ports.length ? `<table class="table"><thead><tr><th>Puerto</th><th>Servicio</th><th>Versión</th><th>Desde</th></tr></thead><tbody>
      ${d.ports.map((p) => `<tr><td class="ip">${esc(p.port)}/${esc(p.proto)}</td><td>${esc(p.service || "")}</td>
        <td class="small">${esc([p.product, p.version, p.extrainfo].filter(Boolean).join(" "))}</td>
        <td class="small" title="${esc(fmtDate(p.first_seen))}">${esc(ago(p.first_seen))}</td></tr>`).join("")}
    </tbody></table>`
    : `<p class="muted">${d.last_port_scan ? "Ningún puerto abierto en el último escaneo." : "Aún no se han escaneado sus puertos."}</p>`;
  const hops = d.trace.length ? `<section><h3>Ruta (traceroute) · ${d.trace.length} salto${d.trace.length === 1 ? "" : "s"}</h3><div class="hops">
      ${d.trace.map((h) => `<div class="hop"><b>${esc(h.ttl)}</b>
        <span><span class="ip">${esc(h.ip)}</span> <span class="sub">${esc(h.host || "")}</span></span>
        <span class="sub">${h.rtt != null ? `${esc(h.rtt)} ms` : ""}</span></div>`).join("")}</div></section>` : "";
  return `
    <div class="drawer-head">
      <div><h2>${esc(d.name)}</h2><div class="sub">${esc(names.join(" · "))}</div></div>
      <div class="row">
        <button class="star ${d.watched ? "on" : ""}" data-star="${d.id}" title="${d.watched ? "Dejar de vigilar" : "Vigilar"}">${d.watched ? "★" : "☆"}</button>
        <button class="ghost" data-close-drawer title="Cerrar (Esc)">✕</button>
      </div>
    </div>
    <div class="info-grid">
      ${info("IP actual", esc(d.current_ip || "—"), "ip")}
      ${info("Estado", statusHtml(d.status))}
      ${info("MAC", esc(d.mac || "—"), "mono")}
      ${info("Fabricante", esc(d.vendor || "—"))}
      ${info("Distancia", esc(distanceText(d.distance)))}
      ${info("Sistema", esc(sys))}
      ${info("Visto por primera vez", esc(fmtDate(d.first_seen)))}
      ${info("Última vez visto", esc(fmtDate(d.last_seen)))}
      ${info("Última respuesta", esc(fmtDate(d.last_up)))}
      ${info("Último escaneo de puertos", esc(fmtDate(d.last_port_scan)))}
    </div>
    <section><h3>Acciones</h3><div class="row wrap">
      <select id="dev-profile">${profileOptions(profile)}</select>
      <button class="primary" data-dev-scan="${d.id}" ${d.current_ip ? "" : "disabled"}>Escanear puertos</button>
      <button data-dev-trace="${d.id}" ${d.current_ip ? "" : "disabled"}>Traceroute</button>
      <button data-copy="${esc(d.current_ip || "")}" ${d.current_ip ? "" : "disabled"}>Copiar IP</button>
      <button class="danger" data-dev-del="${d.id}">Eliminar</button>
    </div></section>
    <section><h3>Alias y notas</h3>
      <form id="dev-form" data-id="${d.id}">
        <label class="field">Alias (el nombre con el que tú lo reconoces)
          <input name="alias" value="${esc(d.alias || "")}" placeholder="p. ej. PC de Juan (contabilidad)"></label>
        <label class="field">Notas<textarea name="notes" rows="2">${esc(d.notes || "")}</textarea></label>
        <button type="submit">Guardar</button>
      </form></section>
    <section><h3>Puertos abiertos (${d.ports.length})</h3>${ports}</section>
    ${hops}
    <section><h3>Historial de IPs</h3>
      <table class="table"><thead><tr><th>IP</th><th>Primera vez</th><th>Última vez</th><th>Respondió</th><th>Visto por</th></tr></thead><tbody>
        ${d.ip_history.map((h) => `<tr><td class="ip">${esc(h.ip)}${h.ip === d.current_ip ? " ←" : ""}</td>
          <td class="small">${esc(fmtDate(h.first_seen))}</td><td class="small">${esc(fmtDate(h.last_seen))}</td>
          <td class="small">${esc(h.last_up ? ago(h.last_up) : "nunca")}</td>
          <td class="small">${esc(SOURCE_LABEL[h.source] || h.source || "")}</td></tr>`).join("")}
      </tbody></table></section>
    <section><h3>Novedades</h3><div class="event-list">${eventsHtml(d.events)}</div></section>`;
}

// ---------------------------------------------------------------------------
// eventos
// ---------------------------------------------------------------------------

async function onClick(ev) {
  if (DESKTOP) {
    // Sin navegador no hay descargas: Python pregunta dónde guardar el fichero.
    const link = ev.target.closest('a[href^="/api/"]');
    if (link) {
      ev.preventDefault();
      desktopDownload(link.getAttribute("href")).catch((e) => toast(e.message, "error"));
      return;
    }
  }
  const t = ev.target.closest(
    "[data-select],[data-star],[data-ack],[data-cancel],[data-close-job],[data-close-drawer],[data-net-run]," +
    "[data-net-del],[data-net-load],[data-dev-scan],[data-dev-trace],[data-dev-del],[data-copy],[data-target]," +
    "[data-more],[data-quick],[data-device],[data-job]");
  if (!t) return;
  const ds = t.dataset;
  try {
    if (ds.select) {
      const id = Number(ds.select);
      if (t.checked) state.selected.add(id); else state.selected.delete(id);
      t.closest("tr").classList.toggle("selected", t.checked);
      updateSelectionBar();
    } else if (ds.star) {
      ev.preventDefault();
      const on = !t.classList.contains("on");
      await api(`/api/devices/${ds.star}`, { method: "PATCH", body: { watched: on } });
      toast(on ? "Equipo vigilado: aparecerá en el Panel" : "Ya no se vigila", "ok");
      if (state.openDevice) refreshDrawer(true);
      refreshView(true);
    } else if (ds.ack) {
      await api(`/api/alerts/${ds.ack}/ack`, { method: "POST", body: {} });
      loadMonitor();
    } else if (ds.cancel) {
      await api(`/api/jobs/${ds.cancel}/cancel`, { method: "POST", body: {} });
      toast("Cancelando…");
      state.jobDetailKey = "";
    } else if ("closeJob" in ds) {
      state.openJob = null;
      $("#job-detail").classList.add("hidden");
      history.replaceState(null, "", "#jobs");
      loadJobs();
    } else if ("closeDrawer" in ds) {
      closeDrawer();
    } else if (ds.netRun) {
      const r = await api(`/api/networks/${ds.netRun}/run`, { method: "POST", body: {} });
      toast(`Tarea #${r.job_id} en marcha`, "ok");
      loadNetworks();
    } else if (ds.netDel) {
      if (!confirm("¿Borrar esta red guardada?")) return;
      await api(`/api/networks/${ds.netDel}`, { method: "DELETE" });
      loadNetworks();
    } else if (ds.netLoad) {
      const net = state.networks.find((n) => n.id === Number(ds.netLoad));
      if (net) loadNetworkIntoForm(net);
    } else if (ds.devScan) {
      const jobId = await scanDevices([Number(ds.devScan)], "ports", { profile: $("#dev-profile").value, timing: "T4" });
      closeDrawer();
      location.hash = `#jobs/${jobId}`;
    } else if (ds.devTrace) {
      await scanDevices([Number(ds.devTrace)], "ping", { traceroute: true, timing: "T4" }, "Traceroute");
      toast("La ruta aparecerá en la ficha cuando termine la tarea");
    } else if (ds.devDel) {
      if (!confirm("¿Eliminar este equipo del inventario? (volverá a aparecer si se detecta de nuevo)")) return;
      await api(`/api/devices/${ds.devDel}`, { method: "DELETE" });
      closeDrawer();
      refreshView(false);
    } else if ("copy" in ds) {
      await copyText(ds.copy);
      toast(`Copiado: ${ds.copy}`, "ok");
    } else if (ds.target) {
      const input = state.view === "scan" ? $("#scan-targets") : $("#quick-target");
      input.value = ds.target;
      if (state.view === "scan") updatePreview();
    } else if (ds.more) {
      $("#hosts-q").value = ds.more;
      $("#finder-results").innerHTML = "";
      location.hash = "#hosts";
    } else if (ds.quick) {
      await quickAction(ds.quick);
    } else if (ds.device) {
      ev.preventDefault();
      await openDevice(Number(ds.device));
    } else if (ds.job) {
      location.hash = `#jobs/${ds.job}`;
      if (state.view === "jobs") { state.openJob = Number(ds.job); state.jobDetailKey = ""; loadJobs(); }
    }
  } catch (e) {
    toast(e.message, "error", 7000);
  }
}

function bind() {
  window.addEventListener("hashchange", route);
  document.addEventListener("click", onClick);
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && state.openDevice) closeDrawer(); });
  $("#drawer-backdrop").addEventListener("click", closeDrawer);

  $("#finder").addEventListener("input", finderSearch);
  $("#finder").addEventListener("keydown", finderKeys);
  document.addEventListener("click", (ev) => { if (!ev.target.closest(".finder")) $("#finder-results").innerHTML = ""; });
  try { $("#quick-target").value = recentTargets()[0] || ""; } catch { /* nada */ }

  const reloadHosts = debounce(() => loadHosts().catch((e) => toast(e.message, "error")), 200);
  $("#hosts-q").addEventListener("input", reloadHosts);
  for (const id of ["#hosts-status", "#hosts-watched", "#hosts-ports"]) $(id).addEventListener("change", reloadHosts);
  $("#import-file").addEventListener("change", (ev) => {
    importFiles([...ev.target.files]).catch((e) => toast(e.message, "error"));
    ev.target.value = "";
  });
  $("#sel-all").addEventListener("change", (ev) => {
    for (const d of state.hostsItems) {
      if (ev.target.checked) state.selected.add(d.id); else state.selected.delete(d.id);
    }
    $("#hosts-table tbody").innerHTML = state.hostsItems.map(hostRow).join("");
    updateSelectionBar();
  });
  const selIds = () => [...state.selected];
  const guard = (fn) => () => fn().catch((e) => toast(e.message, "error", 7000));
  $("#sel-scan").addEventListener("click", guard(async () => {
    const jobId = await scanDevices(selIds(), "ports", { profile: $("#sel-profile").value, timing: "T4" });
    location.hash = `#jobs/${jobId}`;
  }));
  $("#sel-trace").addEventListener("click", guard(async () => {
    await scanDevices(selIds(), "ping", { traceroute: true, timing: "T4" }, "Traceroute");
  }));
  $("#sel-watch").addEventListener("click", guard(async () => { await setWatched(selIds(), true); loadHosts(); }));
  $("#sel-unwatch").addEventListener("click", guard(async () => { await setWatched(selIds(), false); loadHosts(); }));
  $("#sel-clear").addEventListener("click", () => { state.selected.clear(); loadHosts(); });

  const form = $("#scan-form");
  form.addEventListener("submit", (ev) => submitScan(ev).catch((e) => toast(e.message, "error", 7000)));
  form.addEventListener("input", () => updatePreview());
  form.addEventListener("change", (ev) => { if (ev.target.name === "kind") updateModeOptions(); updatePreview(); });
  $("#net-save").addEventListener("click", guard(saveNetwork));
  document.addEventListener("change", (ev) => {
    const id = ev.target.dataset && ev.target.dataset.netInterval;
    if (!id) return;
    api(`/api/networks/${id}`, { method: "PATCH", body: { interval_min: Number(ev.target.value) } })
      .then(() => { toast("Programación actualizada", "ok"); loadNetworks(); })
      .catch((e) => toast(e.message, "error"));
  });

  $("#jobs-clear").addEventListener("click", guard(async () => {
    await api("/api/jobs", { method: "DELETE" });
    state.openJob = null;
    $("#job-detail").classList.add("hidden");
    loadJobs();
  }));

  $("#mon-toggle").addEventListener("click", toggleMonitor);
  $("#alerts-ack").addEventListener("click", guard(async () => {
    await api("/api/alerts/ack-all", { method: "POST", body: {} });
    loadMonitor();
  }));
  $("#alerts-clear").addEventListener("click", guard(async () => {
    if (!confirm("¿Borrar todas las alertas?")) return;
    await api("/api/alerts", { method: "DELETE" });
    loadMonitor();
  }));

  $("#settings-form").addEventListener("submit", (ev) => saveSettings(ev).catch((e) => toast(e.message, "error", 7000)));
  $("#diag-refresh").addEventListener("click", guard(async () => {
    renderDiag(await api("/api/diagnostics?refresh=1"));
    toast("Diagnóstico actualizado", "ok");
  }));
  $("#inventory-clear").addEventListener("click", guard(async () => {
    const answer = prompt("Esto borra todos los equipos, puertos e historial. Escribe BORRAR para confirmar:");
    if (answer !== "BORRAR") return;
    await api("/api/inventory?confirm=BORRAR", { method: "DELETE" });
    toast("Inventario borrado", "ok");
  }));

  document.addEventListener("submit", (ev) => {
    if (ev.target.id !== "dev-form") return;
    ev.preventDefault();
    const f = ev.target;
    api(`/api/devices/${f.dataset.id}`, { method: "PATCH", body: { alias: f.alias.value, notes: f.notes.value } })
      .then(() => { toast("Guardado", "ok"); f.querySelector("button").blur(); refreshDrawer(true); refreshView(true); })
      .catch((e) => toast(e.message, "error"));
  });
}

async function init() {
  bind();
  if (DESKTOP) {
    await new Promise((resolve) => {
      if (window.pywebview && window.pywebview.api) resolve();
      else window.addEventListener("pywebviewready", resolve, { once: true });
    });
  }
  state.ready = true;
  try {
    state.meta = await api("/api/meta");
  } catch (e) {
    toast(`No se puede contactar con el servidor: ${e.message}`, "error", 10000);
    return;
  }
  $("#scan-profile").innerHTML = profileOptions("rapido");
  $("#sel-profile").innerHTML = profileOptions("rapido");
  route();
  api("/api/diagnostics").then((d) => {
    state.diag = d;
    renderSideStatus();
    updateSuggestions();
    if (!d.nmap_path) toast("No se encuentra nmap: revisa «Ajustes».", "error", 10000);
  }).catch(() => {});
  api("/api/networks").then((n) => { state.networks = n; updateSuggestions(); }).catch(() => {});
  api("/api/summary").then(applyCounts).catch(() => {});
}

init();
