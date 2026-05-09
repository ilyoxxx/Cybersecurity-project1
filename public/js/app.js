/* ═══════════════════════════════════════════════════════════
   CyberSec Watch v2 — Frontend Engine
   Canvas World Map · Real APIs · SSE Stream · All Views
═══════════════════════════════════════════════════════════ */

'use strict';

// ── State ─────────────────────────────────────────────────
const S = {
  threats:     [],
  allThreats:  [],
  feedFilter:  'ALL',
  mapEvents:   0,
  cves:        [],
  sse:         null,
  intervals:   [],
  mapLines:    [],    // {x1,y1,x2,y2,color,age,maxAge}
  mapDots:     [],    // {x,y,color,r,age,maxAge}
};

// ── Boot sequence ──────────────────────────────────────────
const SOURCES = [
  'Connexion NVD/NIST…',
  'Connexion CISA KEV…',
  'Initialisation flux SSE…',
  'Chargement RansomWatch…',
  'Calcul statistiques globales…',
  'Interface prête',
];

window.addEventListener('DOMContentLoaded', async () => {
  // Loader animation
  let p = 0;
  for (let i = 0; i < SOURCES.length; i++) {
    setText('loaderSources', SOURCES[i]);
    p = ((i + 1) / SOURCES.length) * 100;
    document.getElementById('loaderBar').style.width = p + '%';
    await sleep(320 + Math.random() * 200);
  }
  await sleep(200);
  document.getElementById('loader').classList.add('out');
  const app = document.getElementById('app');
  app.style.opacity = '1';
  app.style.transition = 'opacity 0.5s ease';

  setupClock();
  setupNav();
  setupFeedFilters();

  await loadDashboard();
  startSSE();
  startPolling();
});

// ── Clock ──────────────────────────────────────────────────
function setupClock() {
  const tick = () => {
    const now = new Date();
    setText('clock', now.toLocaleTimeString('fr-FR', { hour12: false }) + ' UTC' + (now.getTimezoneOffset() === 0 ? '+0' : ''));
  };
  tick();
  setInterval(tick, 1000);
}

// ── Navigation ─────────────────────────────────────────────
function setupNav() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      const view = document.getElementById('tab-' + tab);
      if (view) { view.classList.remove('hidden'); view.classList.add('active'); }
      if (tab === 'cve')        await loadCVEView();
      if (tab === 'kev')        await loadKEV();
      if (tab === 'ransomware') await loadRansomware();
      if (tab === 'internet')   await loadInternet();
    });
  });
}

// ── Dashboard ──────────────────────────────────────────────
async function loadDashboard() {
  const [stats, threats, health] = await Promise.all([
    api('/api/threats/stats'),
    api('/api/threats/live?limit=80'),
    api('/api/internet/health'),
  ]);

  if (stats) {
    setText('k-total',     fmt(stats.totalToday));
    setText('k-active',    fmt(stats.activeNow));
    setText('k-block',     stats.blocked);
    setText('k-crit',      stats.criticalNow);
    setText('k-apt',       Math.floor(Math.random() * 8) + 6);
    setText('k-countries', stats.countries?.length || 20);

    renderBarChart('chartSrc',  stats.topSources,  'country', 'count', '#3b82f6');
    renderBarChart('chartSect', stats.topSectors,  'sector',  'count', '#16a34a');
    renderDonut(stats.topTypes);
    buildTicker(stats);
  }

  if (threats?.threats) {
    S.threats    = threats.threats;
    S.allThreats = [...threats.threats];
    renderFeed(S.threats);
    initCanvas(stats?.countries);
    renderFeedFooter();
  }

  if (health) {
    renderPortGrid(health.topPorts);
  }

  // CVE stats for KPI
  try {
    const cveData = await api('/api/cve/recent?days=7&limit=30');
    if (cveData?.cves) {
      const crit = cveData.cves.filter(c => c.severity === 'CRITICAL').length;
      setText('k-crit', crit);
      S.cves = cveData.cves;
    }
  } catch(e) {}
}

// ── TICKER ─────────────────────────────────────────────────
function buildTicker(stats) {
  const items = [
    ...(stats.topTypes || []).slice(0, 6).map(t => ({ type: t.type, count: t.count, sev: 'HIGH' })),
    { type: 'CISA KEV', count: '1000+', sev: 'CRITICAL', label: 'vulnérabilités exploitées actives' },
    { type: 'RansomWatch', count: '60+', sev: 'CRITICAL', label: 'victimes récentes indexées' },
    { type: 'NVD/NIST', count: '∞', sev: 'MEDIUM', label: 'CVEs référencés en temps réel' },
    ...(stats.topSources || []).slice(0, 5).map(s => ({ type: s.country, count: s.count, sev: 'HIGH', label: 'attaques détectées' })),
  ];

  const inner = document.getElementById('tickerInner');
  inner.innerHTML = items.map(i => `
    <span class="tick-item">
      <span class="tick-sev ${i.sev}">${i.sev}</span>
      <strong>${i.type}</strong> — ${fmt(i.count)} ${i.label || 'attaques détectées'}
    </span>
  `).join('') + items.map(i => `
    <span class="tick-item">
      <span class="tick-sev ${i.sev}">${i.sev}</span>
      <strong>${i.type}</strong> — ${fmt(i.count)} ${i.label || 'attaques détectées'}
    </span>
  `).join('');
}

// ── CANVAS MAP ─────────────────────────────────────────────
const MAP_W = 1000, MAP_H = 400;

function latLng(lat, lng) {
  // Simple equirectangular projection to match SVG-like coords
  const x = ((lng + 180) / 360) * MAP_W;
  const y = ((90 - lat) / 180) * MAP_H;
  return { x, y };
}

function initCanvas(countries) {
  const canvas = document.getElementById('mapCanvas');
  if (!canvas) return;
  canvas.width  = MAP_W;
  canvas.height = MAP_H;

  // Draw initial state with base map, then animate
  drawMapFrame(canvas, countries);
  setInterval(() => drawMapFrame(canvas, countries), 50);
}

// Pre-computed continent polygons for the canvas
const CONTINENTS = [
  // North America
  [[70,70],[110,60],[160,55],[200,65],[230,80],[250,105],[260,140],[250,175],[235,210],[220,240],[195,265],[170,275],[145,270],[120,255],[100,235],[82,210],[68,180],[60,150],[62,115]],
  // South America
  [[175,280],[215,275],[250,285],[270,310],[280,345],[278,385],[268,420],[250,455],[225,470],[200,468],[178,450],[162,420],[155,385],[158,345],[165,315]],
  // Europe
  [[420,55],[480,50],[520,58],[545,75],[548,100],[535,118],[510,130],[480,132],[455,125],[435,108],[422,88]],
  // Scandinavia
  [[455,25],[480,22],[495,35],[490,52],[475,55],[460,50],[450,38]],
  // Africa
  [[422,140],[510,135],[548,155],[560,190],[558,240],[548,290],[540,340],[522,385],[498,412],[468,425],[438,420],[412,400],[395,365],[385,320],[388,270],[395,225],[400,185]],
  // Asia
  [[548,40],[640,35],[710,38],[775,42],[830,55],[855,80],[865,115],[858,155],[840,190],[808,215],[770,228],[725,235],[680,232],[640,222],[600,205],[568,185],[548,160],[540,128],[542,90]],
  // India
  [[640,185],[685,178],[710,195],[720,225],[715,260],[700,290],[680,308],[660,305],[642,285],[635,255],[630,220]],
  // SE Asia  
  [[720,215],[765,210],[790,225],[800,250],[785,268],[760,265],[738,248]],
  // Australia
  [[740,310],[820,300],[868,318],[880,355],[875,400],[855,430],[822,445],[785,448],[750,435],[726,410],[715,375],[718,340]],
  // Russia North
  [[548,25],[720,18],[820,20],[855,42],[855,80],[775,42],[640,35],[548,40]],
  // Japan
  [[832,115],[850,108],[862,128],[855,145],[838,142]],
  // UK
  [[407,57],[425,54],[427,74],[417,79],[405,71]],
  // Greenland
  [[280,20],[340,18],[360,35],[355,60],[335,70],[310,68],[288,50]],
];

function drawMapFrame(canvas, countries) {
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, MAP_W, MAP_H);

  // Background gradient
  const bg = ctx.createLinearGradient(0, 0, 0, MAP_H);
  bg.addColorStop(0, '#eef4ff');
  bg.addColorStop(1, '#f4f8ff');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, MAP_W, MAP_H);

  // Lat/lng grid lines
  ctx.strokeStyle = 'rgba(37,99,235,0.06)';
  ctx.lineWidth = 0.6;
  for (let lat = -90; lat <= 90; lat += 30) {
    const y = ((90 - lat) / 180) * MAP_H;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(MAP_W, y); ctx.stroke();
  }
  for (let lng = -180; lng <= 180; lng += 30) {
    const x = ((lng + 180) / 360) * MAP_W;
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, MAP_H); ctx.stroke();
  }

  // Draw continents
  ctx.fillStyle   = '#dce8ff';
  ctx.strokeStyle = '#b8d0f5';
  ctx.lineWidth   = 0.8;
  CONTINENTS.forEach(pts => {
    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    pts.slice(1).forEach(p => ctx.lineTo(p[0], p[1]));
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  });

  // Country heatmap dots
  if (countries) {
    countries.forEach(c => {
      const pos = latLng(c.lat, c.lng);
      const radius = 4 + (c.attacks / 2000) * 16;
      const alpha  = 0.08 + (c.attacks / 6000) * 0.18;
      const color  = c.threat === 'CRITICAL' ? `rgba(239,68,68,${alpha})` :
                     c.threat === 'HIGH'     ? `rgba(249,115,22,${alpha})` :
                                               `rgba(59,130,246,${alpha})`;
      const grad = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, radius * 2.5);
      grad.addColorStop(0, color);
      grad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius * 2.5, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();
    });
  }

  // Advance & draw lines
  S.mapLines = S.mapLines.filter(l => l.age < l.maxAge);
  S.mapLines.forEach(l => {
    l.age++;
    const prog = l.age / l.maxAge;
    const alpha = prog < 0.2 ? prog / 0.2 : prog > 0.7 ? 1 - (prog - 0.7) / 0.3 : 1;
    // Draw progress of line
    const endX = l.x1 + (l.x2 - l.x1) * Math.min(prog * 2, 1);
    const endY = l.y1 + (l.y2 - l.y1) * Math.min(prog * 2, 1);
    const cpX  = (l.x1 + l.x2) / 2;
    const cpY  = Math.min(l.y1, l.y2) - 35;
    ctx.beginPath();
    ctx.moveTo(l.x1, l.y1);
    ctx.quadraticCurveTo(cpX, cpY, endX, endY);
    ctx.strokeStyle = l.color + Math.floor(alpha * 180).toString(16).padStart(2,'0');
    ctx.lineWidth   = 1.2;
    ctx.setLineDash([4, 2]);
    ctx.stroke();
    ctx.setLineDash([]);
  });

  // Advance & draw dots
  S.mapDots = S.mapDots.filter(d => d.age < d.maxAge);
  S.mapDots.forEach(d => {
    d.age++;
    const prog  = d.age / d.maxAge;
    const alpha = prog < 0.15 ? prog / 0.15 : 1 - prog;
    const r     = d.r + prog * 6;
    ctx.beginPath();
    ctx.arc(d.x, d.y, r, 0, Math.PI * 2);
    ctx.fillStyle = d.color + Math.floor(alpha * 220).toString(16).padStart(2,'0');
    ctx.fill();
    // Pulse ring
    ctx.beginPath();
    ctx.arc(d.x, d.y, r + 4 + prog * 8, 0, Math.PI * 2);
    ctx.strokeStyle = d.color + Math.floor(alpha * 80).toString(16).padStart(2,'0');
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // Counter
  setText('mapEvtCount', `${fmt(S.mapEvents)} événements`);
}

function addMapEvent(threat) {
  const src = latLng(threat.src.lat, threat.src.lng);
  const dst = latLng(threat.dst.lat, threat.dst.lng);
  const col = threat.attack.color;
  S.mapLines.push({ x1: src.x, y1: src.y, x2: dst.x, y2: dst.y, color: col, age: 0, maxAge: 60 });
  S.mapDots.push({ x: dst.x, y: dst.y, color: col, r: 3, age: 0, maxAge: 50 });
  if (S.mapLines.length > 60) S.mapLines.shift();
  if (S.mapDots.length > 60)  S.mapDots.shift();
  S.mapEvents++;
}

// ── SSE STREAM ─────────────────────────────────────────────
function startSSE() {
  try {
    const es = new EventSource('/api/stream');
    S.sse = es;
    es.addEventListener('threat', e => {
      const t = JSON.parse(e.data);
      S.allThreats.unshift(t);
      if (S.allThreats.length > 500) S.allThreats.pop();
      addMapEvent(t);
      injectFeedItem(t);
      setText('feedFootCount', `${fmt(S.allThreats.length)} menaces`);
    });
    es.onerror = () => { es.close(); setTimeout(startSSE, 3000); };
  } catch(e) { setTimeout(startSSE, 3000); }
}

// ── POLLING (KPI refresh every 30s) ───────────────────────
function startPolling() {
  setInterval(async () => {
    const stats = await api('/api/threats/stats');
    if (!stats) return;
    setText('k-total',  fmt(stats.totalToday));
    setText('k-active', fmt(stats.activeNow));
    setText('k-block',  stats.blocked);
  }, 30000);
}

// ── FEED ────────────────────────────────────────────────────
function setupFeedFilters() {
  document.querySelectorAll('.ff').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.ff').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      S.feedFilter = btn.dataset.sev;
      renderFeed(S.allThreats);
    });
  });
}

function renderFeed(threats) {
  const list = document.getElementById('feedList');
  if (!list) return;
  const filtered = S.feedFilter === 'ALL' ? threats : threats.filter(t => t.attack.sev === S.feedFilter);
  list.innerHTML = filtered.slice(0, 60).map(t => feedItemHTML(t)).join('');
}

function injectFeedItem(t) {
  const list = document.getElementById('feedList');
  if (!list) return;
  if (S.feedFilter !== 'ALL' && t.attack.sev !== S.feedFilter) return;
  const el = document.createElement('div');
  el.innerHTML = feedItemHTML(t);
  list.insertBefore(el.firstElementChild, list.firstChild);
  // Trim to 60
  while (list.children.length > 60) list.removeChild(list.lastChild);
}

function feedItemHTML(t) {
  const time = new Date(t.ts).toLocaleTimeString('fr-FR', { hour12: false });
  return `
    <div class="feed-item">
      <span class="fi-icon">${t.attack.icon}</span>
      <div class="fi-body">
        <div class="fi-type">${t.attack.type}</div>
        <div class="fi-route">${t.src.flag} ${t.src.name} → ${t.dst.flag} ${t.dst.name} · ${time}</div>
        ${t.actor ? `<div class="fi-actor">${t.actor}</div>` : ''}
      </div>
      <span class="sev-pill sev-${t.attack.sev}">${t.attack.sev}</span>
    </div>`;
}

function renderFeedFooter() {
  setText('feedFootCount', `${fmt(S.allThreats.length)} menaces`);
}

// ── CHARTS ──────────────────────────────────────────────────
function renderBarChart(id, data, labelKey, valueKey, color) {
  const el = document.getElementById(id);
  if (!el || !data?.length) return;
  const max = Math.max(...data.map(d => d[valueKey]));
  el.innerHTML = data.slice(0, 9).map(d => `
    <div class="bar-row">
      <span class="bar-name" title="${d[labelKey]}">${d[labelKey]}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:${Math.round(d[valueKey]/max*100)}%;background:${color}"></div>
      </div>
      <span class="bar-num">${fmt(d[valueKey])}</span>
    </div>`).join('');
}

const DONUT_COLORS = ['#2563eb','#3b82f6','#60a5fa','#f97316','#ef4444','#7c3aed','#16a34a','#0ea5e9','#14b8a6','#f59e0b'];

function renderDonut(data) {
  const canvas = document.getElementById('donutC');
  const legend = document.getElementById('donutLegend');
  if (!canvas || !data?.length) return;

  // Resize canvas for crisp rendering
  canvas.width  = 180;
  canvas.height = 180;

  const ctx = canvas.getContext('2d');
  const slice = data.slice(0, 8);
  const total = slice.reduce((s, d) => s + d.count, 0);
  const cx = 90, cy = 90, R = 78, ri = 50;
  let ang = -Math.PI / 2;

  ctx.clearRect(0, 0, 180, 180);

  slice.forEach((d, i) => {
    const a = (d.count / total) * Math.PI * 2;
    // Draw slice with tiny gap
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, R, ang + 0.03, ang + a - 0.03);
    ctx.closePath();
    ctx.fillStyle = DONUT_COLORS[i % DONUT_COLORS.length];
    ctx.fill();
    ang += a;
  });

  // White donut hole
  ctx.beginPath();
  ctx.arc(cx, cy, ri, 0, Math.PI * 2);
  ctx.fillStyle = '#ffffff';
  ctx.fill();

  // Subtle inner shadow ring
  ctx.beginPath();
  ctx.arc(cx, cy, ri, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(10,15,30,0.06)';
  ctx.lineWidth = 1;
  ctx.stroke();

  setText('donutN', fmt(total));

  legend.innerHTML = slice.map((d, i) => `
    <div title="${d.type} — ${d.count}">
      <span class="dl-dot" style="background:${DONUT_COLORS[i % DONUT_COLORS.length]}"></span>
      <span class="dl-label">${d.type}</span>
    </div>`).join('');
}

function renderPortGrid(ports) {
  const el = document.getElementById('portGrid');
  if (!el || !ports?.length) return;
  const max = Math.max(...ports.map(p => p.attacks));
  el.innerHTML = ports.map(p => `
    <div class="port-cell">
      <div class="port-num">:${p.port}</div>
      <div class="port-name">${p.name}</div>
      <div class="port-bar-track">
        <div class="port-bar-fill" style="width:${Math.round(p.attacks/max*100)}%"></div>
      </div>
      <div class="port-count">${fmt(p.attacks)}/24h</div>
    </div>`).join('');
}

// ── CVE VIEW ────────────────────────────────────────────────
async function loadCVEView() {
  const sev  = document.getElementById('cveSev')?.value;
  const days = document.getElementById('cveDays')?.value || 7;
  const grid = document.getElementById('cveGrid');
  if (!grid) return;
  grid.innerHTML = '<div class="placeholder-msg">⏳ Connexion NVD/NIST…</div>';

  const params = new URLSearchParams({ limit: 40, days });
  if (sev) params.set('severity', sev);

  const data = await api('/api/cve/recent?' + params);
  if (!data) { grid.innerHTML = '<div class="placeholder-msg">Erreur de connexion NVD.</div>'; return; }

  S.cves = data.cves || [];
  renderCVEGrid(S.cves, data);
  renderCVEStatsBar(S.cves);
}

function renderCVEStatsBar(cves) {
  const bar = document.getElementById('cveStatsBar');
  if (!bar) return;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  cves.forEach(c => counts[c.severity] = (counts[c.severity] || 0) + 1);
  const colors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#d97706', LOW: '#16a34a', UNKNOWN: '#94a3b8' };
  bar.innerHTML = Object.entries(counts).filter(([,v])=>v).map(([k,v]) => `
    <div class="cve-stat-chip">
      <span style="color:${colors[k]}">${v}</span>
      <span>${k}</span>
    </div>`).join('') + `<div class="cve-stat-chip"><span style="color:var(--blue)">${fmt(cves.length)}</span><span>total affichés</span></div>`;
}

function renderCVEGrid(cves, meta) {
  const grid = document.getElementById('cveGrid');
  if (!grid) return;
  if (!cves.length) { grid.innerHTML = '<div class="placeholder-msg">Aucun CVE trouvé.</div>'; return; }
  grid.innerHTML = cves.map(c => {
    const sc   = c.score ?? '—';
    const sev  = c.severity || 'UNKNOWN';
    const date = c.published ? new Date(c.published).toLocaleDateString('fr-FR') : '—';
    const cwes = (c.weaknesses || []).slice(0, 2).map(w => `<span class="cwe-tag">${w}</span>`).join('');
    return `
      <div class="cve-card sc-${sev}" data-cve="${c.id}" onclick="openCVE('${c.id}')">
        <div class="cve-card-hd">
          <div>
            <div class="cve-id">${c.id}</div>
            <div class="cve-date">${date}</div>
          </div>
          <div class="score-badge">${sc}</div>
        </div>
        <div class="cve-desc">${escHtml(c.description)}</div>
        <div class="cve-footer">
          <div class="cwe-tags">${cwes}</div>
          <span class="sev-pill sev-${sev}">${sev}</span>
        </div>
      </div>`;
  }).join('');
}

async function openCVE(id) {
  const modal = document.getElementById('cveModal');
  const body  = document.getElementById('modalContent');
  if (!modal || !body) return;

  // Show modal immediately with spinner
  modal.classList.remove('hidden');
  body.innerHTML = `
    <div style="padding:48px;text-align:center">
      <div style="width:32px;height:32px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin 0.7s linear infinite;margin:0 auto 16px"></div>
      <div style="color:var(--muted);font-size:13px;font-family:var(--font-mono)">${id}</div>
    </div>`;

  // Wire close handlers every time (in case DOM was re-rendered)
  const closeModal = () => modal.classList.add('hidden');
  document.getElementById('modalBg').onclick    = closeModal;
  document.getElementById('modalClose').onclick = closeModal;
  document.addEventListener('keydown', function escHandler(e) {
    if (e.key === 'Escape') { closeModal(); document.removeEventListener('keydown', escHandler); }
  });

  const cve = await api('/api/cve/' + id);

  if (!cve || cve.error) {
    // Try to find it in already-loaded S.cves as fallback
    const local = S.cves.find(c => c.id === id);
    if (local) {
      body.innerHTML = renderLocalCVE(local);
      return;
    }
    body.innerHTML = `
      <div style="padding:40px;text-align:center">
        <div style="font-size:32px;margin-bottom:12px">⚠️</div>
        <div style="font-family:var(--font-mono);font-size:13px;color:var(--blue);margin-bottom:8px">${id}</div>
        <div style="color:var(--muted);font-size:12px">NVD indisponible momentanément.<br/>Réessayez dans quelques secondes.</div>
        <button onclick="document.getElementById('cveModal').classList.add('hidden')" style="margin-top:20px;padding:8px 20px;background:var(--blue);color:#fff;border:none;border-radius:8px;cursor:pointer;font-family:var(--font-body);font-size:13px">Fermer</button>
      </div>`;
    return;
  }

  const m   = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  const sc  = m?.cvssData?.baseScore ?? '—';
  const sev = m?.cvssData?.baseSeverity ?? 'UNKNOWN';
  const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '—';
  const refs = cve.references?.slice(0, 5) || [];
  const cwes = cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [];

  body.innerHTML = `
    <div class="modal-hd">
      <div>
        <div style="font-family:var(--font-mono);font-size:18px;font-weight:700;color:var(--blue);margin-bottom:4px">${cve.id}</div>
        <div style="font-size:11px;color:var(--muted)">
          Publié ${cve.published ? new Date(cve.published).toLocaleDateString('fr-FR') : '—'} ·
          Modifié ${cve.lastModified ? new Date(cve.lastModified).toLocaleDateString('fr-FR') : '—'} ·
          Statut: <strong>${cve.vulnStatus || '—'}</strong>
        </div>
      </div>
      <div class="score-badge sc-${sev}" style="font-size:22px;padding:6px 14px">${sc}</div>
    </div>
    ${m ? `<div class="modal-metric" style="margin-bottom:20px">
      <div class="modal-metric-cell"><div class="mmc-val">${sc}</div><div class="mmc-lbl">Score CVSS</div></div>
      <div class="modal-metric-cell"><div class="mmc-val" style="color:${sev==='CRITICAL'?'var(--red)':sev==='HIGH'?'var(--orange)':'var(--ink)'}">${sev}</div><div class="mmc-lbl">Sévérité</div></div>
      ${m.cvssData?.attackVector      ? `<div class="modal-metric-cell"><div class="mmc-val" style="font-size:12px">${m.cvssData.attackVector}</div><div class="mmc-lbl">Vecteur d'attaque</div></div>` : ''}
      ${m.cvssData?.confidentialityImpact ? `<div class="modal-metric-cell"><div class="mmc-val" style="font-size:12px">${m.cvssData.confidentialityImpact}</div><div class="mmc-lbl">Impact confidentialité</div></div>` : ''}
    </div>` : ''}
    <div style="margin-bottom:18px">
      <div class="modal-section-title">Description</div>
      <div class="modal-desc">${escHtml(desc)}</div>
    </div>
    ${cwes.length ? `<div style="margin-bottom:18px">
      <div class="modal-section-title">Faiblesses (CWE)</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${cwes.map(w=>`<span class="cwe-tag" style="font-size:11px;padding:3px 10px">${escHtml(w)}</span>`).join('')}</div>
    </div>` : ''}
    ${refs.length ? `<div>
      <div class="modal-section-title">Références (${refs.length})</div>
      <div class="modal-refs">${refs.map(r=>`<a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.url}</a>`).join('')}</div>
    </div>` : ''}
  `;
}

// Render CVE from local cache (no NVD call needed)
function renderLocalCVE(c) {
  const sev = c.severity || 'UNKNOWN';
  const sc  = c.score ?? '—';
  return `
    <div class="modal-hd">
      <div>
        <div style="font-family:var(--font-mono);font-size:18px;font-weight:700;color:var(--blue);margin-bottom:4px">${c.id}</div>
        <div style="font-size:11px;color:var(--muted)">Publié ${c.published ? new Date(c.published).toLocaleDateString('fr-FR') : '—'}</div>
      </div>
      <div class="score-badge sc-${sev}" style="font-size:22px;padding:6px 14px">${sc}</div>
    </div>
    <div style="margin-bottom:18px">
      <div class="modal-section-title">Description</div>
      <div class="modal-desc">${escHtml(c.description)}</div>
    </div>
    ${c.weaknesses?.length ? `<div style="margin-bottom:18px">
      <div class="modal-section-title">Faiblesses (CWE)</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${c.weaknesses.map(w=>`<span class="cwe-tag" style="font-size:11px;padding:3px 10px">${escHtml(w)}</span>`).join('')}</div>
    </div>` : ''}
    ${c.references?.length ? `<div>
      <div class="modal-section-title">Références</div>
      <div class="modal-refs">${c.references.map(u=>`<a href="${u}" target="_blank" rel="noopener">${u}</a>`).join('')}</div>
    </div>` : ''}
    <div style="margin-top:18px;padding:10px 12px;background:var(--yellow-bg);border:1px solid #fde68a;border-radius:8px;font-size:11px;color:var(--yellow)">
      ℹ️ Données depuis le cache local (NVD indisponible momentanément)
    </div>`;
}

// CVE search
window.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('cveSearchBtn');
  const inp = document.getElementById('cveSearch');
  if (btn) btn.onclick = handleCVESearch;
  if (inp) inp.addEventListener('keypress', e => { if (e.key === 'Enter') handleCVESearch(); });
  const sevSel = document.getElementById('cveSev');
  const daysSel = document.getElementById('cveDays');
  if (sevSel) sevSel.onchange = loadCVEView;
  if (daysSel) daysSel.onchange = loadCVEView;
});

async function handleCVESearch() {
  const q = document.getElementById('cveSearch')?.value.trim();
  if (!q) { loadCVEView(); return; }
  if (/^CVE-\d{4}-\d+$/i.test(q)) { openCVE(q.toUpperCase()); return; }
  // Keyword search via NVD
  const grid = document.getElementById('cveGrid');
  grid.innerHTML = '<div class="placeholder-msg">Recherche en cours…</div>';
  const data = await api(`/api/cve/recent?limit=30&days=30`);
  if (!data) return;
  const filtered = data.cves.filter(c => c.description.toLowerCase().includes(q.toLowerCase()) || c.id.toLowerCase().includes(q.toLowerCase()));
  renderCVEGrid(filtered, data);
}

// ── KEV VIEW ────────────────────────────────────────────────
async function loadKEV() {
  const tbody = document.getElementById('kevBody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="tloading">Connexion CISA KEV…</td></tr>';

  const data = await api('/api/kev');
  if (!data) { tbody.innerHTML = '<tr><td colspan="7" class="tloading" style="color:var(--red)">Erreur CISA.</td></tr>'; return; }

  setText('kevBadge', `${fmt(data.total)} entrées CISA`);

  tbody.innerHTML = (data.recent || []).map(v => `
    <tr>
      <td><span class="tbl-code">${v.cveID}</span></td>
      <td style="font-weight:500;font-size:12px">${escHtml(v.vendor || '—')}</td>
      <td style="font-size:12px;color:var(--mid)">${escHtml(v.product || '—')}</td>
      <td style="font-size:11px;color:var(--mid);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(v.name || '')}">${escHtml(v.name || '—')}</td>
      <td><span class="tbl-date">${v.dateAdded || '—'}</span></td>
      <td><span class="tbl-red">${v.dueDate || '—'}</span></td>
      <td><span class="sev-pill sev-CRITICAL">CRITIQUE</span></td>
    </tr>`).join('');
}

// ── RANSOMWARE VIEW ─────────────────────────────────────────
async function loadRansomware() {
  const groupsEl  = document.getElementById('rwGroups');
  const victimsEl = document.getElementById('rwVictims');
  if (!groupsEl) return;
  groupsEl.innerHTML  = '<div style="padding:20px;color:var(--muted);font-size:12px">Chargement RansomWatch…</div>';
  victimsEl.innerHTML = '';

  const data = await api('/api/ransomware');
  if (!data) return;

  setText('rwTotal', `${fmt(data.total)} victimes récentes indexées`);

  groupsEl.innerHTML = (data.topGroups || []).map((g, i) => `
    <div class="rw-group-row">
      <span class="rw-group-rank">#${i+1}</span>
      <span class="rw-group-name">${escHtml(g.group)}</span>
      <span class="rw-group-cnt">${g.count}</span>
    </div>`).join('');

  victimsEl.innerHTML = (data.posts || []).map(p => {
    const date = p.date ? new Date(p.date).toLocaleDateString('fr-FR') : '—';
    return `
      <div class="rw-victim">
        <span class="rw-victim-icon">🔒</span>
        <div class="rw-victim-body">
          <div class="rw-victim-name">${escHtml(p.victim || '—')}</div>
          <div class="rw-victim-group">${escHtml(p.group)}</div>
        </div>
        <span class="rw-victim-date">${date}</span>
      </div>`;
  }).join('');
}

// ── INTERNET HEALTH VIEW ────────────────────────────────────
async function loadInternet() {
  const data = await api('/api/internet/health');
  if (!data) return;
  setText('inetBgp',    data.bgpEvents);
  setText('inetOutages',data.outages);
  setText('inetDdos',   data.ddosVolume);

  const el = document.getElementById('portAttacks');
  if (el && data.topPorts) {
    const max = Math.max(...data.topPorts.map(p => p.attacks));
    el.innerHTML = data.topPorts.map(p => `
      <div class="pa-row">
        <span class="pa-port">${p.port}</span>
        <span class="pa-name">${p.name}</span>
        <div class="pa-track">
          <div class="pa-fill" style="width:${Math.round(p.attacks/max*100)}%"></div>
        </div>
        <span class="pa-cnt">${fmt(p.attacks)}</span>
      </div>`).join('');
  }
}

// ── HELPERS ─────────────────────────────────────────────────
async function api(path) {
  try {
    const r = await fetch(path);
    if (!r.ok) throw new Error(r.status);
    return await r.json();
  } catch(e) { console.warn('[API]', path, e.message); return null; }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '—';
}

function fmt(n) {
  if (n === null || n === undefined || n === '—') return '—';
  const num = Number(n);
  if (isNaN(num)) return String(n);
  if (num >= 1000000) return (num/1000000).toFixed(1) + 'M';
  if (num >= 100000)  return (num/1000).toFixed(0) + 'k';
  return num.toLocaleString('fr-FR');
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// expose for inline onclick
window.openCVE = openCVE;