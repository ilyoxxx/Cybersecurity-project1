require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const path      = require('path');
const axios     = require('axios');
const NodeCache = require('node-cache');

const app   = express();
const PORT  = process.env.PORT || 3000;
const cache = new NodeCache({ stdTTL: 300 });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ──────────────────────────────────────────────────────────────
//  REAL PUBLIC APIs (no auth required)
// ──────────────────────────────────────────────────────────────

// 1. NVD CVEs récents
app.get('/api/cve/recent', async (req, res) => {
  const { days = 7, severity, limit = 40 } = req.query;
  const key = `cve_${days}_${severity}_${limit}`;
  if (cache.has(key)) return res.json(cache.get(key));
  try {
    const start = new Date(Date.now() - days * 86400000).toISOString().split('.')[0] + '.000';
    const end   = new Date().toISOString().split('.')[0] + '.000';
    const params = { pubStartDate: start, pubEndDate: end, resultsPerPage: Math.min(+limit, 100) };
    if (severity) params.cvssV3Severity = severity.toUpperCase();
    const r = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params, timeout: 15000, headers: { 'User-Agent': 'CyberSecWatch/2.0' }
    });
    const cves = (r.data.vulnerabilities || []).map(v => {
      const c = v.cve;
      const m = c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0] || c.metrics?.cvssMetricV2?.[0];
      return {
        id: c.id,
        published: c.published,
        modified: c.lastModified,
        description: c.descriptions?.find(d => d.lang === 'en')?.value?.substring(0, 500) || '',
        score: m?.cvssData?.baseScore ?? null,
        severity: m?.cvssData?.baseSeverity ?? 'UNKNOWN',
        weaknesses: c.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [],
        references: c.references?.slice(0, 3).map(r => r.url) || [],
        vector: m?.cvssData?.vectorString || null,
      };
    });
    const out = { total: r.data.totalResults, cves, source: 'NVD/NIST', updatedAt: new Date().toISOString() };
    cache.set(key, out, 600);
    res.json(out);
  } catch(e) {
    console.error('[CVE]', e.message);
    res.json(fallbackCVEs(+limit));
  }
});

// 2. NVD CVE détail
app.get('/api/cve/:id', async (req, res) => {
  const { id } = req.params;
  if (!/^CVE-\d{4}-\d{4,}$/i.test(id)) return res.status(400).json({ error: 'Invalid CVE ID' });
  const key = `cve_d_${id}`;
  if (cache.has(key)) return res.json(cache.get(key));
  try {
    const r = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: { cveId: id }, timeout: 10000, headers: { 'User-Agent': 'CyberSecWatch/2.0' }
    });
    const v = r.data.vulnerabilities?.[0]?.cve;
    if (!v) return res.status(404).json({ error: 'Not found' });
    cache.set(key, v, 3600);
    res.json(v);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 3. CISA KEV — Known Exploited Vulnerabilities
app.get('/api/kev', async (req, res) => {
  if (cache.has('kev')) return res.json(cache.get('kev'));
  try {
    const r = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      timeout: 12000, headers: { 'User-Agent': 'CyberSecWatch/2.0' }
    });
    const vulns = (r.data.vulnerabilities || []).slice(0, 60).map(v => ({
      cveID: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      action: v.requiredAction,
      description: v.shortDescription,
    }));
    const out = {
      total: r.data.vulnerabilities?.length || 0,
      recent: vulns,
      catalogVersion: r.data.catalogVersion,
      dateReleased: r.data.dateReleased,
      source: 'CISA KEV'
    };
    cache.set('kev', out, 1800);
    res.json(out);
  } catch(e) {
    console.error('[KEV]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// 4. Ransomwatch (public GitHub raw)
app.get('/api/ransomware', async (req, res) => {
  if (cache.has('ransomware')) return res.json(cache.get('ransomware'));
  try {
    const r = await axios.get('https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', {
      timeout: 10000, headers: { 'User-Agent': 'CyberSecWatch/2.0' }
    });
    const posts = (r.data || [])
      .filter(p => p.discovered)
      .sort((a, b) => new Date(b.discovered) - new Date(a.discovered))
      .slice(0, 60)
      .map(p => ({
        group: p.group_name || 'Unknown',
        victim: p.post_title || '—',
        date: p.discovered,
        website: p.website || null,
      }));
    const groups = {};
    posts.forEach(p => groups[p.group] = (groups[p.group] || 0) + 1);
    const out = {
      total: posts.length,
      posts,
      topGroups: Object.entries(groups).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([g,c])=>({group:g,count:c})),
      source: 'RansomWatch/GitHub'
    };
    cache.set('ransomware', out, 900);
    res.json(out);
  } catch(e) {
    console.error('[RW]', e.message);
    res.json({ total: 0, posts: fallbackRansomware(), topGroups: [], source: 'Fallback' });
  }
});

// 5. Flux d'attaques live (simulation réaliste haute-fréquence)
app.get('/api/threats/live', (req, res) => {
  const { limit = 80 } = req.query;
  res.json(generateLiveThreats(+limit));
});

// 6. Stats agrégées
app.get('/api/threats/stats', (req, res) => {
  res.json(generateThreatStats());
});

// 7. Internet health
app.get('/api/internet/health', (req, res) => {
  res.json(generateInternetHealth());
});

// 8. SSE stream temps réel
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = () => {
    try {
      const t = generateSingleThreat();
      res.write(`event: threat\ndata: ${JSON.stringify(t)}\n\n`);
    } catch(e) {}
  };
  send();
  const iv = setInterval(send, 1500 + Math.random() * 2000);
  req.on('close', () => { clearInterval(iv); });
});

// Health
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ──────────────────────────────────────────────────────────────
//  DATA GENERATION
// ──────────────────────────────────────────────────────────────
const COUNTRIES = [
  { code:'CN', name:'Chine',          lat:35.86,  lng:104.19, flag:'🇨🇳', threat:'CRITICAL' },
  { code:'RU', name:'Russie',         lat:61.52,  lng:105.31, flag:'🇷🇺', threat:'CRITICAL' },
  { code:'US', name:'États-Unis',     lat:37.09,  lng:-95.71, flag:'🇺🇸', threat:'HIGH'     },
  { code:'KP', name:'Corée du Nord',  lat:40.33,  lng:127.51, flag:'🇰🇵', threat:'CRITICAL' },
  { code:'IR', name:'Iran',           lat:32.42,  lng:53.68,  flag:'🇮🇷', threat:'HIGH'     },
  { code:'BR', name:'Brésil',         lat:-14.23, lng:-51.92, flag:'🇧🇷', threat:'MEDIUM'   },
  { code:'IN', name:'Inde',           lat:20.59,  lng:78.96,  flag:'🇮🇳', threat:'MEDIUM'   },
  { code:'UA', name:'Ukraine',        lat:48.37,  lng:31.16,  flag:'🇺🇦', threat:'HIGH'     },
  { code:'NL', name:'Pays-Bas',       lat:52.13,  lng:5.29,   flag:'🇳🇱', threat:'MEDIUM'   },
  { code:'NG', name:'Nigéria',        lat:9.08,   lng:8.67,   flag:'🇳🇬', threat:'MEDIUM'   },
  { code:'DE', name:'Allemagne',      lat:51.16,  lng:10.45,  flag:'🇩🇪', threat:'LOW'      },
  { code:'GB', name:'Royaume-Uni',    lat:55.37,  lng:-3.43,  flag:'🇬🇧', threat:'LOW'      },
  { code:'FR', name:'France',         lat:46.22,  lng:2.21,   flag:'🇫🇷', threat:'LOW'      },
  { code:'JP', name:'Japon',          lat:36.20,  lng:138.25, flag:'🇯🇵', threat:'LOW'      },
  { code:'AU', name:'Australie',      lat:-25.27, lng:133.77, flag:'🇦🇺', threat:'LOW'      },
  { code:'CA', name:'Canada',         lat:56.13,  lng:-106.34,flag:'🇨🇦', threat:'LOW'      },
  { code:'SG', name:'Singapour',      lat:1.35,   lng:103.81, flag:'🇸🇬', threat:'MEDIUM'   },
  { code:'TR', name:'Turquie',        lat:38.96,  lng:35.24,  flag:'🇹🇷', threat:'MEDIUM'   },
  { code:'PL', name:'Pologne',        lat:51.91,  lng:19.14,  flag:'🇵🇱', threat:'LOW'      },
  { code:'KR', name:'Corée du Sud',   lat:35.90,  lng:127.76, flag:'🇰🇷', threat:'LOW'      },
];

const ATK_TYPES = [
  { type:'DDoS',              icon:'💥', sev:'HIGH',     color:'#f87171' },
  { type:'Ransomware',        icon:'🔒', sev:'CRITICAL', color:'#ef4444' },
  { type:'Phishing',          icon:'🎣', sev:'HIGH',     color:'#fb923c' },
  { type:'SQL Injection',     icon:'💉', sev:'CRITICAL', color:'#dc2626' },
  { type:'Brute Force',       icon:'🔨', sev:'MEDIUM',   color:'#fbbf24' },
  { type:'Malware C2',        icon:'🦠', sev:'CRITICAL', color:'#a78bfa' },
  { type:'Zero-Day',          icon:'💀', sev:'CRITICAL', color:'#be123c' },
  { type:'Supply Chain',      icon:'⛓️', sev:'CRITICAL', color:'#c2410c' },
  { type:'XSS/CSRF',          icon:'⚡', sev:'MEDIUM',   color:'#38bdf8' },
  { type:'Port Scan',         icon:'🔍', sev:'LOW',      color:'#94a3b8' },
  { type:'DNS Hijack',        icon:'🌐', sev:'HIGH',     color:'#3b82f6' },
  { type:'MITM',              icon:'👥', sev:'HIGH',     color:'#14b8a6' },
];

const APT = ['APT28','Lazarus','APT41','Sandworm','APT29','Equation','Turla','Kimsuky','FIN7','Cl0p'];
const SECTORS = ['Finance','Santé','Gouvernement','Énergie','Télécoms','Défense','Infrastructure','Pharma'];

let _tid = 0;

function rnd(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function generateSingleThreat() {
  const src = rnd(COUNTRIES);
  let dst; do { dst = rnd(COUNTRIES); } while (dst.code === src.code);
  const atk = rnd(ATK_TYPES);
  return {
    id:      `T${++_tid}`,
    ts:      new Date().toISOString(),
    src:     { ...src, lat: src.lat + (Math.random()-.5)*10, lng: src.lng + (Math.random()-.5)*10 },
    dst:     { ...dst, lat: dst.lat + (Math.random()-.5)*10, lng: dst.lng + (Math.random()-.5)*10 },
    attack:  atk,
    sector:  rnd(SECTORS),
    actor:   Math.random() < 0.12 ? rnd(APT) : null,
    blocked: Math.random() < 0.62,
    magnitude: Math.floor(Math.random()*100)+1,
  };
}

function generateLiveThreats(n) {
  return { threats: Array.from({length:n}, (_,i) => { const t=generateSingleThreat(); t.ts=new Date(Date.now()-(n-i)*5500).toISOString(); return t; }), generatedAt: new Date().toISOString() };
}

function generateThreatStats() {
  const bySev={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  const byType={}; const bySrc={}; const bySect={};
  for(let i=0;i<600;i++){
    const t=generateSingleThreat();
    bySev[t.attack.sev]=(bySev[t.attack.sev]||0)+1;
    byType[t.attack.type]=(byType[t.attack.type]||0)+1;
    bySrc[t.src.name]=(bySrc[t.src.name]||0)+1;
    bySect[t.sector]=(bySect[t.sector]||0)+1;
  }
  return {
    totalToday:   180000+Math.floor(Math.random()*80000),
    activeNow:    2000  +Math.floor(Math.random()*800),
    blocked:      (58+Math.random()*12).toFixed(1)+'%',
    criticalNow:  Math.floor(Math.random()*40)+20,
    bySeverity:   bySev,
    topTypes:     Object.entries(byType).sort((a,b)=>b[1]-a[1]).map(([k,v])=>({type:k,count:v})),
    topSources:   Object.entries(bySrc).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([k,v])=>({country:k,count:v})),
    topSectors:   Object.entries(bySect).sort((a,b)=>b[1]-a[1]).map(([k,v])=>({sector:k,count:v})),
    countries:    COUNTRIES.map(c=>({...c, attacks:Math.floor(Math.random()*(c.threat==='CRITICAL'?6000:c.threat==='HIGH'?3000:800))+50})),
  };
}

function generateInternetHealth() {
  return {
    bgpEvents:    Math.floor(Math.random()*18)+4,
    outages:      Math.floor(Math.random()*6)+1,
    ddosVolume:   `${(Math.random()*600+200).toFixed(0)} Gbps`,
    topPorts: [
      {port:22,  name:'SSH',    attacks:Math.floor(Math.random()*50000)+100000},
      {port:3389,name:'RDP',    attacks:Math.floor(Math.random()*40000)+80000},
      {port:80,  name:'HTTP',   attacks:Math.floor(Math.random()*30000)+60000},
      {port:443, name:'HTTPS',  attacks:Math.floor(Math.random()*25000)+50000},
      {port:23,  name:'Telnet', attacks:Math.floor(Math.random()*20000)+30000},
      {port:445, name:'SMB',    attacks:Math.floor(Math.random()*15000)+25000},
    ],
  };
}

function fallbackCVEs(n=40) {
  const sevs=['CRITICAL','CRITICAL','HIGH','HIGH','MEDIUM','LOW'];
  const vend=['Microsoft','Apache','OpenSSL','Linux Kernel','VMware','Cisco','Oracle','Fortinet','Palo Alto','Ivanti'];
  const type=['Buffer Overflow','RCE','SQL Injection','XSS','Privilege Escalation','Path Traversal','SSRF','Memory Corruption','Use-After-Free'];
  return { total:n, cves:Array.from({length:n},(_,i)=>{ const sev=rnd(sevs); const sc=sev==='CRITICAL'?(9+Math.random()).toFixed(1):sev==='HIGH'?(7+Math.random()*2).toFixed(1):sev==='MEDIUM'?(4+Math.random()*3).toFixed(1):(1+Math.random()*3).toFixed(1); return { id:`CVE-2024-${String(10000+i*317).padStart(5,'0')}`, published:new Date(Date.now()-Math.random()*7*86400000).toISOString(), score:parseFloat(sc), severity:sev, description:`${rnd(type)} vulnerability in ${rnd(vend)} allows remote attackers to execute arbitrary code, bypass security controls, or cause denial of service.`, weaknesses:[rnd(type)], references:[] }; }), source:'Fallback' };
}

function fallbackRansomware() {
  const groups=['LockBit 3.0','BlackCat/ALPHV','Cl0p','Black Basta','Play','Akira','8Base','Medusa','Rhysida','NoEscape'];
  return Array.from({length:20},(_,i)=>({ group:rnd(groups), victim:`company-target-${i+1}`, date:new Date(Date.now()-i*86400000*1.5).toISOString() }));
}

app.listen(PORT, () => console.log(`\n🛡️  CyberSec Watch v2 — http://localhost:${PORT}\n`));
module.exports = app;
