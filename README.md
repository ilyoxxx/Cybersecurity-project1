
https://raw.githubusercontent.com/ilyoxxx/VEILLE-DE-cybers-curit-/4a3d620f89668fd3825f615d115646cbb48b1ae4/cybersec_watch_banner.svg

# 🛡️ CyberSec Watch v2

**Plateforme de veille mondiale en cybersécurité** — Dashboard temps réel sans authentification, connecté aux vraies APIs publiques mondiales.

---

## 🚀 Lancement en 30 secondes

```bash
npm install
npm start
# → http://localhost:3000
```

C'est tout. Aucune clé API requise.

---

## 🌍 Sources de données réelles

| Source | Endpoint | Données |
|--------|----------|---------|
| **NVD/NIST** | `services.nvd.nist.gov` | CVEs temps réel, scores CVSS |
| **CISA KEV** | `cisa.gov` | Vulnérabilités activement exploitées |
| **RansomWatch** | GitHub `joshhighet/ransomwatch` | Groupes ransomware & victimes |
| **Shodan/Censys** | Simulé honeypot-style | Ports exposés, stats exposition |
| **Live Threat Feed** | `/api/stream` SSE | Attaques mondiales en direct |

---

## 📡 API REST — tous les endpoints

```
GET  /api/cve/recent?days=7&severity=CRITICAL&limit=40   CVEs récents NVD
GET  /api/cve/:id                                         Détail CVE
GET  /api/kev                                             CISA KEV catalogue
GET  /api/ransomware                                      Groupes & victimes
GET  /api/threats/live?limit=80                           Attaques simulées
GET  /api/threats/stats                                   Statistiques globales
GET  /api/internet/health                                 Santé internet, BGP
GET  /api/stream                                          SSE flux temps réel
```

---

## 🖥️ Vues du dashboard

| Onglet | Contenu |
|--------|---------|
| **Dashboard** | Carte mondiale live, flux d'attaques, KPIs, graphiques |
| **CVE Database** | Bibliothèque NVD avec recherche, filtres, scores CVSS |
| **CISA KEV** | Catalogue officiel US des vulnérabilités exploitées |
| **Ransomware** | Top groupes actifs, victimes récentes indexées |
| **Internet** | Santé réseau mondial, BGP, DDoS, ports exposés |

---

## 🏗️ Architecture

```
cybersec-watch/
├── server.js          Express + toutes les routes API
├── public/
│   ├── index.html     SPA single-page
│   ├── css/style.css  Design system (Syne + JetBrains Mono)
│   └── js/app.js      Canvas map, SSE, fetch APIs, vues
└── package.json
```

---

## 🎨 Stack technique

- **Backend** : Node.js + Express, node-cache, axios, SSE
- **Frontend** : Vanilla JS ES6+, Canvas API (world map), CSS Grid
- **Typo** : Syne (display) · JetBrains Mono (données) · Outfit (corps)
- **Design** : Blanc/Bleu électrique, war room aesthetic

---

> ⭐ Fait pour les CVs. Montre des vraies compétences : API REST, SSE, Canvas, design système, intégration données publiques.
