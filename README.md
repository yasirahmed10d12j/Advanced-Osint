# 🔍 Advanced OSINT

An all-in-one, browser-based OSINT workstation with a **live terminal-style scan log** and a **GUI report dashboard**. Built for security research, recon and portfolio demonstration — public/legal data sources only.

**Stack:** HTML/CSS/JS · Flask proxy (CORS-free) · Leaflet maps · zero paid APIs

## Features

| Module | What it does |
|---|---|
| 🌐 IP & Network | Geolocation (multi-API triangulation), Shodan InternetDB ports/CVEs, RDAP ownership, reverse DNS, **Tor exit-node check**, EXIF GPS from photos, WebRTC leak test |
| 🔎 Domain & DNS | A/AAAA/MX/TXT/NS/CNAME/SOA, RDAP/WHOIS, subdomains via crt.sh, Wayback history, website scraper, **A–F DNS security grade** (SPF/DMARC/DKIM/CAA/DNSSEC/wildcard) |
| 📧 Email | Gravatar, MX validation, disposable-domain check, SPF/DMARC infrastructure |
| 👤 Username | Auto-check on 11 APIs (GitHub, GitLab, Mastodon, HN, Chess.com, Reddit, Keybase, Dev.to, Codewars, npm, PyPI) **with per-platform status audit**, plus 40+ manual links |
| 📱 Phone | Country code + national number parsing, validation, OSINT links |
| 🪙 Crypto | BTC (Blockstream) and ETH (Blockchair) balances/transactions |
| 🎣 URL Threat | Phishing heuristics: typosquatting (Levenshtein + confusables), homograph/punycode, suspicious TLD, `@` tricks, IP-literal hosts, entropy, page-level login/urgency/brand-mismatch detection → risk score |
| 🗂️ Case Files | Save targets + notes locally (localStorage), search, export/import JSON, 50-scan history |

## Highlights

- **Live terminal log** — `→ GET api...`, `← 200 23ms`, per-module timers and `✓ OK / ✗ NO DATA` lines stream line-by-line during each scan so you always know what the tool is doing
- **GUI report cards** — key/value tiles, colored badges, link chips and status pills instead of a raw text dump; `.txt` report download still available
- **Local Flask proxy** — all API calls go server-side, so Edge/Chrome CORS blocking is a non-issue; SSRF guard blocks localhost/private networks
- **Honest limitations** — blocked APIs (e.g. Reddit/npm 403) and manual-only platforms are labeled explicitly instead of silently skipped

## Run

```bash
pip install flask
python server.py
```

Open **http://127.0.0.1:8899** and enter any IP, domain, email, phone, username, BTC/ETH address or name into the universal search box.

> `python -m http.server` also works for browsing, but API lookups need the Flask proxy (`server.py`) to avoid CORS issues.

## Tests

```bash
node test_terminal.js    # live log + GUI cards (jsdom)
node test_username.js    # auto-check status audit
node test_phone.js       # +91 country-code parsing
node test_advanced.js    # phishing detection heuristics
python verify_structure.py
```

## Ethics

Public data only. Use for authorized research, security audits and journalism. No stalking, harassment or doxxing. IP geolocation is ISP-gateway level — never exact street addresses.

---

*Cybersecurity portfolio project by Ahmed (yasirahmed10d12j).*
