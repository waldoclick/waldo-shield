# External Integrations

**Analysis Date:** 2026-03-16

## Target Platform (Scanned — Not Owned by This Tool)

This scanner tool itself has **no external service integrations**. It makes outbound HTTP/DNS/TCP connections only to the scan target. The external services below are the **waldo.click platform infrastructure** that the scanner assesses.

---

## APIs & External Services (Scan Targets)

**CDN / Proxy / Security:**
- Cloudflare — all traffic to `*.waldo.click` and `*.waldoclick.dev` passes through Cloudflare proxy
  - SSL certificates issued by Google Trust Services (managed by Cloudflare)
  - Cloudflare Zero Trust protects `dashboard.*` and `api.*/admin` (returns 302 redirects to `cloudflareaccess.com`)
  - Detection signature in `src/modules/tech_detection.py`: `cf-ray` header, `server: cloudflare`

**AI / Search (Strapi API endpoints on `api.*`):**
- Tavily — search API, endpoint `/api/search/tavily`
  - Restricted to `manager` role via Cloudflare Zero Trust
  - Not reachable from public internet

**Transactional Email:**
- Mailgun — sends from `@waldo.click` and `@waldoclick.dev` domains
  - SPF/DMARC records for these domains are verified by `src/modules/dns_analysis.py`

**Corporate Email:**
- Zoho — `contacto@waldo.click`
  - MX records checked by `src/modules/dns_analysis.py`

---

## Scanner Tool Outbound Connections

**HTTP (via `requests` library):**
- GET requests to scan target URLs — `src/modules/headers.py`, `src/modules/tech_detection.py`, `src/modules/vulnerabilities.py`
- OPTIONS requests for CORS testing — `src/modules/vulnerabilities.py`
- Probe URLs: `/admin`, `/admin/login`, `/.git/HEAD`, `/.env`, `/phpinfo.php`, etc. — `src/modules/vulnerabilities.py`

**DNS (via `dnspython` library):**
- A, AAAA, MX, NS, TXT, CAA, DNSKEY record queries — `src/modules/dns_analysis.py`
- AXFR (zone transfer) attempts against discovered nameservers — `src/modules/dns_analysis.py`

**TCP (via `socket` standard library):**
- Direct TCP port probing on 19 common ports — `src/modules/port_scan.py`
  - Ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis), 8080, 8443, 8888, 27017 (MongoDB)

**SSL/TLS (via `ssl` + `socket` standard libraries):**
- Direct TLS handshake to extract certificate metadata — `src/modules/ssl_tls.py`

---

## Data Storage

**Databases:**
- None — scanner does not use any database

**File Storage:**
- Local filesystem only — JSON reports written to `reports/` directory (gitignored)
  - Output path: `<hostname>_report_<timestamp>.json` (default) or custom via `--output`

**Caching:**
- None

## Authentication & Identity

**Auth Provider:**
- None — scanner is unauthenticated CLI tool
- Sends requests as a browser-spoofed User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0`

## Monitoring & Observability

**Error Tracking:**
- None — errors captured per-module and written into JSON report under `"error"` field

**Logs:**
- stdout only — progress printed during scan execution (`src/scanner.py: run_module()`)

## CI/CD & Deployment

**Hosting:**
- Not deployed — local CLI tool only

**CI Pipeline:**
- None detected

## Environment Configuration

**Required env vars:**
- None — no environment variables required or read by the scanner

**Secrets location:**
- None — scanner holds no secrets; `.env` is gitignored as precaution

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None — scanner only makes read-only probing requests; no webhooks

---

*Integration audit: 2026-03-16*
