# AGENTS.md — waldo-shield

Context and instructions for AI agents working on this project.

---

## Project

Security vulnerability assessment tool for the waldo.click platform.  
Scans for issues and tracks remediation progress over time.

## Targets

| Environment | URLs |
|-------------|------|
| Staging | `api.waldoclick.dev` · `dashboard.waldoclick.dev` · `www.waldoclick.dev` |
| Prod | `api.waldo.click` · `dashboard.waldo.click` · `www.waldo.click` |

## Stack

- **API / CMS:** Strapi (Node.js) — `api.*`
- **Dashboard:** internal admin app — `dashboard.*` (protected by Cloudflare Zero Trust)
- **Frontend:** Nuxt.js — `www.*`
- **DNS / Proxy / Security:** Cloudflare
- **Transactional email:** Mailgun (sends from `@waldo.click` and `@waldoclick.dev`)
- **Corporate email:** Zoho — `contacto@waldo.click`

## Infrastructure Notes

- All traffic goes through Cloudflare proxy (orange cloud)
- `dashboard.*` and `api.*/admin` are protected by Cloudflare Zero Trust — scanner will get 302 redirects, not real content
- SSL certificates issued by Google Trust Services (not Let's Encrypt)
- Cloudflare auto-renews SSL certificates

## Scanner Usage

```bash
pip install -r src/requirements.txt

# Full scan
python src/scanner.py https://api.waldoclick.dev

# Headers only
python src/scanner.py https://api.waldoclick.dev --modules headers

# Custom output
python src/scanner.py https://api.waldoclick.dev --output reports/my_report.json
```

## Business Context (important for security assessment)

- **AI endpoints** (`/api/ia/*`, `/api/search/tavily`) — only used from `dashboard.*` by users with `manager` role. Protected by Cloudflare Zero Trust. SEC-004/028 from security-report.md are **not exploitable** from public internet.
- **Cron runner** (`/api/cron-runner/*`) — same, only triggered from dashboard by managers. SEC-005 severity is reduced by Zero Trust.
- **Images upload** — single request (not batched), safe for POST rate limiting rules.

---

## Known False Positives

| Issue | Reason |
|-------|--------|
| `.env` / `.git/HEAD` on `dashboard.*` | Zero Trust returns 302, scanner sees it as accessible |
| `phpinfo.php` on `www.*` | Nuxt returns 404 with "Phpinfo Php" as page title |
| Admin panel on `dashboard.*` | Zero Trust 302, not a real 200 |

## Sessions

Work sessions are logged in `sessions/YYYY-MM-DD.md`.  
Start each session by reading the latest session file to understand current state.

## Pending Work

See latest session file in `sessions/` for current pending items.
