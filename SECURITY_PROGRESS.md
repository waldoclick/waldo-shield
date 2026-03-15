# Security Hardening Progress — waldo.click

**Last updated:** 2026-03-15  
**Scope:** api.waldoclick.dev · dashboard.waldoclick.dev · www.waldoclick.dev  
**Prod equivalents:** api.waldo.click · dashboard.waldo.click · www.waldo.click

---

## Baseline (2026-03-15 ~19:27)

First full scan of `api.waldoclick.dev` (all modules).

| Metric | Value |
|--------|-------|
| Risk Score | 47/100 |
| Risk Level | HIGH |
| Total Issues | 14 (0 critical, 0 high, 11 medium, 3 low) |

### Issues found at baseline

| # | Severity | Module | Issue |
|---|----------|--------|-------|
| 1 | MEDIUM | DNS | No SPF record |
| 2 | MEDIUM | DNS | No DMARC record |
| 3 | MEDIUM | Headers | Missing Permissions-Policy |
| 4 | MEDIUM | Headers | Missing Cache-Control |
| 5 | MEDIUM | Headers | Missing Cross-Origin-Embedder-Policy (COEP) |
| 6 | MEDIUM | Headers | Missing Cross-Origin-Opener-Policy (COOP) |
| 7 | MEDIUM | Headers | Missing Cross-Origin-Resource-Policy (CORP) |
| 8 | MEDIUM | SSL | Certificate expires in 38 days (auto-renewed by Cloudflare) |
| 9 | MEDIUM | Tech | Admin panel accessible at /admin (HTTP 200) |
| 10 | MEDIUM | Tech | Admin panel accessible at /admin/login (HTTP 200) |
| 11 | MEDIUM | Vulns | robots.txt publicly accessible |
| 12 | LOW | DNS | No CAA records |
| 13 | LOW | DNS | DNSSEC not enabled |
| 14 | LOW | Headers | Server header exposes: cloudflare |

---

## Fixes Applied

### 2026-03-15 — Cloudflare Response Headers Rule (staging + prod)

Added a Cloudflare Transform Rule → "Modify Response Header" applied to **All incoming requests**
on both `waldoclick.dev` and `waldo.click` zones.

| Header | Value | Resolves |
|--------|-------|---------|
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Issue #4 |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Issue #5 |
| `Cross-Origin-Opener-Policy` | `same-origin` | Issue #6 |
| `Cross-Origin-Resource-Policy` | `same-origin` | Issue #7 |
| `Permissions-Policy` | `camera=(self), microphone=(), geolocation=(), payment=(self), usb=(), interest-cohort=()` | Issue #3 |

**Verified via curl** — all 5 headers present in response.

### 2026-03-15 — Zero Trust Access Policy

Blocked public access to sensitive routes:

| Route | Status |
|-------|--------|
| `https://dashboard.waldoclick.dev` | Blocked via Cloudflare Zero Trust |
| `https://dashboard.waldo.click` | Blocked via Cloudflare Zero Trust |
| `https://api.waldoclick.dev/admin` | Blocked via Cloudflare Zero Trust |
| `https://api.waldo.click/admin` | Blocked via Cloudflare Zero Trust |

Resolves issues #9 and #10 (admin panels were HTTP 200 → now require Zero Trust auth).

### 2026-03-15 — SPF + DMARC (staging + prod)

| Domain | Record | Value |
|--------|--------|-------|
| `waldoclick.dev` | SPF | `v=spf1 include:mailgun.org -all` |
| `waldoclick.dev` | DMARC | `v=DMARC1; p=reject; adkim=s; aspf=s` |
| `waldo.click` | SPF | `v=spf1 include:zoho.com include:mailgun.org -all` |
| `waldo.click` | DMARC | `v=DMARC1; p=reject; rua=mailto:contacto@waldo.click; adkim=s; aspf=s` |

**Verified via DNS query** — todos propagados correctamente.

---

## Full Scan — All 6 URLs (2026-03-15 ~20:53)

### api.waldoclick.dev

| Metric | Before | After |
|--------|--------|-------|
| Risk Score | 47/100 | **1/100** |
| Risk Level | HIGH | **LOW** |
| Total Issues | 14 | **1** |

| Issue | Status |
|-------|--------|
| Missing Permissions-Policy | ✅ Fixed (Cloudflare header) |
| Missing Cache-Control | ✅ Fixed (Cloudflare header) |
| Missing COEP | ✅ Fixed (Cloudflare header) |
| Missing COOP | ✅ Fixed (Cloudflare header) |
| Missing CORP | ✅ Fixed (Cloudflare header) |
| Admin /admin accessible | ✅ Fixed (Zero Trust) |
| Admin /admin/login accessible | ✅ Fixed (Zero Trust) |
| No SPF record | ✅ Fixed (DNS) |
| No DMARC record | ✅ Fixed (DNS) |
| robots.txt accessible | ✅ Fixed (Zero Trust) |
| SSL cert expires in 38 days | ⚠️ Monitor — auto-renew by Cloudflare |
| No CAA records | ⏳ Pending |
| DNSSEC not enabled | ⏳ Pending |
| Server header exposes: cloudflare | ℹ️ No accionable |

### api.waldo.click

| Metric | Value |
|--------|-------|
| Risk Score | 47/100 |
| Risk Level | HIGH |
| Total Issues | 14 |

Mismo estado que `api.waldoclick.dev` antes de fixes. Los headers de Cloudflare aplican igual, pendiente verificar con scan post-fixes.

### www.waldoclick.dev

| Metric | Value |
|--------|-------|
| Risk Score | 57/100 (baseline) → **1/100** post headers |
| Risk Level | HIGH → **LOW** |

Headers confirmados presentes. Issue `phpinfo.php` es **falso positivo** — Nuxt devuelve 404 con ese titulo en la ruta, no hay PHP expuesto.

### www.waldo.click

| Metric | Value |
|--------|-------|
| Risk Score | 61/100 (baseline) |

Issue `phpinfo.php` es **falso positivo** — igual que www.waldoclick.dev, Nuxt renderiza 404.  
Pendiente: aplicar headers y verificar.

### dashboard.waldoclick.dev

Protegido por Zero Trust. Scanner no accede. ✅  
Issues de `.git/HEAD`, `.env`, `phpinfo.php` son **falsos positivos** — Zero Trust devuelve 302 al login, el scanner lo interpreta como accesible.

### dashboard.waldo.click

Protegido por Zero Trust. Scanner no accede. ✅  
Misma situación que dashboard.waldoclick.dev — falsos positivos del scanner.

---

## Falsos Positivos del Scanner

| URL | Issue reportado | Realidad |
|-----|----------------|----------|
| `dashboard.*.*/` `.env` | CRITICAL — .env expuesto | Zero Trust redirige a login (302) |
| `dashboard.*.*/` `.git/HEAD` | CRITICAL — Git repo expuesto | Zero Trust redirige a login (302) |
| `dashboard.*.*/` `phpinfo.php` | CRITICAL — PHP info expuesto | Zero Trust redirige a login (302) |
| `www.*.*/ phpinfo.php` | CRITICAL — PHP info expuesto | Nuxt devuelve 404 con ese titulo |

> El scanner necesita actualizar la logica de vulnerabilidades para ignorar respuestas 302 a Zero Trust y verificar el contenido real del 200.

---

## Remaining Issues (Pending)

| Priority | Issue | Aplica a | Action needed |
|----------|-------|----------|---------------|
| ⚠️ MEDIUM | SSL cert (38 dias) | ambos | Monitor — Cloudflare auto-renews |
| ⏳ LOW | No CAA records | ambos | Add CAA records en Cloudflare DNS |
| ⏳ LOW | DNSSEC not enabled | ambos | Toggle en Cloudflare DNS |
| ℹ️ LOW | Server header exposes cloudflare | ambos | No accionable |
