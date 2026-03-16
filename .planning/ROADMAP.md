# Roadmap: waldo-shield

**Created:** 2026-03-16  
**Granularity:** Coarse  
**Core Value:** Visibilidad continua del estado de seguridad de waldo.click — staging y producción — sin intervención manual.

---

## Phases

- [ ] **Phase 1: Foundation & Config** - Environment-aware configuration and credential management
- [ ] **Phase 2: Data Collection** - DNS/email checks and Cloudflare API integration
- [ ] **Phase 3: Report & Delivery** - HTML report generation, email delivery, and cron operations

---

## Phase Details

### Phase 1: Foundation & Config

**Goal:** System can load environment-specific configuration and access external APIs securely

**Depends on:** Nothing (first phase)

**Requirements:** CONF-01, CONF-02

**Success Criteria** (what must be TRUE):
1. Running `python src/monitor.py --env staging` loads staging targets and recipients
2. Running `python src/monitor.py --env prod` loads production targets and recipients
3. API tokens are read from environment variables, never appear in code or logs

**Plans:** TBD

---

### Phase 2: Data Collection

**Goal:** System collects comprehensive security data from DNS records and Cloudflare API

**Depends on:** Phase 1 (needs config for API tokens and zone IDs)

**Requirements:** DNS-01, DNS-02, DNS-03, DNS-04, CF-01, CF-02, CF-03

**Success Criteria** (what must be TRUE):
1. Scanner outputs SPF, DKIM, and DMARC validation results for both domains
2. Scanner outputs CAA record validation showing expected CAs (pki.goog)
3. System retrieves WAF events from Cloudflare for both zones
4. System retrieves traffic analytics (total requests, blocked percentage) from Cloudflare
5. System retrieves configured rate limiting rules from Cloudflare

**Plans:** TBD

---

### Phase 3: Report & Delivery

**Goal:** System generates consolidated reports, delivers via email, and runs reliably as cron job

**Depends on:** Phase 2 (needs collected data for report)

**Requirements:** RPT-01, RPT-02, RPT-03, RPT-04, EMAIL-01, EMAIL-02, OPS-01, OPS-02

**Success Criteria** (what must be TRUE):
1. System generates HTML report containing all findings (scanner, DNS, Cloudflare)
2. Report shows executive summary with risk score, issue counts, and key metrics
3. Report highlights new issues and fixed issues compared to previous scan
4. Email is sent via Mailgun only when threshold exceeded or new critical/high issues found
5. Cron job execution returns non-zero exit code when critical/high issues exist

**Plans:** TBD

---

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation & Config | 0/? | Not started | - |
| 2. Data Collection | 0/? | Not started | - |
| 3. Report & Delivery | 0/? | Not started | - |

---

## Coverage

| Category | Requirements | Phase |
|----------|--------------|-------|
| Configuration | CONF-01, CONF-02 | Phase 1 |
| DNS/Email | DNS-01, DNS-02, DNS-03, DNS-04 | Phase 2 |
| Cloudflare | CF-01, CF-02, CF-03 | Phase 2 |
| Reports | RPT-01, RPT-02, RPT-03, RPT-04 | Phase 3 |
| Email | EMAIL-01, EMAIL-02 | Phase 3 |
| Operations | OPS-01, OPS-02 | Phase 3 |

**Total:** 17/17 requirements mapped ✓

---

*Roadmap created: 2026-03-16*
