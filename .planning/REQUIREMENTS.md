# Requirements: waldo-shield

**Defined:** 2026-03-16
**Core Value:** Visibilidad continua del estado de seguridad de waldo.click — staging y producción — sin intervención manual.

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Configuration

- [x] **CONF-01**: System loads environment-specific config (staging vs prod targets, recipients, thresholds)
- [x] **CONF-02**: API tokens read from environment variables, never hardcoded

### DNS/Email Checks

- [ ] **DNS-01**: Scanner validates SPF records for waldo.click and waldoclick.dev
- [ ] **DNS-02**: Scanner validates DKIM records for both domains
- [ ] **DNS-03**: Scanner validates DMARC policies for both domains
- [ ] **DNS-04**: Scanner checks CAA records match expected CAs (pki.goog)

### Cloudflare Integration

- [ ] **CF-01**: System retrieves WAF events from Cloudflare API for both zones
- [ ] **CF-02**: System retrieves traffic analytics (requests, blocked percentage)
- [ ] **CF-03**: System retrieves configured rate limiting rules

### Report Generation

- [ ] **RPT-01**: System generates consolidated HTML report with all findings
- [ ] **RPT-02**: Report includes executive summary (risk score, issue counts, key metrics)
- [ ] **RPT-03**: Report shows historical trends (comparison with previous scan)
- [ ] **RPT-04**: Report highlights new issues and fixed issues with visual indicators

### Email Delivery

- [ ] **EMAIL-01**: System sends report via Mailgun to configured recipients
- [ ] **EMAIL-02**: System only sends email when threshold exceeded or new critical/high found

### Operations

- [ ] **OPS-01**: System runs as cron job compatible with Laravel Forge
- [ ] **OPS-02**: System exits with non-zero code when critical/high issues found

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Comparison

- **CMP-01**: System compares security posture between staging and prod (environment parity)

### Additional Integrations

- **INT-01**: Multi-target support (scan all 6 URLs in single execution)

### Monitoring

- **MON-01**: Dead man's switch integration (healthchecks.io or similar)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Real-time dashboard | Adds significant infrastructure (web server, auth, hosting) |
| Slack/PagerDuty alerts | Over-engineering, email is sufficient |
| PDF report generation | HTML is viewable in email, print-to-PDF if needed |
| Vulnerability database (CVE) | External dependency, scope creep |
| Penetration testing features | Scanner is assessment tool, not attack tool |
| Multi-tenant/SaaS features | Internal tool for waldo.click only |
| Custom rule engine | Over-engineering for 6 fixed targets |
| API endpoint | Runs as cron job, doesn't need to be API server |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONF-01 | Phase 1 | Complete |
| CONF-02 | Phase 1 | Complete |
| DNS-01 | Phase 2 | Pending |
| DNS-02 | Phase 2 | Pending |
| DNS-03 | Phase 2 | Pending |
| DNS-04 | Phase 2 | Pending |
| CF-01 | Phase 2 | Pending |
| CF-02 | Phase 2 | Pending |
| CF-03 | Phase 2 | Pending |
| RPT-01 | Phase 3 | Pending |
| RPT-02 | Phase 3 | Pending |
| RPT-03 | Phase 3 | Pending |
| RPT-04 | Phase 3 | Pending |
| EMAIL-01 | Phase 3 | Pending |
| EMAIL-02 | Phase 3 | Pending |
| OPS-01 | Phase 3 | Pending |
| OPS-02 | Phase 3 | Pending |

**Coverage:**
- v1 requirements: 17 total
- Mapped to phases: 17 ✓
- Unmapped: 0

---
*Requirements defined: 2026-03-16*
*Last updated: 2026-03-16 after completing Phase 1*
