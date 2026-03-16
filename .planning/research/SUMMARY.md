# Research Summary

**Project:** waldo-shield (Security Monitoring Additions)  
**Synthesized:** 2026-03-16  
**Research Files:** STACK.md, FEATURES.md, ARCHITECTURE.md, PITFALLS.md

---

## Executive Summary

Building security monitoring and reporting capabilities for waldo-shield follows a well-established pattern: extend the existing scanner with API collectors (Cloudflare), add a report pipeline (Jinja2 HTML templating), and deliver via email (Mailgun). The existing architecture is well-designed with a modular `analyze(url) -> dict` interface that makes extension straightforward without modifying core scanner code.

The recommended approach layers three components on top of the existing scanner: (1) Cloudflare API collectors for WAF events and traffic data, (2) a report pipeline that aggregates data, renders HTML, and handles email delivery, and (3) a cron orchestrator (`monitor.py`) that ties everything together. All dependencies are mature, well-documented Python libraries with synchronous APIs suitable for cron execution. The official Cloudflare SDK (`cloudflare>=4.3.1`) replaces the deprecated community package and handles rate limiting/retries automatically.

Key risks center on API integration reliability and email delivery: Cloudflare rate limits (1,200 req/5min), API token over-permissioning, Silent cron failures, and email HTML rendering quirks. Mitigation is straightforward with proper configuration (READ-ONLY tokens), centralized error handling, dead man's switch monitoring, and table-based email templates. The existing false positive detection for Cloudflare Zero Trust 302 redirects must be extended to all new HTTP-based checks.

---

## Key Findings

### From STACK.md

| Technology | Purpose | Rationale |
|------------|---------|-----------|
| `cloudflare>=4.3.1` | Cloudflare API (WAF events, traffic analytics) | Official SDK with auto-retry, replaces deprecated `python-cloudflare` |
| `checkdmarc>=5.14.1` | SPF/DKIM/DMARC validation | Full validation beyond raw DNS queries, counts SPF lookups |
| `jinja2>=3.1.6` | HTML report templating | Industry standard, fast, secure (auto-escaping) |
| `python-dotenv>=1.2.2` | Environment variable loading | Works with `.env` files and Laravel Forge env injection |
| `requests>=2.32.5` | Mailgun API client | Already a dependency, simpler than adding Mailgun SDK |

**Critical:** Python 3.10+ required (dnspython, python-dotenv constraints). Current environment is 3.12.3 - no issues.

### From FEATURES.md

**Must Have (Table Stakes):**
- Consolidated HTML report (self-contained, email-compatible)
- Email delivery via Mailgun
- Multi-target support (all 6 URLs in one run)
- Environment-aware config (staging vs prod recipients)
- DNS/Email security checks (SPF, DKIM, DMARC, CAA)

**Should Have (Differentiators):**
- Cloudflare WAF events integration
- Historical trend tracking (JSON storage)
- Delta highlighting (new/resolved issues)

**Defer (Anti-Features):**
- Real-time dashboard
- PDF reports
- Slack/PagerDuty alerts
- Compliance mapping

### From ARCHITECTURE.md

**Component Structure:**
1. **Orchestration Layer** (`src/monitor.py`) - Cron entry point, environment config, coordinates scanner + collectors
2. **Data Collection Layer** - Existing scanner modules + new `src/collectors/cloudflare.py`
3. **Report Pipeline** - `generator.py` (aggregation) -> `html_renderer.py` (Jinja2) -> `email_sender.py` (Mailgun)

**Key Patterns:**
- Consistent module interface: `collect(zone_id, api_token) -> dict`
- Configuration via environment variables (12-factor app)
- Catch-and-continue for collectors (partial data > no data)
- Inline CSS for email HTML compatibility

**Build Order:** Config -> Cloudflare collector -> Report generator -> HTML renderer -> Email sender -> Monitor orchestrator

### From PITFALLS.md

**Top 5 Pitfalls to Prevent:**

| Pitfall | Severity | Prevention |
|---------|----------|------------|
| Cloudflare API rate limits | CRITICAL | Use official SDK with built-in retry; sequential zone processing |
| API token over-permissioning | CRITICAL | READ-ONLY token: Analytics:Read, DNS:Read, Zone:Read, WAF:Read |
| Cron job silent failures | CRITICAL | Dead man's switch (Healthchecks.io), explicit exit codes, failure notifications |
| Credentials in reports/logs | CRITICAL | Sanitization pass before delivery, never log API keys |
| Zero Trust 302 false positives | MODERATE | Centralized redirect detection, extend existing false positive list |

**Additional Warnings:**
- Cloudflare data retention varies by plan (24h Free/Pro, 72h Business, 30d Enterprise)
- Email HTML must use table layout and inline CSS (<100KB total)
- Mailgun region mismatch (US vs EU endpoint)
- Always use UTC timestamps with explicit timezone display

---

## Implications for Roadmap

Based on combined research, the features should be built in this order to respect dependencies and enable incremental testing:

### Phase 1: Foundation & Config
**Delivers:** Configuration management, environment separation, CLI infrastructure  
**Rationale:** All subsequent phases depend on config loading. Build once, use everywhere.

**Includes:**
- `src/config.py` with environment-specific settings
- `.env` template with required variables
- READ-ONLY Cloudflare API token (before any API code)
- Mailgun region verification

**Pitfalls to avoid:** Token over-permissioning (#2), Region mismatch (#8)

**Research needed:** None - standard patterns

### Phase 2: DNS/Email Security Enhancement
**Delivers:** Comprehensive email authentication validation (SPF, DKIM, DMARC, CAA, DNSSEC)  
**Rationale:** Extends existing `dns_analysis.py` with minimal new dependencies. Self-contained, testable.

**Includes:**
- Integration of `checkdmarc` library
- CAA record validation
- DNSSEC status check
- Combined "email security score"

**Pitfalls to avoid:** Wrong apex domain (#5) - verify domain extraction logic

**Research needed:** None - well-documented library

### Phase 3: Cloudflare API Integration
**Delivers:** WAF events and traffic analytics data collection  
**Rationale:** Independent of report pipeline; can test with CLI. Highest complexity, isolate early.

**Includes:**
- `src/collectors/cloudflare.py` with GraphQL queries
- WAF events collection (action, IP, path, source)
- Traffic summary stats
- Rate-aware implementation with retries

**Pitfalls to avoid:** Rate limits (#1), Data retention (#6), GraphQL complexity (#12)

**Research needed:** May need `/gsd-research-phase` for GraphQL query optimization if hitting limits

### Phase 4: Report Generation & HTML Rendering
**Delivers:** Aggregated report with HTML output  
**Rationale:** Needs scanner output (exists) and Cloudflare data (Phase 3). Core value delivery.

**Includes:**
- `src/reports/generator.py` - data aggregation, risk scoring, delta detection
- `src/reports/html_renderer.py` - Jinja2 templating
- `src/templates/` - email-compatible HTML templates
- JSON storage for historical comparison

**Pitfalls to avoid:** Credential exposure (#3), Email rendering (#7), Timezone confusion (#10)

**Research needed:** None - standard Jinja2 patterns

### Phase 5: Email Delivery
**Delivers:** Mailgun integration for report distribution  
**Rationale:** Requires HTML output from Phase 4. Simple API call, but critical path.

**Includes:**
- `src/reports/email_sender.py` - Mailgun REST API
- JSON report attachment
- Recipient management per environment
- Send verification and error handling

**Pitfalls to avoid:** Region mismatch (#8), Large attachments (#11)

**Research needed:** None - well-documented API

### Phase 6: Orchestration & Cron
**Delivers:** Production-ready cron execution with monitoring  
**Rationale:** Integration layer - only makes sense when all parts work. Includes monitoring.

**Includes:**
- `src/monitor.py` - entry point coordinating all components
- Exit codes for CI/CD integration
- Dead man's switch integration (Healthchecks.io recommended)
- Failure notification fallback (email even if scan fails)

**Pitfalls to avoid:** Silent failures (#4), Missing heartbeat

**Research needed:** None - operational patterns

### Phase 7: Documentation & Deployment
**Delivers:** Laravel Forge configuration, runbook, environment setup guide  
**Rationale:** After all code works. Captures setup procedures.

**Includes:**
- Forge cron configuration
- Environment variable documentation
- Deployment runbook
- Troubleshooting guide

---

## Research Flags

| Phase | Research Recommendation |
|-------|------------------------|
| Phase 1 (Foundation) | **Skip** - Standard config patterns |
| Phase 2 (DNS/Email) | **Skip** - checkdmarc library is well-documented |
| Phase 3 (Cloudflare API) | **May need research** - GraphQL complexity limits may require optimization |
| Phase 4 (Report Generation) | **Skip** - Standard Jinja2 patterns |
| Phase 5 (Email Delivery) | **Skip** - Simple REST API |
| Phase 6 (Orchestration) | **Skip** - Standard operational patterns |

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All libraries verified on PyPI, official documentation reviewed |
| Features | HIGH | Based on industry standards (OWASP, Nuclei patterns) and existing codebase analysis |
| Architecture | HIGH | Extends proven existing scanner architecture, verified API documentation |
| Pitfalls | HIGH | Official Cloudflare docs, existing project context (AGENTS.md), operational best practices |

**Gaps to Address:**
1. **Cloudflare plan retention** - Need to verify actual plan (Free/Pro/Business/Enterprise) to set correct query time range
2. **Mailgun region** - Verify US vs EU endpoint for `waldo.click` and `waldoclick.dev` domains
3. **Monitoring service** - Choose dead man's switch provider (Healthchecks.io, Cronitor, etc.)

---

## Sources

All sources verified HIGH confidence unless noted:

**Cloudflare:**
- [API Rate Limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/)
- [GraphQL Analytics](https://developers.cloudflare.com/analytics/graphql-api/)
- [Security Events](https://developers.cloudflare.com/waf/analytics/security-events/)
- [Python SDK](https://github.com/cloudflare/cloudflare-python) (official)

**Email/DNS:**
- [checkdmarc](https://github.com/domainaware/checkdmarc)
- [Mailgun API](https://documentation.mailgun.com/docs/mailgun/api-reference/intro/)
- [DMARC documentation](https://dmarcian.com/what-is-a-dmarc-record/)

**Python Libraries:**
- [Jinja2](https://pypi.org/project/jinja2/) (Pallets project)
- [python-dotenv](https://pypi.org/project/python-dotenv/)
- [dnspython](https://pypi.org/project/dnspython/)

**Project-Specific:**
- Existing codebase: `src/scanner.py`, `src/modules/dns_analysis.py`
- Project context: `AGENTS.md`, `.planning/codebase/ARCHITECTURE.md`

---

*Synthesis completed: 2026-03-16*
