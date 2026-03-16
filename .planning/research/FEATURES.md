# Feature Landscape

**Domain:** Security Monitoring & Reporting Tool  
**Researched:** 2026-03-16  
**Context:** Subsequent milestone adding reporting and notification features to existing waldo-shield scanner

## Table Stakes

Features users expect in security monitoring/reporting tools. Missing = product feels incomplete.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Consolidated HTML Report** | Standard output format for security tools (OWASP, Nuclei, commercial scanners all provide human-readable reports) | Medium | Must be self-contained, no external dependencies |
| **Severity Categorization** | Industry standard (Critical/High/Medium/Low/Info) for prioritizing fixes | Low | Already exists in scanner - carry through to report |
| **Executive Summary Section** | Managers need quick overview without reading full technical details | Low | Risk score, issue counts, delta from previous scan |
| **Issue Detail with Remediation** | Security findings without fix guidance are unhelpful | Low | Already in scanner JSON output |
| **Multi-Target Support** | Scanning multiple URLs/environments in one run is baseline expectation | Medium | 6 targets defined (staging + prod, 3 subdomains each) |
| **Email Delivery** | Periodic reports via email is the minimum notification channel | Medium | Mailgun integration, already used by platform |
| **Environment-Aware Config** | Different settings for staging vs prod (recipients, thresholds, etc.) | Low | Simple YAML/JSON config per environment |
| **SSL Certificate Monitoring** | Certificate expiry is a common cause of outages | Low | Already in scanner, ensure prominent in report |
| **DNS Record Verification** | SPF/DKIM/DMARC validation is table stakes for email-sending domains | Low | Extend existing dns_analysis module |
| **False Positive Management** | Tools without FP handling waste operator time | Medium | Already partially implemented (Zero Trust detection) |
| **Timestamp & Version Info** | Reports must show when scan ran and tool version | Low | Already in scanner meta |
| **Exit Code for CI/CD** | Non-zero exit on critical/high findings for automation | Low | Easy addition to scanner.py |

## Differentiators

Features that set waldo-shield apart from generic scanners. Not universally expected, but add clear value for this use case.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Cloudflare WAF Events Integration** | Unique visibility into blocked attacks, not just vulnerabilities | High | Requires Cloudflare API, plan-specific data retention (24h Free, 72h Business, 30d Enterprise) |
| **Cloudflare Traffic Analytics** | Show request volume, blocked vs served percentages | Medium | GraphQL API (httpRequestsAdaptiveGroups) |
| **Historical Trend Tracking** | Show security posture over time, not just point-in-time | Medium | Store results in JSON files, compare with previous |
| **Delta Highlighting** | "New issue" / "Fixed issue" badges in report | Medium | Requires comparison with previous scan |
| **Platform-Specific False Positive Rules** | Knows about Nuxt 404 titles, Zero Trust 302s, etc. | Low | Already partially built, formalize as config |
| **Dual-Environment Parity Check** | Flag when staging and prod have different security postures | Medium | Compare results between waldoclick.dev and waldo.click |
| **CAA Record Validation** | Ensure only expected CAs can issue certs | Low | Add to dns_analysis, compare against expected (pki.goog) |
| **DNSSEC Status Check** | Verify DNSSEC is enabled and valid | Low | Check DNSKEY records, report DS record status |
| **Email Authentication Health** | Combined SPF+DKIM+DMARC pass/fail summary | Low | Extend dns_analysis, aggregate to single "email security" score |
| **Threshold-Based Alerting** | Only email if score exceeds threshold or new critical found | Low | Config option, reduces alert fatigue |
| **Rate Limiting Rule Audit** | Report what Cloudflare rate limits are configured | Medium | Useful for security review, requires API access |

## Anti-Features

Features to explicitly NOT build. Reduce scope, avoid complexity, stay focused.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Real-Time Dashboard** | Out of scope for v1, adds significant infrastructure (web server, auth, hosting) | Email-based periodic reports are sufficient |
| **Real-Time Alerts (Slack/PagerDuty)** | Over-engineering for current needs, email is sufficient notification channel | Stick with email delivery |
| **Vulnerability Database Integration** | Adds external dependency, scope creep (CVE lookups, NVD API) | Focus on configuration/posture issues, not CVE scanning |
| **Penetration Testing Features** | Scanner is assessment tool, not an attack tool | Keep to passive checks only |
| **Multi-Tenant/SaaS Features** | This is an internal tool for waldo.click platform only | Single-tenant design, no user management |
| **Scheduling UI** | Cron is sufficient and already available via Laravel Forge | Configure via cron, not UI |
| **PDF Report Generation** | Adds complexity (wkhtmltopdf, Puppeteer, etc.) | HTML report is viewable in email, print-to-PDF if needed |
| **Interactive Filtering** | Reports are static; interactivity requires JS framework | Static HTML that's email-friendly |
| **Agent-Based Scanning** | Internal network scanning is out of scope | Scan from external perspective only (like an attacker) |
| **Compliance Mapping** | HIPAA/PCI/SOC2 mapping is complex and not needed | Focus on technical security posture, not compliance |
| **Custom Rule Engine** | Nuclei-style template system is over-engineering for 6 fixed targets | Hardcoded modules with config are sufficient |
| **API Endpoint** | Scanner runs as cron job, doesn't need to be an API server | Keep as CLI tool |

## Feature Dependencies

```
Cloudflare API Token → Cloudflare WAF Events
Cloudflare API Token → Cloudflare Traffic Analytics  
Cloudflare API Token → Rate Limiting Rule Audit

dns_analysis module → Email Authentication Health
dns_analysis module → CAA Record Validation
dns_analysis module → DNSSEC Status Check

JSON storage → Historical Trend Tracking
Historical Trend Tracking → Delta Highlighting
Delta Highlighting → Threshold-Based Alerting (new critical detection)

Multi-Target Support → Dual-Environment Parity Check

Mailgun API Token → Email Delivery
Environment Config → Email Delivery (recipients per environment)
HTML Report Generation → Email Delivery (attach/embed report)
```

## MVP Recommendation

Prioritize for initial milestone (ordered by value/effort ratio):

### Must Have (Phase 1)
1. **Consolidated HTML Report** — Core output format, required for email delivery
2. **Email Delivery via Mailgun** — Primary notification mechanism  
3. **Multi-Target Support** — Scan all 6 URLs in one execution
4. **Environment Config** — Separate staging/prod settings
5. **DNS/Email Security Checks** — SPF, DKIM, DMARC, CAA validation

### Should Have (Phase 2)
6. **Cloudflare WAF Events** — High differentiation value
7. **Historical Trend Tracking** — Enables delta comparison
8. **Delta Highlighting** — Shows what changed since last scan

### Could Have (Phase 3)
9. **Threshold-Based Alerting** — Nice-to-have, reduces noise
10. **Cloudflare Traffic Analytics** — Additional context in report
11. **Dual-Environment Parity Check** — Quality assurance feature
12. **Exit Code for CI/CD** — Enables future automation

### Defer
- **Rate Limiting Rule Audit** — Lower priority, manual review is acceptable
- **Interactive features** — Explicitly out of scope

## Complexity Estimates

| Feature | Effort | Dependencies | Risk |
|---------|--------|--------------|------|
| HTML Report | 2-3 days | Jinja2 or plain string templating | Low - straightforward |
| Email Delivery | 1 day | Mailgun API key, existing `requests` lib | Low - well-documented API |
| Multi-Target | 1 day | Config file | Low - iteration over existing scanner |
| DNS/Email Checks | 1-2 days | `dnspython` (already in use) | Low - extend existing module |
| Cloudflare WAF Events | 2-3 days | Cloudflare API token, zone IDs | Medium - API complexity, rate limits |
| Historical Tracking | 1 day | Local JSON storage | Low |
| Delta Highlighting | 1 day | Historical tracking | Low |
| Traffic Analytics | 1-2 days | Cloudflare GraphQL API | Medium - different API pattern |
| Threshold Alerting | 0.5 days | Config file | Low |
| Environment Parity | 0.5 days | Multi-target output | Low |

## Sources

**HIGH Confidence (Official Documentation):**
- Cloudflare Security Events: https://developers.cloudflare.com/waf/analytics/security-events/
- Cloudflare Security Analytics: https://developers.cloudflare.com/waf/analytics/security-analytics/
- Cloudflare API: https://developers.cloudflare.com/api/
- DMARC Records: https://dmarcian.com/what-is-a-dmarc-record/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

**MEDIUM Confidence (Industry Patterns):**
- Nuclei documentation (output formats, reporting): https://docs.projectdiscovery.io/tools/nuclei/running
- Industry standard severity levels: CVSS-adjacent (Critical/High/Medium/Low/Info)

**Project-Specific Context:**
- Existing scanner architecture: `.planning/codebase/ARCHITECTURE.md`
- Current integrations: `.planning/codebase/INTEGRATIONS.md`
- Session progress: `sessions/2026-03-15.md`
- Security progress: `SECURITY_PROGRESS.md`

---

*Features research completed: 2026-03-16*
