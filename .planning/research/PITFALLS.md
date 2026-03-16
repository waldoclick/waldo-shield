# Domain Pitfalls

**Domain:** Security monitoring system with API integrations (Cloudflare, Mailgun), HTML reporting, cron execution
**Project:** waldo-shield
**Researched:** 2026-03-16
**Confidence:** HIGH (official docs, existing codebase analysis)

---

## Critical Pitfalls

Mistakes that cause system failures, missed alerts, or security issues.

### Pitfall 1: Cloudflare API Rate Limits Causing Scan Failures

**What goes wrong:** Scanner makes too many API calls in a short period, gets 429 errors, and the scan silently fails or produces incomplete data. With multiple zones (staging + prod, ~6 targets), rate limits are easy to hit.

**Why it happens:** Cloudflare's global rate limit is **1,200 requests per 5 minutes per account token**. GraphQL has a separate limit of **300 queries per 5 minutes**. Developers often don't account for retries, pagination, or parallel requests.

**Consequences:**
- Incomplete security reports (missing WAF events, traffic data)
- False "all clear" reports when data wasn't actually fetched
- 5-minute lockout if limit is exceeded

**Prevention:**
```python
# Bad: Parallel requests without rate awareness
for zone in zones:
    threading.Thread(target=fetch_events, args=(zone,)).start()

# Good: Centralized rate limiter with backoff
from cloudflare import Cloudflare
client = Cloudflare(max_retries=2)  # SDK handles 429s automatically
# Process zones sequentially or with controlled concurrency
```

**Detection:** 
- Monitor for 429 responses in logs
- Compare expected vs actual data fetched
- Alert if any module returns empty results unexpectedly

**Phase to address:** Cloudflare API Integration phase. Build rate-aware client wrapper first.

**Source:** [Cloudflare API Rate Limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/) - Verified HIGH confidence

---

### Pitfall 2: API Token Over-Permissioning

**What goes wrong:** Using an API token with write permissions when only read is needed. A leaked token can then modify WAF rules, DNS records, or delete zones.

**Why it happens:** It's easier to create an "All zones" + "All permissions" token during development. The principle of least privilege is often forgotten.

**Consequences:**
- Compromised token = full account takeover
- Attacker can disable WAF, modify DNS, exfiltrate data
- Audit log shows malicious changes coming from "security scanner"

**Prevention:**
```
Token permissions (minimum required):
- Zone:Analytics:Read (for security events)
- Zone:DNS:Read (for DNS validation)
- Zone:Zone:Read (for zone listing)
- Zone:WAF:Read (for WAF events)
- Account:Account Settings:Read (for account-level data)

DO NOT include:
- Any :Edit or :Write permissions
- Zone:Zone Settings:Edit
- Zone:DNS:Edit
```

**Detection:**
- Document required permissions in config
- Token should fail if it tries to write (verify this in tests)
- Rotate tokens periodically, audit their usage

**Phase to address:** Project setup / infrastructure phase. Create minimal-permission token before any code.

**Source:** Cloudflare API documentation, security best practices - HIGH confidence

---

### Pitfall 3: Email Credentials Exposed in Reports or Logs

**What goes wrong:** Mailgun API keys, email addresses, or internal system details leak into the HTML report that gets sent externally or logged in plain text.

**Why it happens:** Debug mode left on, error messages include stack traces with environment variables, report templates include diagnostic info.

**Consequences:**
- Mailgun API key leaked = attacker sends emails from your domain
- Internal infrastructure details exposed
- Compliance/privacy violations

**Prevention:**
```python
# Bad: Logging full error with secrets
except Exception as e:
    logger.error(f"Mailgun failed: {e}, key={MAILGUN_API_KEY}")

# Good: Sanitized logging
except Exception as e:
    logger.error(f"Email delivery failed: {type(e).__name__}")
    # Log details only to secure location, never to report

# HTML report should NEVER include:
# - API keys or tokens
# - Internal IP addresses
# - Full stack traces
# - Environment variable values
```

**Detection:**
- Grep generated reports for patterns: `key=`, `token=`, `password=`, `secret=`
- Review report templates for any `{{ config.*}}` or debug blocks
- Audit logs for sensitive data patterns

**Phase to address:** HTML report generation phase. Implement report sanitization before any external delivery.

**Source:** Security best practices - HIGH confidence

---

### Pitfall 4: Cron Job Silent Failures

**What goes wrong:** Cron job runs but fails silently. No email is sent, no error is logged. Security issues go undetected for days/weeks.

**Why it happens:** 
- Cron doesn't capture stdout/stderr properly
- Script exits with code 0 even on failure
- No monitoring of "last successful run" timestamp
- Laravel Forge cron doesn't email errors by default

**Consequences:**
- False sense of security ("no emails = no problems")
- Security issues accumulate undetected
- No visibility into system health

**Prevention:**
```bash
# Bad: Simple cron entry
0 6 * * * /usr/bin/python3 /path/to/scanner.py

# Good: Capture output, check exit codes, heartbeat
0 6 * * * /usr/bin/python3 /path/to/scanner.py >> /var/log/waldo-shield.log 2>&1 || curl -X POST "https://heartbeat.yourservice.com/fail"

# Even better: Dedicated monitoring
# - Dead man's switch (e.g., Healthchecks.io, Cronitor)
# - Send heartbeat on SUCCESS, alert if missed
```

```python
# In script: Explicit exit codes
def main():
    try:
        run_scan()
        send_report()
        sys.exit(0)  # Explicit success
    except Exception as e:
        logger.critical(f"Scan failed: {e}")
        send_failure_notification()  # Even if report fails, notify
        sys.exit(1)  # Explicit failure
```

**Detection:**
- Implement "last successful scan" timestamp check
- Dead man's switch: external service expects ping every X hours
- Log rotation + monitoring of log file sizes

**Phase to address:** Cron job execution phase. Build monitoring before deploying to production.

**Source:** Operational best practices, Laravel Forge documentation - HIGH confidence

---

### Pitfall 5: DNS/Email Validation Against Wrong Domain Apex

**What goes wrong:** SPF/DKIM/DMARC checks run against `api.waldoclick.dev` instead of apex domain `waldoclick.dev`. Results are incorrect or empty.

**Why it happens:** Email authentication records live at the apex domain (or specific subdomains like `_dmarc.example.com`), not at arbitrary subdomains. Code that extracts domain from URL may keep the full hostname.

**Consequences:**
- False negatives: "No SPF record" when one exists
- False positives: Reporting issues that aren't real
- Misleading security recommendations

**Prevention:**
```python
# The existing dns_analysis.py handles this correctly:
# api.waldoclick.dev -> waldoclick.dev
parts = domain.split(".")
apex_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain

# Validate this works for your specific domains:
# www.waldo.click -> waldo.click (correct)
# dashboard.waldoclick.dev -> waldoclick.dev (correct)
# api.waldo.click -> waldo.click (correct)
```

**Detection:**
- Unit tests with subdomain inputs
- Compare results with manual DNS lookup: `dig TXT waldoclick.dev`
- Log which domain was actually queried

**Phase to address:** DNS/Email validation phase. Add explicit domain extraction tests.

**Source:** Existing codebase (`dns_analysis.py`), DNS standards - HIGH confidence

---

## Moderate Pitfalls

Mistakes that cause degraded functionality or confusing reports.

### Pitfall 6: Cloudflare Security Events Data Retention Mismatch

**What goes wrong:** Scanner queries for 30 days of security events, but the Cloudflare plan only retains 24-72 hours. API returns empty or partial data without error.

**Why it happens:** Security Events retention varies by plan:
- Free: 24 hours
- Pro: 24 hours
- Business: 72 hours
- Enterprise: 30 days

**Consequences:**
- "No WAF events this month" when events were actually pruned
- Inconsistent week-over-week comparisons
- Misleading trend analysis

**Prevention:**
```python
# Query only available time range based on known plan
RETENTION_HOURS = {
    "free": 24,
    "pro": 24,
    "business": 72,
    "enterprise": 720  # 30 days
}

# For waldo.click, verify actual plan and adjust
# Or always query only last 24 hours (safe baseline)
```

**Detection:**
- Check if returned data count is suspiciously low
- Log actual time range returned by API
- Document expected plan in config

**Phase to address:** Cloudflare API Integration phase. Determine actual plan retention first.

**Source:** [Cloudflare Security Events Availability](https://developers.cloudflare.com/waf/analytics/security-events/#availability) - HIGH confidence

---

### Pitfall 7: HTML Email Rendering Inconsistencies

**What goes wrong:** HTML report looks perfect in browser but is garbled in Outlook, Gmail clips it, or mobile view is unreadable.

**Why it happens:** Email HTML is NOT web HTML. No external CSS, limited CSS support, many clients strip/modify content. Gmail clips emails > 102KB.

**Consequences:**
- Critical security info hidden below "View entire message" link
- Tables render incorrectly, making data hard to read
- Recipients ignore reports because they look unprofessional

**Prevention:**
```html
<!-- Bad: External CSS, modern features -->
<link rel="stylesheet" href="styles.css">
<div style="display: grid;">

<!-- Good: Inline styles, table layout, minimal CSS -->
<table style="width: 100%; border-collapse: collapse;">
  <tr>
    <td style="padding: 10px; border: 1px solid #ccc;">...</td>
  </tr>
</table>

<!-- Keep total size under 100KB -->
<!-- Test with: Litmus, Email on Acid, or real clients -->
```

**Detection:**
- Test rendered output in actual email clients (Gmail, Outlook)
- Check total HTML size before sending
- Include plain-text alternative

**Phase to address:** HTML report generation phase. Design for email constraints from the start.

**Source:** Email development best practices - MEDIUM confidence

---

### Pitfall 8: Mailgun Domain/Region Mismatch

**What goes wrong:** API calls to `api.mailgun.net` fail because the domain is configured in EU region (`api.eu.mailgun.net`), or vice versa.

**Why it happens:** Mailgun has separate US and EU infrastructures. Domain must be accessed via the correct regional endpoint. Easy to miss during setup.

**Consequences:**
- All email sends fail with 401/404 errors
- No reports delivered
- Confusing error messages ("domain not found")

**Prevention:**
```python
# Check domain region in Mailgun dashboard first
# Configure endpoint accordingly

# US region (default)
MAILGUN_API_BASE = "https://api.mailgun.net/v3"

# EU region
MAILGUN_API_BASE = "https://api.eu.mailgun.net/v3"

# Verify at startup
def verify_mailgun_config():
    response = requests.get(
        f"{MAILGUN_API_BASE}/domains/{MAILGUN_DOMAIN}",
        auth=("api", MAILGUN_API_KEY)
    )
    if response.status_code != 200:
        raise ConfigError(f"Mailgun domain check failed: {response.status_code}")
```

**Detection:**
- Explicit config verification on startup
- Test email send during deployment
- Log full Mailgun response on errors

**Phase to address:** Mailgun email delivery phase. Verify region before any code.

**Source:** Mailgun documentation - MEDIUM confidence

---

### Pitfall 9: Zero Trust 302s Counted as Real Vulnerabilities

**What goes wrong:** Scanner finds `.env` file "accessible" on `dashboard.waldoclick.dev`, generates critical alert. But the 302 is from Cloudflare Zero Trust, not actual file access.

**Why it happens:** Vulnerability checks see HTTP 302 and interpret "got a response" as "file exists". The existing scanner already has some false positive detection, but new checks may not.

**Consequences:**
- Alert fatigue from repeated false positives
- Real issues buried in noise
- Credibility of scanner undermined

**Prevention:**
```python
# The project already handles this (see AGENTS.md):
# Known false positives:
# - .env / .git/HEAD on dashboard.* -> Zero Trust 302
# - phpinfo.php on www.* -> Nuxt 404 with matching title
# - Admin panel on dashboard.* -> Zero Trust 302

# New modules MUST check:
def is_zero_trust_redirect(response, url):
    """Detect Cloudflare Zero Trust redirects."""
    if response.status_code == 302:
        location = response.headers.get("Location", "")
        if "cloudflareaccess.com" in location:
            return True
        if "/cdn-cgi/access/" in location:
            return True
    return False
```

**Detection:**
- Log redirect locations, not just status codes
- Maintain explicit false positive list per target
- Review new findings against known infrastructure

**Phase to address:** Every module that makes HTTP requests. Centralize false positive detection.

**Source:** Existing `AGENTS.md`, project-specific knowledge - HIGH confidence

---

## Minor Pitfalls

Issues that cause inconvenience or technical debt.

### Pitfall 10: Timezone Confusion in Reports

**What goes wrong:** Report says "Scan completed at 06:00" but it's unclear if that's UTC, server local time, or recipient's time. Cloudflare API returns UTC; server may be in different timezone.

**Why it happens:** Mixing UTC timestamps from APIs with local time from Python's `datetime.now()`.

**Prevention:**
```python
# Always use UTC internally
from datetime import datetime, timezone

scan_time = datetime.now(timezone.utc)

# Display with explicit timezone
report_time = scan_time.strftime("%Y-%m-%d %H:%M UTC")
```

**Detection:**
- Grep codebase for `datetime.now()` without timezone
- Verify all displayed times include timezone indicator

**Phase to address:** Report generation phase. Standardize on UTC early.

---

### Pitfall 11: Large Report Attachments Blocked by Email Servers

**What goes wrong:** Full JSON report attached to email is rejected or stripped by recipient's email server due to attachment policies.

**Why it happens:** Many corporate email systems block attachments, limit size, or quarantine unfamiliar file types.

**Prevention:**
- Include summary in email body (not just attachment)
- Keep attachments small (< 5MB)
- Consider linking to report instead of attaching
- Use common formats (.pdf) or inline the data

**Detection:**
- Check Mailgun delivery events for bounces/blocks
- Test with actual recipient addresses

**Phase to address:** Report delivery phase.

---

### Pitfall 12: GraphQL Query Complexity Limits

**What goes wrong:** Complex Cloudflare GraphQL queries fail with "Query too complex" error when requesting too many fields or time ranges.

**Why it happens:** GraphQL API has undocumented complexity limits that vary by query. Large date ranges or many fields increase cost.

**Prevention:**
```graphql
# Bad: Request everything
query {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(limit: 10000, ...) {
        # 20+ fields
      }
    }
  }
}

# Good: Request only needed fields, paginate
query {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(limit: 100, ...) {
        datetime
        action
        clientIP
        ruleId
      }
    }
  }
}
```

**Detection:**
- Test queries with expected data volumes
- Handle complexity errors gracefully
- Implement pagination for large result sets

**Phase to address:** Cloudflare API integration phase.

**Source:** [Cloudflare GraphQL Limits](https://developers.cloudflare.com/analytics/graphql-api/limits/) - HIGH confidence

---

## Phase-Specific Warnings

| Phase | Likely Pitfall | Mitigation |
|-------|---------------|------------|
| Cloudflare API Integration | Rate limits (#1), Token permissions (#2), Data retention (#6), GraphQL complexity (#12) | Use official SDK with retry handling, minimal permissions, query only available time range |
| DNS/Email Validation | Wrong apex domain (#5) | Unit test domain extraction with all target subdomains |
| HTML Report Generation | Email rendering (#7), Credential exposure (#3), Timezone (#10) | Table-based layout, sanitization pass, UTC timestamps |
| Mailgun Email Delivery | Region mismatch (#8), Attachment blocking (#11) | Verify region at startup, inline critical data in body |
| Cron Job Execution | Silent failures (#4) | Dead man's switch, explicit exit codes, failure notifications |
| All HTTP Modules | Zero Trust false positives (#9) | Centralized redirect detection, maintain false positive list |

---

## Pre-Implementation Checklist

- [ ] Cloudflare API token created with READ-ONLY permissions
- [ ] Mailgun domain region verified (US vs EU)
- [ ] Target domains' Cloudflare plan retention limits documented
- [ ] False positive list reviewed against current infrastructure
- [ ] Cron monitoring solution selected (healthchecks.io, Cronitor, etc.)
- [ ] HTML email template tested in real email clients
- [ ] Exit codes and failure notifications implemented
- [ ] Sensitive data sanitization in place for reports/logs

---

## Sources

| Source | Confidence | Used For |
|--------|------------|----------|
| [Cloudflare API Rate Limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/) | HIGH | Pitfall #1 |
| [Cloudflare GraphQL Limits](https://developers.cloudflare.com/analytics/graphql-api/limits/) | HIGH | Pitfall #6, #12 |
| [Cloudflare Security Events](https://developers.cloudflare.com/waf/analytics/security-events/) | HIGH | Pitfall #6 |
| [Cloudflare Python SDK (PyPI)](https://pypi.org/project/cloudflare/) | HIGH | Pitfall #1 best practices |
| Existing codebase (`dns_analysis.py`, `AGENTS.md`) | HIGH | Pitfalls #5, #9 |
| Email development best practices | MEDIUM | Pitfall #7 |
| Operational/security best practices | HIGH | Pitfalls #2, #3, #4 |
