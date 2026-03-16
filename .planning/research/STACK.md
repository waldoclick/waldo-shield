# Technology Stack

**Project:** waldo-shield (Security Monitoring Additions)
**Researched:** 2026-03-16
**Mode:** Stack dimension for security monitoring/reporting system

## Recommended Stack

### Cloudflare API Integration

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `cloudflare` | `>=4.3.1` | Official Cloudflare API client | **Official SDK** maintained by Cloudflare. Type-safe, async support, covers WAF events, firewall rules, traffic analytics. Uses `httpx` under the hood. Replaces deprecated `python-cloudflare` community package. | HIGH |

**Rationale:** The `cloudflare` package (PyPI) is Cloudflare's official Python SDK, released 2024 and actively maintained (v4.3.1 as of June 2025). It provides typed access to the entire Cloudflare API including:
- `client.firewall.waf` - WAF events and rules
- `client.radar.traffic_anomaly` - Traffic analysis
- `client.zones` - Zone management
- Auto-pagination, retry logic, error handling built-in

**Source:** https://github.com/cloudflare/cloudflare-python (415 stars, Apache-2.0)

### DNS/Email Security Checks (SPF, DKIM, DMARC)

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `checkdmarc` | `>=5.14.1` | SPF/DMARC validation and parsing | **Standard library** for email authentication checks. Parses and validates SPF/DMARC records, checks reporting authorization, validates BIMI, MTA-STS. More comprehensive than raw dnspython queries. | HIGH |
| `dnspython` | `>=2.8.0` | DNS toolkit (already in use) | **Already a dependency**. Latest version 2.8.0 requires Python 3.10+. Used by checkdmarc internally. Keep for low-level DNS operations. | HIGH |

**Rationale:** The existing scanner has basic SPF/DMARC checking using raw `dnspython` queries (see `src/modules/dns_analysis.py`). `checkdmarc` provides:
- Full SPF validation with lookup counting (10 lookup limit enforcement)
- DMARC parsing with policy analysis
- BIMI mark validation
- MTA-STS policy checking
- Warnings for ineffective policies (`pct`, `sp` issues)

The current code only checks for record presence and basic pattern matching. `checkdmarc` does proper validation.

**Source:** https://github.com/domainaware/checkdmarc (310 stars, Apache-2.0)

### HTML Report Generation

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `jinja2` | `>=3.1.6` | Template engine for HTML reports | **Industry standard** for Python templating. Fast (compiled templates), secure (auto-escaping), flexible. Used by Flask, Ansible, dbt. Perfect for generating HTML reports from JSON scan data. | HIGH |

**Rationale:** Jinja2 is the de facto standard for Python template rendering. For generating HTML reports from JSON security scan results:
- Template inheritance for consistent layout
- Filters for formatting (dates, severity colors, etc.)
- Auto-escaping prevents XSS if user data appears in reports
- No dependencies beyond `MarkupSafe`

**Alternative considered:** `weasyprint` for PDF generation - rejected because email HTML is the target output and WeasyPrint adds significant dependencies (cairo, pango).

**Source:** https://pypi.org/project/Jinja2/ (official Pallets project)

### Email Sending (Mailgun)

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `requests` | `>=2.32.5` | HTTP client for Mailgun API | **Already a dependency**. Mailgun's API is REST-based. Using `requests` directly is simpler than adding another SDK for a single endpoint (send email). The project already uses requests. | HIGH |

**Rationale:** The project already uses `requests>=2.31.0`. Mailgun's Python SDKs:
- `mailgun` (1.6.0) - Official SDK, but adds abstraction layer for simple send operation
- `mailgun2` (2.0.1) - Unofficial, API v2 only

For a security monitoring tool that only needs to send HTML emails, using `requests` directly against Mailgun's REST API is simpler and more transparent:

```python
requests.post(
    f"https://api.mailgun.net/v3/{domain}/messages",
    auth=("api", MAILGUN_API_KEY),
    data={
        "from": sender,
        "to": recipients,
        "subject": subject,
        "html": html_content,
    }
)
```

This avoids adding a dependency for one function and keeps the HTTP layer visible.

**Source:** https://documentation.mailgun.com/docs/mailgun/api-reference/intro/

### Environment Configuration

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `python-dotenv` | `>=1.2.2` | Load environment variables from `.env` | **Standard practice** for secrets management. Loads `.env` file variables into `os.environ`. Compatible with Laravel Forge's env var injection. Required Python 3.10+. | HIGH |

**Rationale:** The project needs to manage several API credentials:
- `CLOUDFLARE_API_TOKEN`
- `MAILGUN_API_KEY`
- `MAILGUN_DOMAIN`

`python-dotenv` is the standard solution:
- Development: load from `.env` file
- Production (Laravel Forge): environment variables injected directly
- Works with both scenarios transparently

**Source:** https://pypi.org/project/python-dotenv/

## Dependencies Summary

### New Dependencies

```
cloudflare>=4.3.1       # Cloudflare API (WAF, firewall, traffic)
checkdmarc>=5.14.1      # SPF/DMARC validation
jinja2>=3.1.6           # HTML template rendering
python-dotenv>=1.2.2    # Environment variable loading
```

### Updated Dependencies

```
dnspython>=2.8.0        # Updated from >=2.4.2 (checkdmarc requires 2.7+)
requests>=2.32.5        # Updated from >=2.31.0 (security patches)
```

### Unchanged Dependencies

```
cryptography>=41.0.0    # SSL/TLS analysis
beautifulsoup4>=4.12.0  # HTML parsing
lxml>=4.9.3             # XML/HTML parser
python-whois>=0.8.0     # WHOIS lookups
```

## What NOT to Use

| Library | Why Not |
|---------|---------|
| `python-cloudflare` | **Deprecated**. Community package replaced by official `cloudflare` SDK in 2024. |
| `weasyprint` | **Overkill**. Adds cairo/pango dependencies for PDF generation when HTML email is the target. |
| `mailgun-python-sdk` | **Unofficial** (version 0.3). Low activity, unnecessary abstraction for simple email sending. |
| `mailgun` official SDK | **Adds complexity** for a single send operation. Direct `requests` call is clearer and project already uses requests. |
| `aiohttp` / async | **Unnecessary**. Cron job runs sequentially, no concurrency needed. Sync code is simpler to debug. |

## Installation

```bash
# Full installation
pip install -r src/requirements.txt

# Or individually (new deps only)
pip install cloudflare>=4.3.1 checkdmarc>=5.14.1 jinja2>=3.1.6 python-dotenv>=1.2.2
```

## Updated requirements.txt

```
# Core dependencies (existing, updated)
requests>=2.32.5
dnspython>=2.8.0
cryptography>=41.0.0
beautifulsoup4>=4.12.0
lxml>=4.9.3
python-whois>=0.8.0

# New dependencies
cloudflare>=4.3.1
checkdmarc>=5.14.1
jinja2>=3.1.6
python-dotenv>=1.2.2
```

## Python Version Note

The updated stack requires **Python 3.10+**:
- `cloudflare>=4.3.1` requires Python 3.8+
- `python-dotenv>=1.2.2` requires Python 3.10+
- `dnspython>=2.8.0` requires Python 3.10+

Current environment uses Python 3.12.3 - no issues.

## Environment Variables Required

```bash
# .env file (development) or Forge env vars (production)
CLOUDFLARE_API_TOKEN=xxx    # API token with zone:read, firewall:read
MAILGUN_API_KEY=xxx         # Mailgun private API key
MAILGUN_DOMAIN=waldo.click  # Sending domain (or waldoclick.dev for staging)
REPORT_RECIPIENTS=email1@example.com,email2@example.com
```

## Cron Compatibility

All recommended libraries are:
- **Synchronous** (no async complexity for cron context)
- **Stateless** (no daemon processes)
- **CLI-friendly** (can be invoked via `python script.py`)

Compatible with Laravel Forge cron syntax:
```bash
0 8 * * 1 cd /path/to/waldo-shield && /usr/bin/python3 src/report.py >> /var/log/waldo-shield.log 2>&1
```

## Sources

| Source | Confidence | Type |
|--------|------------|------|
| https://pypi.org/project/cloudflare/ | HIGH | PyPI (official package info) |
| https://github.com/cloudflare/cloudflare-python | HIGH | Official repository |
| https://pypi.org/project/checkdmarc/ | HIGH | PyPI (official package info) |
| https://github.com/domainaware/checkdmarc | HIGH | Official repository |
| https://pypi.org/project/jinja2/ | HIGH | PyPI (Pallets project) |
| https://documentation.mailgun.com/docs/mailgun/ | HIGH | Official documentation |
| https://pypi.org/project/python-dotenv/ | HIGH | PyPI (official package info) |
| https://pypi.org/project/dnspython/ | HIGH | PyPI (official package info) |

---

*Stack research: 2026-03-16*
