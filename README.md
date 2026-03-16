# waldo-shield

Security monitoring system for the waldo.click platform.

Automatically scans `waldo.click` (prod) or `waldoclick.dev` (staging) and sends email reports when issues are found.

## Quick Start

```bash
# Install dependencies
pip install -r src/requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your values

# Run scan (dry run - no email)
cd src && python3 monitor.py --dry-run

# Run scan (sends email if issues found)
cd src && python3 monitor.py
```

## Configuration

Set these in `.env`:

```bash
DOMAIN=waldo.click              # or waldoclick.dev
CLOUDFLARE_API_TOKEN=xxx        # Cloudflare API token
CLOUDFLARE_ZONE_ID=xxx          # Zone ID for the domain
MAILGUN_API_KEY=xxx             # Mailgun API key
```

## What It Scans

Each app has specific security checks:

| App | URL | Checks |
|-----|-----|--------|
| Dashboard | `dashboard.{domain}` | Zero Trust protection only |
| API | `api.{domain}` | Headers, SSL, robots.txt, `/admin` Zero Trust |
| Website | `www.{domain}` | Full analysis (headers, SSL, DNS, tech) |

Plus:
- **Email Auth**: SPF, DKIM, DMARC, CAA records
- **Cloudflare**: WAF events, traffic analytics, rate limiting rules

## Output

```
============================================================
  SCAN COMPLETE: waldo.click
============================================================
  ✓ dashboard    | NONE     | Score:   0 | Issues: 0
  ✓ api          | NONE     | Score:   0 | Issues: 0
  ✓ www          | LOW      | Score:   1 | Issues: 1
============================================================
```

Reports saved to `reports/{environment}/scan_{timestamp}.json`

## Cron Setup

For Laravel Forge:

```bash
0 6 * * * cd /path/to/waldo-shield/src && /usr/bin/python3 monitor.py --quiet
```

Exit codes:
- `0` - No critical/high issues
- `1` - Critical or high issues found
- `2` - Execution error

## Structure

```
waldo-shield/
├── src/
│   ├── monitor.py           # Main entry point
│   ├── config/              # Environment configuration
│   ├── modules/
│   │   ├── app_scanner.py   # App-specific scanning rules
│   │   ├── headers.py       # HTTP security headers
│   │   ├── ssl_tls.py       # SSL/TLS analysis
│   │   ├── dns_analysis.py  # DNS records
│   │   ├── email_auth.py    # SPF/DKIM/DMARC/CAA
│   │   └── cloudflare_api.py # Cloudflare integration
│   ├── report/              # HTML report generation
│   └── mailer/              # Mailgun email delivery
├── reports/                 # Scan output (gitignored)
└── tests/                   # Test suite
```

## Email Alerts

Emails are sent via Mailgun only when:
- Risk score exceeds threshold (20+)
- New critical or high severity issues found

Reports include:
- Executive summary with risk score
- Per-app findings
- Historical comparison (NEW/FIXED badges)
- Trend indicators (improved/degraded/stable)
