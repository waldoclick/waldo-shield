# waldo-shield

Security monitoring system for the waldo.click platform.

Collects security data from multiple sources and sends consolidated weekly reports.

## Quick Start

```bash
# Install dependencies
pip install -r src/requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your values

# Test collectors manually
cd src
python3 -m collectors.http
python3 -m collectors.github
python3 -m collectors.sentry
python3 -m collectors.codacy

# Test email (dry run)
python3 -m sender.report --dry-run

# Send real email
python3 -m sender.report
```

## Configuration

Set these in `.env`:

```bash
# Required
DOMAIN=waldo.click                    # or waldoclick.dev
CLOUDFLARE_API_TOKEN=xxx
CLOUDFLARE_ZONE_ID=xxx
MAILGUN_API_KEY=xxx
GITHUB_TOKEN=xxx
SENTRY_AUTH_TOKEN=xxx
SENTRY_ORG=waldoclick
SENTRY_ENV=production
CODACY_API_TOKEN=xxx
CODACY_ORG=waldoclick
CODACY_REPO=waldo-project

# Email settings
REPORT_RECIPIENTS=security@waldo.click,admin@waldo.click
REPORT_ZIP_PASSWORD=your_password_here

# Optional (for external scanning)
WEBSENTRY_API_KEY=ss_xxx              # Requires WebSentry Pro $12/mo
```

## Data Sources

| Source | What it collects |
|--------|------------------|
| **HTTP Scanner** | Headers, SSL, Zero Trust, email auth (SPF/DKIM/DMARC) |
| **GitHub** | Open issues from repository |
| **Sentry** | Unresolved runtime errors by project |
| **Codacy** | Code quality issues (security, unused code, etc.) |
| **WebSentry** | External DAST scan (optional, paid) |

## Cron Setup

### Option 1: Direct crontab

```bash
crontab -e
```

Add these lines (adjust `/path/to/waldo-shield`):

```bash
# =============================================================
# WALDO-SHIELD SECURITY MONITORING
# =============================================================

# Daily collectors (6am)
0 6 * * * cd /path/to/waldo-shield/src && /usr/bin/python3 -m collectors.http >> /var/log/waldo-shield.log 2>&1
0 6 * * * cd /path/to/waldo-shield/src && /usr/bin/python3 -m collectors.github >> /var/log/waldo-shield.log 2>&1
0 6 * * * cd /path/to/waldo-shield/src && /usr/bin/python3 -m collectors.sentry >> /var/log/waldo-shield.log 2>&1

# Weekly collectors (Monday 6am)
0 6 * * 1 cd /path/to/waldo-shield/src && /usr/bin/python3 -m collectors.codacy >> /var/log/waldo-shield.log 2>&1

# External scan 3x/month (days 1, 10, 20 at 6am) - requires WEBSENTRY_API_KEY
0 6 1,10,20 * * cd /path/to/waldo-shield/src && /usr/bin/python3 -m collectors.websentry >> /var/log/waldo-shield.log 2>&1

# Weekly email report (Monday 8am)
0 8 * * 1 cd /path/to/waldo-shield/src && /usr/bin/python3 -m sender.report >> /var/log/waldo-shield.log 2>&1
```

### Option 2: Laravel Forge

In Forge → Server → Scheduled Jobs, create these jobs:

| Command | Frequency | User |
|---------|-----------|------|
| `cd /home/forge/waldo-shield/src && python3 -m collectors.http` | Daily at 6:00 | forge |
| `cd /home/forge/waldo-shield/src && python3 -m collectors.github` | Daily at 6:00 | forge |
| `cd /home/forge/waldo-shield/src && python3 -m collectors.sentry` | Daily at 6:00 | forge |
| `cd /home/forge/waldo-shield/src && python3 -m collectors.codacy` | Weekly (Mon) at 6:00 | forge |
| `cd /home/forge/waldo-shield/src && python3 -m sender.report` | Weekly (Mon) at 8:00 | forge |

### Option 3: Systemd timers

Create `/etc/systemd/system/waldo-shield-daily.service`:

```ini
[Unit]
Description=Waldo Shield Daily Collectors

[Service]
Type=oneshot
WorkingDirectory=/path/to/waldo-shield/src
ExecStart=/usr/bin/python3 -m collectors.http
ExecStart=/usr/bin/python3 -m collectors.github
ExecStart=/usr/bin/python3 -m collectors.sentry
User=www-data
```

Create `/etc/systemd/system/waldo-shield-daily.timer`:

```ini
[Unit]
Description=Run Waldo Shield daily at 6am

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl enable waldo-shield-daily.timer
sudo systemctl start waldo-shield-daily.timer
```

## Verify Cron is Working

```bash
# Check cron logs
grep waldo-shield /var/log/syslog

# Check our log
tail -f /var/log/waldo-shield.log

# List scheduled jobs
crontab -l

# Verify reports are being created
ls -la /path/to/waldo-shield/reports/*/prod/
```

## Reports Structure

```
reports/
├── http/prod/
│   └── http_20260316_060000.json
├── github/prod/
│   └── github_20260316_060000.json
├── sentry/prod/
│   └── sentry_20260316_060000.json
├── codacy/prod/
│   └── codacy_20260311_060000.json
└── websentry/prod/
    └── websentry_20260310_060000.json
```

Reports older than 7 days are automatically deleted.

## Email Report

Weekly email includes:
- Summary cards (HTTP issues, GitHub issues, Sentry errors, Codacy issues)
- Scan timestamps for each source
- HTTP security status per app
- WebSentry grades (if configured)
- Codacy breakdown by severity
- **ZIP attachment** with full JSON reports (password protected)

## Project Structure

```
waldo-shield/
├── src/
│   ├── collectors/          # Independent data collectors
│   │   ├── http.py         # HTTP headers, SSL, apps
│   │   ├── github.py       # GitHub issues
│   │   ├── sentry.py       # Sentry errors
│   │   ├── codacy.py       # Code quality
│   │   └── websentry.py    # External DAST
│   ├── sender/
│   │   └── report.py       # Consolidate + ZIP + email
│   ├── modules/            # API integrations
│   ├── config/             # Environment config
│   ├── report/             # HTML templates
│   └── mailer/             # Mailgun sender
├── reports/                # JSON output (gitignored)
└── .env                    # Configuration (gitignored)
```
