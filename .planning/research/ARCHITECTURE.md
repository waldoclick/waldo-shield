# Architecture Patterns

**Domain:** Security monitoring/reporting system extension
**Researched:** 2026-03-16
**Confidence:** HIGH

## Executive Summary

The existing waldo-shield architecture is well-designed for extension. The plugin-based CLI scanner with uniform module interfaces (`analyze(url) -> dict`) provides a solid foundation. New features (Cloudflare API, email delivery, HTML reports, cron orchestration) integrate naturally as additional layers without modifying the core scanner logic.

The recommended architecture adds three new layers on top of the existing scanner:
1. **Data Collectors** — Cloudflare API client (parallel to scanner modules)
2. **Report Pipeline** — JSON aggregation → HTML rendering → Email delivery
3. **Orchestration** — Cron-compatible entry point that coordinates everything

## Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATION LAYER                              │
│                                                                          │
│  src/monitor.py                                                          │
│  ├── Entry point for cron execution                                     │
│  ├── Loads environment config (staging vs prod)                         │
│  ├── Coordinates scanner + collectors in parallel                       │
│  └── Triggers report pipeline                                           │
└─────────────────┬───────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA COLLECTION LAYER                             │
│                                                                          │
│  ┌─────────────────────┐    ┌─────────────────────┐                     │
│  │   Existing Scanner   │    │   Cloudflare API     │                    │
│  │   src/scanner.py     │    │   src/collectors/    │                    │
│  │                      │    │   cloudflare.py      │                    │
│  │   • headers          │    │                      │                    │
│  │   • ssl_tls          │    │   • WAF events       │                    │
│  │   • dns_analysis     │    │   • Traffic stats    │                    │
│  │   • port_scan        │    │   • Security events  │                    │
│  │   • tech_detection   │    │                      │                    │
│  │   • vulnerabilities  │    │                      │                    │
│  └─────────┬────────────┘    └──────────┬──────────┘                    │
│            │                            │                                │
│            └──────────┬─────────────────┘                                │
│                       ▼                                                  │
│              Consolidated Report Data                                    │
│              (dict with scanner_results + cloudflare_data)               │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        REPORT PIPELINE                                   │
│                                                                          │
│  ┌─────────────────────┐                                                │
│  │   Report Generator   │  src/reports/generator.py                     │
│  │                      │  • Aggregates scanner + Cloudflare data       │
│  │                      │  • Calculates combined risk score             │
│  │                      │  • Detects delta from previous report         │
│  └─────────┬────────────┘                                               │
│            │                                                             │
│            ▼                                                             │
│  ┌─────────────────────┐                                                │
│  │   HTML Renderer      │  src/reports/html_renderer.py                 │
│  │                      │  • Jinja2 templates in src/templates/         │
│  │                      │  • Generates standalone HTML                  │
│  │                      │  • Inline CSS for email compatibility         │
│  └─────────┬────────────┘                                               │
│            │                                                             │
│            ▼                                                             │
│  ┌─────────────────────┐                                                │
│  │   Email Sender       │  src/reports/email_sender.py                  │
│  │                      │  • Mailgun API client                         │
│  │                      │  • Sends HTML report as email body            │
│  │                      │  • Attaches JSON for archival                 │
│  └──────────────────────┘                                               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Boundaries

| Component | Responsibility | Communicates With | Input | Output |
|-----------|---------------|-------------------|-------|--------|
| `src/monitor.py` | Cron entry point, environment config, orchestration | scanner, collectors, report pipeline | CLI args, env vars | Exit code, logs |
| `src/scanner.py` | HTTP-based security scanning (existing) | Analysis modules | URL | Scanner report dict |
| `src/collectors/cloudflare.py` | Cloudflare GraphQL API client | Cloudflare API | Zone ID, API token | Cloudflare data dict |
| `src/reports/generator.py` | Data aggregation, risk calculation, delta detection | Scanner, collectors | Scanner + Cloudflare dicts | Consolidated report dict |
| `src/reports/html_renderer.py` | Jinja2 HTML templating | Templates | Report dict | HTML string |
| `src/reports/email_sender.py` | Mailgun API integration | Mailgun API | HTML, recipients | Send status |
| `src/config.py` | Environment-specific configuration | All components | Env vars | Config dict |

### Data Flow

```
1. Cron triggers: python src/monitor.py --env staging

2. monitor.py loads config:
   ├── Reads WALDO_ENV (staging/prod)
   ├── Loads targets from config
   └── Loads API credentials from env

3. Data collection (parallel):
   ├── Thread 1: scanner.scan() for each target URL
   │   └── Returns: {meta, risk_summary, all_issues, modules}
   └── Thread 2: cloudflare.collect() for each zone
       └── Returns: {waf_events, traffic_stats, security_summary}

4. Report generation:
   ├── generator.aggregate(scanner_results, cloudflare_data)
   │   ├── Merges all scanner reports
   │   ├── Adds Cloudflare security events
   │   ├── Calculates combined risk score
   │   └── Detects changes from last report (stored in reports/)
   └── Returns: {meta, combined_risk, scanner_summary, cloudflare_summary, issues, delta}

5. HTML rendering:
   ├── html_renderer.render(report)
   │   ├── Loads template from src/templates/report.html
   │   ├── Applies Jinja2 with report data
   │   └── Inlines CSS for email compatibility
   └── Returns: HTML string

6. Email delivery:
   ├── email_sender.send(html, recipients, subject)
   │   ├── POST to Mailgun API
   │   ├── Attaches JSON report
   │   └── Retries on transient failures
   └── Returns: {success: bool, message_id: str}

7. Exit with appropriate code
```

## Directory Structure

```
src/
├── scanner.py              # Existing - unchanged
├── monitor.py              # NEW - cron entry point
├── config.py               # NEW - environment configuration
├── modules/                # Existing - unchanged
│   ├── headers.py
│   ├── ssl_tls.py
│   ├── dns_analysis.py
│   ├── port_scan.py
│   ├── tech_detection.py
│   └── vulnerabilities.py
├── collectors/             # NEW - API data collectors
│   ├── __init__.py
│   └── cloudflare.py
├── reports/                # NEW - report pipeline
│   ├── __init__.py
│   ├── generator.py
│   ├── html_renderer.py
│   └── email_sender.py
└── templates/              # NEW - Jinja2 templates
    ├── report.html
    └── partials/
        ├── header.html
        ├── risk_summary.html
        ├── scanner_section.html
        ├── cloudflare_section.html
        └── footer.html

reports/                    # Existing - JSON output
config/                     # NEW - environment configs
├── staging.json
└── production.json
```

## Interface Contracts

### Scanner Interface (Existing)
```python
# src/scanner.py
def scan(url: str, selected_modules: list) -> dict:
    """Run security scan on a single URL.
    
    Returns:
        {
            "meta": {
                "tool": str,
                "url": str,
                "hostname": str,
                "scan_date": str (ISO8601),
                "modules_run": list[str],
            },
            "risk_summary": {
                "score": int (0-100),
                "risk_level": str,
                "issue_counts": dict[str, int],
                "total_issues": int,
            },
            "all_issues": list[dict],
            "modules": dict[str, dict],
        }
    """
```

### Cloudflare Collector Interface (New)
```python
# src/collectors/cloudflare.py
def collect(zone_id: str, api_token: str, lookback_hours: int = 24) -> dict:
    """Collect security data from Cloudflare GraphQL API.
    
    Args:
        zone_id: Cloudflare zone ID
        api_token: API token with Analytics:Read permission
        lookback_hours: How far back to query events
    
    Returns:
        {
            "zone_id": str,
            "collected_at": str (ISO8601),
            "waf_events": {
                "total": int,
                "by_action": {"block": int, "challenge": int, ...},
                "by_source": {"waf": int, "rate_limit": int, ...},
                "top_ips": list[{"ip": str, "count": int}],
                "top_paths": list[{"path": str, "count": int}],
            },
            "traffic_summary": {
                "requests": int,
                "threats": int,
                "threat_rate": float,
            },
            "error": str | None,
        }
    """
```

### Report Generator Interface (New)
```python
# src/reports/generator.py
def aggregate(
    scanner_results: dict[str, dict],  # hostname -> scanner report
    cloudflare_data: dict[str, dict],  # zone_id -> cloudflare data
    previous_report_path: str | None = None,
) -> dict:
    """Aggregate all data into consolidated report.
    
    Returns:
        {
            "meta": {
                "generated_at": str,
                "environment": str,
                "targets": list[str],
            },
            "combined_risk": {
                "score": int,
                "level": str,
                "trend": "improving" | "stable" | "degrading" | None,
            },
            "scanner_summary": {
                "total_issues": int,
                "by_severity": dict[str, int],
                "by_target": dict[str, dict],
            },
            "cloudflare_summary": {
                "total_events": int,
                "blocked_threats": int,
                "top_attack_vectors": list[str],
            },
            "all_issues": list[dict],  # Combined, sorted by severity
            "delta": {
                "new_issues": list[dict],
                "resolved_issues": list[dict],
                "score_change": int,
            } | None,
        }
    """
```

### HTML Renderer Interface (New)
```python
# src/reports/html_renderer.py
def render(report: dict) -> str:
    """Render report as standalone HTML.
    
    Args:
        report: Consolidated report dict from generator
    
    Returns:
        HTML string with inlined CSS, ready for email
    """
```

### Email Sender Interface (New)
```python
# src/reports/email_sender.py
def send(
    html_body: str,
    subject: str,
    to: list[str],
    from_email: str,
    domain: str,
    api_key: str,
    json_attachment: str | None = None,
) -> dict:
    """Send HTML email via Mailgun API.
    
    Returns:
        {
            "success": bool,
            "message_id": str | None,
            "error": str | None,
        }
    """
```

## Patterns to Follow

### Pattern 1: Consistent Module Interface
**What:** All data collectors follow the same pattern as scanner modules
**When:** Adding any new data source
**Why:** Enables parallel execution, uniform error handling, consistent testing
**Example:**
```python
# src/collectors/cloudflare.py
def collect(zone_id: str, api_token: str, **options) -> dict:
    result = {
        "collector": "cloudflare",
        "zone_id": zone_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "error": None,
        # ... data fields
    }
    try:
        # ... fetch data
    except Exception as e:
        result["error"] = str(e)
    return result
```

### Pattern 2: Configuration via Environment
**What:** All secrets and environment-specific values come from env vars
**When:** Any API credential, email address, or environment-dependent setting
**Why:** Security, 12-factor app compliance, works with Forge/systemd
**Example:**
```python
# src/config.py
import os

def load_config(env: str = None) -> dict:
    env = env or os.getenv("WALDO_ENV", "staging")
    
    return {
        "env": env,
        "cloudflare_api_token": os.environ["CLOUDFLARE_API_TOKEN"],
        "cloudflare_zones": {
            "waldo.click": os.environ.get("CF_ZONE_WALDO_CLICK"),
            "waldoclick.dev": os.environ.get("CF_ZONE_WALDOCLICK_DEV"),
        },
        "mailgun_api_key": os.environ["MAILGUN_API_KEY"],
        "mailgun_domain": os.getenv("MAILGUN_DOMAIN", "waldo.click"),
        "email_recipients": os.getenv("REPORT_RECIPIENTS", "security@waldo.click").split(","),
        "targets": TARGETS[env],
    }

TARGETS = {
    "staging": [
        "https://api.waldoclick.dev",
        "https://dashboard.waldoclick.dev",
        "https://www.waldoclick.dev",
    ],
    "production": [
        "https://api.waldo.click",
        "https://dashboard.waldo.click",
        "https://www.waldo.click",
    ],
}
```

### Pattern 3: Catch-and-Continue for Collectors
**What:** Collector failures don't abort the entire run
**When:** Any external API call
**Why:** Cloudflare API down shouldn't prevent scanner reports; partial data is better than no data
**Example:**
```python
# src/monitor.py
def run_collectors(config: dict) -> dict:
    results = {}
    for zone_name, zone_id in config["cloudflare_zones"].items():
        if not zone_id:
            continue
        try:
            results[zone_name] = cloudflare.collect(zone_id, config["cloudflare_api_token"])
        except Exception as e:
            results[zone_name] = {"error": str(e), "zone_id": zone_id}
    return results
```

### Pattern 4: Inline CSS for Email HTML
**What:** All CSS styles are inlined in the HTML elements
**When:** Generating HTML for email delivery
**Why:** Most email clients strip `<style>` tags; Gmail, Outlook, etc. require inline styles
**Example:**
```html
<!-- src/templates/report.html -->
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #1a1a1a; border-bottom: 2px solid #e5e5e5; padding-bottom: 10px;">
    Security Report: {{ meta.environment | title }}
  </h1>
  ...
</div>
```

## Anti-Patterns to Avoid

### Anti-Pattern 1: Modifying Existing Scanner Code
**What:** Changing `src/scanner.py` or modules to accommodate new features
**Why bad:** Breaks existing CLI usage, introduces regression risk
**Instead:** Layer new functionality on top; `monitor.py` imports and uses `scanner.scan()`

### Anti-Pattern 2: Hardcoded Credentials
**What:** API keys, tokens, or emails in source code
**Why bad:** Security risk, can't deploy to different environments
**Instead:** All secrets via environment variables; config files only contain structure

### Anti-Pattern 3: Synchronous API Calls in Sequence
**What:** Calling Cloudflare API for each zone sequentially
**Why bad:** Slow; 3 zones × 5 seconds = 15 seconds wasted
**Instead:** Use `concurrent.futures.ThreadPoolExecutor` for parallel API calls

### Anti-Pattern 4: External CSS Files for Email
**What:** Using `<link rel="stylesheet">` or `<style>` tags
**Why bad:** Email clients strip them; report looks broken
**Instead:** Inline all styles; use a CSS inliner tool if needed

## Integration Points

### Cloudflare GraphQL API
**Endpoint:** `https://api.cloudflare.com/client/v4/graphql`
**Auth:** Bearer token with `Analytics:Read` permission
**Data source:** `firewallEventsAdaptive` for security events

```python
# src/collectors/cloudflare.py
GRAPHQL_QUERY = """
query FirewallEvents($zoneTag: string!, $filter: FirewallEventsAdaptiveFilter_InputObject) {
    viewer {
        zones(filter: { zoneTag: $zoneTag }) {
            firewallEventsAdaptive(filter: $filter, limit: 100, orderBy: [datetime_DESC]) {
                action
                clientIP
                clientCountryName
                clientRequestPath
                datetime
                source
                userAgent
            }
        }
    }
}
"""

def collect(zone_id: str, api_token: str, lookback_hours: int = 24) -> dict:
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    
    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    
    response = requests.post(
        "https://api.cloudflare.com/client/v4/graphql",
        headers=headers,
        json={
            "query": GRAPHQL_QUERY,
            "variables": {
                "zoneTag": zone_id,
                "filter": {"datetime_geq": since}
            }
        }
    )
    # ... process response
```

### Mailgun API
**Endpoint:** `https://api.mailgun.net/v3/{domain}/messages`
**Auth:** Basic auth with `api` as username, API key as password
**Method:** POST with form-data

```python
# src/reports/email_sender.py
def send(html_body: str, subject: str, to: list[str], from_email: str, 
         domain: str, api_key: str, json_attachment: str = None) -> dict:
    
    data = {
        "from": from_email,
        "to": ",".join(to),
        "subject": subject,
        "html": html_body,
    }
    
    files = None
    if json_attachment:
        files = [("attachment", ("report.json", json_attachment, "application/json"))]
    
    response = requests.post(
        f"https://api.mailgun.net/v3/{domain}/messages",
        auth=("api", api_key),
        data=data,
        files=files,
    )
    
    if response.ok:
        return {"success": True, "message_id": response.json().get("id")}
    else:
        return {"success": False, "error": response.text}
```

### Laravel Forge Cron
**Schedule:** Cron expression in Forge UI
**Command:** `cd /path/to/waldo-shield && /path/to/venv/bin/python src/monitor.py --env production`
**Environment:** Set env vars in Forge "Environment" section

## Suggested Build Order

Components have dependencies; build in this order to enable incremental testing:

| Phase | Components | Rationale |
|-------|------------|-----------|
| 1 | `src/config.py` | Foundation; all other components depend on config loading |
| 2 | `src/collectors/cloudflare.py` | Independent of report pipeline; can test with CLI |
| 3 | `src/reports/generator.py` | Needs only existing scanner output to test |
| 4 | `src/templates/`, `src/reports/html_renderer.py` | Needs generator output |
| 5 | `src/reports/email_sender.py` | Needs HTML output; can test with Mailgun sandbox |
| 6 | `src/monitor.py` | Orchestration; ties everything together |
| 7 | Documentation, Forge setup | After code is working |

**Build order rationale:**
1. **Config first** — Everything needs environment settings
2. **Cloudflare collector second** — Can test independently, doesn't need other new code
3. **Generator third** — Can test with existing scanner output (JSON files in reports/)
4. **HTML rendering fourth** — Needs generator output; test by opening HTML in browser
5. **Email sender fifth** — Needs HTML; test with Mailgun test mode
6. **Monitor last** — Integration layer; only makes sense when all parts work

## Sources

- Cloudflare GraphQL Analytics API: https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/ [VERIFIED]
- Mailgun Send API: https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/messages/ [VERIFIED]
- Jinja2 Templating: https://jinja.palletsprojects.com/en/3.1.x/api/ [VERIFIED]
- Existing codebase: `src/scanner.py`, `src/modules/` [VERIFIED]
- Project requirements: `.planning/PROJECT.md` [VERIFIED]

---

*Architecture analysis: 2026-03-16*
