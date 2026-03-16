# Phase 2: Data Collection - Research

**Researched:** 2026-03-16
**Domain:** DNS email security validation & Cloudflare API integration
**Confidence:** HIGH

## Summary

Phase 2 implements data collection from two sources: DNS-based email security records (SPF, DKIM, DMARC, CAA) and Cloudflare API (WAF events, traffic analytics, rate limiting rules). The project already has a `dns_analysis.py` module with basic SPF/DMARC checking that needs enhancement using the `checkdmarc` library for proper validation. Cloudflare integration requires the official `cloudflare` SDK (v4.3.1+) with careful attention to API rate limits and data retention periods.

Key insight: The existing `dns_analysis.py` handles apex domain extraction correctly but does basic pattern matching. The `checkdmarc` library provides proper validation including SPF lookup counting (10-lookup limit enforcement), DMARC policy analysis, and DKIM selector validation. For Cloudflare, the official SDK handles retry logic and rate limiting automatically, but we must query within the plan's data retention window.

**Primary recommendation:** Replace basic DNS checks with `checkdmarc.check_domains()` for comprehensive validation; use Cloudflare official SDK with explicit zone IDs from config; query only last 24 hours of security events (safe for all plans).

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `cloudflare` | `>=4.3.1` | Cloudflare API client | Official SDK by Cloudflare, typed, handles retries/rate limits automatically |
| `checkdmarc` | `>=5.13.4` | SPF/DKIM/DMARC validation | Industry standard for email authentication checks, counts DNS lookups, validates policy effectiveness |
| `dnspython` | `>=2.8.0` | DNS toolkit | Already in use, required by checkdmarc |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `requests` | `>=2.32.5` | HTTP client | Already in use, for any non-Cloudflare API calls |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `cloudflare` SDK | Raw `requests` + GraphQL | SDK handles rate limits, pagination, retries; raw requests require manual implementation |
| `checkdmarc` | Manual `dnspython` queries | checkdmarc validates policy effectiveness, counts lookups, handles edge cases |

**Installation:**
```bash
pip install cloudflare>=4.3.1 checkdmarc>=5.13.4
# Update existing: dnspython>=2.8.0
```

## Architecture Patterns

### Recommended Project Structure
```
src/
├── config/                # Phase 1 - existing
│   ├── __init__.py
│   ├── loader.py
│   └── settings.py
├── modules/               # Data collection modules
│   ├── __init__.py
│   ├── dns_analysis.py    # Extend with checkdmarc
│   └── cloudflare_api.py  # NEW: Cloudflare data collection
├── collectors/            # ALTERNATIVE: Separate collector layer
│   ├── __init__.py
│   ├── dns.py
│   └── cloudflare.py
└── scanner.py             # Existing CLI entry point
```

**Recommended approach:** Extend existing `modules/dns_analysis.py` rather than creating new collector layer. Add new `modules/cloudflare_api.py` for Cloudflare integration.

### Pattern 1: Cloudflare Client Initialization
**What:** Initialize Cloudflare client once with token from config
**When to use:** At module import or scanner startup
**Example:**
```python
# Source: https://github.com/cloudflare/cloudflare-python README
from cloudflare import Cloudflare

def get_cloudflare_client(token: str) -> Cloudflare:
    """Initialize Cloudflare client with API token."""
    return Cloudflare(
        api_token=token,
        max_retries=2,  # SDK handles 429s automatically
    )
```

### Pattern 2: Zone-Scoped Data Collection
**What:** Query Cloudflare API using zone_id, not zone name
**When to use:** For all zone-specific queries (WAF, analytics, rules)
**Example:**
```python
# Source: Cloudflare Python SDK
def get_waf_events(client: Cloudflare, zone_id: str, hours: int = 24) -> list:
    """Retrieve WAF events for the last N hours."""
    # Use GraphQL for security events (REST API deprecated for this)
    # SDK provides client.graphql.post() for GraphQL queries
    query = '''
    query {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            limit: 1000,
            filter: {datetime_gt: $since}
            orderBy: [datetime_DESC]
          ) {
            datetime
            action
            clientIP
            ruleId
            source
          }
        }
      }
    }
    '''
    # Implementation details in code examples section
```

### Pattern 3: checkdmarc Domain Validation
**What:** Use checkdmarc's `check_domains()` for comprehensive validation
**When to use:** For all SPF/DKIM/DMARC checks
**Example:**
```python
# Source: https://domainaware.github.io/checkdmarc/api.html
import checkdmarc

def validate_email_security(domain: str) -> dict:
    """Validate SPF, DKIM, DMARC for a domain."""
    result = checkdmarc.check_domains(
        [domain],
        skip_tls=True,  # Don't test STARTTLS (not needed for our use case)
        timeout=5.0,
    )
    return result
```

### Pattern 4: CAA Record Validation
**What:** Check CAA records against expected CAs
**When to use:** Validate certificate authority restrictions
**Example:**
```python
# checkdmarc doesn't include CAA, keep using existing dnspython approach
import dns.resolver

def check_caa_records(domain: str, expected_ca: str = "pki.goog") -> dict:
    """Validate CAA records match expected CA."""
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        records = [str(rdata) for rdata in answers]
        has_expected = any(expected_ca in r for r in records)
        return {
            "records": records,
            "expected_ca": expected_ca,
            "valid": has_expected,
            "issues": [] if has_expected else [{
                "severity": "medium",
                "message": f"CAA records do not include expected CA ({expected_ca})"
            }]
        }
    except dns.resolver.NoAnswer:
        return {"records": [], "valid": False, "issues": [...]}
```

### Anti-Patterns to Avoid
- **Creating Cloudflare client per request:** Initialize once, reuse
- **Querying beyond data retention:** Events may be silently empty
- **Ignoring checkdmarc warnings:** They indicate policy ineffectiveness
- **Hardcoding zone IDs:** Get from config, derived from domain

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SPF lookup counting | Manual recursive lookup counter | `checkdmarc.spf.check_spf()` | SPF has 10-lookup limit, void lookup limits, include loops |
| DMARC policy validation | String parsing for p=, sp=, pct= | `checkdmarc.dmarc.check_dmarc()` | Policy effectiveness depends on multiple tag interactions |
| DKIM selector discovery | Guessing common selectors | `checkdmarc` with known selectors | DKIM selectors are arbitrary, validation needs specific selector |
| Cloudflare rate limiting | Manual 429 handling | `cloudflare` SDK | SDK has exponential backoff, respects Retry-After |
| GraphQL pagination | Manual cursor handling | SDK auto-pagination | SDK handles pagination transparently |

**Key insight:** Email authentication (SPF/DKIM/DMARC) has many edge cases that seem simple but cause false positives/negatives when hand-rolled.

## Common Pitfalls

### Pitfall 1: Cloudflare Data Retention Mismatch
**What goes wrong:** Query 30 days of events but plan only retains 24-72 hours. API returns empty/partial data without error.
**Why it happens:** Retention varies by plan (Free/Pro: 24h, Business: 72h, Enterprise: 30d)
**How to avoid:** Query only last 24 hours (safe baseline). Document expected plan tier.
**Warning signs:** Suspiciously few events returned, zero events for busy zone

### Pitfall 2: DKIM Requires Known Selectors
**What goes wrong:** Attempting to validate DKIM without knowing selectors returns "no DKIM"
**Why it happens:** DKIM records are at `<selector>._domainkey.<domain>`. No way to enumerate selectors.
**How to avoid:** Document known DKIM selectors for waldo.click domains (likely from Mailgun)
**Warning signs:** All domains show "DKIM not found" when email clearly works

### Pitfall 3: checkdmarc Warnings vs Errors
**What goes wrong:** Treating only errors as issues, ignoring warnings
**Why it happens:** DMARC with `p=none` or `pct=0` parses successfully but is ineffective
**How to avoid:** Include checkdmarc warnings in security findings
**Warning signs:** "Valid" DMARC records that don't actually protect anything

### Pitfall 4: Zone ID vs Domain Name
**What goes wrong:** Cloudflare API calls fail or return wrong data
**Why it happens:** Some endpoints need zone_id, some accept domain name, confusion ensues
**How to avoid:** Always use zone_id from config; never derive dynamically
**Warning signs:** 404 errors, wrong zone's data returned

### Pitfall 5: Apex Domain Extraction for Email Records
**What goes wrong:** SPF/DMARC checks run against `api.waldoclick.dev` instead of `waldoclick.dev`
**Why it happens:** Email records live at apex domain, not subdomains
**How to avoid:** Existing `dns_analysis.py` already handles this correctly - maintain pattern
**Warning signs:** "No SPF record" when one exists at apex

## Code Examples

Verified patterns from official sources:

### Comprehensive DNS/Email Check with checkdmarc
```python
# Source: https://domainaware.github.io/checkdmarc/api.html
import checkdmarc

def check_email_security(domain: str) -> dict:
    """
    Comprehensive email security check for a domain.
    Returns SPF, DKIM, DMARC validation results.
    """
    # Extract apex domain for email checks
    parts = domain.split(".")
    apex_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain
    
    result = checkdmarc.check_domains(
        [apex_domain],
        skip_tls=True,  # Don't need STARTTLS for security assessment
        timeout=5.0,
        timeout_retries=2,
    )
    
    # checkdmarc returns single result for single domain
    if isinstance(result, list):
        result = result[0]
    
    return {
        "domain": apex_domain,
        "spf": result.get("spf", {}),
        "dmarc": result.get("dmarc", {}),
        "dnssec": result.get("dnssec", False),
        "ns": result.get("ns", {}),
        "mx": result.get("mx", {}),
    }
```

### Cloudflare WAF Events via GraphQL
```python
# Source: Cloudflare GraphQL API docs + Python SDK
from datetime import datetime, timedelta, timezone
from cloudflare import Cloudflare

def get_security_events(client: Cloudflare, zone_id: str, hours: int = 24) -> dict:
    """
    Retrieve WAF/security events from Cloudflare.
    Uses GraphQL API for comprehensive event data.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    
    query = '''
    query GetSecurityEvents($zoneTag: String!, $since: String!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            limit: 1000,
            filter: {datetime_gt: $since}
            orderBy: [datetime_DESC]
          ) {
            datetime
            action
            clientIP
            clientCountryName
            ruleId
            source
            userAgent
          }
        }
      }
    }
    '''
    
    # Use SDK's graphql method
    response = client.graphql.post(
        body={
            "query": query,
            "variables": {
                "zoneTag": zone_id,
                "since": since,
            }
        }
    )
    
    events = response.get("data", {}).get("viewer", {}).get("zones", [{}])[0].get("firewallEventsAdaptive", [])
    
    return {
        "zone_id": zone_id,
        "period_hours": hours,
        "total_events": len(events),
        "events": events,
        "by_action": _group_by(events, "action"),
        "by_source": _group_by(events, "source"),
    }
```

### Cloudflare Rate Limiting Rules
```python
# Source: Cloudflare Python SDK api.md
from cloudflare import Cloudflare

def get_rate_limit_rules(client: Cloudflare, zone_id: str) -> list:
    """
    Retrieve configured rate limiting rules for a zone.
    """
    # Rate limiting rules are part of the ruleset API
    # Get zone rulesets and filter for rate limiting phase
    rulesets = client.rulesets.list(zone_id=zone_id)
    
    rate_limit_rules = []
    for ruleset in rulesets:
        if ruleset.phase == "http_ratelimit":
            # Get full ruleset with rules
            full_ruleset = client.rulesets.get(
                ruleset_id=ruleset.id,
                zone_id=zone_id
            )
            rate_limit_rules.extend(full_ruleset.rules or [])
    
    return rate_limit_rules
```

### Traffic Analytics via GraphQL
```python
# Source: Cloudflare GraphQL Analytics API
def get_traffic_analytics(client: Cloudflare, zone_id: str, hours: int = 24) -> dict:
    """
    Retrieve traffic analytics (requests, blocked percentage).
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    
    query = '''
    query GetTrafficAnalytics($zoneTag: String!, $since: String!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 1,
            filter: {datetime_gt: $since}
          ) {
            sum {
              requests
              cachedRequests
              encryptedRequests
            }
            dimensions {
              datetimeHour
            }
          }
          firewallEventsAdaptiveGroups(
            limit: 1,
            filter: {datetime_gt: $since}
          ) {
            count
          }
        }
      }
    }
    '''
    
    response = client.graphql.post(
        body={"query": query, "variables": {"zoneTag": zone_id, "since": since}}
    )
    
    # Parse response for traffic metrics
    # Implementation extracts totals and calculates percentages
    ...
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `python-cloudflare` community package | `cloudflare` official SDK | 2024 | Better typing, maintained by Cloudflare |
| REST API for security events | GraphQL API | 2022+ | More flexible queries, better aggregation |
| Manual SPF/DMARC parsing | `checkdmarc` library | Stable | Proper validation, not just presence checks |

**Deprecated/outdated:**
- `python-cloudflare`: Deprecated, use `cloudflare` (official)
- Cloudflare Firewall Rules API: Migrated to Rulesets API
- Zone-level rate limiting (old): Replaced by rate limiting rules

## Open Questions

1. **DKIM Selectors for waldo.click/waldoclick.dev**
   - What we know: Mailgun is used for transactional email
   - What's unclear: Exact DKIM selector names (often `mx` or `smtp` for Mailgun)
   - Recommendation: Check Mailgun dashboard or query common selectors

2. **Cloudflare Plan Tier**
   - What we know: Using Cloudflare for all domains
   - What's unclear: Exact plan tier (affects data retention)
   - Recommendation: Query 24h only (safe for all plans), log actual tier in reports

3. **Zone IDs for waldo.click and waldoclick.dev**
   - What we know: Need zone IDs for API calls
   - What's unclear: Whether to auto-discover or require in config
   - Recommendation: Add to config as `CLOUDFLARE_ZONE_ID_PROD` and `CLOUDFLARE_ZONE_ID_STAGING`

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.0+ |
| Config file | `pyproject.toml` or `pytest.ini` (to be created if needed) |
| Quick run command | `pytest tests/ -x --tb=short` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DNS-01 | SPF validation for both domains | unit | `pytest tests/test_dns.py::test_spf_validation -x` | Wave 0 |
| DNS-02 | DKIM validation for both domains | unit | `pytest tests/test_dns.py::test_dkim_validation -x` | Wave 0 |
| DNS-03 | DMARC validation for both domains | unit | `pytest tests/test_dns.py::test_dmarc_validation -x` | Wave 0 |
| DNS-04 | CAA validation (pki.goog expected) | unit | `pytest tests/test_dns.py::test_caa_validation -x` | Wave 0 |
| CF-01 | WAF events retrieval | integration | `pytest tests/test_cloudflare.py::test_waf_events -x` | Wave 0 |
| CF-02 | Traffic analytics retrieval | integration | `pytest tests/test_cloudflare.py::test_traffic_analytics -x` | Wave 0 |
| CF-03 | Rate limit rules retrieval | integration | `pytest tests/test_cloudflare.py::test_rate_limit_rules -x` | Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_dns.py tests/test_cloudflare.py -x --tb=short`
- **Per wave merge:** `pytest tests/ -v`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_dns.py` — DNS/email security validation tests (mock checkdmarc)
- [ ] `tests/test_cloudflare.py` — Cloudflare API integration tests (mock SDK)
- [ ] Test fixtures for mocking external APIs
- [ ] Framework install: Already have pytest>=8.0.0 in requirements.txt

## Sources

### Primary (HIGH confidence)
- https://github.com/cloudflare/cloudflare-python - Official Cloudflare Python SDK
- https://domainaware.github.io/checkdmarc/api.html - checkdmarc API documentation
- https://developers.cloudflare.com/waf/analytics/security-events/ - Security Events data retention
- https://developers.cloudflare.com/analytics/graphql-api/limits/ - GraphQL API limits
- https://developers.cloudflare.com/waf/rate-limiting-rules/ - Rate limiting rules API

### Secondary (MEDIUM confidence)
- Existing `src/modules/dns_analysis.py` - Current implementation patterns

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Official SDKs, well-documented libraries
- Architecture: HIGH - Extends existing patterns from Phase 1
- Pitfalls: HIGH - Verified from official Cloudflare docs

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (30 days - stable libraries)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DNS-01 | Scanner validates SPF records for waldo.click and waldoclick.dev | `checkdmarc.spf.check_spf()` provides full validation with lookup counting |
| DNS-02 | Scanner validates DKIM records for both domains | `checkdmarc.check_domains()` validates DKIM with known selectors |
| DNS-03 | Scanner validates DMARC policies for both domains | `checkdmarc.dmarc.check_dmarc()` validates and warns on ineffective policies |
| DNS-04 | Scanner checks CAA records match expected CAs (pki.goog) | Existing dnspython approach in dns_analysis.py, enhance with explicit CA validation |
| CF-01 | System retrieves WAF events from Cloudflare API for both zones | Cloudflare SDK + GraphQL `firewallEventsAdaptive` query |
| CF-02 | System retrieves traffic analytics (requests, blocked percentage) | Cloudflare SDK + GraphQL `httpRequestsAdaptiveGroups` query |
| CF-03 | System retrieves configured rate limiting rules | Cloudflare SDK `client.rulesets.list()` with phase filter |
</phase_requirements>
