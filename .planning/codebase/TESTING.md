# Testing Patterns

**Analysis Date:** 2026-03-16

## Test Framework

**Runner:**
- None configured — no `pytest.ini`, `setup.cfg`, `pyproject.toml`, `tox.ini`, or `vitest.config.*` found
- No test runner installed in `src/requirements.txt`

**Assertion Library:**
- Not applicable — no test framework present

**Run Commands:**
```bash
# No test commands defined — tests do not exist in the codebase
```

## Test File Organization

**Location:**
- No test files found anywhere in the codebase
- No `tests/` or `test/` directory exists
- No `test_*.py` or `*_test.py` files present

**Naming:**
- Not applicable

**Structure:**
```
waldo-shield/
├── src/
│   ├── scanner.py          # No corresponding test_scanner.py
│   └── modules/
│       ├── headers.py       # No corresponding test_headers.py
│       ├── ssl_tls.py       # No corresponding test_ssl_tls.py
│       ├── dns_analysis.py  # No corresponding test_dns_analysis.py
│       ├── port_scan.py     # No corresponding test_port_scan.py
│       ├── tech_detection.py# No corresponding test_tech_detection.py
│       └── vulnerabilities.py # No corresponding test_vulnerabilities.py
└── reports/                # Manual test output (JSON files from actual scans)
```

## Test Evidence in Reports

**Manual testing artifacts** exist in `reports/` (gitignored):
- `reports/api_dns_test.json` — DNS module output from manual run
- `reports/dashboard_tech_test.json` — tech detection output
- `reports/dashboard_vulns_test.json` — vulnerability scan output
- `reports/www_tech_test.json` — frontend tech detection
- `reports/www_vulns_test.json` — frontend vulnerability scan

These are manual scan outputs, not automated tests.

## What Would Be Tested (Guidance for Adding Tests)

Given the codebase structure, tests should be introduced using **pytest** as the runner and **unittest.mock** / **pytest-mock** for network isolation.

### Recommended test structure:
```
waldo-shield/
└── tests/
    ├── __init__.py
    ├── test_scanner.py
    └── modules/
        ├── test_headers.py
        ├── test_ssl_tls.py
        ├── test_dns_analysis.py
        ├── test_port_scan.py
        ├── test_tech_detection.py
        └── test_vulnerabilities.py
```

### Module interface pattern to test:
Every module exposes `analyze(url: str) -> dict`. All tests should verify:
1. Return dict contains required keys: `"module"`, `"url"`, `"issues"`, `"error"`
2. Each issue dict has `"severity"`, `"message"`, `"recommendation"` keys
3. Error states return `error` as a string, not `None`, with `issues` still as a list

### Unit test example pattern (recommended):
```python
from unittest.mock import MagicMock, patch
import pytest
from src.modules import headers

def test_analyze_returns_required_keys():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.history = []
    mock_response.cookies = []

    with patch("requests.Session.get", return_value=mock_response):
        result = headers.analyze("https://example.com")

    assert "module" in result
    assert "issues" in result
    assert "error" in result
    assert isinstance(result["issues"], list)

def test_missing_hsts_raises_medium_issue():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}  # No HSTS header
    mock_response.history = []

    with patch("requests.Session.get", return_value=mock_response):
        result = headers.analyze("https://example.com")

    hsts_issue = next(
        (i for i in result["issues"] if "Strict-Transport-Security" in i["message"]),
        None
    )
    assert hsts_issue is not None
    assert hsts_issue["severity"] == "medium"
```

### What to Mock:
- `requests.Session.get` / `requests.get` — all HTTP calls in `headers.py`, `vulnerabilities.py`, `tech_detection.py`
- `socket.create_connection` — port scanning in `port_scan.py`
- `ssl.SSLContext.wrap_socket` — TLS checks in `ssl_tls.py`
- `dns.resolver.resolve` — DNS queries in `dns_analysis.py`

### What NOT to Mock:
- Pure computation: `calculate_risk_score()`, `normalize_url()`, `_check_weak_cipher()`, `_extract_js_versions()`
- Data structure builders that transform already-fetched data

## Mocking

**Framework:** Not installed — would use `unittest.mock` (stdlib) or `pytest-mock`

**Pattern for HTTP mocking:**
```python
from unittest.mock import patch, MagicMock

with patch("requests.Session") as mock_session:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-security-policy": "default-src 'self'"}
    mock_resp.history = []
    mock_session.return_value.get.return_value = mock_resp
    result = headers.analyze("https://example.com")
```

## Fixtures and Factories

**Test Data:**
- Not established — no fixtures exist
- Recommended: create fixture dicts matching the real module output format to test `calculate_risk_score()` and `print_summary()` in isolation

**Location:**
- Would go in `tests/fixtures/` or as `@pytest.fixture` functions in `conftest.py`

## Coverage

**Requirements:** None enforced

**View Coverage:**
```bash
# Once pytest is added:
pytest --cov=src --cov-report=term-missing
```

## Test Types

**Unit Tests:**
- Not present — should cover pure functions (`calculate_risk_score`, `normalize_url`, `_check_weak_cipher`, `_extract_js_versions`, `_is_zero_trust_redirect`, `_is_real_sensitive_content`) without any mocking

**Integration Tests:**
- Not present — should cover full `analyze()` call per module with HTTP/socket mocked

**E2E Tests:**
- Not used — manual scanning against real targets substitutes for this (see `reports/`)

## Priority Areas for Testing

Given the module structure, highest-value tests to add first:

1. **`src/scanner.py` — `calculate_risk_score()`** — pure function, zero dependencies, easy to unit test with issue lists
2. **`src/modules/vulnerabilities.py` — `_is_real_sensitive_content()`** — pure function, tests content signature matching logic  
3. **`src/modules/headers.py` — `analyze()`** — most logic, most issues generated, most impactful
4. **`src/modules/dns_analysis.py` — `_check_spf()`, `_check_dmarc()`** — pure logic after DNS resolution mocked
5. **`src/modules/ssl_tls.py` — `_check_weak_cipher()`** — pure function, trivial to test

---

*Testing analysis: 2026-03-16*
