# Coding Conventions

**Analysis Date:** 2026-03-16

## Naming Patterns

**Files:**
- Module files: `snake_case.py` (e.g. `dns_analysis.py`, `tech_detection.py`, `ssl_tls.py`)
- Private helpers: prefix with single underscore `_function_name` (e.g. `_check_spf`, `_test_xss_reflection`, `_is_zero_trust_redirect`)
- Constants: `UPPER_SNAKE_CASE` (e.g. `SECURITY_HEADERS`, `DANGEROUS_HEADERS`, `RISKY_PORTS`, `SEVERITY_ORDER`)

**Functions:**
- Public module entry point: always named `analyze(url: str) -> dict` — every module in `src/modules/` exposes this exact signature
- Private helpers: `_verb_noun` pattern — `_check_port`, `_query`, `_check_spf`, `_test_sensitive_files`, `_extract_js_versions`
- Orchestrator functions: descriptive verbs — `scan`, `run_module`, `normalize_url`, `calculate_risk_score`, `print_summary`

**Variables:**
- Local variables: `snake_case`
- Loop variables: short and descriptive — `issue`, `rdn`, `attr`, `m`, `future`
- Results dict: always named `result` inside module functions

**Types:**
- Type hints used consistently on all public/private function signatures
- Return types always `-> dict` for `analyze()` and `-> list` for helper checkers
- Inline type annotations used occasionally: `subject: dict = {}`, `issuer: dict = {}`

## Code Style

**Formatting:**
- No auto-formatter config file detected (no `.prettierrc`, `pyproject.toml`, or `setup.cfg`)
- Indentation: 4 spaces consistently
- Line length: generally under 100 chars; long strings (user-agent, recommendations) kept on single lines
- Trailing commas in multi-line dicts and lists

**Linting:**
- No linting config detected (no `.flake8`, `.pylintrc`, `ruff.toml`)
- Style is clean and consistent despite lack of tooling config

## Import Organization

**Order:**
1. Standard library (`sys`, `json`, `ssl`, `socket`, `re`, `datetime`, `concurrent.futures`)
2. Third-party (`requests`, `dns.resolver`, `bs4`)
3. Local/internal (`from modules import headers, ssl_tls, dns_analysis, ...`)

**Path Aliases:**
- None — modules imported by name from `src/modules/` package

**Pattern:**
```python
# scanner.py
import sys
import json
import time
import argparse
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules import headers, ssl_tls, dns_analysis, port_scan, tech_detection, vulnerabilities
```

## Module Return Contract

Every `analyze()` function returns a dict with this mandatory structure:
```python
{
    "module": "<module_name>",  # string identifier
    "url": url,                 # target URL
    "issues": [],               # list of issue dicts
    "error": None,              # string or None
    # ... module-specific fields
}
```

Every issue dict follows this structure:
```python
{
    "severity": "critical|high|medium|low|info",
    "message": "Human-readable description",
    "recommendation": "Actionable fix guidance",
    # optional: "header", "url", and other context fields
}
```

## Error Handling

**Strategy:** Catch-and-continue — errors are stored in `result["error"]` and the function always returns a complete dict. Never raises to caller.

**Patterns:**
- Specific exception types caught first, broad `Exception` as fallback:
  ```python
  except requests.exceptions.SSLError as e:
      result["error"] = f"SSL error: {str(e)}"
      result["issues"].append({...})
  except requests.exceptions.ConnectionError as e:
      result["error"] = f"Connection error: {str(e)}"
  except requests.exceptions.Timeout:
      result["error"] = "Connection timed out."
  except Exception as e:
      result["error"] = str(e)
  ```
- Helper functions use bare `except Exception: pass` to silently skip individual check failures without aborting the whole scan:
  ```python
  # vulnerabilities.py — each sub-check
  except Exception:
      pass
  ```
- `run_module()` in `src/scanner.py` wraps each module call in a try/except that stores the error and an empty issues list, ensuring the report always assembles completely

## Data Structures

**Constants as dicts:**
Module-level constants use dicts for rich configuration data:
```python
SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "...",
        "recommendation": "...",
    },
    ...
}
```

**Dict spreading for issue context:**
```python
issue_with_module = {**issue, "source_module": mod_result.get("module", "unknown")}
```

## Logging

**Framework:** `print()` to stdout — no logging library used

**Patterns:**
- `[*]` prefix for "starting" messages: `[*] Running: {name}...`
- `[+]` prefix for "done" messages: `[+] Done: {name} ({elapsed}s)`
- `flush=True` used on progress prints to ensure real-time output
- `print_summary()` in `src/scanner.py` formats a structured ASCII summary with `=` separator lines

## Comments

**When to Comment:**
- Short inline comments on non-obvious logic: `# Normalize to 0-100 (cap at 100)`
- Section separators inside functions: `# Check security headers`, `# Parallel: dns + ports`
- Clarifying business logic: `# Skip Zero Trust redirects — not a real exposure`

**Docstrings:**
- Module-level docstrings: every module file has a 3-line module docstring (name + description)
- Function docstrings: public functions with non-obvious behavior get one-line docstrings
- Entry-point (`scanner.py`) has an extended usage docstring used as CLI epilog

```python
"""
Module: HTTP Security Headers Analysis
Analyzes security-related HTTP response headers.
"""
```

## Function Design

**Size:** Helper functions are focused and small (10–50 lines); `analyze()` functions are longer (50–100 lines) but logically sectioned with inline comments

**Parameters:**
- Module `analyze()` functions take exactly `(url: str)` — consistent interface
- Helper functions take `(domain_or_url: str, session: requests.Session)` when they need HTTP
- Private socket helpers take optional `timeout: float` with a default

**Return Values:**
- Always a `dict` from `analyze()`
- Always a `list` from `_check_*` and `_test_*` helpers (list of issue dicts)
- `bool` from low-level checks like `_check_port()` and `_check_weak_cipher()`

## Module Design

**Exports:**
- Each module exports only `analyze` as the public function
- `src/modules/__init__.py` is minimal (comment only); imports done explicitly in `scanner.py`

**Barrel Files:**
- Not used — `scanner.py` imports each module by name:
  ```python
  from modules import headers, ssl_tls, dns_analysis, port_scan, tech_detection, vulnerabilities
  ```

## Concurrency Pattern

Parallel execution used for network-independent modules. Pattern in `src/scanner.py`:
```python
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    futures = {
        executor.submit(run_module, module_map[m][0], module_map[m][1], url): m
        for m in parallel_modules
    }
    for future in concurrent.futures.as_completed(futures):
        mod_key = futures[future]
        results[mod_key] = future.result()
```

Port scanning in `src/modules/port_scan.py` uses `max_workers=50` for high-concurrency port checks.

---

*Convention analysis: 2026-03-16*
