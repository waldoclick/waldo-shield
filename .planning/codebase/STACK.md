# Technology Stack

**Analysis Date:** 2026-03-16

## Languages

**Primary:**
- Python 3.12 - Scanner tool (`src/scanner.py`, `src/modules/*.py`)

**Secondary:**
- None — this is a pure Python project

## Runtime

**Environment:**
- Python 3.12.3 (system-installed on Linux)

**Package Manager:**
- pip 24.0
- Lockfile: Not present — only `src/requirements.txt` with minimum version pins

## Frameworks

**Core:**
- None — standard library + third-party packages only; no web framework

**Testing:**
- Not detected — no test framework configured

**Build/Dev:**
- None — no build tooling; run directly with `python src/scanner.py`

## Key Dependencies

**Critical:**
- `requests>=2.31.0` — all HTTP scanning (headers, vulnerability checks, tech detection)
- `dnspython>=2.4.2` — DNS record resolution, DNSSEC checks, zone transfer tests (`src/modules/dns_analysis.py`)
- `cryptography>=41.0.0` — SSL/TLS certificate analysis (`src/modules/ssl_tls.py`)
- `beautifulsoup4>=4.12.0` — HTML parsing for technology detection (`src/modules/tech_detection.py`)
- `lxml>=4.9.3` — HTML parser backend for BeautifulSoup (`src/modules/tech_detection.py`)
- `python-whois>=0.8.0` — listed as dependency but not actively imported in current modules

**Infrastructure:**
- Standard library: `ssl`, `socket`, `concurrent.futures`, `json`, `argparse`, `datetime`, `re`, `urllib.parse`

## Configuration

**Environment:**
- No `.env` file in use by the scanner itself
- `.env` is gitignored (`src/.gitignore`)
- No runtime configuration required — all parameters via CLI arguments

**Build:**
- `src/requirements.txt` — only dependency manifest; no `setup.py`, `pyproject.toml`, or `poetry.lock`

## Platform Requirements

**Development:**
- Python 3.12+
- Install deps: `pip install -r src/requirements.txt`
- No virtual environment enforced (`.venv/` is gitignored as optional)

**Production:**
- CLI tool only — not deployed as a service
- Run directly: `python src/scanner.py <url> [--modules ...] [--output ...]`
- Output: JSON files written to `reports/` (gitignored)

---

*Stack analysis: 2026-03-16*
