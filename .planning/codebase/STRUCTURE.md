# Codebase Structure

**Analysis Date:** 2026-03-16

## Directory Layout

```
waldo-shield/
├── src/                    # All executable source code
│   ├── scanner.py          # Main CLI entry point and orchestrator
│   ├── requirements.txt    # Python dependencies
│   └── modules/            # Individual security analysis modules
│       ├── __init__.py     # Package marker (minimal)
│       ├── headers.py      # HTTP security headers analysis
│       ├── ssl_tls.py      # SSL/TLS certificate and cipher analysis
│       ├── dns_analysis.py # DNS records, SPF, DMARC, DNSSEC, zone transfer
│       ├── port_scan.py    # Common port scanning and risk classification
│       ├── tech_detection.py  # Technology fingerprinting (CMS, frameworks, JS libs)
│       └── vulnerabilities.py # Web vulnerability probes (XSS, CORS, cookies, files)
├── reports/                # Generated JSON scan reports (gitignored or committed)
├── sessions/               # Human-authored work session logs (Markdown)
│   └── YYYY-MM-DD.md       # One file per work session
├── .planning/              # GSD planning documents
│   └── codebase/           # Codebase analysis outputs (this directory)
├── AGENTS.md               # AI agent context: project overview, targets, stack, usage
├── CLAUDE.md               # Claude-specific instructions (if present)
├── README.md               # Project documentation
└── SECURITY_PROGRESS.md    # Remediation tracking: baselines, fixes applied, scores
```

## Directory Purposes

**`src/`:**
- Purpose: All runnable Python code
- Contains: Entry point (`scanner.py`), dependency manifest (`requirements.txt`), modules package
- Key files: `src/scanner.py` (orchestrator), `src/requirements.txt` (dependencies)

**`src/modules/`:**
- Purpose: One module per security analysis domain; each is independently importable
- Contains: Six analysis modules, all exposing `analyze(url: str) -> dict`
- Key files: `src/modules/vulnerabilities.py` (most complex, ~297 lines), `src/modules/dns_analysis.py` (~206 lines)

**`reports/`:**
- Purpose: Output directory for JSON scan reports
- Contains: Files named `<hostname>_report_<timestamp>.json` or manually named outputs
- Generated: Yes — by `src/scanner.py` at scan completion
- Committed: Yes (historical reports are tracked in git for trend comparison)

**`sessions/`:**
- Purpose: Human-authored logs of work sessions — what was scanned, what was fixed, what is pending
- Contains: One Markdown file per session, named `YYYY-MM-DD.md`
- Committed: Yes — serves as the operational change log
- Key files: `sessions/2026-03-15.md` (most recent session)

**`.planning/`:**
- Purpose: GSD planning documents for AI-assisted development
- Contains: `codebase/` subdirectory with analysis documents (STACK.md, ARCHITECTURE.md, etc.)
- Generated: Yes — by GSD map-codebase tooling
- Committed: Yes

## Key File Locations

**Entry Points:**
- `src/scanner.py`: CLI entry point — `main()` at line 178, `scan()` at line 75

**Configuration:**
- `src/requirements.txt`: Python package dependencies
- `AGENTS.md`: Canonical project context for AI agents — targets, stack, known false positives, business context

**Core Logic:**
- `src/scanner.py`: Orchestration, parallel dispatch, risk scoring, report assembly
- `src/modules/headers.py`: Security header checks (`SECURITY_HEADERS`, `DANGEROUS_HEADERS` dicts)
- `src/modules/ssl_tls.py`: Certificate validity, protocol version, cipher strength
- `src/modules/dns_analysis.py`: SPF, DMARC, DNSSEC, CAA, zone transfer checks
- `src/modules/port_scan.py`: TCP port probing with `RISKY_PORTS` classification
- `src/modules/tech_detection.py`: Signature-based tech detection, JS version checks, admin panel probes
- `src/modules/vulnerabilities.py`: Sensitive file probes, CORS, XSS reflection, cookie flags, open redirect, directory listing

**Progress Tracking:**
- `SECURITY_PROGRESS.md`: Baseline scores, fixes applied with dates, remaining issues
- `sessions/YYYY-MM-DD.md`: Detailed session notes including false positives and pending actions

**Reports:**
- `reports/`: All historical JSON reports — naming convention `<hostname>_report_<timestamp>.json`

## Naming Conventions

**Files:**
- Module files: `snake_case.py` (e.g. `dns_analysis.py`, `tech_detection.py`, `ssl_tls.py`)
- Report files: `<hostname>_<descriptor>.json` or `<hostname>_report_<YYYYMMDD_HHMMSS>.json`
- Session files: `YYYY-MM-DD.md`

**Directories:**
- Lowercase, no separators (e.g. `modules/`, `reports/`, `sessions/`)

**Functions:**
- Public functions: `snake_case` (e.g. `analyze`, `calculate_risk_score`, `normalize_url`)
- Private helpers: `_snake_case` with leading underscore (e.g. `_check_spf`, `_test_sensitive_files`, `_is_zero_trust_redirect`)

**Constants:**
- `UPPER_SNAKE_CASE` for module-level dicts and lists (e.g. `SECURITY_HEADERS`, `RISKY_PORTS`, `ZERO_TRUST_INDICATORS`, `SEVERITY_ORDER`)

**Module result keys:**
- Snake case strings matching the module's domain (e.g. `"http_headers"`, `"ssl_tls"`, `"dns_analysis"`, `"port_scan"`, `"tech_detection"`, `"vulnerabilities"`)

## Where to Add New Code

**New Analysis Module:**
- Implementation: `src/modules/<module_name>.py`
- Must export: `def analyze(url: str) -> dict` returning `{"module": str, "issues": list, "error": str|None, ...}`
- Register in: `src/scanner.py` — add to `module_map` dict (line ~86) and `all_modules` list (line ~198)
- Execution group: Add to `parallel_modules` list if network-independent (DNS/socket-based), or `sequential_modules` if HTTP-dependent

**New Check within Existing Module:**
- Implementation: Add a `_check_<thing>()` or `_test_<thing>()` private helper function in the relevant module
- Wire in: Call from the module's `analyze()` function; extend `result["issues"]` with returned issues

**New Report Field:**
- Add to the module's result dict initialization at the top of `analyze()`
- The orchestrator in `src/scanner.py` passes through each module result dict intact under `report["modules"]`

**New Session Log:**
- Create: `sessions/YYYY-MM-DD.md`
- Format: Follow pattern of `sessions/2026-03-15.md` — sections for Scope, Completed, Pending

**New Scan Report:**
- Generated automatically — run `python src/scanner.py <url>` and use `--output reports/<name>.json`

## Special Directories

**`reports/`:**
- Purpose: Historical JSON scan reports used to track security posture over time
- Generated: Yes — by scanner at runtime
- Committed: Yes — reports are committed for historical comparison

**`.planning/codebase/`:**
- Purpose: AI-generated codebase analysis documents consumed by GSD planning tools
- Generated: Yes — by GSD map-codebase
- Committed: Yes

**`src/modules/__pycache__/`:**
- Purpose: Python bytecode cache
- Generated: Yes — by Python interpreter
- Committed: No — excluded via `.gitignore`

---

*Structure analysis: 2026-03-16*
