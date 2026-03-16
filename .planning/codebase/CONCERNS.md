# Codebase Concerns

**Analysis Date:** 2026-03-16

---

## Tech Debt

**`python-whois` unused dependency:**
- Issue: `python-whois>=0.8.0` is listed in `src/requirements.txt` but is not imported or used anywhere in the source code.
- Files: `src/requirements.txt`
- Impact: Unnecessary install weight; installs a dependency that could introduce transitive vulnerabilities without benefit.
- Fix approach: Remove the `python-whois` line from `src/requirements.txt`.

**Hardcoded tool version string:**
- Issue: `"version": "1.0.0"` is hardcoded in the report metadata inside `scan()`, not derived from any version file or package manifest.
- Files: `src/scanner.py` (line 129)
- Impact: Version number will drift out of sync over time; can mislead report consumers about which scanner version produced a report.
- Fix approach: Add a `__version__` constant at the top of `scanner.py` or a `pyproject.toml`/`setup.cfg`, and reference it in the report.

**No `requirements-dev.txt` or environment pinning:**
- Issue: `src/requirements.txt` uses `>=` ranges (e.g. `requests>=2.31.0`) with no lockfile. There is no `.python-version`, `pyproject.toml`, or `Pipfile.lock`.
- Files: `src/requirements.txt`
- Impact: Reproducibility risk; a `pip install` six months from now may pull a breaking major version. No guarantee of a consistent environment between developer machines and CI.
- Fix approach: Add a `requirements-lock.txt` (generated via `pip freeze`) or adopt `pip-tools` / `poetry` for deterministic installs.

**`tech_detection.py` uses bare `requests.get` instead of a shared session:**
- Issue: `tech_detection.analyze()` opens three separate `requests.get()` calls (main page, url_probe, admin panels) without a shared `requests.Session`. Every other module creates a session explicitly.
- Files: `src/modules/tech_detection.py` (lines 88, 124, 158)
- Impact: No connection pooling or shared cookie jar, minor inefficiency; inconsistent pattern vs. other modules.
- Fix approach: Create a `session = requests.Session()` at the top of `analyze()` and replace all bare `requests.get()` calls with `session.get()`.

---

## Known Bugs

**False positives: Zero Trust `dashboard.*` endpoints:**
- Symptoms: Scanner reports `/.env`, `/.git/HEAD`, and `/phpinfo.php` on `dashboard.*` as CRITICAL vulnerabilities (accessible at HTTP 200).
- Files: `src/modules/vulnerabilities.py` (lines 126–155), `src/modules/tech_detection.py` (lines 151–183)
- Trigger: Cloudflare Zero Trust redirects (HTTP 302 to `cloudflareaccess.com`) are followed by `_test_sensitive_files()` in a second request to the `Location` header value, which can return 200. The Zero Trust check in `_is_zero_trust_redirect()` only catches direct 302s, not chained redirects.
- Status: Partially mitigated — `_is_zero_trust_redirect()` blocks direct 302s, but the follow-redirect logic at lines 133–136 in `vulnerabilities.py` re-fetches the `location` without re-checking for Zero Trust indicators.
- Fix approach: After following any redirect in `_test_sensitive_files()`, call `_is_zero_trust_redirect()` on the new response before evaluating its status code. Also validate against `ZERO_TRUST_INDICATORS` in the final `location` URL string.

**False positive: `www.*` Nuxt renders 404 pages with `/phpinfo.php` in the title:**
- Symptoms: Scanner flags `phpinfo.php` as CRITICAL on `www.*` hosts because Nuxt returns HTTP 200 with page title containing "Phpinfo Php".
- Files: `src/modules/vulnerabilities.py` (lines 67–81, `CONTENT_SIGNATURES`)
- Trigger: `_is_real_sensitive_content()` checks for `["phpinfo()", "PHP Version", "<table>"]` in the first 2KB of body, but a Nuxt 404 page may contain generic HTML `<table>` elements.
- Fix approach: Make the `phpinfo.php` signature stricter — check for `phpinfo()` AND `PHP Version` (both must be present), not just any single hit. Remove the generic `<table>` signature match.

**`robots.txt` always reported as a vulnerability:**
- Symptoms: `robots.txt` is listed under `sensitive_paths` with description "robots.txt may reveal hidden paths" and will always appear as a `medium` issue on any well-configured site that intentionally publishes `robots.txt`.
- Files: `src/modules/vulnerabilities.py` (line 107)
- Trigger: Any site serving robots.txt at HTTP 200, which is expected and standard.
- Fix approach: Downgrade to `info` severity (or remove from sensitive_paths) since a publicly accessible `robots.txt` is expected behavior, not a vulnerability. Apply content-signature analysis to check for actually sensitive paths listed inside it.

---

## Security Considerations

**Scanner makes live requests with a real browser User-Agent:**
- Risk: The scanner impersonates a Chrome browser (`Chrome/120.0.0.0`). If scan targets have bot-detection or WAF rules, this could result in IP blocks or legal liability if run against third-party targets.
- Files: `src/modules/vulnerabilities.py` (lines 255–261), `src/modules/tech_detection.py` (lines 81–87)
- Current mitigation: None.
- Recommendations: Add a `--user-agent` CLI flag. Consider defaulting to a clearly identified security-scanner user-agent string (e.g., `waldo-shield/1.0`) to avoid ambiguity.

**XSS probe sends a real `<script>` tag to production endpoints:**
- Risk: `_test_xss_reflection()` fires `<script>alert(1)</script>` as query parameters against the live production URL on every full scan. If these requests are logged, they could pollute application logs or trigger WAF alerts. Running against a production environment is inherently disruptive.
- Files: `src/modules/vulnerabilities.py` (lines 159–178)
- Current mitigation: None.
- Recommendations: Add a `--safe-mode` flag that disables active probes (XSS, open redirect, directory listing) for production scans. Document the distinction between passive and active modules.

**Output report files saved in current working directory by default:**
- Risk: If the scanner is run from a directory tracked by git and `--output` is not specified, report files (which may contain sensitive scan results and infrastructure details) could be accidentally committed. The `reports/` directory is in `.gitignore`, but only if the user runs from the project root.
- Files: `src/scanner.py` (lines 215–216)
- Current mitigation: `reports/` directory is gitignored, but the default output path is the CWD, not `reports/`.
- Recommendations: Default the output path to `reports/<hostname>_report_<timestamp>.json` so reports always land in the gitignored directory.

---

## Performance Bottlenecks

**Port scanner uses 50 threads with no configurable limit:**
- Problem: `port_scan.analyze()` spawns a `ThreadPoolExecutor(max_workers=50)` to check 19 ports simultaneously against a remote host. On slower networks or with rate-limited targets, this creates a burst of 19 parallel TCP connections.
- Files: `src/modules/port_scan.py` (line 83)
- Cause: Fixed worker count is hardcoded with no CLI tuning option.
- Improvement path: Reduce `max_workers` to match the number of ports (19), or expose `--timeout` and `--port-threads` as CLI options. Current default `timeout=1.5s` per port is reasonable.

**Sequential execution of 4 HTTP modules with no parallelism:**
- Problem: `headers`, `ssl`, `tech`, and `vulns` modules all run sequentially in `scanner.py` even though `headers` and `ssl` are completely independent. On a slow target, this multiplies latency.
- Files: `src/scanner.py` (lines 98–112)
- Cause: The comment says "to avoid hammering server" but `headers` + `ssl` do not hammer (they are single-connection each). Only `vulns` and `tech` make multiple requests.
- Improvement path: Move `ssl` into the parallel group alongside `dns` and `ports`. Keep `headers`, `tech`, and `vulns` sequential to avoid overloading the target.

---

## Fragile Areas

**Apex domain extraction breaks for ccTLD domains (`.co.uk`, `.com.mx`):**
- Files: `src/modules/dns_analysis.py` (lines 131–132)
- Why fragile: The logic `".".join(parts[-2:])` always takes the last two parts of the hostname. For domains like `api.company.co.uk`, this yields `co.uk` instead of `company.co.uk`. SPF, DMARC, CAA, and DNSSEC checks would then query the wrong domain.
- Safe modification: Use a PSL (Public Suffix List) library (e.g. `tldextract`) to correctly extract the registered domain. Current targets (`waldo.click`, `waldoclick.dev`) are simple two-part TLDs and are not affected.
- Test coverage: No tests for this logic.

**`ssl_tls.py` uses `datetime.datetime.utcnow()` (deprecated in Python 3.12+):**
- Files: `src/modules/ssl_tls.py` (line 125)
- Why fragile: `datetime.utcnow()` is deprecated since Python 3.12 and will be removed in a future version. It also produces a naive datetime that is silently wrong if the system timezone is not UTC.
- Safe modification: Replace with `datetime.datetime.now(datetime.timezone.utc)` and make the comparison timezone-aware.
- Test coverage: No tests.

**`_test_sensitive_files()` follow-redirect logic is one level deep only:**
- Files: `src/modules/vulnerabilities.py` (lines 133–136)
- Why fragile: The code follows at most one redirect. A multi-hop redirect chain (e.g., 302 → 301 → 200) would not be followed, causing false negatives. Conversely, following a single redirect without re-checking Zero Trust status causes false positives (see Known Bugs above).
- Safe modification: Remove the manual follow-redirect block entirely and instead use `allow_redirects=True` with a custom redirect hook that aborts on Zero Trust indicators.

---

## Scaling Limits

**No rate limiting or per-host concurrency control:**
- Current capacity: Scanner fires all HTTP checks serially within each module but runs dns+ports in parallel. No delay between requests.
- Limit: A Cloudflare WAF or aggressive bot-protection rule could temporarily ban the scanner's IP after bulk requests.
- Scaling path: Add a configurable inter-request delay (e.g., `--delay 0.5`) and honor `Retry-After` headers in exceptions.

---

## Dependencies at Risk

**`python-whois` declared but unused:**
- Risk: Orphaned dependency; any future CVE in `python-whois` would show up in dependency audits for a package that provides no value.
- Impact: None currently (unused), but audit noise.
- Migration plan: Remove from `src/requirements.txt`.

**No pinned versions / lockfile:**
- Risk: `>=` constraints allow major-version bumps. `beautifulsoup4`, `lxml`, and `dnspython` have all had breaking changes between major versions.
- Impact: Silent breakage on fresh installs if a new incompatible version is published.
- Migration plan: Run `pip freeze > src/requirements-lock.txt` and add a note in README to use `pip install -r src/requirements-lock.txt` for reproducible installs.

---

## Test Coverage Gaps

**Zero test files exist in the project:**
- What's not tested: Every module (`headers.py`, `ssl_tls.py`, `dns_analysis.py`, `port_scan.py`, `tech_detection.py`, `vulnerabilities.py`, `scanner.py`)
- Files: All of `src/`
- Risk: Regressions in false-positive logic, apex-domain extraction, content-signature matching, or redirect handling will not be caught before deployment.
- Priority: High — especially for `vulnerabilities.py` where false-positive/false-negative correctness directly affects trust in the tool's output.

**No regression tests for known false positives:**
- What's not tested: The `ZERO_TRUST_INDICATORS` bypass logic, `_is_real_sensitive_content()` content matching, and Nuxt 404 detection heuristic in `tech_detection.py` are not covered by automated tests.
- Files: `src/modules/vulnerabilities.py`, `src/modules/tech_detection.py`
- Risk: Any future change to these heuristics could silently re-introduce false positives that were manually identified and documented in `AGENTS.md` and session notes.
- Priority: High — these are the most important correctness properties of the tool.

---

## Missing Critical Features

**No `--safe-mode` / passive-only scan option:**
- Problem: Active probes (XSS reflection, open redirect, directory listing) send potentially disruptive requests to the target. There is no way to run a purely passive scan (headers, SSL, DNS, tech fingerprint) without also triggering active vulnerability checks.
- Blocks: Running the scanner safely in scheduled/automated mode against production.

**No environment gate on `/api/cron-runner/*` in target application:**
- Problem: Per `AGENTS.md`, the `/api/cron-runner/*` endpoint in the Strapi API is intended only for `local`/`dev` environments but has no code-level environment check preventing it from responding in staging or production.
- Blocks: This is not a scanner code issue but a target-application issue documented as pending. The scanner cannot currently detect this gap.
- Action needed: Add an environment check in Strapi: respond only when `NODE_ENV` is `development` or `local`.

**No CI/CD pipeline:**
- Problem: No automated test runner, linter, or dependency audit is configured. Changes are validated manually.
- Blocks: Catching regressions before merging, dependency CVE scanning, code quality enforcement.

---

*Concerns audit: 2026-03-16*
