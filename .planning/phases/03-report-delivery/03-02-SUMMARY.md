---
phase: 03-report-delivery
plan: 02
subsystem: report
tags: [comparison, trends, badges, storage, json, historical-data]

# Dependency graph
requires:
  - phase: 03-report-delivery/01
    provides: generate_report() function, HTML templates, issue rendering
provides:
  - compare_scans() for delta detection between scan runs
  - save_scan() / load_latest_scan() for scan persistence
  - NEW/FIXED badges in HTML reports
  - Trend indicators (improved/degraded/stable) in executive summary
affects: [03-report-delivery/03]

# Tech tracking
tech-stack:
  added: []  # No new dependencies - pure Python
  patterns:
    - "Issue matching by (source_module, severity, message) tuple"
    - "Timestamped JSON files for scan history: reports/{env}/scan_{timestamp}.json"
    - "Trend calculation: score_delta positive = degraded, negative = improved"
    - "Badge injection into existing issue table rows"

key-files:
  created:
    - src/report/storage.py
    - src/report/comparison.py
    - tests/test_comparison.py
  modified:
    - src/report/generator.py
    - src/report/templates.py
    - tests/test_report.py

key-decisions:
  - "Store scans as timestamped JSON in reports/{env}/ directory"
  - "Issue matching uses (source_module, severity, message) tuple - handles same issue appearing in consecutive scans"
  - "Positive score_delta = risk increased (degraded), negative = risk decreased (improved)"
  - "Fixed issues shown with strikethrough text + FIXED badge"

patterns-established:
  - "save_scan(env, data) -> Path: Persist scan to reports/{env}/scan_{timestamp}.json"
  - "load_latest_scan(env) -> dict | None: Get most recent scan for comparison"
  - "compare_scans(current, previous) -> dict | None: Detect new/fixed issues and trend"
  - "NEW_BADGE / FIXED_BADGE templates for visual indicators"

requirements-completed: [RPT-03, RPT-04]

# Metrics
duration: 4min
completed: 2026-03-16
---

# Phase 03 Plan 02: Historical Comparison Summary

**Scan comparison with NEW/FIXED badges, trend indicators, and persistent JSON storage for tracking security posture changes over time**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T17:53:18Z
- **Completed:** 2026-03-16T17:57:53Z
- **Tasks:** 3 (2 TDD, 1 auto)
- **Files created/modified:** 6

## Accomplishments

- Created `src/report/storage.py` for scan persistence with timestamped JSON files
- Created `src/report/comparison.py` with compare_scans() for delta detection
- Added NEW badge for issues appearing since last scan
- Added FIXED section with strikethrough for resolved issues
- Added trend indicators (↓ Improved / ↑ Degraded / → Stable) in executive summary
- 20 new tests covering storage, comparison, and display functionality

## Task Commits

Each task was committed atomically:

1. **Task 1: Scan storage module (TDD)** - `121cd3c` (feat)
2. **Task 2: Comparison logic (TDD)** - `19bae27` (feat)
3. **Task 3: Comparison display in HTML** - `3af040c` (feat)

## Files Created/Modified

- `src/report/storage.py` - Scan persistence (save_scan, load_latest_scan)
- `src/report/comparison.py` - Delta detection (compare_scans)
- `src/report/templates.py` - NEW_BADGE, FIXED_BADGE, trend templates
- `src/report/generator.py` - Updated to render comparison data
- `tests/test_comparison.py` - 15 tests for storage and comparison
- `tests/test_report.py` - 5 new tests for comparison display

## Decisions Made

1. **Timestamped JSON storage** - Scans saved as `reports/{env}/scan_{timestamp}.json` for simple file-based history
2. **Issue matching tuple** - Issues matched by (source_module, severity, message) to identify same issues across scans
3. **Score delta convention** - Positive delta = worse (degraded), negative = better (improved)
4. **Badge placement** - NEW badge appended to issue message in table, FIXED issues in separate section

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tasks completed successfully with TDD flow (RED-GREEN-REFACTOR).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Comparison module ready for Phase 3 Plan 03 (email delivery via Mailgun)
- generate_report() accepts optional `comparison` dict for trend display
- Storage module can be used by monitor.py to save/load scans
- All 35 tests passing, ready for integration

## Self-Check: PASSED

- [x] src/report/storage.py exists
- [x] src/report/comparison.py exists
- [x] tests/test_comparison.py exists
- [x] Commit 121cd3c (storage) exists
- [x] Commit 19bae27 (comparison) exists
- [x] Commit 3af040c (display) exists

---
*Phase: 03-report-delivery*
*Completed: 2026-03-16*
