---
phase: 2
slug: data-collection
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-16
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x (from Phase 1) |
| **Config file** | tests/conftest.py (exists) |
| **Quick run command** | `pytest tests/ -x -q` |
| **Full suite command** | `pytest tests/ -v` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -x -q`
- **After every plan wave:** Run `pytest tests/ -v`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | DNS-01 | unit | `pytest tests/test_email_auth.py -k spf` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | DNS-02 | unit | `pytest tests/test_email_auth.py -k dkim` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | DNS-03 | unit | `pytest tests/test_email_auth.py -k dmarc` | ❌ W0 | ⬜ pending |
| 02-01-04 | 01 | 1 | DNS-04 | unit | `pytest tests/test_email_auth.py -k caa` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 1 | CF-01 | unit | `pytest tests/test_cloudflare.py -k waf` | ❌ W0 | ⬜ pending |
| 02-02-02 | 02 | 1 | CF-02 | unit | `pytest tests/test_cloudflare.py -k traffic` | ❌ W0 | ⬜ pending |
| 02-02-03 | 02 | 1 | CF-03 | unit | `pytest tests/test_cloudflare.py -k rate_limit` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_email_auth.py` — stubs for DNS-01, DNS-02, DNS-03, DNS-04
- [ ] `tests/test_cloudflare.py` — stubs for CF-01, CF-02, CF-03
- [ ] `tests/fixtures/` — mock responses for checkdmarc and Cloudflare API

*Existing infrastructure from Phase 1 covers pytest setup.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real Cloudflare data | CF-01, CF-02, CF-03 | Requires live API access | Run with real tokens, verify JSON response matches expected schema |
| Real DNS records | DNS-01, DNS-02, DNS-03, DNS-04 | Network dependency | Query waldo.click/waldoclick.dev, verify output matches mxtoolbox |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
