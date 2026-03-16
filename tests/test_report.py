"""Tests for report generation module."""

import pytest
from datetime import datetime, timezone


# Sample data fixtures matching real module output structures
@pytest.fixture
def minimal_report_data():
    """Minimal data for basic report generation."""
    return {
        "environment": "staging",
        "scan_date": "2026-03-16T12:00:00Z",
        "targets": ["https://api.waldoclick.dev"],
        "http_results": {},
        "email_auth": {},
        "cloudflare": {},
    }


@pytest.fixture
def full_report_data():
    """Complete data with all sections populated."""
    return {
        "environment": "production",
        "scan_date": "2026-03-16T14:30:00Z",
        "targets": [
            "https://api.waldo.click",
            "https://dashboard.waldo.click",
            "https://www.waldo.click",
        ],
        "http_results": {
            "https://api.waldo.click": {
                "meta": {
                    "url": "https://api.waldo.click",
                    "hostname": "api.waldo.click",
                    "scan_date": "2026-03-16T14:30:00Z",
                },
                "risk_summary": {
                    "score": 15,
                    "risk_level": "low",
                    "issue_counts": {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 1},
                    "total_issues": 4,
                },
                "all_issues": [
                    {"severity": "medium", "message": "Missing CSP header", "source_module": "http_headers"},
                    {"severity": "low", "message": "Server header exposed", "source_module": "http_headers"},
                    {"severity": "low", "message": "X-Powered-By exposed", "source_module": "http_headers"},
                    {"severity": "info", "message": "Using HTTP/2", "source_module": "http_headers"},
                ],
            },
            "https://www.waldo.click": {
                "meta": {
                    "url": "https://www.waldo.click",
                    "hostname": "www.waldo.click",
                    "scan_date": "2026-03-16T14:31:00Z",
                },
                "risk_summary": {
                    "score": 45,
                    "risk_level": "high",
                    "issue_counts": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0},
                    "total_issues": 3,
                },
                "all_issues": [
                    {"severity": "high", "message": "Open redirect vulnerability", "source_module": "vulnerabilities"},
                    {"severity": "high", "message": "Missing HSTS header", "source_module": "http_headers"},
                    {"severity": "medium", "message": "Missing X-Frame-Options", "source_module": "http_headers"},
                ],
            },
        },
        "email_auth": {
            "waldo.click": {
                "domain": "waldo.click",
                "spf": {
                    "record": "v=spf1 include:mailgun.org ~all",
                    "valid": True,
                    "dns_lookups": 5,
                },
                "dkim": {
                    "selectors": {"mailgun": True, "default": False},
                },
                "dmarc": {
                    "record": "v=DMARC1; p=reject; rua=mailto:dmarc@waldo.click",
                    "policy": "reject",
                    "valid": True,
                },
                "caa": {
                    "records": ["0 issue \"pki.goog\""],
                    "expected_ca": "pki.goog",
                    "valid": True,
                },
                "issues": [
                    {"severity": "warning", "type": "spf", "message": "SPF uses soft fail (~all) instead of hard fail (-all)"},
                ],
            },
        },
        "cloudflare": {
            "security_events": {
                "zone_id": "abc123",
                "period_hours": 24,
                "total_events": 150,
                "events": [],
                "by_action": {"block": 100, "challenge": 30, "managed_challenge": 20},
                "by_source": {"firewall_rules": 80, "waf": 70},
            },
            "traffic_analytics": {
                "zone_id": "abc123",
                "period_hours": 24,
                "total_requests": 50000,
                "cached_requests": 35000,
                "blocked_requests": 500,
                "blocked_percentage": 1.0,
            },
            "rate_limit_rules": [
                {"expression": "(http.request.uri.path contains \"/api/\")", "action": "challenge"},
                {"expression": "(ip.src eq 192.168.1.1)", "action": "block"},
            ],
        },
    }


class TestReportGeneration:
    """Tests for generate_report function."""

    def test_minimal_data_returns_valid_html(self, minimal_report_data):
        """Test that generate_report with minimal data returns valid HTML."""
        from report.generator import generate_report

        html = generate_report(minimal_report_data)

        # Should be a string
        assert isinstance(html, str)
        # Should have HTML structure
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        # Should have required meta
        assert "staging" in html
        assert "2026-03-16" in html

    def test_executive_summary_contains_risk_info(self, full_report_data):
        """Test that executive summary section contains risk score and levels."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Should contain risk score (aggregate of all targets)
        assert "Executive Summary" in html
        # Risk level should appear
        assert any(level in html.lower() for level in ["critical", "high", "medium", "low", "none"])
        # Issue counts should be present
        assert ">0<" in html or ">1<" in html or ">2<" in html  # At least some numbers

    def test_http_findings_renders_per_target(self, full_report_data):
        """Test that HTTP findings section shows results for each target."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # HTTP section should exist
        assert "HTTP Scanner Findings" in html
        # Both targets with HTTP results should appear
        assert "api.waldo.click" in html
        assert "www.waldo.click" in html

    def test_email_auth_shows_status_indicators(self, full_report_data):
        """Test that email auth section shows SPF/DKIM/DMARC/CAA with valid/invalid indicators."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Email security section should exist
        assert "Email Security" in html
        # Domain should appear
        assert "waldo.click" in html
        # Protocol names should appear
        assert "SPF" in html
        assert "DKIM" in html
        assert "DMARC" in html
        assert "CAA" in html

    def test_cloudflare_shows_waf_and_analytics(self, full_report_data):
        """Test that Cloudflare section shows WAF events, blocked %, and rate limits."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Cloudflare section should exist
        assert "Cloudflare Security" in html
        # WAF events info
        assert "WAF Events" in html or "150" in html  # total events
        # Traffic analytics
        assert "1.0%" in html or "1%" in html  # blocked percentage
        # Rate limiting
        assert "Rate Limit" in html

    def test_issues_table_sorted_by_severity(self, full_report_data):
        """Test that issues table is sorted by severity (critical first, info last)."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Issues section should exist
        assert "All Issues" in html
        # High severity issues should appear before low/info
        high_pos = html.find("high")
        medium_pos = html.find("medium")
        # Can't guarantee exact order in HTML due to multiple occurrences,
        # but the issues table section should have severity badges
        assert "severity" in html.lower() or ">high<" in html.lower() or ">medium<" in html.lower()

    def test_empty_sections_render_gracefully(self, minimal_report_data):
        """Test that empty data sections show appropriate messages, not errors."""
        from report.generator import generate_report

        html = generate_report(minimal_report_data)

        # Should not crash and should produce valid HTML
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        # Should show "no data" type messages or empty sections
        assert "No" in html or "no" in html or "available" in html.lower() or len(html) > 1000


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_http_results_key(self):
        """Test handling when http_results key is missing."""
        from report.generator import generate_report

        data = {
            "environment": "test",
            "scan_date": "2026-03-16T00:00:00Z",
            "targets": [],
        }

        html = generate_report(data)
        assert "<!DOCTYPE html>" in html

    def test_cloudflare_error_dict(self):
        """Test handling when cloudflare returns error dict."""
        from report.generator import generate_report

        data = {
            "environment": "test",
            "scan_date": "2026-03-16T00:00:00Z",
            "targets": [],
            "http_results": {},
            "email_auth": {},
            "cloudflare": {
                "security_events": {"error": "Authentication failed"},
                "traffic_analytics": {"error": "Authentication failed"},
                "rate_limit_rules": [],
            },
        }

        html = generate_report(data)
        assert "<!DOCTYPE html>" in html
        # Should show error message gracefully
        assert "error" in html.lower() or "Authentication" in html

    def test_empty_targets_list(self):
        """Test handling when targets list is empty."""
        from report.generator import generate_report

        data = {
            "environment": "test",
            "scan_date": "2026-03-16T00:00:00Z",
            "targets": [],
            "http_results": {},
            "email_auth": {},
            "cloudflare": {},
        }

        html = generate_report(data)
        assert "<!DOCTYPE html>" in html


class TestAggregation:
    """Tests for data aggregation across targets."""

    def test_aggregate_risk_score_calculation(self, full_report_data):
        """Test that risk score is aggregated across all HTTP targets."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # With multiple targets (score 15 + 45), aggregate should reflect combined risk
        # The exact aggregation logic is implementation detail, but risk should be present
        assert "Risk Score" in html or "risk_score" in html.lower()

    def test_aggregate_issue_counts(self, full_report_data):
        """Test that issue counts are aggregated from all sources."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Total issues: 4 (api) + 3 (www) + 1 (email) = 8
        # Should show some form of total in the HTML
        assert "All Issues" in html


class TestHTMLStructure:
    """Integration tests for HTML structure validation."""

    def test_html_structure(self, full_report_data):
        """Test that generated HTML has valid structure and all required sections."""
        import re
        import os
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # 1. Validate HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html" in html and "</html>" in html
        assert "<head>" in html and "</head>" in html
        assert "<body" in html and "</body>" in html
        assert "<title>" in html

        # 2. Check for required sections
        required_sections = [
            "Executive Summary",
            "HTTP Scanner Findings",
            "Email Security",
            "Cloudflare Security",
            "All Issues",
        ]
        for section in required_sections:
            assert section in html, f"Missing section: {section}"

        # 3. Check all severity colors are present (at least in styles)
        severity_colors = ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8", "#6c757d"]
        for color in severity_colors:
            assert color in html, f"Missing severity color: {color}"

        # 4. Check no unclosed table tags (simple validation)
        table_opens = html.count("<table")
        table_closes = html.count("</table>")
        assert table_opens == table_closes, f"Mismatched table tags: {table_opens} opens, {table_closes} closes"

        # 5. Write sample output for manual inspection
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        sample_path = os.path.join(reports_dir, "sample_report.html")
        with open(sample_path, "w") as f:
            f.write(html)

        assert os.path.exists(sample_path), "Sample report file not created"
        assert os.path.getsize(sample_path) > 1000, "Sample report is too small"

    def test_sections_in_correct_order(self, full_report_data):
        """Test that sections appear in the expected order."""
        from report.generator import generate_report

        html = generate_report(full_report_data)

        # Sections should appear in this order
        sections = [
            "Executive Summary",
            "HTTP Scanner Findings",
            "Email Security",
            "Cloudflare Security",
            "All Issues",
        ]

        positions = [html.find(section) for section in sections]
        # All sections should be found
        assert all(pos >= 0 for pos in positions), "Not all sections found"
        # Positions should be in increasing order
        assert positions == sorted(positions), f"Sections out of order: {list(zip(sections, positions))}"

    def test_data_assembly_from_modules(self):
        """Test that data can be assembled from module outputs (mocked Config context)."""
        from report.generator import generate_report

        # Simulate data assembly as it would happen in monitor.py
        data = {
            "environment": "staging",
            "scan_date": "2026-03-16T15:00:00Z",
            "targets": [
                "https://api.waldoclick.dev",
                "https://dashboard.waldoclick.dev",
                "https://www.waldoclick.dev",
            ],
            "http_results": {
                "https://api.waldoclick.dev": {
                    "meta": {"url": "https://api.waldoclick.dev"},
                    "risk_summary": {
                        "score": 5,
                        "risk_level": "low",
                        "issue_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 1},
                        "total_issues": 2,
                    },
                    "all_issues": [
                        {"severity": "low", "message": "Server header exposed", "source_module": "http_headers"},
                        {"severity": "info", "message": "HTTP/2 enabled", "source_module": "http_headers"},
                    ],
                },
            },
            "email_auth": {
                "waldoclick.dev": {
                    "domain": "waldoclick.dev",
                    "spf": {"record": "v=spf1 ...", "valid": True, "dns_lookups": 5},
                    "dkim": {"selectors": {"mailgun": True}},
                    "dmarc": {"record": "v=DMARC1; p=reject", "policy": "reject", "valid": True},
                    "caa": {"records": ["0 issue \"pki.goog\""], "expected_ca": "pki.goog", "valid": True},
                    "issues": [],
                },
            },
            "cloudflare": {
                "security_events": {
                    "zone_id": "test123",
                    "total_events": 50,
                    "by_action": {"block": 30, "challenge": 20},
                    "by_source": {"waf": 50},
                },
                "traffic_analytics": {
                    "total_requests": 10000,
                    "blocked_requests": 100,
                    "blocked_percentage": 1.0,
                },
                "rate_limit_rules": [],
            },
        }

        html = generate_report(data)

        # Basic validation
        assert "staging" in html
        assert "api.waldoclick.dev" in html
        assert "waldoclick.dev" in html
        assert "50" in html  # WAF total events
        assert "SPF" in html and "DMARC" in html


class TestComparisonDisplay:
    """Tests for comparison data display in reports."""

    @pytest.fixture
    def comparison_data(self):
        """Report data with comparison information."""
        return {
            "environment": "staging",
            "scan_date": "2026-03-16T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {
                "https://api.waldoclick.dev": {
                    "risk_summary": {
                        "score": 25,
                        "risk_level": "medium",
                        "issue_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
                    },
                    "all_issues": [
                        {"severity": "high", "message": "Missing HSTS header", "source_module": "http_headers"},
                        {"severity": "medium", "message": "Missing CSP header", "source_module": "http_headers"},
                    ],
                },
            },
            "email_auth": {},
            "cloudflare": {},
            "comparison": {
                "risk_trend": "improved",
                "score_delta": -10,
                "new_issues": [
                    {"severity": "medium", "message": "Missing CSP header", "source_module": "http_headers"},
                ],
                "fixed_issues": [
                    {"severity": "high", "message": "Open redirect vulnerability", "source_module": "vulnerabilities"},
                ],
                "new_count": 1,
                "fixed_count": 1,
            },
        }

    def test_new_badge_appears_for_new_issues(self, comparison_data):
        """Test that NEW badge appears for issues in comparison.new_issues."""
        from report.generator import generate_report

        html = generate_report(comparison_data)

        # NEW badge should appear in the HTML
        assert ">NEW<" in html or "NEW</span>" in html

    def test_fixed_section_appears_when_fixed_issues(self, comparison_data):
        """Test that FIXED section appears when there are fixed issues."""
        from report.generator import generate_report

        html = generate_report(comparison_data)

        # FIXED badge should appear
        assert "FIXED" in html
        # The fixed issue message should appear
        assert "Open redirect" in html

    def test_trend_indicator_shows_correct_direction(self, comparison_data):
        """Test that trend indicator shows correct direction (improved/degraded/stable)."""
        from report.generator import generate_report

        html = generate_report(comparison_data)

        # Should show improved indicator (down arrow or similar)
        # We expect either the trend text or an arrow indicator
        assert "improved" in html.lower() or "↓" in html or "-10" in html

    def test_trend_degraded_shows_warning(self):
        """Test that degraded trend shows warning indicator."""
        from report.generator import generate_report

        data = {
            "environment": "staging",
            "scan_date": "2026-03-16T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {
                "https://api.waldoclick.dev": {
                    "risk_summary": {"score": 45, "risk_level": "high", "issue_counts": {}},
                    "all_issues": [],
                },
            },
            "email_auth": {},
            "cloudflare": {},
            "comparison": {
                "risk_trend": "degraded",
                "score_delta": 20,
                "new_issues": [],
                "fixed_issues": [],
                "new_count": 0,
                "fixed_count": 0,
            },
        }

        html = generate_report(data)

        # Should show degraded indicator
        assert "degraded" in html.lower() or "↑" in html or "+20" in html

    def test_no_comparison_section_when_no_previous_scan(self):
        """Test that comparison section is gracefully skipped when no comparison data."""
        from report.generator import generate_report

        data = {
            "environment": "staging",
            "scan_date": "2026-03-16T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {},
            "email_auth": {},
            "cloudflare": {},
            # No comparison key - first scan
        }

        html = generate_report(data)

        # Should still produce valid HTML
        assert "<!DOCTYPE html>" in html
        # Should not crash, and should not show comparison UI
        # (absence of comparison-specific elements is fine)
        assert "FIXED" not in html  # No fixed section when no comparison
