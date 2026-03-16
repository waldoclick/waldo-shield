"""Tests for scan comparison and storage modules."""

import json
import os
import pytest
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path


# ============================================================================
# Storage Module Tests
# ============================================================================


class TestStorageModule:
    """Tests for scan result persistence."""

    @pytest.fixture(autouse=True)
    def setup_temp_reports_dir(self, monkeypatch):
        """Create temporary reports directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.reports_path = Path(self.temp_dir) / "reports"
        # Patch the REPORTS_DIR in the storage module
        import sys
        # Clear any cached module
        if "report.storage" in sys.modules:
            del sys.modules["report.storage"]
        yield
        # Cleanup
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_scan_history_path_returns_correct_directory(self, monkeypatch):
        """Test that get_scan_history_path returns reports/{env}/ path."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        path = storage.get_scan_history_path("staging")

        assert path == self.reports_path / "staging"

    def test_save_scan_creates_json_file(self, monkeypatch):
        """Test that save_scan writes JSON file to reports/{env}/scan_{timestamp}.json."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        scan_data = {
            "environment": "staging",
            "scan_date": "2026-03-16T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {},
        }

        path = storage.save_scan("staging", scan_data)

        # File should exist
        assert path.exists()
        # File should be in correct directory
        assert path.parent == self.reports_path / "staging"
        # File name should match pattern
        assert path.name.startswith("scan_")
        assert path.suffix == ".json"
        # Content should be valid JSON with our data
        with open(path) as f:
            saved = json.load(f)
        assert saved["environment"] == "staging"
        assert saved["targets"] == ["https://api.waldoclick.dev"]

    def test_save_scan_creates_directory_if_not_exists(self, monkeypatch):
        """Test that save_scan creates the environment directory if needed."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        scan_data = {"environment": "production", "scan_date": "2026-03-16T12:00:00Z"}

        # Directory doesn't exist yet
        assert not (self.reports_path / "production").exists()

        path = storage.save_scan("production", scan_data)

        # Now it should exist
        assert (self.reports_path / "production").exists()
        assert path.exists()

    def test_load_latest_scan_returns_most_recent(self, monkeypatch):
        """Test that load_latest_scan returns the most recent scan data."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        env_dir = self.reports_path / "staging"
        env_dir.mkdir(parents=True)

        # Create two scan files with different timestamps
        older_scan = {"environment": "staging", "scan_date": "2026-03-15T10:00:00Z", "data": "older"}
        newer_scan = {"environment": "staging", "scan_date": "2026-03-16T10:00:00Z", "data": "newer"}

        # Write older first (filename will have earlier timestamp based on modification time)
        older_path = env_dir / "scan_20260315_100000.json"
        with open(older_path, "w") as f:
            json.dump(older_scan, f)

        # Write newer second
        newer_path = env_dir / "scan_20260316_100000.json"
        with open(newer_path, "w") as f:
            json.dump(newer_scan, f)

        result = storage.load_latest_scan("staging")

        assert result is not None
        assert result["data"] == "newer"
        assert result["scan_date"] == "2026-03-16T10:00:00Z"

    def test_load_latest_scan_returns_none_if_no_history(self, monkeypatch):
        """Test that load_latest_scan returns None if no previous scan exists."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        result = storage.load_latest_scan("staging")

        assert result is None

    def test_load_latest_scan_returns_none_if_empty_directory(self, monkeypatch):
        """Test that load_latest_scan returns None if directory exists but is empty."""
        import report.storage as storage
        monkeypatch.setattr(storage, "REPORTS_DIR", self.reports_path)

        # Create empty directory
        env_dir = self.reports_path / "staging"
        env_dir.mkdir(parents=True)

        result = storage.load_latest_scan("staging")

        assert result is None


# ============================================================================
# Comparison Module Tests
# ============================================================================


class TestComparisonModule:
    """Tests for scan comparison logic."""

    @pytest.fixture
    def current_scan(self):
        """Current scan data with some issues."""
        return {
            "environment": "staging",
            "scan_date": "2026-03-16T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {
                "https://api.waldoclick.dev": {
                    "risk_summary": {
                        "score": 25,
                        "risk_level": "medium",
                        "issue_counts": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0},
                    },
                    "all_issues": [
                        {"severity": "high", "message": "Missing HSTS", "source_module": "http_headers"},
                        {"severity": "medium", "message": "Missing CSP", "source_module": "http_headers"},
                        {"severity": "low", "message": "Server exposed", "source_module": "http_headers"},
                    ],
                },
            },
            "email_auth": {},
            "cloudflare": {},
        }

    @pytest.fixture
    def previous_scan(self):
        """Previous scan data with some different issues."""
        return {
            "environment": "staging",
            "scan_date": "2026-03-15T12:00:00Z",
            "targets": ["https://api.waldoclick.dev"],
            "http_results": {
                "https://api.waldoclick.dev": {
                    "risk_summary": {
                        "score": 35,
                        "risk_level": "high",
                        "issue_counts": {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0},
                    },
                    "all_issues": [
                        {"severity": "high", "message": "Missing HSTS", "source_module": "http_headers"},
                        {"severity": "high", "message": "Open redirect", "source_module": "vulnerabilities"},
                        {"severity": "low", "message": "Server exposed", "source_module": "http_headers"},
                    ],
                },
            },
            "email_auth": {},
            "cloudflare": {},
        }

    def test_compare_scans_returns_none_for_no_previous(self, current_scan):
        """Test that compare_scans returns None when no previous scan."""
        from report.comparison import compare_scans

        result = compare_scans(current_scan, None)

        assert result is None

    def test_compare_scans_identifies_new_issues(self, current_scan, previous_scan):
        """Test that compare_scans identifies issues in current but not in previous."""
        from report.comparison import compare_scans

        result = compare_scans(current_scan, previous_scan)

        assert result is not None
        # "Missing CSP" is new (not in previous)
        new_messages = [i["message"] for i in result["new_issues"]]
        assert "Missing CSP" in new_messages
        assert result["new_count"] == 1

    def test_compare_scans_identifies_fixed_issues(self, current_scan, previous_scan):
        """Test that compare_scans identifies issues that were fixed (in previous but not current)."""
        from report.comparison import compare_scans

        result = compare_scans(current_scan, previous_scan)

        assert result is not None
        # "Open redirect" was fixed (in previous but not current)
        fixed_messages = [i["message"] for i in result["fixed_issues"]]
        assert "Open redirect" in fixed_messages
        assert result["fixed_count"] == 1

    def test_compare_scans_risk_trend_improved(self, current_scan, previous_scan):
        """Test that risk_trend is 'improved' when score decreased."""
        from report.comparison import compare_scans

        # current score 25, previous score 35 -> improved
        result = compare_scans(current_scan, previous_scan)

        assert result is not None
        assert result["risk_trend"] == "improved"
        assert result["score_delta"] == -10  # 25 - 35 = -10

    def test_compare_scans_risk_trend_degraded(self, current_scan, previous_scan):
        """Test that risk_trend is 'degraded' when score increased."""
        from report.comparison import compare_scans

        # Swap: previous (25) -> current (35) = degraded
        result = compare_scans(previous_scan, current_scan)  # Note: swapped

        assert result is not None
        assert result["risk_trend"] == "degraded"
        assert result["score_delta"] == 10  # 35 - 25 = +10

    def test_compare_scans_risk_trend_stable(self):
        """Test that risk_trend is 'stable' when score unchanged."""
        from report.comparison import compare_scans

        scan1 = {
            "http_results": {
                "https://test.com": {
                    "risk_summary": {"score": 20},
                    "all_issues": [],
                }
            }
        }
        scan2 = {
            "http_results": {
                "https://test.com": {
                    "risk_summary": {"score": 20},
                    "all_issues": [],
                }
            }
        }

        result = compare_scans(scan1, scan2)

        assert result is not None
        assert result["risk_trend"] == "stable"
        assert result["score_delta"] == 0

    def test_issue_matching_by_key_tuple(self, current_scan, previous_scan):
        """Test that issue matching uses (source, severity, message) tuple."""
        from report.comparison import compare_scans

        # The unchanged issue "Missing HSTS" should NOT be in new or fixed
        result = compare_scans(current_scan, previous_scan)

        new_messages = [i["message"] for i in result["new_issues"]]
        fixed_messages = [i["message"] for i in result["fixed_issues"]]

        # "Missing HSTS" exists in both - should not be in new or fixed
        assert "Missing HSTS" not in new_messages
        assert "Missing HSTS" not in fixed_messages

        # "Server exposed" exists in both - also unchanged
        assert "Server exposed" not in new_messages
        assert "Server exposed" not in fixed_messages

    def test_score_delta_positive_means_worse(self):
        """Test that positive score_delta indicates risk increased."""
        from report.comparison import compare_scans

        current = {"http_results": {"url": {"risk_summary": {"score": 50}, "all_issues": []}}}
        previous = {"http_results": {"url": {"risk_summary": {"score": 30}, "all_issues": []}}}

        result = compare_scans(current, previous)

        # Score went 30 -> 50 = +20 = worse
        assert result["score_delta"] == 20
        assert result["score_delta"] > 0  # Positive = worse
        assert result["risk_trend"] == "degraded"

    def test_score_delta_negative_means_better(self):
        """Test that negative score_delta indicates risk decreased."""
        from report.comparison import compare_scans

        current = {"http_results": {"url": {"risk_summary": {"score": 10}, "all_issues": []}}}
        previous = {"http_results": {"url": {"risk_summary": {"score": 40}, "all_issues": []}}}

        result = compare_scans(current, previous)

        # Score went 40 -> 10 = -30 = better
        assert result["score_delta"] == -30
        assert result["score_delta"] < 0  # Negative = better
        assert result["risk_trend"] == "improved"
