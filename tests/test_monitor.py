"""Tests for monitor.py CLI."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestMonitorExitCodes:
    """Tests for monitor exit codes."""

    def test_exit_code_0_when_no_critical_high_issues(self):
        """monitor.py should exit with 0 when no critical/high issues."""
        from monitor import has_critical_or_high
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 10,
                        "issue_counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 3},
                    },
                    "all_issues": [],
                }
            },
            "email_auth": {},
            "cloudflare": {},
        }
        
        assert has_critical_or_high(scan_data) is False

    def test_exit_code_1_when_critical_issues_exist(self):
        """monitor.py should exit with 1 when critical issues exist."""
        from monitor import has_critical_or_high
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 50,
                        "issue_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                    },
                    "all_issues": [{"severity": "critical", "message": "test"}],
                }
            },
            "email_auth": {},
            "cloudflare": {},
        }
        
        assert has_critical_or_high(scan_data) is True

    def test_exit_code_1_when_high_issues_exist(self):
        """monitor.py should exit with 1 when high severity issues exist."""
        from monitor import has_critical_or_high
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 30,
                        "issue_counts": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
                    },
                    "all_issues": [{"severity": "high", "message": "test"}],
                }
            },
            "email_auth": {},
            "cloudflare": {},
        }
        
        assert has_critical_or_high(scan_data) is True

    def test_exit_code_1_when_email_auth_high_issues(self):
        """monitor.py should exit with 1 when email auth has high severity issues."""
        from monitor import has_critical_or_high
        
        scan_data = {
            "http_results": {},
            "email_auth": {
                "waldo.click": {
                    "issues": [{"severity": "high", "message": "DMARC not configured"}]
                }
            },
            "cloudflare": {},
        }
        
        assert has_critical_or_high(scan_data) is True

    def test_exit_code_1_when_high_cloudflare_events(self):
        """monitor.py should exit with 1 when Cloudflare has many security events."""
        from monitor import has_critical_or_high
        
        scan_data = {
            "http_results": {},
            "email_auth": {},
            "cloudflare": {
                "security_events": {"total_events": 150},
            },
        }
        
        assert has_critical_or_high(scan_data) is True


class TestMonitorDryRun:
    """Tests for --dry-run flag."""

    @patch("monitor.Config.load")
    @patch("monitor.collect_all_data")
    @patch("monitor.load_latest_scan")
    @patch("monitor.compare_scans")
    @patch("monitor.generate_report")
    @patch("monitor.save_scan")
    @patch("monitor.send_report")
    @patch("monitor.should_send_email")
    def test_dry_run_skips_email_send(
        self,
        mock_should_send,
        mock_send,
        mock_save,
        mock_gen,
        mock_compare,
        mock_load,
        mock_collect,
        mock_config,
    ):
        """--dry-run should skip sending email even if should_send_email returns True."""
        from monitor import main
        
        # Setup mocks
        mock_config.return_value = MagicMock(
            environment="staging",
            targets=["https://example.com"],
            recipients=["test@example.com"],
            mailgun_domain="mg.example.com",
            mailgun_api_key="key",
        )
        mock_collect.return_value = {
            "http_results": {},
            "email_auth": {},
            "cloudflare": {},
        }
        mock_load.return_value = None
        mock_compare.return_value = None
        mock_gen.return_value = "<html></html>"
        mock_save.return_value = Path("/tmp/scan.json")
        mock_should_send.return_value = True
        
        # Run with --dry-run
        with patch("sys.argv", ["monitor.py", "--env", "staging", "--dry-run"]):
            with pytest.raises(SystemExit) as exc:
                main()
            
            # Should exit 0 (no critical issues)
            assert exc.value.code == 0
            
            # send_report should NOT be called
            mock_send.assert_not_called()


class TestMonitorQuiet:
    """Tests for --quiet flag."""

    def test_quiet_sets_warning_level(self):
        """--quiet should set logging to WARNING level."""
        import logging
        from monitor import setup_logging
        
        # Clear existing handlers for clean test
        root_logger = logging.getLogger()
        root_logger.handlers = []
        
        # Verbose mode should set INFO
        setup_logging(verbose=True)
        assert root_logger.level == logging.INFO
        
        # Clear handlers again
        root_logger.handlers = []
        
        # Quiet mode should set WARNING
        setup_logging(verbose=False)
        assert root_logger.level == logging.WARNING


class TestCronSimulation:
    """Tests for cron-compatible execution."""

    @patch("monitor.Config.load")
    @patch("monitor.collect_all_data")
    @patch("monitor.load_latest_scan")
    @patch("monitor.compare_scans")
    @patch("monitor.generate_report")
    @patch("monitor.save_scan")
    @patch("monitor.should_send_email")
    @patch("monitor.send_report")
    def test_cron_simulation_no_prompts(
        self,
        mock_send,
        mock_should_send,
        mock_save,
        mock_gen,
        mock_compare,
        mock_load,
        mock_collect,
        mock_config,
    ):
        """Simulate cron execution - should complete without interactive prompts."""
        from monitor import main
        
        # Setup mocks
        mock_config.return_value = MagicMock(
            environment="prod",
            targets=["https://api.waldo.click"],
            recipients=["security@waldo.click"],
            mailgun_domain="waldo.click",
            mailgun_api_key="key-123",
        )
        mock_collect.return_value = {
            "http_results": {
                "https://api.waldo.click": {
                    "risk_summary": {"score": 5, "issue_counts": {"critical": 0, "high": 0}},
                    "all_issues": [],
                }
            },
            "email_auth": {},
            "cloudflare": {},
        }
        mock_load.return_value = None
        mock_compare.return_value = None
        mock_gen.return_value = "<html></html>"
        mock_save.return_value = Path("/tmp/scan.json")
        mock_should_send.return_value = False
        
        # Run with --quiet (cron mode)
        with patch("sys.argv", ["monitor.py", "--env", "prod", "--quiet"]):
            with pytest.raises(SystemExit) as exc:
                main()
            
            # Should exit 0 - no critical issues
            assert exc.value.code == 0


class TestMonitorConfigError:
    """Tests for configuration error handling."""

    @patch("monitor.Config.load")
    def test_exit_code_2_on_config_error(self, mock_config):
        """monitor.py should exit with 2 when config fails."""
        from monitor import main
        
        mock_config.side_effect = EnvironmentError("Missing CLOUDFLARE_API_TOKEN")
        
        with patch("sys.argv", ["monitor.py", "--env", "staging"]):
            with pytest.raises(SystemExit) as exc:
                main()
            
            assert exc.value.code == 2
