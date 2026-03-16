"""Tests for Mailgun email sender module."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestShouldSendEmail:
    """Tests for should_send_email() decision logic."""

    def test_returns_true_when_critical_issues_exist(self):
        """Email should be sent when any critical issues exist."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 10,
                        "issue_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                    },
                    "all_issues": [{"severity": "critical", "message": "Test critical", "source_module": "headers"}],
                }
            }
        }
        
        assert should_send_email(scan_data) is True

    def test_returns_true_when_high_issues_exist(self):
        """Email should be sent when any high severity issues exist."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 10,
                        "issue_counts": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
                    },
                    "all_issues": [{"severity": "high", "message": "Test high", "source_module": "headers"}],
                }
            }
        }
        
        assert should_send_email(scan_data) is True

    def test_returns_true_when_score_exceeds_threshold(self):
        """Email should be sent when risk score >= threshold."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 25,
                        "issue_counts": {"critical": 0, "high": 0, "medium": 5, "low": 0, "info": 0},
                    },
                    "all_issues": [],
                }
            }
        }
        
        assert should_send_email(scan_data, threshold_score=20) is True

    def test_returns_false_when_only_low_medium_info_issues(self):
        """Email should NOT be sent when only low/medium/info issues and score below threshold."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 8,  # Below threshold
                        "issue_counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 3},
                    },
                    "all_issues": [
                        {"severity": "medium", "message": "Test medium", "source_module": "headers"},
                        {"severity": "low", "message": "Test low", "source_module": "ssl"},
                    ],
                }
            }
        }
        
        assert should_send_email(scan_data, threshold_score=20) is False

    def test_returns_true_when_new_critical_issues_in_comparison(self):
        """Email should be sent when comparison shows new critical issues."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 5,
                        "issue_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                    },
                    "all_issues": [],
                }
            }
        }
        
        comparison = {
            "new_issues": [
                {"severity": "critical", "message": "New critical", "source_module": "ssl"},
            ],
            "new_count": 1,
            "fixed_count": 0,
        }
        
        assert should_send_email(scan_data, comparison=comparison, threshold_score=20) is True

    def test_returns_true_when_new_high_issues_in_comparison(self):
        """Email should be sent when comparison shows new high severity issues."""
        from mailer import should_send_email
        
        scan_data = {
            "http_results": {
                "https://example.com": {
                    "risk_summary": {
                        "score": 5,
                        "issue_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                    },
                    "all_issues": [],
                }
            }
        }
        
        comparison = {
            "new_issues": [
                {"severity": "high", "message": "New high issue", "source_module": "headers"},
            ],
            "new_count": 1,
            "fixed_count": 0,
        }
        
        assert should_send_email(scan_data, comparison=comparison, threshold_score=20) is True


class TestSendReport:
    """Tests for send_report() Mailgun integration."""

    def test_calls_mailgun_api_with_correct_endpoint(self):
        """Verify correct Mailgun API endpoint is called."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "test-id"})
            
            send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="key-123",
                environment="staging",
            )
            
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://api.mailgun.net/v3/mg.example.com/messages"

    def test_sends_to_all_recipients(self):
        """Verify all recipients receive the email."""
        from mailer import send_report
        
        recipients = ["alice@example.com", "bob@example.com"]
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "test-id"})
            
            send_report(
                html_content="<h1>Test</h1>",
                recipients=recipients,
                mailgun_domain="mg.example.com",
                mailgun_api_key="key-123",
                environment="prod",
            )
            
            call_data = mock_post.call_args[1]["data"]
            assert call_data["to"] == recipients

    def test_uses_correct_auth(self):
        """Verify API key is passed correctly as basic auth."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "test-id"})
            
            send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="my-secret-key",
                environment="staging",
            )
            
            call_auth = mock_post.call_args[1]["auth"]
            assert call_auth == ("api", "my-secret-key")

    def test_returns_success_on_200(self):
        """Verify success response structure on HTTP 200."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"id": "<msg-id-123@mg.example.com>"}
            )
            
            result = send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="key-123",
                environment="staging",
            )
            
            assert result["success"] is True
            assert result["message_id"] == "<msg-id-123@mg.example.com>"

    def test_returns_error_on_failure(self):
        """Verify error response on non-200 status code."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=401,
                text="Unauthorized"
            )
            
            result = send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="wrong-key",
                environment="staging",
            )
            
            assert "error" in result
            assert "401" in result["error"]

    def test_uses_default_subject_with_environment(self):
        """Verify default subject line includes environment."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "test-id"})
            
            send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="key-123",
                environment="prod",
            )
            
            call_data = mock_post.call_args[1]["data"]
            assert "PROD" in call_data["subject"] or "prod" in call_data["subject"].lower()

    def test_uses_custom_subject_when_provided(self):
        """Verify custom subject overrides default."""
        from mailer import send_report
        
        with patch("mailer.sender.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "test-id"})
            
            send_report(
                html_content="<h1>Test</h1>",
                recipients=["test@example.com"],
                mailgun_domain="mg.example.com",
                mailgun_api_key="key-123",
                environment="staging",
                subject="Custom Alert Subject",
            )
            
            call_data = mock_post.call_args[1]["data"]
            assert call_data["subject"] == "Custom Alert Subject"
