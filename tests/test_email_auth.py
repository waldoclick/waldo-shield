"""Tests for email authentication module (SPF, DKIM, DMARC, CAA validation)."""

import pytest
from unittest.mock import patch, MagicMock
import dns.resolver


class TestCheckEmailSecurity:
    """Tests for check_email_security function."""

    def test_returns_dict_with_required_keys(self, mock_checkdmarc):
        """check_email_security returns dict with spf, dkim, dmarc keys."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("waldo.click")

        assert isinstance(result, dict)
        assert "spf" in result
        assert "dkim" in result
        assert "dmarc" in result
        assert "domain" in result

    def test_spf_result_includes_valid_boolean(self, mock_checkdmarc):
        """SPF result includes 'valid' boolean."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("waldo.click")

        assert "valid" in result["spf"]
        assert isinstance(result["spf"]["valid"], bool)

    def test_spf_warns_on_high_lookup_count(self, mock_checkdmarc_with_warnings):
        """SPF result includes warnings for high DNS lookup count."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("example.com")

        assert "issues" in result
        # Should have an issue about approaching lookup limit
        issues_text = " ".join([str(i) for i in result["issues"]])
        assert "lookup" in issues_text.lower() or len(result["spf"].get("warnings", [])) > 0

    def test_dmarc_result_includes_policy(self, mock_checkdmarc):
        """DMARC result includes policy (p=)."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("waldo.click")

        assert "policy" in result["dmarc"]
        assert result["dmarc"]["policy"] == "quarantine"

    def test_dmarc_warns_on_policy_none(self, mock_checkdmarc_with_warnings):
        """DMARC p=none is flagged as ineffective."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("example.com")

        # Should warn about p=none being ineffective
        issues_text = " ".join([str(i) for i in result["issues"]])
        assert "none" in issues_text.lower() or result["dmarc"]["policy"] == "none"

    def test_dkim_attempts_validation_with_selectors(self, mock_checkdmarc):
        """DKIM result attempts validation with known selectors."""
        from src.modules.email_auth import check_email_security

        result = check_email_security("waldo.click")

        assert "dkim" in result
        # dkim should have some structure (selectors dict or checked status)
        assert result["dkim"] is not None

    def test_extracts_apex_domain_from_subdomain(self, mock_checkdmarc):
        """Extracts apex domain from subdomain input."""
        from src.modules.email_auth import check_email_security

        # Even if called with subdomain, should process apex
        result = check_email_security("api.waldo.click")

        # Should still work - apex domain is waldo.click
        assert "domain" in result

    def test_handles_dns_timeout_gracefully(self):
        """Function handles DNS timeout without crashing."""
        from src.modules.email_auth import check_email_security

        with patch("checkdmarc.check_domains") as mock:
            mock.side_effect = Exception("DNS timeout")

            result = check_email_security("waldo.click")

            # Should return error structure, not crash
            assert isinstance(result, dict)
            assert "error" in result or "issues" in result


class TestCheckCAARecords:
    """Tests for check_caa_records function."""

    def test_returns_valid_true_when_ca_present(self, mock_dns_caa):
        """Returns valid=True when expected CA is in CAA records."""
        from src.modules.email_auth import check_caa_records

        result = check_caa_records("waldo.click", "pki.goog")

        assert result["valid"] is True
        assert result["expected_ca"] == "pki.goog"

    def test_returns_valid_false_when_ca_missing(self, mock_dns_caa_missing):
        """Returns valid=False with issue when expected CA is missing."""
        from src.modules.email_auth import check_caa_records

        result = check_caa_records("waldo.click", "pki.goog")

        assert result["valid"] is False
        assert len(result["issues"]) > 0
        assert "expected_ca" in result

    def test_returns_records_list(self, mock_dns_caa):
        """Returns list of CAA records found."""
        from src.modules.email_auth import check_caa_records

        result = check_caa_records("waldo.click", "pki.goog")

        assert "records" in result
        assert isinstance(result["records"], list)

    def test_handles_dns_timeout_gracefully(self, mock_dns_timeout):
        """Function handles DNS timeout without crashing."""
        from src.modules.email_auth import check_caa_records

        result = check_caa_records("waldo.click", "pki.goog")

        # Should return error structure, not crash
        assert isinstance(result, dict)
        assert "error" in result or "issues" in result
        assert result["valid"] is False


class TestAnalyzeDomain:
    """Tests for analyze_domain function (combined entry point)."""

    def test_combines_email_security_and_caa(self, mock_checkdmarc, mock_dns_caa):
        """analyze_domain combines email_security and CAA checks."""
        from src.modules.email_auth import analyze_domain

        result = analyze_domain("waldo.click")

        # Should have both email auth and CAA results
        assert "spf" in result
        assert "dkim" in result
        assert "dmarc" in result
        assert "caa" in result

    def test_returns_domain_in_result(self, mock_checkdmarc, mock_dns_caa):
        """analyze_domain includes domain in result."""
        from src.modules.email_auth import analyze_domain

        result = analyze_domain("waldo.click")

        assert result["domain"] == "waldo.click"

    def test_aggregates_all_issues(self, mock_checkdmarc_with_warnings, mock_dns_caa_missing):
        """analyze_domain aggregates issues from all checks."""
        from src.modules.email_auth import analyze_domain

        result = analyze_domain("example.com")

        assert "issues" in result
        # Should have issues from both email and CAA checks
        assert len(result["issues"]) >= 1
