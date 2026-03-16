"""Pytest fixtures for waldo-shield tests."""

import os
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def clean_env(monkeypatch):
    """Clear config-related environment variables before/after test."""
    env_vars = [
        "CLOUDFLARE_API_TOKEN",
        "MAILGUN_API_KEY",
        "CLOUDFLARE_ZONE_ID_STAGING",
        "CLOUDFLARE_ZONE_ID_PROD",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    yield
    # monkeypatch auto-restores after test


@pytest.fixture
def mock_secrets(monkeypatch):
    """Set test values for required secrets."""
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test_cf_token_12345")
    monkeypatch.setenv("MAILGUN_API_KEY", "test_mg_key_67890")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID_STAGING", "test_zone_staging_123")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID_PROD", "test_zone_prod_456")
    yield


@pytest.fixture
def mock_checkdmarc():
    """Mock checkdmarc.check_domains for testing email auth module.
    
    Note: checkdmarc returns a DomainCheckResult dict directly (not nested by domain)
    when checking a single domain.
    """
    mock_result = {
        "domain": "waldo.click",
        "base_domain": "waldo.click",
        "spf": {
            "record": "v=spf1 include:mailgun.org ~all",
            "valid": True,
            "dns_lookups": 3,
            "warnings": [],
            "errors": []
        },
        "dkim": {
            "selectors": {
                "default": {"public_key_type": "rsa", "key_size": 2048}
            }
        },
        "dmarc": {
            "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@waldo.click",
            "valid": True,
            "warnings": [],
            "errors": [],
            "tags": {
                "p": {"value": "quarantine", "explicit": True},
                "pct": {"value": 100, "explicit": False}
            }
        }
    }
    with patch("checkdmarc.check_domains") as mock:
        mock.return_value = mock_result
        yield mock


@pytest.fixture
def mock_checkdmarc_with_warnings():
    """Mock checkdmarc with policy warnings (p=none is ineffective)."""
    mock_result = {
        "domain": "example.com",
        "base_domain": "example.com",
        "spf": {
            "record": "v=spf1 include:a.com include:b.com include:c.com ~all",
            "valid": True,
            "dns_lookups": 9,
            "warnings": ["SPF record is approaching 10 DNS lookup limit"],
            "errors": []
        },
        "dkim": {
            "selectors": {}
        },
        "dmarc": {
            "record": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
            "valid": True,
            "warnings": ["Policy p=none provides no protection"],
            "errors": [],
            "tags": {
                "p": {"value": "none", "explicit": True},
                "pct": {"value": 100, "explicit": False}
            }
        }
    }
    with patch("checkdmarc.check_domains") as mock:
        mock.return_value = mock_result
        yield mock


@pytest.fixture
def mock_dns_caa():
    """Mock dns.resolver.resolve for CAA record testing."""
    from dns.rdatatype import CAA
    from dns.name import from_text
    
    mock_caa_record = MagicMock()
    mock_caa_record.flags = 0
    mock_caa_record.tag = b"issue"
    mock_caa_record.value = b"pki.goog"
    
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_caa_record])
    
    with patch("dns.resolver.resolve") as mock:
        mock.return_value = mock_answer
        yield mock


@pytest.fixture
def mock_dns_caa_missing():
    """Mock dns.resolver.resolve when expected CA is NOT in CAA records."""
    mock_caa_record = MagicMock()
    mock_caa_record.flags = 0
    mock_caa_record.tag = b"issue"
    mock_caa_record.value = b"letsencrypt.org"
    
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_caa_record])
    
    with patch("dns.resolver.resolve") as mock:
        mock.return_value = mock_answer
        yield mock


@pytest.fixture
def mock_dns_timeout():
    """Mock dns.resolver.resolve to raise timeout exception."""
    import dns.resolver
    
    with patch("dns.resolver.resolve") as mock:
        mock.side_effect = dns.resolver.LifetimeTimeout()
        yield mock
