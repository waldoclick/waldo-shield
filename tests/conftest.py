"""Pytest fixtures for waldo-shield tests."""

import os
import pytest


@pytest.fixture
def clean_env(monkeypatch):
    """Clear config-related environment variables before/after test."""
    env_vars = ["CLOUDFLARE_API_TOKEN", "MAILGUN_API_KEY"]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    yield
    # monkeypatch auto-restores after test


@pytest.fixture
def mock_secrets(monkeypatch):
    """Set test values for required secrets."""
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test_cf_token_12345")
    monkeypatch.setenv("MAILGUN_API_KEY", "test_mg_key_67890")
    yield
