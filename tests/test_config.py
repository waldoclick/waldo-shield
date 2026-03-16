"""Tests for config module - TDD RED phase."""

import pytest


class TestStagingConfig:
    """Test staging environment configuration."""

    def test_staging_config(self, mock_secrets):
        """Config.load("staging") returns config with waldoclick.dev targets."""
        from config import Config

        config = Config.load("staging")

        assert config.environment == "staging"
        assert len(config.targets) == 3
        assert all("waldoclick.dev" in target for target in config.targets)
        assert "https://api.waldoclick.dev" in config.targets
        assert "https://dashboard.waldoclick.dev" in config.targets
        assert "https://www.waldoclick.dev" in config.targets


class TestProdConfig:
    """Test production environment configuration."""

    def test_prod_config(self, mock_secrets):
        """Config.load("prod") returns config with waldo.click targets."""
        from config import Config

        config = Config.load("prod")

        assert config.environment == "prod"
        assert len(config.targets) == 3
        assert all("waldo.click" in target for target in config.targets)
        assert "https://api.waldo.click" in config.targets
        assert "https://dashboard.waldo.click" in config.targets
        assert "https://www.waldo.click" in config.targets


class TestInvalidEnvironment:
    """Test error handling for invalid environments."""

    def test_invalid_env(self, mock_secrets):
        """Config.load("invalid") raises ValueError."""
        from config import Config

        with pytest.raises(ValueError) as exc_info:
            Config.load("invalid")

        assert "invalid" in str(exc_info.value).lower()


class TestSecretLoading:
    """Test secret loading from environment variables."""

    def test_secrets_from_env(self, mock_secrets):
        """Config.load() reads CLOUDFLARE_API_TOKEN from os.environ."""
        from config import Config

        config = Config.load("staging")

        assert config.cloudflare_token == "test_cf_token_12345"
        assert config.mailgun_api_key == "test_mg_key_67890"

    def test_missing_secret_error(self, clean_env):
        """Missing required env var raises EnvironmentError with clear message."""
        from config import Config

        with pytest.raises(EnvironmentError) as exc_info:
            Config.load("staging")

        error_msg = str(exc_info.value)
        assert "CLOUDFLARE_API_TOKEN" in error_msg or "MAILGUN_API_KEY" in error_msg


class TestZoneIdLoading:
    """Test Cloudflare zone ID loading from environment variables."""

    def test_staging_zone_id(self, mock_secrets):
        """Config.load("staging") includes zone_id from CLOUDFLARE_ZONE_ID_STAGING."""
        from config import Config

        config = Config.load("staging")

        assert config.zone_id == "test_zone_staging_123"

    def test_prod_zone_id(self, mock_secrets):
        """Config.load("prod") includes zone_id from CLOUDFLARE_ZONE_ID_PROD."""
        from config import Config

        config = Config.load("prod")

        assert config.zone_id == "test_zone_prod_456"

    def test_missing_zone_id_raises_error(self, monkeypatch):
        """Missing zone ID raises EnvironmentError with clear message."""
        from config import Config

        # Set other required secrets but NOT zone ID
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test_cf_token_12345")
        monkeypatch.setenv("MAILGUN_API_KEY", "test_mg_key_67890")
        # Ensure zone ID is not set
        monkeypatch.delenv("CLOUDFLARE_ZONE_ID_STAGING", raising=False)

        with pytest.raises(EnvironmentError) as exc_info:
            Config.load("staging")

        error_msg = str(exc_info.value)
        assert "CLOUDFLARE_ZONE_ID_STAGING" in error_msg
