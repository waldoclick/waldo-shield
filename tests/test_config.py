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
