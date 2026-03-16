"""Configuration loading with secret validation."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

from dotenv import load_dotenv

from .settings import get_env_settings


@dataclass(frozen=True)
class Config:
    """Application configuration."""

    environment: str
    targets: List[str]
    recipients: List[str]
    cloudflare_token: str
    mailgun_api_key: str
    mailgun_domain: str

    @classmethod
    def load(cls, env_name: str) -> "Config":
        """Load configuration for specified environment.

        Args:
            env_name: Environment name ("staging" or "prod")

        Returns:
            Config instance with environment settings and secrets

        Raises:
            ValueError: If env_name is not recognized
            EnvironmentError: If required secrets are missing
        """
        # Load .env file from project root
        project_root = Path(__file__).resolve().parent.parent.parent
        env_path = project_root / ".env"
        load_dotenv(dotenv_path=env_path)

        # Get environment-specific settings (validates env_name)
        env_settings = get_env_settings(env_name)

        # Load and validate secrets
        secrets = load_secrets()

        return cls(
            environment=env_name,
            targets=list(env_settings.targets),
            recipients=list(env_settings.recipients),
            cloudflare_token=secrets["CLOUDFLARE_API_TOKEN"],
            mailgun_api_key=secrets["MAILGUN_API_KEY"],
            mailgun_domain=env_settings.mailgun_domain,
        )


def load_secrets() -> dict:
    """Load and validate required secrets from environment.

    Returns:
        Dict with secret values

    Raises:
        EnvironmentError: If any required secret is missing
    """
    required = [
        "CLOUDFLARE_API_TOKEN",
        "MAILGUN_API_KEY",
    ]

    secrets = {}
    missing = []

    for key in required:
        value = os.environ.get(key)
        if not value:
            missing.append(key)
        else:
            secrets[key] = value

    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            f"Set them in .env file or environment."
        )

    return secrets
