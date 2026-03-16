"""Configuration loading with secret validation."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    """Application configuration."""

    domain: str  # e.g., "waldo.click" or "waldoclick.dev"
    cloudflare_token: str
    cloudflare_zone_id: str
    mailgun_api_key: str
    mailgun_domain: str
    github_token: str
    sentry_token: str
    sentry_org: str
    sentry_env: str
    recipients: List[str]

    @property
    def dashboard_url(self) -> str:
        return f"https://dashboard.{self.domain}"

    @property
    def api_url(self) -> str:
        return f"https://api.{self.domain}"

    @property
    def api_admin_url(self) -> str:
        return f"https://api.{self.domain}/admin"

    @property
    def www_url(self) -> str:
        return f"https://www.{self.domain}"

    @property
    def is_production(self) -> bool:
        return self.domain == "waldo.click"

    @property
    def environment(self) -> str:
        return "prod" if self.is_production else "staging"

    @classmethod
    def load(cls) -> "Config":
        """Load configuration from environment variables.

        Returns:
            Config instance

        Raises:
            EnvironmentError: If required variables are missing
        """
        # Load .env file from project root
        project_root = Path(__file__).resolve().parent.parent.parent
        env_path = project_root / ".env"
        load_dotenv(dotenv_path=env_path)

        # Load and validate all required env vars
        required = [
            "DOMAIN",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ZONE_ID",
            "MAILGUN_API_KEY",
            "GITHUB_TOKEN",
            "SENTRY_AUTH_TOKEN",
            "SENTRY_ORG",
            "SENTRY_ENV",
        ]

        values = {}
        missing = []

        for key in required:
            value = os.environ.get(key)
            if not value:
                missing.append(key)
            else:
                values[key] = value

        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"Set them in .env file or environment."
            )

        domain = values["DOMAIN"]
        
        # Derive mailgun domain and recipients from domain
        mailgun_domain = domain
        recipients = [f"security@{domain}"]

        return cls(
            domain=domain,
            cloudflare_token=values["CLOUDFLARE_API_TOKEN"],
            cloudflare_zone_id=values["CLOUDFLARE_ZONE_ID"],
            mailgun_api_key=values["MAILGUN_API_KEY"],
            mailgun_domain=mailgun_domain,
            github_token=values["GITHUB_TOKEN"],
            sentry_token=values["SENTRY_AUTH_TOKEN"],
            sentry_org=values["SENTRY_ORG"],
            sentry_env=values["SENTRY_ENV"],
            recipients=recipients,
        )
