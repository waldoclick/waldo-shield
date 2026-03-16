"""Environment-specific settings for waldo-shield."""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class EnvironmentConfig:
    """Configuration for a specific environment."""

    name: str
    targets: List[str]
    recipients: List[str]
    mailgun_domain: str
    zone_id_env_var: str  # Environment variable name for Cloudflare zone ID


ENVIRONMENTS = {
    "staging": EnvironmentConfig(
        name="staging",
        targets=[
            "https://api.waldoclick.dev",
            "https://dashboard.waldoclick.dev",
            "https://www.waldoclick.dev",
        ],
        recipients=["security@waldoclick.dev"],
        mailgun_domain="waldoclick.dev",
        zone_id_env_var="CLOUDFLARE_ZONE_ID_STAGING",
    ),
    "prod": EnvironmentConfig(
        name="prod",
        targets=[
            "https://api.waldo.click",
            "https://dashboard.waldo.click",
            "https://www.waldo.click",
        ],
        recipients=["security@waldo.click"],
        mailgun_domain="waldo.click",
        zone_id_env_var="CLOUDFLARE_ZONE_ID_PROD",
    ),
}


def get_env_settings(env_name: str) -> EnvironmentConfig:
    """Get environment-specific (non-secret) settings.

    Args:
        env_name: Environment name ("staging" or "prod")

    Returns:
        EnvironmentConfig for the specified environment

    Raises:
        ValueError: If env_name is not recognized
    """
    if env_name not in ENVIRONMENTS:
        raise ValueError(
            f"Unknown environment: {env_name}. Valid options: {', '.join(ENVIRONMENTS.keys())}"
        )
    return ENVIRONMENTS[env_name]
