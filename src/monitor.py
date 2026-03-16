#!/usr/bin/env python3
"""
Security Monitor for waldo.click Infrastructure
================================================
Runs security checks and generates consolidated reports for staging and production.

Usage:
    python monitor.py --env staging --dry-run
    python monitor.py --env prod

Environment Variables Required:
    CLOUDFLARE_API_TOKEN  - Cloudflare API token (API Tokens, not Global API Key)
    MAILGUN_API_KEY       - Mailgun API key for email delivery
"""

import argparse
import sys

from config import Config


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Security monitor for waldo.click infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--env",
        "-e",
        choices=["staging", "prod"],
        required=True,
        help="Environment to monitor (staging or prod)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run checks but don't send email",
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    try:
        config = Config.load(args.env)
    except EnvironmentError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {config.environment} config with {len(config.targets)} targets")
    print()
    print("Targets:")
    for target in config.targets:
        print(f"  - {target}")
    print()
    print(f"Recipients: {', '.join(config.recipients)}")
    print(f"Mailgun domain: {config.mailgun_domain}")

    if args.dry_run:
        print()
        print("(dry run - no actions taken)")

    sys.exit(0)


if __name__ == "__main__":
    main()
