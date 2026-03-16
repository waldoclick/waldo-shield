#!/usr/bin/env python3
"""Sentry Collector - fetches unresolved issues from Sentry.

Usage:
    python -m collectors.sentry
    
Cron (daily at 6am):
    0 6 * * * cd /path/to/waldo-shield && python -m src.collectors.sentry
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.sentry_issues import get_sentry_issues
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run Sentry collection and save report."""
    config = Config.load()
    logging.info(f"Sentry collector starting for {config.sentry_org} ({config.sentry_env})")
    
    try:
        result = get_sentry_issues(
            config.sentry_org,
            config.sentry_token,
            config.sentry_env,
        )
    except Exception as e:
        logging.error(f"Failed to fetch Sentry issues: {e}")
        result = {"error": str(e)}
    
    # Build report
    report = {
        "org": config.sentry_org,
        "environment": config.sentry_env,
        "total": result.get("total", 0),
        "by_project": result.get("by_project", {}),
        "projects": result.get("projects", {}),
        "error": result.get("error"),
    }
    
    # Save
    filepath = save_report("sentry", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  SENTRY ISSUES COLLECTED")
        print(f"{'='*60}")
        if report.get("error"):
            print(f"  ✗ Error: {report['error']}")
        else:
            print(f"  ✓ Org: {report['org']} ({report['environment']})")
            print(f"  ✓ Total issues: {report['total']}")
            for project, count in report.get("by_project", {}).items():
                print(f"    - {project}: {count}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"Sentry collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
