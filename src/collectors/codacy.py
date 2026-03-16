#!/usr/bin/env python3
"""Codacy Collector - fetches code quality issues from Codacy.

Usage:
    python -m collectors.codacy
    
Cron (weekly on Monday at 6am):
    0 6 * * 1 cd /path/to/waldo-shield && python -m src.collectors.codacy
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.codacy_issues import get_codacy_issues
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run Codacy collection and save report."""
    config = Config.load()
    logging.info(f"Codacy collector starting for {config.codacy_org}/{config.codacy_repo}")
    
    try:
        result = get_codacy_issues(
            config.codacy_token,
            config.codacy_provider,
            config.codacy_org,
            config.codacy_repo,
        )
    except Exception as e:
        logging.error(f"Failed to fetch Codacy issues: {e}")
        result = {"error": str(e)}
    
    # Build report
    report = {
        "provider": config.codacy_provider,
        "organization": config.codacy_org,
        "repository": config.codacy_repo,
        "total": result.get("total", 0),
        "by_category": result.get("by_category", {}),
        "by_level": result.get("by_level", {}),
        "issues": result.get("issues", []),
        "error": result.get("error"),
    }
    
    # Save
    filepath = save_report("codacy", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  CODACY ISSUES COLLECTED")
        print(f"{'='*60}")
        if report.get("error"):
            print(f"  ✗ Error: {report['error']}")
        else:
            print(f"  ✓ Repo: {report['organization']}/{report['repository']}")
            print(f"  ✓ Total issues: {report['total']}")
            print(f"  ✓ By level:")
            for level, count in report.get("by_level", {}).items():
                print(f"      {level}: {count}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"Codacy collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
