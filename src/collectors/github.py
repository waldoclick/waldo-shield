#!/usr/bin/env python3
"""GitHub Collector - fetches open issues from GitHub.

Usage:
    python -m collectors.github
    
Cron (daily at 6am):
    0 6 * * * cd /path/to/waldo-shield && python -m src.collectors.github
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.github_issues import get_open_issues
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run GitHub collection and save report."""
    config = Config.load()
    logging.info(f"GitHub collector starting")
    
    # For now, hardcode the repo - could be moved to config
    repo = "waldoclick/waldo-project"
    
    logging.info(f"Fetching issues from {repo}")
    try:
        result = get_open_issues(repo, config.github_token)
    except Exception as e:
        logging.error(f"Failed to fetch GitHub issues: {e}")
        result = {"error": str(e)}
    
    # Build report
    report = {
        "repo": repo,
        "total": result.get("total", 0),
        "issues": result.get("issues", []),
        "error": result.get("error"),
    }
    
    # Save
    filepath = save_report("github", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  GITHUB ISSUES COLLECTED")
        print(f"{'='*60}")
        if report.get("error"):
            print(f"  ✗ Error: {report['error']}")
        else:
            print(f"  ✓ Repo: {report['repo']}")
            print(f"  ✓ Open issues: {report['total']}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"GitHub collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
