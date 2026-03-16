#!/usr/bin/env python3
"""WebSentry Collector - external security scanner.

Usage:
    python -m collectors.websentry
    
Cron (3x per month - days 1, 10, 20 at 6am):
    0 6 1,10,20 * * cd /path/to/waldo-shield && python -m src.collectors.websentry
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.websentry_api import scan_and_get_results
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run WebSentry collection and save report."""
    config = Config.load()
    logging.info(f"WebSentry collector starting for {config.domain}")
    
    # Only scan www and api (not dashboard - it's Zero Trust protected)
    targets = [
        f"https://www.{config.domain}",
        f"https://api.{config.domain}",
    ]
    
    results = {}
    for url in targets:
        logging.info(f"Scanning {url}")
        try:
            result = scan_and_get_results(config.websentry_api_key, url)
            results[url] = result
        except Exception as e:
            logging.error(f"Failed to scan {url}: {e}")
            results[url] = {"error": str(e)}
    
    # Build report
    report = {
        "targets": targets,
        "results": results,
    }
    
    # Save
    filepath = save_report("websentry", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  WEBSENTRY SCAN COMPLETE")
        print(f"{'='*60}")
        for url, data in report.get("results", {}).items():
            if data.get("error"):
                print(f"  ✗ {url}")
                print(f"    Error: {data['error']}")
            else:
                grade = data.get("grade", "?")
                score = data.get("score", 0)
                failed = len(data.get("failed_checks", []))
                print(f"  ✓ {url}")
                print(f"    Grade: {grade} | Score: {score} | Failed checks: {failed}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"WebSentry collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
