#!/usr/bin/env python3
"""HTTP Collector - scans HTTP headers, SSL, and app-specific checks.

Usage:
    python -m collectors.http
    
Cron (daily at 6am):
    0 6 * * * cd /path/to/waldo-shield && python -m src.collectors.http
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.app_scanner import scan_dashboard, scan_api, scan_www
from modules.email_auth import analyze_domain
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run HTTP collection and save report."""
    config = Config.load()
    logging.info(f"HTTP collector starting for {config.domain}")
    
    # Scan apps
    apps = {}
    scanners = {
        "dashboard": scan_dashboard,
        "api": scan_api,
        "www": scan_www,
    }
    
    for app_name, scanner_func in scanners.items():
        logging.info(f"Scanning {app_name}.{config.domain}")
        try:
            apps[app_name] = scanner_func(config.domain)
        except Exception as e:
            logging.error(f"Failed to scan {app_name}: {e}")
            apps[app_name] = {"error": str(e)}
    
    # Email authentication
    logging.info(f"Checking email auth for {config.domain}")
    try:
        email_auth = analyze_domain(config.domain)
    except Exception as e:
        logging.error(f"Failed to check email auth: {e}")
        email_auth = {"error": str(e)}
    
    # Build report
    report = {
        "apps": apps,
        "email_auth": email_auth,
    }
    
    # Save
    filepath = save_report("http", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  HTTP SCAN COMPLETE")
        print(f"{'='*60}")
        for app_name, data in report.get("apps", {}).items():
            if "error" in data:
                print(f"  ✗ {app_name:12} | ERROR: {data['error']}")
            else:
                score = data.get("score", 0)
                issues = len(data.get("issues", []))
                print(f"  ✓ {app_name:12} | Score: {score:3} | Issues: {issues}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"HTTP collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
