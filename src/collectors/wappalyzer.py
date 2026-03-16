#!/usr/bin/env python3
"""Wappalyzer Collector - detects technologies used on websites.

Usage:
    python -m collectors.wappalyzer
    
Cron (weekly on Monday at 6am):
    0 6 * * 1 cd /path/to/waldo-shield && python -m src.collectors.wappalyzer
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def detect_technologies(url: str) -> dict:
    """Detect technologies used on a website.
    
    Args:
        url: URL to analyze
        
    Returns:
        Dict with technologies and categories
    """
    try:
        from Wappalyzer import Wappalyzer, WebPage
        
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        
        # Get detected technologies
        techs = wappalyzer.analyze(webpage)
        
        # Get detailed info with categories
        detailed = wappalyzer.analyze_with_categories(webpage)
        
        return {
            "url": url,
            "technologies": list(techs),
            "by_category": detailed,
            "error": None,
        }
        
    except Exception as e:
        return {
            "url": url,
            "technologies": [],
            "by_category": {},
            "error": str(e),
        }


def collect() -> dict:
    """Run Wappalyzer collection and save report."""
    config = Config.load()
    logging.info(f"Wappalyzer collector starting for {config.domain}")
    
    # Scan www and api (not dashboard - it's Zero Trust protected)
    targets = {
        "www": f"https://www.{config.domain}",
        "api": f"https://api.{config.domain}",
    }
    
    results = {}
    all_techs = set()
    
    for name, url in targets.items():
        logging.info(f"Analyzing {url}")
        result = detect_technologies(url)
        results[name] = result
        all_techs.update(result.get("technologies", []))
    
    # Build report
    report = {
        "targets": targets,
        "results": results,
        "all_technologies": sorted(list(all_techs)),
        "total_technologies": len(all_techs),
    }
    
    # Save
    filepath = save_report("wappalyzer", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  WAPPALYZER SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Total technologies detected: {report['total_technologies']}")
        print()
        for name, data in report.get("results", {}).items():
            if data.get("error"):
                print(f"  ✗ {name}: Error - {data['error']}")
            else:
                techs = data.get("technologies", [])
                print(f"  ✓ {name}: {len(techs)} technologies")
                for tech in sorted(techs)[:10]:
                    print(f"      - {tech}")
                if len(techs) > 10:
                    print(f"      ... and {len(techs) - 10} more")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"Wappalyzer collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
