#!/usr/bin/env python3
"""Dependencies Collector - audits npm/yarn dependencies for vulnerabilities.

Uses GitHub API to read package.json/yarn.lock and OSV.dev to check vulnerabilities.

Usage:
    python -m collectors.dependencies
    
Cron (weekly on Monday at 6am):
    0 6 * * 1 cd /path/to/waldo-shield && python -m src.collectors.dependencies
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from modules.osv_audit import audit_repo
from collectors.base import save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def collect() -> dict:
    """Run dependency audit and save report."""
    config = Config.load()
    
    repo = config.github_repo
    branch = config.github_branch
    
    logging.info(f"Dependencies collector starting for {repo}@{branch}")
    
    try:
        result = audit_repo(config.github_token, repo, branch)
    except Exception as e:
        logging.error(f"Failed to audit dependencies: {e}")
        result = {"error": str(e)}
    
    # Build report
    report = {
        "repo": repo,
        "branch": branch,
        "total_packages": result.get("total_packages", 0),
        "vulnerable_packages": result.get("vulnerable_packages", 0),
        "vulnerabilities": result.get("vulnerabilities", []),
        "by_severity": result.get("by_severity", {}),
        "error": result.get("error"),
    }
    
    # Save
    filepath = save_report("dependencies", config.domain, report)
    logging.info(f"Report saved to {filepath}")
    
    return report


def main():
    """Entry point."""
    try:
        report = collect()
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  DEPENDENCY AUDIT COMPLETE")
        print(f"{'='*60}")
        if report.get("error"):
            print(f"  ✗ Error: {report['error']}")
        else:
            print(f"  ✓ Repo: {report['repo']}@{report['branch']}")
            print(f"  ✓ Total packages: {report['total_packages']}")
            print(f"  ✓ Vulnerable: {report['vulnerable_packages']}")
            if report.get("by_severity"):
                print(f"  ✓ By severity:")
                for sev, count in report["by_severity"].items():
                    print(f"      {sev}: {count}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logging.error(f"Dependencies collector failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
