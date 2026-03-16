#!/usr/bin/env python3
"""
Security Monitor for waldo.click Infrastructure
================================================
Runs security checks and generates consolidated reports.

Usage:
    python monitor.py
    python monitor.py --dry-run
    python monitor.py --quiet

Cron example (Laravel Forge):
    0 6 * * * cd /path/to/waldo-shield/src && /usr/bin/python3 monitor.py --quiet

Exit codes:
    0 - No critical/high issues found
    1 - Critical or high issues found (alert condition)
    2 - Error during execution (config, network, etc.)

Environment Variables Required:
    DOMAIN                 - Domain to scan (e.g., "waldo.click" or "waldoclick.dev")
    CLOUDFLARE_API_TOKEN   - Cloudflare API token
    CLOUDFLARE_ZONE_ID     - Cloudflare Zone ID for the domain
    MAILGUN_API_KEY        - Mailgun API key for email delivery
"""

import argparse
import logging
import sys
from datetime import datetime, timezone

from config import Config
from modules.app_scanner import scan_all
from modules.email_auth import analyze_domain
from modules.cloudflare_api import collect_cloudflare_data
from modules.github_issues import get_open_issues
from report import generate_report
from report.comparison import compare_scans
from report.storage import load_latest_scan, save_scan
from mailer import send_report, should_send_email


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Security monitor for waldo.click infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run checks but don't send email",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Reduce output (for cron jobs)",
    )
    return parser.parse_args()


def setup_logging(verbose: bool = True) -> None:
    """Configure logging level based on verbosity."""
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def collect_all_data(config: Config) -> dict:
    """Collect data from all security sources.
    
    Args:
        config: Application configuration
    
    Returns:
        Consolidated scan data dict
    """
    logging.info(f"Starting scan for {config.domain}")
    
    # Scan all apps (dashboard, api, www)
    logging.info("Scanning apps...")
    app_results = scan_all(config.domain)
    
    # Email auth for domain
    logging.info(f"Checking email authentication for {config.domain}")
    try:
        email_auth = {config.domain: analyze_domain(config.domain)}
    except Exception as e:
        logging.error(f"Failed to check email auth: {e}")
        email_auth = {config.domain: {"error": str(e), "issues": []}}
    
    # Cloudflare data
    logging.info("Collecting Cloudflare security data")
    try:
        cloudflare = collect_cloudflare_data(config.cloudflare_token, config.cloudflare_zone_id)
    except Exception as e:
        logging.error(f"Failed to collect Cloudflare data: {e}")
        cloudflare = {"error": str(e)}
    
    # GitHub issues
    logging.info("Fetching GitHub issues")
    try:
        github_issues = get_open_issues("waldoclick/waldo-project", config.github_token)
    except Exception as e:
        logging.error(f"Failed to fetch GitHub issues: {e}")
        github_issues = {"error": str(e)}
    
    return {
        "domain": config.domain,
        "environment": config.environment,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "apps": app_results,
        "email_auth": email_auth,
        "cloudflare": cloudflare,
        "github_issues": github_issues,
    }


def has_critical_or_high(scan_data: dict) -> bool:
    """Check if scan has any critical or high severity issues.
    
    Args:
        scan_data: Consolidated scan results
    
    Returns:
        True if any critical or high severity issues found
    """
    apps = scan_data.get("apps", {})
    
    for app_name in ["dashboard", "api", "www"]:
        app_data = apps.get(app_name, {})
        risk = app_data.get("risk_summary", {})
        counts = risk.get("issue_counts", {})
        if counts.get("critical", 0) > 0 or counts.get("high", 0) > 0:
            return True
    
    # Check email auth issues
    for domain, auth in scan_data.get("email_auth", {}).items():
        if isinstance(auth, dict):
            for issue in auth.get("issues", []):
                severity = issue.get("severity", "").lower()
                if severity in ("critical", "high", "error"):
                    return True
    
    return False


def print_summary(scan_data: dict) -> None:
    """Print a summary of the scan results."""
    domain = scan_data.get("domain", "unknown")
    apps = scan_data.get("apps", {})
    
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE: {domain}")
    print(f"{'='*60}")
    
    for app_name in ["dashboard", "api", "www"]:
        app = apps.get(app_name, {})
        risk = app.get("risk_summary", {})
        level = risk.get("risk_level", "unknown").upper()
        score = risk.get("score", 0)
        total = risk.get("total_issues", 0)
        
        # Get critical count
        counts = risk.get("issue_counts", {})
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        
        status = "✓" if critical == 0 and high == 0 else "✗"
        print(f"  {status} {app_name:12} | {level:8} | Score: {score:3} | Issues: {total}")
    
    print(f"{'='*60}\n")


def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging (quiet for cron, verbose for manual runs)
    setup_logging(verbose=not args.quiet)
    
    try:
        config = Config.load()
    except EnvironmentError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Unexpected error loading config: {e}", file=sys.stderr)
        sys.exit(2)
    
    logging.info(f"Loaded config for {config.domain}")
    
    try:
        # Collect data from all sources
        scan_data = collect_all_data(config)
        
        # Load previous scan for comparison
        previous = load_latest_scan(config.environment)
        comparison = compare_scans(scan_data, previous)
        scan_data["comparison"] = comparison
        
        # Generate report
        html_report = generate_report(scan_data)
        
        # Save current scan
        saved_path = save_scan(config.environment, scan_data)
        logging.info(f"Scan saved to {saved_path}")
        
        # Print summary unless quiet
        if not args.quiet:
            print_summary(scan_data)
        
        # Send email (unless dry-run or threshold not met)
        if args.dry_run:
            logging.info("Dry run - skipping email send")
        elif should_send_email(scan_data, comparison):
            logging.info("Sending email report...")
            result = send_report(
                html_report,
                config.recipients,
                config.mailgun_domain,
                config.mailgun_api_key,
                config.environment,
            )
            if "error" in result:
                logging.error(f"Email send failed: {result['error']}")
            else:
                logging.info(f"Email sent successfully: {result.get('message_id', 'no-id')}")
        else:
            logging.info("No email needed - no critical/high issues and below threshold")
        
        # Exit with appropriate code
        if has_critical_or_high(scan_data):
            logging.warning("Critical or high severity issues found")
            sys.exit(1)
        else:
            logging.info("Scan complete - no critical/high issues")
            sys.exit(0)
            
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
