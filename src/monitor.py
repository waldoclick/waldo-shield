#!/usr/bin/env python3
"""
Security Monitor for waldo.click Infrastructure
================================================
Runs security checks and generates consolidated reports for staging and production.

Usage:
    python monitor.py --env staging --dry-run
    python monitor.py --env prod

Cron example (Laravel Forge):
    0 6 * * * cd /path/to/waldo-shield && /usr/bin/python3 src/monitor.py --env prod --quiet

Exit codes:
    0 - No critical/high issues found
    1 - Critical or high issues found (alert condition)
    2 - Error during execution (config, network, etc.)

Environment Variables Required:
    CLOUDFLARE_API_TOKEN       - Cloudflare API token (API Tokens, not Global API Key)
    CLOUDFLARE_ZONE_ID_STAGING - Zone ID for staging environment
    CLOUDFLARE_ZONE_ID_PROD    - Zone ID for production environment
    MAILGUN_API_KEY            - Mailgun API key for email delivery
"""

import argparse
import logging
import sys
from datetime import datetime, timezone

from config import Config
from scanner import scan as http_scan
from modules.email_auth import analyze_domain
from modules.cloudflare_api import collect_cloudflare_data
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
    logging.info(f"Starting scan for {config.environment} environment")
    
    # HTTP scan all targets
    http_results = {}
    for target in config.targets:
        logging.info(f"Scanning {target}")
        try:
            http_results[target] = http_scan(target, ["headers", "ssl", "dns", "tech", "vulns"])
        except Exception as e:
            logging.error(f"Failed to scan {target}: {e}")
            http_results[target] = {"error": str(e), "all_issues": [], "risk_summary": {"score": 0, "issue_counts": {}}}
    
    # Email auth for domain (extract apex domain from first target)
    # For waldo.click targets, the domain is waldo.click or waldoclick.dev
    domain = config.mailgun_domain
    logging.info(f"Checking email authentication for {domain}")
    try:
        email_auth = {domain: analyze_domain(domain)}
    except Exception as e:
        logging.error(f"Failed to check email auth for {domain}: {e}")
        email_auth = {domain: {"error": str(e), "issues": []}}
    
    # Cloudflare data
    logging.info("Collecting Cloudflare security data")
    try:
        cloudflare = collect_cloudflare_data(config.cloudflare_token, config.zone_id)
    except Exception as e:
        logging.error(f"Failed to collect Cloudflare data: {e}")
        cloudflare = {"error": str(e)}
    
    return {
        "environment": config.environment,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "targets": config.targets,
        "http_results": http_results,
        "email_auth": email_auth,
        "cloudflare": cloudflare,
    }


def has_critical_or_high(scan_data: dict) -> bool:
    """Check if scan has any critical or high severity issues.
    
    Args:
        scan_data: Consolidated scan results
    
    Returns:
        True if any critical or high severity issues found
    """
    # Check HTTP results
    for target, result in scan_data.get("http_results", {}).items():
        if isinstance(result, dict) and "risk_summary" in result:
            counts = result["risk_summary"].get("issue_counts", {})
            if counts.get("critical", 0) > 0 or counts.get("high", 0) > 0:
                return True
    
    # Check email auth issues
    for domain, auth in scan_data.get("email_auth", {}).items():
        if isinstance(auth, dict):
            for issue in auth.get("issues", []):
                severity = issue.get("severity", "").lower()
                if severity in ("critical", "high", "error"):
                    return True
    
    # Check Cloudflare (high security event count indicates issues)
    cf = scan_data.get("cloudflare", {})
    if isinstance(cf, dict):
        events = cf.get("security_events", {})
        if isinstance(events, dict) and events.get("total_events", 0) > 100:
            return True
    
    return False


def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging (quiet for cron, verbose for manual runs)
    setup_logging(verbose=not args.quiet)
    
    try:
        config = Config.load(args.env)
    except EnvironmentError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Unexpected error loading config: {e}", file=sys.stderr)
        sys.exit(2)
    
    logging.info(f"Loaded {config.environment} config with {len(config.targets)} targets")
    
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
        sys.exit(2)


if __name__ == "__main__":
    main()
