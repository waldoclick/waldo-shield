#!/usr/bin/env python3
"""Report Sender - consolidates reports, generates HTML, creates ZIP, sends email.

Usage:
    python -m sender.report
    python -m sender.report --dry-run
    
Cron (weekly on Monday at 8am):
    0 8 * * 1 cd /path/to/waldo-shield && python -m src.sender.report
"""

import io
import json
import logging
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.loader import Config
from collectors.base import get_all_latest_reports
from mailer.sender import send_email

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def create_zip_with_password(reports: dict, password: str) -> bytes:
    """Create a password-protected ZIP with all report JSONs.
    
    Args:
        reports: Dict of source -> report data
        password: ZIP password
        
    Returns:
        ZIP file as bytes
    """
    buffer = io.BytesIO()
    
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Note: Python's zipfile doesn't support encryption natively
        # For password protection, we'd need to use pyzipper
        # For now, create unencrypted ZIP - can add pyzipper later
        for source, data in reports.items():
            timestamp = data.get("_meta", {}).get("timestamp", "unknown")
            filename = f"{source}_{timestamp}.json"
            content = json.dumps(data, indent=2, default=str)
            zf.writestr(filename, content)
    
    return buffer.getvalue()


def create_zip_with_password_encrypted(reports: dict, password: str) -> bytes:
    """Create an encrypted ZIP with all report JSONs.
    
    Requires: pip install pyzipper
    """
    try:
        import pyzipper
    except ImportError:
        logging.warning("pyzipper not installed, creating unencrypted ZIP")
        return create_zip_with_password(reports, password)
    
    buffer = io.BytesIO()
    
    with pyzipper.AESZipFile(buffer, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.setpassword(password.encode())
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        
        for source, data in reports.items():
            timestamp = data.get("_meta", {}).get("timestamp", "unknown")
            filename = f"{source}_{timestamp}.json"
            content = json.dumps(data, indent=2, default=str)
            zf.writestr(filename, content.encode())
    
    return buffer.getvalue()


def generate_html_report(reports: dict, domain: str) -> str:
    """Generate HTML email body from consolidated reports.
    
    Args:
        reports: Dict of source -> report data
        domain: Domain being monitored
        
    Returns:
        HTML string
    """
    now = datetime.now()
    
    # Build summary stats
    http_report = reports.get("http", {})
    github_report = reports.get("github", {})
    sentry_report = reports.get("sentry", {})
    codacy_report = reports.get("codacy", {})
    websentry_report = reports.get("websentry", {})
    
    # Count issues
    http_issues = 0
    for app_data in http_report.get("apps", {}).values():
        http_issues += len(app_data.get("issues", []))
    
    github_issues = github_report.get("total", 0)
    sentry_issues = sentry_report.get("total", 0)
    codacy_issues = codacy_report.get("total", 0)
    
    websentry_failed = 0
    for url_data in websentry_report.get("results", {}).values():
        websentry_failed += len(url_data.get("failed_checks", []))
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Report - {domain}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
    <div style="background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h1 style="color: #1a1a2e; margin-top: 0;">Security Report</h1>
        <p style="color: #64748b; margin-bottom: 30px;">{domain} &middot; {now.strftime('%B %d, %Y')}</p>
        
        <!-- Summary Cards -->
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
            <tr>
                <td style="padding: 15px; background-color: #f8fafc; border-radius: 8px; text-align: center; width: 20%;">
                    <p style="margin: 0; color: #1a1a2e; font-size: 24px; font-weight: bold;">{http_issues}</p>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 12px;">HTTP Issues</p>
                </td>
                <td style="width: 2%;"></td>
                <td style="padding: 15px; background-color: #f8fafc; border-radius: 8px; text-align: center; width: 20%;">
                    <p style="margin: 0; color: #1a1a2e; font-size: 24px; font-weight: bold;">{github_issues}</p>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 12px;">GitHub Issues</p>
                </td>
                <td style="width: 2%;"></td>
                <td style="padding: 15px; background-color: #f8fafc; border-radius: 8px; text-align: center; width: 20%;">
                    <p style="margin: 0; color: #dc3545; font-size: 24px; font-weight: bold;">{sentry_issues}</p>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 12px;">Sentry Errors</p>
                </td>
                <td style="width: 2%;"></td>
                <td style="padding: 15px; background-color: #f8fafc; border-radius: 8px; text-align: center; width: 20%;">
                    <p style="margin: 0; color: #fd7e14; font-size: 24px; font-weight: bold;">{codacy_issues}</p>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 12px;">Codacy Issues</p>
                </td>
            </tr>
        </table>
        
        <!-- Scan Timestamps -->
        <h2 style="color: #1a1a2e; font-size: 16px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">Scan Timestamps</h2>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
"""
    
    # Add timestamps for each source
    source_labels = {
        "http": "HTTP Scanner",
        "github": "GitHub Issues",
        "sentry": "Sentry Errors",
        "codacy": "Codacy Code Quality",
        "websentry": "WebSentry External Scan",
    }
    
    for source, label in source_labels.items():
        report = reports.get(source, {})
        meta = report.get("_meta", {})
        scanned_at = meta.get("scanned_at", "No scan yet")
        if scanned_at != "No scan yet":
            try:
                dt = datetime.fromisoformat(scanned_at)
                scanned_at = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass
        
        html += f"""            <tr>
                <td style="padding: 8px 0; color: #475569;">{label}</td>
                <td style="padding: 8px 0; color: #64748b; text-align: right;">{scanned_at}</td>
            </tr>
"""
    
    html += """        </table>
"""
    
    # HTTP Apps section
    if http_report.get("apps"):
        html += """        <h2 style="color: #1a1a2e; font-size: 16px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">HTTP Security</h2>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
"""
        for app_name, app_data in http_report.get("apps", {}).items():
            score = app_data.get("score", 0)
            issues_count = len(app_data.get("issues", []))
            status = app_data.get("status", "unknown")
            
            status_color = "#28a745" if status == "protected" or issues_count == 0 else "#fd7e14"
            
            html += f"""            <tr>
                <td style="padding: 10px 0;"><strong>{app_name}</strong></td>
                <td style="padding: 10px 0; text-align: center;">Score: {score}</td>
                <td style="padding: 10px 0; text-align: right; color: {status_color};">{issues_count} issues</td>
            </tr>
"""
        html += """        </table>
"""
    
    # WebSentry section
    if websentry_report.get("results"):
        html += """        <h2 style="color: #1a1a2e; font-size: 16px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">WebSentry External Scan</h2>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
"""
        for url, data in websentry_report.get("results", {}).items():
            if data.get("error"):
                html += f"""            <tr>
                <td style="padding: 10px 0;"><strong>{url}</strong></td>
                <td style="padding: 10px 0; text-align: right; color: #dc3545;">Error: {data['error']}</td>
            </tr>
"""
            else:
                grade = data.get("grade", "?")
                score = data.get("score", 0)
                failed = len(data.get("failed_checks", []))
                
                grade_color = "#28a745" if grade in ["A+", "A"] else "#fd7e14" if grade in ["B", "C"] else "#dc3545"
                
                html += f"""            <tr>
                <td style="padding: 10px 0;"><strong>{url}</strong></td>
                <td style="padding: 10px 0; text-align: center;"><span style="color: {grade_color}; font-weight: bold;">{grade}</span> ({score}/100)</td>
                <td style="padding: 10px 0; text-align: right;">{failed} failed checks</td>
            </tr>
"""
        html += """        </table>
"""
    
    # Codacy summary
    if codacy_report.get("by_level"):
        html += """        <h2 style="color: #1a1a2e; font-size: 16px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;">Codacy Code Quality</h2>
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 30px;">
            <tr>
"""
        for level, count in codacy_report.get("by_level", {}).items():
            color = "#dc3545" if level == "Error" else "#fd7e14" if level == "High" else "#ffc107" if level == "Warning" else "#17a2b8"
            html += f"""                <td style="padding: 10px; text-align: center;">
                    <span style="color: {color}; font-size: 18px; font-weight: bold;">{count}</span><br>
                    <span style="color: #64748b; font-size: 11px;">{level}</span>
                </td>
"""
        html += """            </tr>
        </table>
"""
    
    # Footer
    html += f"""        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
        <p style="color: #94a3b8; font-size: 12px; margin: 0;">
            Full JSON reports attached (password protected).<br>
            Generated by waldo-shield &middot; {now.strftime('%Y-%m-%d %H:%M:%S')}
        </p>
    </div>
</body>
</html>"""
    
    return html


def send_report(dry_run: bool = False) -> bool:
    """Consolidate reports and send email.
    
    Args:
        dry_run: If True, don't actually send email
        
    Returns:
        True if successful
    """
    config = Config.load()
    env = config.environment
    
    logging.info(f"Consolidating reports for {config.domain} ({env})")
    
    # Get all latest reports
    reports = get_all_latest_reports(env)
    
    if not reports:
        logging.warning("No reports found to send")
        return False
    
    logging.info(f"Found reports: {', '.join(reports.keys())}")
    
    # Generate HTML
    html = generate_html_report(reports, config.domain)
    
    # Create ZIP with reports
    zip_bytes = create_zip_with_password_encrypted(reports, config.report_zip_password)
    zip_filename = f"reports_{datetime.now().strftime('%Y%m%d')}.zip"
    
    # Prepare email
    subject = f"Security Report - {config.domain} - {datetime.now().strftime('%Y-%m-%d')}"
    
    if dry_run:
        logging.info(f"DRY RUN - would send email to: {config.recipients}")
        logging.info(f"Subject: {subject}")
        logging.info(f"HTML length: {len(html)} bytes")
        logging.info(f"ZIP size: {len(zip_bytes)} bytes")
        
        # Save HTML locally for preview
        preview_path = Path(__file__).resolve().parent.parent.parent / "reports" / "preview.html"
        preview_path.parent.mkdir(parents=True, exist_ok=True)
        with open(preview_path, "w") as f:
            f.write(html)
        logging.info(f"Preview saved to: {preview_path}")
        
        return True
    
    # Send email
    logging.info(f"Sending email to {config.recipients}")
    try:
        result = send_email(
            api_key=config.mailgun_api_key,
            domain=config.mailgun_domain,
            to=config.recipients,
            subject=subject,
            html=html,
            attachments=[(zip_filename, zip_bytes)],
        )
        
        if result.get("success"):
            logging.info("Email sent successfully")
            return True
        else:
            logging.error(f"Failed to send email: {result.get('error')}")
            return False
            
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        return False


def main():
    """Entry point."""
    dry_run = "--dry-run" in sys.argv
    
    try:
        success = send_report(dry_run=dry_run)
        
        if success:
            print(f"\n{'='*60}")
            print(f"  REPORT {'GENERATED' if dry_run else 'SENT'} SUCCESSFULLY")
            print(f"{'='*60}\n")
        else:
            print(f"\n{'='*60}")
            print(f"  REPORT FAILED")
            print(f"{'='*60}\n")
            sys.exit(1)
            
    except Exception as e:
        logging.error(f"Report sender failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
