"""Mailgun email sender for security reports."""

import requests
from typing import List, Optional

MAILGUN_API_BASE = "https://api.mailgun.net/v3"


def should_send_email(
    scan_data: dict,
    comparison: Optional[dict] = None,
    threshold_score: int = 20
) -> bool:
    """Determine if email should be sent based on findings.
    
    Email is sent when ANY of:
    - Risk score >= threshold_score
    - Any critical or high severity issues exist
    - New critical or high issues detected (vs previous scan)
    
    Args:
        scan_data: Current scan results
        comparison: Comparison data from compare_scans() or None
        threshold_score: Minimum risk score to trigger email (default 20)
    
    Returns:
        True if email should be sent
    """
    # Check for critical/high issues in current scan
    for target, result in scan_data.get("http_results", {}).items():
        if isinstance(result, dict) and "risk_summary" in result:
            risk = result["risk_summary"]
            counts = risk.get("issue_counts", {})
            
            # Send if any critical or high issues
            if counts.get("critical", 0) > 0 or counts.get("high", 0) > 0:
                return True
            
            # Send if risk score exceeds threshold
            if risk.get("score", 0) >= threshold_score:
                return True
    
    # Check for new critical/high issues in comparison
    if comparison:
        for issue in comparison.get("new_issues", []):
            severity = issue.get("severity", "").lower()
            if severity in ("critical", "high"):
                return True
    
    return False


def send_report(
    html_content: str,
    recipients: List[str],
    mailgun_domain: str,
    mailgun_api_key: str,
    environment: str,
    subject: Optional[str] = None
) -> dict:
    """Send HTML report via Mailgun API.
    
    Args:
        html_content: HTML report content
        recipients: List of email addresses
        mailgun_domain: Mailgun sending domain
        mailgun_api_key: Mailgun API key
        environment: "staging" or "prod" for subject line
        subject: Optional custom subject (default: "Security Report: {environment}")
    
    Returns:
        {"success": True, "message_id": str} on success
        {"error": str} on failure
    """
    if subject is None:
        subject = f"Security Report: {environment.upper()}"
    
    url = f"{MAILGUN_API_BASE}/{mailgun_domain}/messages"
    
    try:
        response = requests.post(
            url,
            auth=("api", mailgun_api_key),
            data={
                "from": f"Security Monitor <noreply@{mailgun_domain}>",
                "to": recipients,
                "subject": subject,
                "html": html_content,
            },
            timeout=30,
        )
        
        if response.status_code == 200:
            return {"success": True, "message_id": response.json().get("id", "")}
        else:
            return {"error": f"Mailgun API error: {response.status_code} - {response.text}"}
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
