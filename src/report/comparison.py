"""Scan comparison for trend analysis and delta detection.

Compares current scan with previous scan to identify:
- New issues (in current but not previous)
- Fixed issues (in previous but not current)
- Risk trend (improved/degraded/stable)
"""

from typing import Any, Optional


def _issue_key(issue: dict) -> tuple:
    """Generate unique key for issue matching.
    
    Issues are matched by (source_module, severity, message) tuple.
    This handles the case where the same issue appears in consecutive scans.
    """
    return (
        issue.get("source_module", ""),
        issue.get("severity", ""),
        issue.get("message", ""),
    )


def compare_scans(current: dict, previous: Optional[dict]) -> Optional[dict]:
    """Compare current scan with previous scan results.
    
    Args:
        current: Current scan data
        previous: Previous scan data (or None)
    
    Returns:
        Comparison dict with new_issues, fixed_issues, risk_trend, score_delta
        or None if no previous scan
    """
    if previous is None:
        return None
    
    # Extract all issues from both scans
    current_issues = _extract_all_issues(current)
    previous_issues = _extract_all_issues(previous)
    
    # Create sets of issue keys for comparison
    current_keys = {_issue_key(i) for i in current_issues}
    previous_keys = {_issue_key(i) for i in previous_issues}
    
    # Find new and fixed issues
    new_keys = current_keys - previous_keys
    fixed_keys = previous_keys - current_keys
    
    new_issues = [i for i in current_issues if _issue_key(i) in new_keys]
    fixed_issues = [i for i in previous_issues if _issue_key(i) in fixed_keys]
    
    # Calculate risk trend
    current_score = _get_risk_score(current)
    previous_score = _get_risk_score(previous)
    score_delta = current_score - previous_score
    
    if score_delta > 0:
        risk_trend = "degraded"
    elif score_delta < 0:
        risk_trend = "improved"
    else:
        risk_trend = "stable"
    
    return {
        "risk_trend": risk_trend,
        "score_delta": score_delta,
        "new_issues": new_issues,
        "fixed_issues": fixed_issues,
        "new_count": len(new_issues),
        "fixed_count": len(fixed_issues),
    }


def _extract_all_issues(scan_data: dict) -> list:
    """Extract all issues from all sources in scan data.
    
    Collects issues from:
    - http_results (scanner output with all_issues)
    - email_auth (domain analysis with issues)
    - cloudflare (currently no issue extraction)
    """
    all_issues = []
    
    # Extract from HTTP results
    http_results = scan_data.get("http_results", {})
    for url, result in http_results.items():
        if isinstance(result, dict) and "all_issues" in result:
            for issue in result.get("all_issues", []):
                # Make a copy to avoid mutation
                issue_copy = dict(issue)
                # Ensure source_module is set
                if "source_module" not in issue_copy:
                    issue_copy["source_module"] = "http"
                all_issues.append(issue_copy)
    
    # Extract from email auth
    email_auth = scan_data.get("email_auth", {})
    for domain, result in email_auth.items():
        if isinstance(result, dict) and "issues" in result:
            for issue in result.get("issues", []):
                issue_copy = dict(issue)
                # Set source_module for email issues
                issue_copy["source_module"] = f"email:{domain}"
                all_issues.append(issue_copy)
    
    # Cloudflare data is operational metrics, not security issues
    # No issue extraction needed
    
    return all_issues


def _get_risk_score(scan_data: dict) -> int:
    """Get aggregate risk score from scan data.
    
    Sums the risk scores from all HTTP results.
    """
    total_score = 0
    
    http_results = scan_data.get("http_results", {})
    for url, result in http_results.items():
        if isinstance(result, dict) and "risk_summary" in result:
            risk = result["risk_summary"]
            total_score += risk.get("score", 0)
    
    return total_score
