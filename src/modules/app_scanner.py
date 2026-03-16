"""
App-specific security scanner.

Each app (dashboard, api, www) has different security requirements:
- dashboard: Must be fully blocked by Zero Trust
- api: Headers, SSL, robots blocked, /admin blocked by Zero Trust  
- www: Full security analysis (headers, SSL, tech detection)
"""

import requests
from typing import Optional
from urllib.parse import urljoin

from .headers import analyze as analyze_headers
from .ssl_tls import analyze as analyze_ssl
from .dns_analysis import analyze as analyze_dns
from .tech_detection import analyze as analyze_tech


def check_zero_trust(url: str) -> dict:
    """Check if URL is protected by Cloudflare Zero Trust.
    
    Returns:
        dict with: protected (bool), redirect_url (str or None), issues (list)
    """
    result = {
        "url": url,
        "protected": False,
        "redirect_url": None,
        "issues": [],
    }
    
    try:
        # Don't follow redirects - we want to see where it goes
        response = requests.get(url, timeout=10, allow_redirects=False)
        
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            result["redirect_url"] = location
            
            if "cloudflareaccess.com" in location:
                result["protected"] = True
                # No issue - this is the expected state
            else:
                # Redirects somewhere else - might still be protected
                # Follow one more redirect to check
                try:
                    response2 = requests.get(location, timeout=10, allow_redirects=False)
                    location2 = response2.headers.get("Location", "")
                    if "cloudflareaccess.com" in location2:
                        result["protected"] = True
                        result["redirect_url"] = location2
                        # No issue - this is the expected state
                except:
                    pass
        
        if not result["protected"]:
            result["issues"].append({
                "severity": "critical",
                "message": f"Endpoint NOT protected by Zero Trust! Got status {response.status_code}",
                "recommendation": "Configure Cloudflare Zero Trust to protect this endpoint immediately.",
            })
                    
    except requests.exceptions.Timeout:
        result["issues"].append({
            "severity": "warning",
            "message": "Timeout checking Zero Trust protection",
            "recommendation": "Verify endpoint is accessible.",
        })
    except Exception as e:
        result["issues"].append({
            "severity": "warning", 
            "message": f"Error checking Zero Trust: {str(e)}",
            "recommendation": "Verify endpoint is accessible.",
        })
    
    return result


def check_robots_blocked(url: str) -> dict:
    """Check if robots.txt blocks all crawlers.
    
    For API endpoints, robots.txt should contain:
    User-agent: *
    Disallow: /
    
    Returns:
        dict with: blocked (bool), content (str), issues (list)
    """
    robots_url = urljoin(url, "/robots.txt")
    result = {
        "url": robots_url,
        "blocked": False,
        "content": None,
        "issues": [],
    }
    
    try:
        response = requests.get(robots_url, timeout=10)
        
        if response.status_code == 200:
            content = response.text.lower()
            result["content"] = response.text[:500]  # First 500 chars
            
            # Check if it blocks everything
            if "disallow: /" in content and "user-agent: *" in content:
                # Make sure it's not just "disallow: /something"
                lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if line == "disallow: /" or line == "disallow:/":
                        result["blocked"] = True
                        break
            
            if not result["blocked"]:
                # API should not expose robots.txt with crawl permissions
                result["issues"].append({
                    "severity": "medium",
                    "message": "API robots.txt is accessible and does not block crawlers",
                    "recommendation": "Block access to robots.txt or add 'Disallow: /'",
                })
        # 403, 404, or other status = good, API shouldn't expose robots.txt
        # No issues for these cases
            
    except requests.exceptions.Timeout:
        result["issues"].append({
            "severity": "warning",
            "message": "Timeout fetching robots.txt",
            "recommendation": "Verify endpoint is accessible.",
        })
    except Exception as e:
        result["issues"].append({
            "severity": "warning",
            "message": f"Error fetching robots.txt: {str(e)}",
            "recommendation": "Verify endpoint is accessible.",
        })
    
    return result


def scan_dashboard(domain: str) -> dict:
    """Scan dashboard app - only checks Zero Trust.
    
    Dashboard must be completely blocked by Zero Trust.
    No other checks needed.
    """
    url = f"https://dashboard.{domain}"
    
    zero_trust = check_zero_trust(url)
    
    # Aggregate issues
    all_issues = zero_trust["issues"]
    
    # Calculate risk
    has_critical = any(i["severity"] == "critical" for i in all_issues)
    
    return {
        "app": "dashboard",
        "url": url,
        "checks": {
            "zero_trust": zero_trust,
        },
        "all_issues": all_issues,
        "risk_summary": {
            "score": 100 if has_critical else 0,
            "risk_level": "critical" if has_critical else "none",
            "issue_counts": _count_issues(all_issues),
            "total_issues": len(all_issues),
        },
    }


def scan_api(domain: str) -> dict:
    """Scan API app - headers, SSL, robots, /admin Zero Trust.
    
    Checks:
    - HTTP security headers
    - SSL/TLS configuration
    - robots.txt blocks crawlers
    - /admin endpoint protected by Zero Trust
    """
    url = f"https://api.{domain}"
    admin_url = f"https://api.{domain}/admin"
    
    # Run checks
    headers_result = analyze_headers(url)
    ssl_result = analyze_ssl(url)
    robots_result = check_robots_blocked(url)
    admin_zero_trust = check_zero_trust(admin_url)
    
    # Aggregate issues
    all_issues = []
    
    for issue in headers_result.get("issues", []):
        issue["source"] = "headers"
        all_issues.append(issue)
    
    for issue in ssl_result.get("issues", []):
        issue["source"] = "ssl"
        all_issues.append(issue)
        
    for issue in robots_result.get("issues", []):
        issue["source"] = "robots"
        all_issues.append(issue)
        
    for issue in admin_zero_trust.get("issues", []):
        issue["source"] = "admin_zero_trust"
        all_issues.append(issue)
    
    # Calculate risk
    issue_counts = _count_issues(all_issues)
    score = _calculate_score(issue_counts)
    
    return {
        "app": "api",
        "url": url,
        "checks": {
            "headers": headers_result,
            "ssl": ssl_result,
            "robots": robots_result,
            "admin_zero_trust": admin_zero_trust,
        },
        "all_issues": all_issues,
        "risk_summary": {
            "score": score,
            "risk_level": _score_to_level(score),
            "issue_counts": issue_counts,
            "total_issues": len(all_issues),
        },
    }


def scan_www(domain: str) -> dict:
    """Scan www app - full security analysis.
    
    Checks:
    - HTTP security headers
    - SSL/TLS configuration  
    - DNS configuration
    - Technology detection
    """
    url = f"https://www.{domain}"
    
    # Run checks
    headers_result = analyze_headers(url)
    ssl_result = analyze_ssl(url)
    dns_result = analyze_dns(url)
    tech_result = analyze_tech(url)
    
    # Aggregate issues
    all_issues = []
    
    for issue in headers_result.get("issues", []):
        issue["source"] = "headers"
        all_issues.append(issue)
    
    for issue in ssl_result.get("issues", []):
        issue["source"] = "ssl"
        all_issues.append(issue)
        
    for issue in dns_result.get("issues", []):
        issue["source"] = "dns"
        all_issues.append(issue)
        
    for issue in tech_result.get("issues", []):
        issue["source"] = "tech"
        all_issues.append(issue)
    
    # Calculate risk
    issue_counts = _count_issues(all_issues)
    score = _calculate_score(issue_counts)
    
    return {
        "app": "www",
        "url": url,
        "checks": {
            "headers": headers_result,
            "ssl": ssl_result,
            "dns": dns_result,
            "tech": tech_result,
        },
        "all_issues": all_issues,
        "risk_summary": {
            "score": score,
            "risk_level": _score_to_level(score),
            "issue_counts": issue_counts,
            "total_issues": len(all_issues),
        },
    }


def scan_all(domain: str) -> dict:
    """Scan all apps for a domain.
    
    Args:
        domain: Base domain (e.g., "waldo.click" or "waldoclick.dev")
    
    Returns:
        dict with results for dashboard, api, www
    """
    return {
        "domain": domain,
        "dashboard": scan_dashboard(domain),
        "api": scan_api(domain),
        "www": scan_www(domain),
    }


def _count_issues(issues: list) -> dict:
    """Count issues by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "warning": 0}
    for issue in issues:
        severity = issue.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _calculate_score(counts: dict) -> int:
    """Calculate risk score from issue counts."""
    score = (
        counts.get("critical", 0) * 25 +
        counts.get("high", 0) * 15 +
        counts.get("medium", 0) * 5 +
        counts.get("low", 0) * 1
    )
    return min(score, 100)


def _score_to_level(score: int) -> str:
    """Convert score to risk level."""
    if score >= 50:
        return "critical"
    elif score >= 30:
        return "high"
    elif score >= 15:
        return "medium"
    elif score > 0:
        return "low"
    return "none"
