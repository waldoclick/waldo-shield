"""
WebSentry API module.

Fetches security scan results from WebSentry.
API docs: https://websentry.dev/docs
"""

import requests
import time
from typing import Optional


WEBSENTRY_API_BASE = "https://websentry.dev/api"


def scan_url(api_key: str, url: str) -> dict:
    """Run a security scan on a URL.
    
    Args:
        api_key: WebSentry API key
        url: URL to scan
        
    Returns:
        dict with: scan_id, grade, score, url, error
    """
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }
    
    try:
        response = requests.post(
            f"{WEBSENTRY_API_BASE}/scan",
            headers=headers,
            json={"url": url},
            timeout=60,
        )
        
        if response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        elif response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}
        
        data = response.json()
        if not data.get("ok"):
            return {"error": data.get("error", "Unknown error")}
        
        return {
            "scan_id": data.get("scanId"),
            "url": data.get("url"),
            "grade": data.get("grade"),
            "score": data.get("score"),
        }
        
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def get_scan_results(api_key: str, scan_id: str) -> dict:
    """Get full scan results.
    
    Args:
        api_key: WebSentry API key
        scan_id: Scan ID from scan_url()
        
    Returns:
        dict with full scan results
    """
    headers = {
        "Authorization": api_key,
    }
    
    try:
        response = requests.get(
            f"{WEBSENTRY_API_BASE}/scan/{scan_id}/json",
            headers=headers,
            timeout=30,
        )
        
        if response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 404:
            return {"error": "Scan not found"}
        elif response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}
        
        data = response.json()
        if not data.get("ok"):
            return {"error": data.get("error", "Unknown error")}
        
        return data.get("scan", {})
        
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def scan_and_get_results(api_key: str, url: str, wait_seconds: int = 5) -> dict:
    """Scan a URL and return full results.
    
    Args:
        api_key: WebSentry API key
        url: URL to scan
        wait_seconds: Seconds to wait before fetching results
        
    Returns:
        dict with: url, grade, score, categories, error
    """
    # Start scan
    scan_result = scan_url(api_key, url)
    if scan_result.get("error"):
        return scan_result
    
    scan_id = scan_result.get("scan_id")
    if not scan_id:
        return {"error": "No scan ID returned"}
    
    # Wait for scan to complete
    time.sleep(wait_seconds)
    
    # Get full results
    full_results = get_scan_results(api_key, scan_id)
    if full_results.get("error"):
        return full_results
    
    # Extract relevant data
    results = full_results.get("results", {})
    categories = results.get("categories", {})
    
    # Process categories into a cleaner format
    processed_categories = {}
    failed_checks = []
    
    for cat_key, cat_data in categories.items():
        cat_name = cat_data.get("name", cat_key)
        cat_grade = cat_data.get("grade", "?")
        cat_score = cat_data.get("score", 0)
        cat_max = cat_data.get("maxScore", 0)
        
        processed_categories[cat_key] = {
            "name": cat_name,
            "grade": cat_grade,
            "score": cat_score,
            "max_score": cat_max,
        }
        
        # Collect failed checks
        for check in cat_data.get("checks", []):
            if check.get("status") in ["fail", "warn"]:
                failed_checks.append({
                    "category": cat_name,
                    "name": check.get("name"),
                    "status": check.get("status"),
                    "value": check.get("value"),
                    "description": check.get("description"),
                })
    
    return {
        "url": results.get("url", url),
        "grade": results.get("grade"),
        "score": results.get("score"),
        "scanned_at": results.get("scannedAt"),
        "duration_ms": results.get("durationMs"),
        "categories": processed_categories,
        "failed_checks": failed_checks,
    }
