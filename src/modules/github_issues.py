"""
GitHub Issues module.

Fetches open issues from the waldo-project repository to include in security reports.
Uses GitHub REST API with token authentication.
"""

import requests
from typing import Optional
from datetime import datetime


GITHUB_API_BASE = "https://api.github.com"


def get_open_issues(repo: str, token: str) -> dict:
    """Fetch open issues from GitHub repository.
    
    Args:
        repo: Repository in format "owner/repo"
        token: GitHub Personal Access Token
    
    Returns:
        dict with: total, issues, by_area, oldest
    """
    result = {
        "repo": repo,
        "total": 0,
        "issues": [],
        "by_area": {},
        "oldest": [],
        "error": None,
    }
    
    try:
        url = f"{GITHUB_API_BASE}/repos/{repo}/issues"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {
            "state": "open",
            "per_page": 100,
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code != 200:
            result["error"] = f"GitHub API error: {response.status_code}"
            return result
        
        issues = response.json()
        
        # Filter out pull requests (GitHub API returns PRs as issues too)
        issues = [i for i in issues if "pull_request" not in i]
        
        result["total"] = len(issues)
        result["issues"] = [
            {
                "number": i.get("number"),
                "title": i.get("title"),
                "url": i.get("html_url"),
                "created": i.get("created_at"),
            }
            for i in issues
        ]
        
        # Group by area (prefix before ":")
        by_area = {}
        for issue in issues:
            title = issue.get("title", "")
            if ":" in title:
                area = title.split(":")[0].strip().lower()
            else:
                area = "other"
            
            if area not in by_area:
                by_area[area] = []
            by_area[area].append(issue.get("number"))
        
        result["by_area"] = {k: len(v) for k, v in by_area.items()}
        
        # Find oldest issues (top 5)
        sorted_issues = sorted(
            issues,
            key=lambda x: x.get("created_at", ""),
        )
        result["oldest"] = [
            {
                "number": i.get("number"),
                "title": i.get("title"),
                "url": i.get("html_url"),
                "created": i.get("created_at"),
                "days_old": _days_since(i.get("created_at")),
            }
            for i in sorted_issues[:5]
        ]
        
    except requests.exceptions.Timeout:
        result["error"] = "Timeout fetching issues"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _days_since(date_str: Optional[str]) -> int:
    """Calculate days since a date string."""
    if not date_str:
        return 0
    try:
        # Parse ISO format: 2026-03-14T01:06:49Z
        date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(date.tzinfo)
        return (now - date).days
    except:
        return 0
