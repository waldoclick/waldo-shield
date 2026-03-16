"""
GitHub Issues module.

Fetches open issues from the waldo-project repository to include in security reports.
"""

import subprocess
import json
from typing import Optional
from datetime import datetime


def get_open_issues(repo: str = "waldoclick/waldo-project") -> dict:
    """Fetch open issues from GitHub repository.
    
    Args:
        repo: Repository in format "owner/repo"
    
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
        # Use gh CLI to fetch issues
        cmd = [
            "gh", "issue", "list",
            "--repo", repo,
            "--state", "open",
            "--json", "number,title,labels,createdAt,url",
            "--limit", "100"
        ]
        
        output = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if output.returncode != 0:
            result["error"] = output.stderr.strip()
            return result
        
        issues = json.loads(output.stdout)
        result["total"] = len(issues)
        result["issues"] = issues
        
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
            by_area[area].append({
                "number": issue.get("number"),
                "title": issue.get("title"),
                "url": issue.get("url"),
                "created": issue.get("createdAt"),
            })
        
        result["by_area"] = {k: len(v) for k, v in by_area.items()}
        
        # Find oldest issues (top 5)
        sorted_issues = sorted(
            issues,
            key=lambda x: x.get("createdAt", ""),
        )
        result["oldest"] = [
            {
                "number": i.get("number"),
                "title": i.get("title"),
                "url": i.get("url"),
                "created": i.get("createdAt"),
                "days_old": _days_since(i.get("createdAt")),
            }
            for i in sorted_issues[:5]
        ]
        
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout fetching issues"
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse issues: {e}"
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
