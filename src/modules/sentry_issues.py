"""
Sentry Issues module.

Fetches unresolved issues from Sentry for all projects in the organization.
"""

import requests
from typing import Optional
from datetime import datetime


SENTRY_API_BASE = "https://sentry.io/api/0"


def get_sentry_issues(org: str, token: str, environment: str) -> dict:
    """Fetch unresolved issues from all Sentry projects.
    
    Args:
        org: Sentry organization slug
        token: Sentry Auth Token
        environment: Environment to filter (e.g., "production", "development")
    
    Returns:
        dict with: total, by_project, issues, error
    """
    result = {
        "org": org,
        "environment": environment,
        "total": 0,
        "by_project": {},
        "issues": [],
        "error": None,
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
    }
    
    try:
        # First, get all projects in the org
        projects_url = f"{SENTRY_API_BASE}/organizations/{org}/projects/"
        projects_response = requests.get(projects_url, headers=headers, timeout=30)
        
        if projects_response.status_code != 200:
            result["error"] = f"Sentry API error: {projects_response.status_code}"
            return result
        
        projects = projects_response.json()
        
        # For each project, get unresolved issues
        all_issues = []
        by_project = {}
        
        for project in projects:
            project_slug = project.get("slug")
            project_name = project.get("name", project_slug)
            
            # Get issues for this project filtered by environment
            issues_url = f"{SENTRY_API_BASE}/projects/{org}/{project_slug}/issues/"
            params = {
                "query": f"is:unresolved environment:{environment}",
                "statsPeriod": "14d",
            }
            
            issues_response = requests.get(
                issues_url, 
                headers=headers, 
                params=params,
                timeout=30
            )
            
            if issues_response.status_code != 200:
                continue
            
            project_issues = issues_response.json()
            
            if project_issues:
                by_project[project_slug] = {
                    "name": project_name,
                    "count": len(project_issues),
                    "issues": [
                        {
                            "id": i.get("id"),
                            "title": i.get("title"),
                            "culprit": i.get("culprit"),
                            "level": i.get("level"),
                            "count": i.get("count"),
                            "first_seen": i.get("firstSeen"),
                            "last_seen": i.get("lastSeen"),
                            "url": i.get("permalink"),
                        }
                        for i in project_issues
                    ]
                }
                all_issues.extend(project_issues)
        
        result["total"] = len(all_issues)
        result["by_project"] = {k: v["count"] for k, v in by_project.items()}
        result["projects"] = by_project
        
    except requests.exceptions.Timeout:
        result["error"] = "Timeout fetching Sentry issues"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    
    return result
