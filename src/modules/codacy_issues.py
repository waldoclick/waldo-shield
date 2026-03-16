"""
Codacy Issues module.

Fetches code quality issues from Codacy for repositories.
Uses Codacy API v3.
"""

import requests
from typing import Optional


CODACY_API_BASE = "https://app.codacy.com/api/v3"


def get_codacy_issues(
    token: str,
    provider: str,
    organization: str,
    repository: str,
    categories: Optional[list] = None,
    levels: Optional[list] = None,
) -> dict:
    """Fetch issues from Codacy repository.

    Args:
        token: Codacy Account API Token
        provider: Git provider (gh, ghe, gl, gle, bb, bbe)
        organization: Organization name
        repository: Repository name
        categories: Filter by categories (e.g., ["Security", "ErrorProne"])
        levels: Filter by levels (e.g., ["Error", "Warning"])

    Returns:
        dict with: total, issues, by_category, by_level, error
    """
    result = {
        "provider": provider,
        "organization": organization,
        "repository": repository,
        "total": 0,
        "issues": [],
        "by_category": {},
        "by_level": {},
        "error": None,
    }

    headers = {
        "api-token": token,
        "Content-Type": "application/json",
    }

    # Build request body
    body = {}
    if categories:
        body["categories"] = categories
    if levels:
        body["levels"] = levels

    try:
        url = f"{CODACY_API_BASE}/analysis/organizations/{provider}/{organization}/repositories/{repository}/issues/search"

        all_issues = []
        cursor = None

        # Paginate through results
        while True:
            params = {"limit": 100}
            if cursor:
                params["cursor"] = cursor

            response = requests.post(
                url,
                headers=headers,
                json=body,
                params=params,
                timeout=30,
            )

            if response.status_code == 401:
                result["error"] = "Invalid API token"
                return result
            elif response.status_code == 404:
                result["error"] = f"Repository not found: {organization}/{repository}"
                return result
            elif response.status_code != 200:
                result["error"] = f"Codacy API error: {response.status_code}"
                return result

            data = response.json()
            issues = data.get("data", [])
            all_issues.extend(issues)

            # Check pagination
            pagination = data.get("pagination", {})
            cursor = pagination.get("cursor")

            # Stop if no more pages or we have enough issues
            if not cursor or len(all_issues) >= 500:
                break

        # Process issues
        by_category = {}
        by_level = {}

        processed_issues = []
        for issue in all_issues:
            pattern_info = issue.get("patternInfo", {})
            commit_info = issue.get("commitInfo", {})

            category = pattern_info.get("category", "Unknown")
            level = pattern_info.get("level", "Unknown")

            by_category[category] = by_category.get(category, 0) + 1
            by_level[level] = by_level.get(level, 0) + 1

            processed_issues.append({
                "pattern_id": pattern_info.get("id"),
                "title": pattern_info.get("title", issue.get("message", "Unknown issue")),
                "category": category,
                "level": level,
                "file_path": issue.get("filePath"),
                "line": issue.get("lineNumber"),
                "message": issue.get("message"),
                "suggestion": issue.get("suggestion"),
                "timestamp": commit_info.get("timestamp"),
                "tool": issue.get("toolInfo", {}).get("name"),
            })

        result["total"] = len(processed_issues)
        result["issues"] = processed_issues
        result["by_category"] = by_category
        result["by_level"] = by_level

    except requests.exceptions.Timeout:
        result["error"] = "Timeout fetching Codacy issues"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result


def get_repository_quality(
    token: str,
    provider: str,
    organization: str,
    repository: str,
) -> dict:
    """Get repository quality overview from Codacy.

    Args:
        token: Codacy Account API Token
        provider: Git provider (gh, ghe, gl, gle, bb, bbe)
        organization: Organization name
        repository: Repository name

    Returns:
        dict with: grade, coverage, issues_count, complexity, duplication, error
    """
    result = {
        "repository": repository,
        "grade": None,
        "coverage": None,
        "issues_count": None,
        "complexity": None,
        "duplication": None,
        "error": None,
    }

    headers = {
        "api-token": token,
    }

    try:
        url = f"{CODACY_API_BASE}/analysis/organizations/{provider}/{organization}/repositories/{repository}"

        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 401:
            result["error"] = "Invalid API token"
            return result
        elif response.status_code == 404:
            result["error"] = f"Repository not found: {organization}/{repository}"
            return result
        elif response.status_code != 200:
            result["error"] = f"Codacy API error: {response.status_code}"
            return result

        data = response.json().get("data", {})
        
        # Extract quality metrics
        result["grade"] = data.get("grade")
        result["coverage"] = data.get("coverage")
        result["issues_count"] = data.get("issuesCount")
        result["complexity"] = data.get("complexity")
        result["duplication"] = data.get("duplication")

    except requests.exceptions.Timeout:
        result["error"] = "Timeout fetching Codacy quality"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result
