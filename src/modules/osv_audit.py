"""
OSV.dev Audit module.

Fetches package.json and yarn.lock from GitHub, then queries OSV.dev for vulnerabilities.
"""

import base64
import json
import re
import requests
from typing import Optional


OSV_API_URL = "https://api.osv.dev/v1/querybatch"
GITHUB_API_URL = "https://api.github.com"


def get_file_content(token: str, repo: str, path: str, branch: str) -> Optional[str]:
    """Fetch file content from GitHub.
    
    Args:
        token: GitHub token
        repo: Repository (owner/name)
        path: File path
        branch: Branch name
        
    Returns:
        File content as string, or None if not found
    """
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    params = {"ref": branch}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 404:
            return None
        elif response.status_code != 200:
            return None
        
        data = response.json()
        
        # Small files are base64 encoded
        if data.get("encoding") == "base64":
            content = base64.b64decode(data["content"]).decode("utf-8")
            return content
        
        # Large files need to be downloaded from download_url
        download_url = data.get("download_url")
        if download_url:
            dl_response = requests.get(download_url, timeout=60)
            if dl_response.status_code == 200:
                return dl_response.text
        
        return None
        
    except Exception:
        return None


def parse_yarn_lock(content: str) -> dict[str, str]:
    """Parse yarn.lock to extract package versions.
    
    Args:
        content: yarn.lock file content
        
    Returns:
        Dict of package_name -> version
    """
    packages = {}
    
    # yarn.lock format:
    # "package@^1.0.0":
    #   version "1.2.3"
    
    lines = content.split("\n")
    current_package = None
    
    for line in lines:
        # Match package declaration: "lodash@^4.17.0", lodash@^4.17.0:
        pkg_match = re.match(r'^"?(@?[^@"]+)@[^"]+', line)
        if pkg_match and not line.startswith(" "):
            current_package = pkg_match.group(1)
        
        # Match version line:   version "4.17.21"
        version_match = re.match(r'^\s+version\s+"([^"]+)"', line)
        if version_match and current_package:
            version = version_match.group(1)
            # Keep the first version found for each package
            if current_package not in packages:
                packages[current_package] = version
            current_package = None
    
    return packages


def parse_package_json(content: str) -> dict[str, str]:
    """Parse package.json to extract dependencies.
    
    Args:
        content: package.json file content
        
    Returns:
        Dict of package_name -> version_spec
    """
    try:
        data = json.loads(content)
        deps = {}
        
        # Merge all dependency types
        for key in ["dependencies", "devDependencies", "peerDependencies"]:
            if key in data:
                deps.update(data[key])
        
        return deps
    except json.JSONDecodeError:
        return {}


def query_osv(packages: dict[str, str]) -> list[dict]:
    """Query OSV.dev for vulnerabilities.
    
    Args:
        packages: Dict of package_name -> version
        
    Returns:
        List of vulnerability results
    """
    if not packages:
        return []
    
    # Build queries (max 1000 per request)
    queries = []
    for name, version in list(packages.items())[:1000]:
        queries.append({
            "package": {
                "name": name,
                "ecosystem": "npm",
            },
            "version": version,
        })
    
    try:
        response = requests.post(
            OSV_API_URL,
            json={"queries": queries},
            timeout=60,
        )
        
        if response.status_code != 200:
            return []
        
        data = response.json()
        return data.get("results", [])
        
    except Exception:
        return []


def audit_repo(token: str, repo: str, branch: str) -> dict:
    """Audit a repository for dependency vulnerabilities.
    
    Args:
        token: GitHub token
        repo: Repository (owner/name)
        branch: Branch name
        
    Returns:
        Audit result with vulnerabilities
    """
    result = {
        "repo": repo,
        "branch": branch,
        "total_packages": 0,
        "vulnerable_packages": 0,
        "vulnerabilities": [],
        "by_severity": {},
        "error": None,
    }
    
    # Fetch yarn.lock (preferred for exact versions)
    yarn_lock = get_file_content(token, repo, "yarn.lock", branch)
    
    if yarn_lock:
        packages = parse_yarn_lock(yarn_lock)
    else:
        # Fallback to package.json (less accurate)
        package_json = get_file_content(token, repo, "package.json", branch)
        if not package_json:
            result["error"] = "Could not fetch package.json or yarn.lock"
            return result
        packages = parse_package_json(package_json)
    
    result["total_packages"] = len(packages)
    
    if not packages:
        return result
    
    # Query OSV for vulnerabilities
    osv_results = query_osv(packages)
    
    # Process results
    vulnerabilities = []
    vulnerable_packages = set()
    by_severity = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "unknown": 0}
    
    package_list = list(packages.keys())
    
    for i, res in enumerate(osv_results):
        if "vulns" in res and res["vulns"]:
            pkg_name = package_list[i] if i < len(package_list) else "unknown"
            pkg_version = packages.get(pkg_name, "unknown")
            vulnerable_packages.add(pkg_name)
            
            for vuln in res["vulns"]:
                # Determine severity
                severity = "unknown"
                if "severity" in vuln:
                    for sev in vuln["severity"]:
                        if sev.get("type") == "CVSS_V3":
                            score = sev.get("score", "")
                            # Parse CVSS score
                            if "CVSS:3" in score:
                                try:
                                    # Extract base score from vector
                                    # This is simplified - real CVSS parsing is more complex
                                    severity = classify_cvss(score)
                                except Exception:
                                    pass
                
                # Also check database_specific severity
                db_specific = vuln.get("database_specific", {})
                if "severity" in db_specific:
                    sev_str = db_specific["severity"].lower()
                    if sev_str in by_severity:
                        severity = sev_str
                
                by_severity[severity] = by_severity.get(severity, 0) + 1
                
                vulnerabilities.append({
                    "id": vuln.get("id"),
                    "package": pkg_name,
                    "version": pkg_version,
                    "summary": vuln.get("summary", ""),
                    "severity": severity,
                    "aliases": vuln.get("aliases", []),
                    "fixed_in": get_fixed_version(vuln, pkg_name),
                    "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                })
    
    result["vulnerable_packages"] = len(vulnerable_packages)
    result["vulnerabilities"] = vulnerabilities
    result["by_severity"] = {k: v for k, v in by_severity.items() if v > 0}
    
    return result


def classify_cvss(cvss_vector: str) -> str:
    """Classify severity from CVSS vector string."""
    # Very simplified CVSS classification
    # Real implementation would parse the full vector
    if "AV:N" in cvss_vector and "AC:L" in cvss_vector:
        return "high"
    return "moderate"


def get_fixed_version(vuln: dict, package: str) -> Optional[str]:
    """Extract fixed version from vulnerability data."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") == package:
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None
