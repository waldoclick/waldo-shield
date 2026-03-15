"""
Module: Vulnerability Checks
Checks for common web vulnerabilities and misconfigurations.
"""

import re
import requests
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse, quote


def _test_open_redirect(base_url: str, session: requests.Session) -> list:
    issues = []
    payloads = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
    ]
    params_to_test = ["redirect", "url", "next", "goto", "return", "returnUrl", "redirect_uri"]
    parsed = urlparse(base_url)

    for param in params_to_test:
        for payload in payloads[:1]:  # Test only one payload per param to be quick
            try:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                resp = session.get(test_url, timeout=5, allow_redirects=False)
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    issues.append({
                        "severity": "high",
                        "message": f"Potential open redirect via parameter '{param}': {test_url}",
                        "recommendation": "Validate and whitelist redirect URLs server-side.",
                    })
                    break
            except Exception:
                pass
    return issues


def _test_directory_listing(base_url: str, session: requests.Session) -> list:
    issues = []
    common_dirs = ["/images/", "/uploads/", "/files/", "/static/", "/assets/", "/backup/", "/tmp/"]
    parsed = urlparse(base_url)

    for d in common_dirs:
        try:
            url = f"{parsed.scheme}://{parsed.netloc}{d}"
            resp = session.get(url, timeout=5)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if "index of" in body_lower or "directory listing" in body_lower or "<title>index of" in body_lower:
                    issues.append({
                        "severity": "medium",
                        "message": f"Directory listing enabled at: {url}",
                        "recommendation": "Disable directory listing in your web server configuration.",
                    })
        except Exception:
            pass
    return issues


def _test_sensitive_files(base_url: str, session: requests.Session) -> list:
    issues = []
    sensitive_paths = [
        ("/.git/HEAD", "Git repository exposed"),
        ("/.env", ".env file with secrets possibly exposed"),
        ("/robots.txt", "robots.txt may reveal hidden paths"),
        ("/sitemap.xml", "sitemap.xml available (informational)"),
        ("/.htaccess", ".htaccess file exposed"),
        ("/phpinfo.php", "PHP info page exposed"),
        ("/server-status", "Apache server-status exposed"),
        ("/server-info", "Apache server-info exposed"),
        ("/.DS_Store", ".DS_Store macOS metadata file exposed"),
        ("/web.config", "web.config file possibly exposed"),
        ("/config.php", "config.php file possibly exposed"),
        ("/wp-config.php.bak", "WordPress config backup possibly exposed"),
        ("/database.yml", "Database configuration file possibly exposed"),
        ("/Dockerfile", "Dockerfile possibly exposed"),
        ("/docker-compose.yml", "docker-compose.yml possibly exposed"),
    ]
    parsed = urlparse(base_url)

    for path, description in sensitive_paths:
        try:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = session.get(url, timeout=5)
            if resp.status_code == 200:
                severity = "critical" if path in ["/.git/HEAD", "/.env", "/phpinfo.php"] else "medium"
                issues.append({
                    "severity": severity,
                    "message": f"Sensitive file accessible at {url} (HTTP 200): {description}",
                    "recommendation": f"Restrict access to '{path}' immediately.",
                    "url": url,
                })
        except Exception:
            pass
    return issues


def _test_xss_reflection(base_url: str, session: requests.Session) -> list:
    """Basic reflected XSS probe - NOT a full scanner."""
    issues = []
    xss_payload = "<script>alert(1)</script>"
    params_to_test = ["q", "search", "query", "s", "id", "name", "input"]
    parsed = urlparse(base_url)

    for param in params_to_test:
        try:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(xss_payload)}"
            resp = session.get(test_url, timeout=5)
            if xss_payload in resp.text:
                issues.append({
                    "severity": "high",
                    "message": f"Potential reflected XSS via parameter '{param}': payload reflected unescaped in response.",
                    "recommendation": "Encode all user-supplied input before rendering it in HTML. Use Content-Security-Policy.",
                })
        except Exception:
            pass
    return issues


def _check_cors(url: str, session: requests.Session) -> list:
    issues = []
    try:
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        }
        resp = session.options(url, headers=headers, timeout=5)
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            issues.append({
                "severity": "medium",
                "message": "CORS policy allows all origins (Access-Control-Allow-Origin: *).",
                "recommendation": "Restrict CORS to specific trusted origins.",
            })
        elif "evil.com" in acao:
            if acac.lower() == "true":
                issues.append({
                    "severity": "critical",
                    "message": "CORS misconfiguration: arbitrary origin 'evil.com' is reflected with credentials allowed.",
                    "recommendation": "Validate the Origin header server-side. Never reflect arbitrary origins with credentials.",
                })
            else:
                issues.append({
                    "severity": "high",
                    "message": "CORS misconfiguration: arbitrary origin 'evil.com' is reflected in Access-Control-Allow-Origin.",
                    "recommendation": "Validate the Origin header against a whitelist.",
                })
    except Exception:
        pass
    return issues


def _check_cookie_security(url: str, session: requests.Session) -> list:
    issues = []
    try:
        resp = session.get(url, timeout=10)
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("missing HttpOnly flag")
            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite:
                flags.append("missing SameSite attribute")
            elif samesite.lower() == "none" and not cookie.secure:
                flags.append("SameSite=None without Secure flag")

            if flags:
                issues.append({
                    "severity": "medium",
                    "message": f"Cookie '{cookie.name}' has security issues: {', '.join(flags)}.",
                    "recommendation": (
                        f"Set the Secure, HttpOnly, and SameSite=Lax/Strict flags on the '{cookie.name}' cookie."
                    ),
                })
    except Exception:
        pass
    return issues


def analyze(url: str) -> dict:
    result = {
        "module": "vulnerabilities",
        "url": url,
        "checks": {},
        "issues": [],
        "error": None,
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    })

    try:
        # Sensitive files
        sf_issues = _test_sensitive_files(url, session)
        result["checks"]["sensitive_files"] = {"issues_found": len(sf_issues)}
        result["issues"].extend(sf_issues)

        # Directory listing
        dl_issues = _test_directory_listing(url, session)
        result["checks"]["directory_listing"] = {"issues_found": len(dl_issues)}
        result["issues"].extend(dl_issues)

        # Open redirect
        or_issues = _test_open_redirect(url, session)
        result["checks"]["open_redirect"] = {"issues_found": len(or_issues)}
        result["issues"].extend(or_issues)

        # Basic XSS reflection
        xss_issues = _test_xss_reflection(url, session)
        result["checks"]["xss_reflection"] = {"issues_found": len(xss_issues)}
        result["issues"].extend(xss_issues)

        # CORS
        cors_issues = _check_cors(url, session)
        result["checks"]["cors"] = {"issues_found": len(cors_issues)}
        result["issues"].extend(cors_issues)

        # Cookie security
        cookie_issues = _check_cookie_security(url, session)
        result["checks"]["cookie_security"] = {"issues_found": len(cookie_issues)}
        result["issues"].extend(cookie_issues)

    except Exception as e:
        result["error"] = str(e)

    return result
