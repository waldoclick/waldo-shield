"""
Module: HTTP Security Headers Analysis
Analyzes security-related HTTP response headers.
"""

import requests
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "description": "Content Security Policy (CSP)",
        "recommendation": "Define a strict CSP to prevent XSS and data injection attacks.",
    },
    "x-frame-options": {
        "description": "X-Frame-Options (Clickjacking protection)",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options (MIME sniffing protection)",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "description": "Referrer-Policy",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Permissions-Policy (formerly Feature-Policy)",
        "recommendation": "Restrict browser features with Permissions-Policy header.",
    },
    "x-xss-protection": {
        "description": "X-XSS-Protection (legacy XSS filter)",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (note: deprecated in modern browsers, use CSP instead)",
    },
    "cache-control": {
        "description": "Cache-Control",
        "recommendation": "For sensitive pages, use: Cache-Control: no-store",
    },
    "cross-origin-embedder-policy": {
        "description": "Cross-Origin-Embedder-Policy (COEP)",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-Origin-Opener-Policy (COOP)",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-Origin-Resource-Policy (CORP)",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}

DANGEROUS_HEADERS = {
    "server": "Exposes server software and version, aiding fingerprinting.",
    "x-powered-by": "Exposes backend technology (e.g., PHP/7.4), enabling targeted attacks.",
    "x-aspnet-version": "Exposes ASP.NET version.",
    "x-aspnetmvc-version": "Exposes ASP.NET MVC version.",
}

# Endpoints that MUST be protected by Cloudflare Zero Trust
ZERO_TRUST_REQUIRED = [
    "dashboard.waldoclick.dev",
    "dashboard.waldo.click",
    "api.waldoclick.dev/admin",
    "api.waldo.click/admin",
]


def _requires_zero_trust(url: str) -> bool:
    """Check if URL requires Zero Trust protection."""
    parsed = urlparse(url)
    full_path = parsed.netloc + parsed.path
    for protected in ZERO_TRUST_REQUIRED:
        if full_path.startswith(protected) or full_path == protected.rstrip("/"):
            return True
    return False


def _is_zero_trust_redirect(redirect_chain: list) -> bool:
    """Check if redirect chain goes to Cloudflare Access."""
    for redirect in redirect_chain:
        redirect_url = redirect.get("url", "")
        if "cloudflareaccess.com" in redirect_url:
            return True
    return False


def analyze(url: str) -> dict:
    result = {
        "module": "http_headers",
        "url": url,
        "status_code": None,
        "redirect_chain": [],
        "security_headers": {},
        "missing_headers": [],
        "dangerous_headers": {},
        "zero_trust": {
            "required": False,
            "protected": False,
        },
        "score": 0,
        "max_score": len(SECURITY_HEADERS),
        "issues": [],
        "error": None,
    }

    requires_zt = _requires_zero_trust(url)
    result["zero_trust"]["required"] = requires_zt

    try:
        session = requests.Session()
        response = session.get(url, timeout=10, allow_redirects=True)

        # Redirect chain
        for r in response.history:
            result["redirect_chain"].append({
                "url": r.url,
                "status_code": r.status_code,
            })
        
        # Check Zero Trust protection for required endpoints
        if requires_zt:
            is_protected = _is_zero_trust_redirect(result["redirect_chain"])
            result["zero_trust"]["protected"] = is_protected
            
            if is_protected:
                # Protected by Zero Trust - skip header analysis, report success
                result["status_code"] = response.status_code
                result["issues"].append({
                    "severity": "info",
                    "header": "zero-trust",
                    "message": "Endpoint protected by Cloudflare Zero Trust",
                    "recommendation": None,
                })
                return result
            else:
                # NOT protected - this is critical!
                result["issues"].append({
                    "severity": "critical",
                    "header": "zero-trust",
                    "message": f"CRITICAL: Protected endpoint is accessible without Zero Trust authentication!",
                    "recommendation": "Configure Cloudflare Zero Trust to protect this endpoint immediately.",
                })
                # Continue with header analysis to report full state

        result["status_code"] = response.status_code
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # Check security headers
        for header, meta in SECURITY_HEADERS.items():
            if header in headers_lower:
                result["security_headers"][header] = {
                    "present": True,
                    "value": headers_lower[header],
                    "description": meta["description"],
                }
                result["score"] += 1
            else:
                result["missing_headers"].append(header)
                result["security_headers"][header] = {
                    "present": False,
                    "value": None,
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                }
                result["issues"].append({
                    "severity": "medium",
                    "header": header,
                    "message": f"Missing security header: {meta['description']}",
                    "recommendation": meta["recommendation"],
                })

        # Check dangerous headers
        for header, reason in DANGEROUS_HEADERS.items():
            if header in headers_lower:
                header_value = headers_lower[header].lower()
                
                # Skip 'server: cloudflare' - that's expected and can't be changed
                if header == "server" and header_value == "cloudflare":
                    continue
                
                result["dangerous_headers"][header] = {
                    "value": headers_lower[header],
                    "reason": reason,
                }
                result["issues"].append({
                    "severity": "low",
                    "header": header,
                    "message": f"Information disclosure via '{header}' header: {headers_lower[header]}",
                    "recommendation": f"Remove or obscure the '{header}' header. {reason}",
                })

        # Check HTTPS
        parsed = urlparse(url)
        if parsed.scheme != "https":
            result["issues"].append({
                "severity": "high",
                "header": "scheme",
                "message": "Site is not using HTTPS.",
                "recommendation": "Migrate to HTTPS and set up HSTS.",
            })

        # Check HSTS specifics if present
        hsts_value = headers_lower.get("strict-transport-security", "")
        if hsts_value:
            if "max-age" not in hsts_value:
                result["issues"].append({
                    "severity": "medium",
                    "header": "strict-transport-security",
                    "message": "HSTS header is present but missing 'max-age' directive.",
                    "recommendation": "Set max-age to at least 31536000 (1 year).",
                })
            elif "includesubdomains" not in hsts_value.lower():
                result["issues"].append({
                    "severity": "low",
                    "header": "strict-transport-security",
                    "message": "HSTS header does not include 'includeSubDomains'.",
                    "recommendation": "Add 'includeSubDomains' to HSTS header.",
                })

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {str(e)}"
        result["issues"].append({
            "severity": "critical",
            "header": "ssl",
            "message": f"SSL/TLS error when connecting: {str(e)}",
            "recommendation": "Fix the SSL/TLS configuration.",
        })
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {str(e)}"
    except requests.exceptions.Timeout:
        result["error"] = "Connection timed out."
    except Exception as e:
        result["error"] = str(e)

    return result
