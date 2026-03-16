"""
Module: Technology Detection
Identifies CMS, frameworks, JavaScript libraries, web servers and other technologies.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


TECH_SIGNATURES = {
    # CMS
    "WordPress": [
        {"type": "header", "header": "x-powered-by", "pattern": r"wordpress"},
        {"type": "body", "pattern": r'wp-content|wp-includes|/wp-json/'},
        {"type": "meta", "name": "generator", "pattern": r"WordPress"},
        {"type": "url_probe", "path": "/wp-login.php"},
    ],
    "Drupal": [
        {"type": "header", "header": "x-generator", "pattern": r"drupal"},
        {"type": "body", "pattern": r'Drupal\.settings|sites/default/files'},
        {"type": "meta", "name": "generator", "pattern": r"Drupal"},
    ],
    "Joomla": [
        {"type": "body", "pattern": r'/media/jui/|Joomla!'},
        {"type": "meta", "name": "generator", "pattern": r"Joomla"},
    ],
    "Shopify": [
        {"type": "header", "header": "x-shopify-stage", "pattern": r".*"},
        {"type": "body", "pattern": r'cdn\.shopify\.com|Shopify\.theme'},
    ],
    "Wix": [
        {"type": "body", "pattern": r'static\.parastorage\.com|wix\.com'},
    ],
    # Frameworks / Languages
    "Laravel": [
        {"type": "cookie", "name": "laravel_session"},
        {"type": "header", "header": "x-powered-by", "pattern": r"php"},
        {"type": "body", "pattern": r'laravel'},
    ],
    "Django": [
        {"type": "cookie", "name": "csrftoken"},
        {"type": "header", "header": "x-frame-options", "pattern": r"SAMEORIGIN"},
    ],
    "Ruby on Rails": [
        {"type": "header", "header": "x-powered-by", "pattern": r"phusion passenger"},
        {"type": "cookie", "name": "_session_id"},
    ],
    "ASP.NET": [
        {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET"},
        {"type": "header", "header": "x-aspnet-version", "pattern": r".*"},
        {"type": "cookie", "name": "ASP.NET_SessionId"},
    ],
    "Next.js": [
        {"type": "header", "header": "x-powered-by", "pattern": r"Next\.js"},
        {"type": "body", "pattern": r'__NEXT_DATA__|/_next/static/'},
    ],
    "Nuxt.js": [
        {"type": "body", "pattern": r'__nuxt|/_nuxt/'},
    ],
    # JS Libraries
    "React": [
        {"type": "body", "pattern": r'react\.development\.js|react\.production\.min\.js|data-reactroot|__REACT'},
    ],
    "Vue.js": [
        {"type": "body", "pattern": r'vue\.min\.js|vue\.js|__vue__'},
    ],
    "Angular": [
        {"type": "body", "pattern": r'ng-version=|angular\.min\.js'},
    ],
    "jQuery": [
        {"type": "body", "pattern": r'jquery[\.\-](\d+[\.\d]+)?\.min\.js|jquery\.js'},
    ],
    # Servers
    "Nginx": [
        {"type": "header", "header": "server", "pattern": r"nginx"},
    ],
    "Apache": [
        {"type": "header", "header": "server", "pattern": r"apache"},
    ],
    "Cloudflare": [
        {"type": "header", "header": "server", "pattern": r"cloudflare"},
        {"type": "header", "header": "cf-ray", "pattern": r".*"},
    ],
    "Vercel": [
        {"type": "header", "header": "x-vercel-id", "pattern": r".*"},
    ],
    "AWS CloudFront": [
        {"type": "header", "header": "via", "pattern": r"cloudfront"},
        {"type": "header", "header": "x-amz-cf-id", "pattern": r".*"},
    ],
    # Analytics / Tracking
    "Google Analytics": [
        {"type": "body", "pattern": r'google-analytics\.com|gtag\(|ga\.js|analytics\.js'},
    ],
    "Google Tag Manager": [
        {"type": "body", "pattern": r'googletagmanager\.com/gtm\.js'},
    ],
    "Facebook Pixel": [
        {"type": "body", "pattern": r'connect\.facebook\.net.*fbevents\.js'},
    ],
}

OUTDATED_JS_PATTERNS = [
    (r'jquery[\.\-](\d+)\.(\d+)\.(\d+)', "jQuery", (3, 7, 0)),
    (r'bootstrap[\.\-](\d+)\.(\d+)\.(\d+)', "Bootstrap", (5, 3, 0)),
    (r'angular[\.\-](\d+)\.(\d+)\.(\d+)', "AngularJS", (1, 8, 0)),
]


def _extract_js_versions(body: str) -> list:
    findings = []
    for pattern, lib, min_version in OUTDATED_JS_PATTERNS:
        matches = re.findall(pattern, body, re.IGNORECASE)
        for match in matches:
            version = tuple(int(x) for x in match)
            findings.append({
                "library": lib,
                "version": ".".join(str(v) for v in version),
                "outdated": version < min_version,
                "minimum_recommended": ".".join(str(v) for v in min_version),
            })
    return findings


def analyze(url: str) -> dict:
    result = {
        "module": "tech_detection",
        "url": url,
        "technologies": [],
        "js_libraries": [],
        "issues": [],
        "error": None,
    }

    try:
        headers_req = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        response = requests.get(url, headers=headers_req, timeout=10, allow_redirects=True)
        body = response.text
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = {c.name: c.value for c in response.cookies}

        soup = BeautifulSoup(body, "lxml")

        detected = set()

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                matched = False
                sig_type = sig.get("type")

                if sig_type == "header":
                    header_val = response_headers.get(sig["header"], "")
                    if header_val and re.search(sig["pattern"], header_val, re.IGNORECASE):
                        matched = True

                elif sig_type == "body":
                    if re.search(sig["pattern"], body, re.IGNORECASE):
                        matched = True

                elif sig_type == "meta":
                    meta = soup.find("meta", attrs={"name": sig["name"]})
                    if meta and meta.get("content"):
                        if re.search(sig["pattern"], str(meta["content"]), re.IGNORECASE):
                            matched = True

                elif sig_type == "cookie":
                    if sig["name"] in cookies:
                        matched = True

                elif sig_type == "url_probe":
                    try:
                        probe_url = urljoin(url, sig["path"])
                        probe_resp = requests.get(probe_url, timeout=5, allow_redirects=False)
                        if probe_resp.status_code in (200, 301, 302):
                            matched = True
                    except Exception:
                        pass

                if matched:
                    detected.add(tech)
                    break

        result["technologies"] = sorted(detected)

        # JS version detection
        js_libs = _extract_js_versions(body)
        result["js_libraries"] = js_libs

        for lib_info in js_libs:
            if lib_info["outdated"]:
                result["issues"].append({
                    "severity": "medium",
                    "message": (
                        f"Outdated JavaScript library detected: {lib_info['library']} "
                        f"v{lib_info['version']} (minimum recommended: v{lib_info['minimum_recommended']})"
                    ),
                    "recommendation": f"Update {lib_info['library']} to the latest stable version.",
                })

        # WordPress specific checks
        if "WordPress" in detected:
            result["issues"].append({
                "severity": "info",
                "message": "WordPress detected. Ensure core, themes and plugins are up to date.",
                "recommendation": "Keep WordPress updated. Disable XML-RPC if not needed. Use a WAF.",
            })

        # Exposed admin panels
        parsed = urlparse(url)
        admin_paths = ["/admin", "/wp-admin", "/administrator", "/admin/login", "/user/login"]
        for path in admin_paths:
            try:
                admin_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                resp = requests.get(admin_url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302):
                    result["issues"].append({
                        "severity": "medium",
                        "message": f"Admin panel accessible at: {admin_url} (HTTP {resp.status_code})",
                        "recommendation": "Restrict access to admin panels via IP whitelist or VPN.",
                    })
            except Exception:
                pass

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result
