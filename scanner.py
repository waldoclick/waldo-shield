#!/usr/bin/env python3
"""
Security Scanner
================
Analyzes a URL for security vulnerabilities and generates a JSON report.

Usage:
    python scanner.py <url> [--output report.json] [--modules all|headers,ssl,dns,ports,tech,vulns]

Example:
    python scanner.py https://example.com
    python scanner.py https://example.com --output my_report.json
    python scanner.py https://example.com --modules headers,ssl,dns
"""

import sys
import json
import time
import argparse
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules import headers, ssl_tls, dns_analysis, port_scan, tech_detection, vulnerabilities


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def calculate_risk_score(all_issues: list) -> dict:
    """Calculate an overall risk score from all issues."""
    total = 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for issue in all_issues:
        sev = issue.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
        total += SEVERITY_SCORES.get(sev, 0)

    # Normalize to 0-100 (cap at 100)
    max_possible = 100
    score = min(total, max_possible)
    risk_level = "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 20 else "low" if score > 0 else "none"

    return {
        "score": score,
        "risk_level": risk_level,
        "issue_counts": counts,
        "total_issues": sum(counts.values()),
    }


def run_module(name: str, func, url: str) -> dict:
    """Run a single analysis module and capture timing + errors."""
    print(f"  [*] Running: {name}...", flush=True)
    start = time.time()
    try:
        result = func(url)
    except Exception as e:
        result = {"module": name, "error": str(e), "issues": []}
    elapsed = round(time.time() - start, 2)
    result["duration_seconds"] = elapsed
    print(f"  [+] Done: {name} ({elapsed}s) - {len(result.get('issues', []))} issue(s) found", flush=True)
    return result


def scan(url: str, selected_modules: list) -> dict:
    """Run all selected modules and assemble the report."""
    url = normalize_url(url)
    parsed = urlparse(url)

    print(f"\n{'='*60}")
    print(f"  Security Scan: {url}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    module_map = {
        "headers": ("HTTP Headers", headers.analyze),
        "ssl":     ("SSL/TLS",      ssl_tls.analyze),
        "dns":     ("DNS",          dns_analysis.analyze),
        "ports":   ("Port Scan",    port_scan.analyze),
        "tech":    ("Technologies", tech_detection.analyze),
        "vulns":   ("Vulnerabilities", vulnerabilities.analyze),
    }

    # Run modules - dns and ports can be parallel; others sequential to avoid hammering server
    results = {}

    # Parallel: dns + ports (network-independent from HTTP)
    parallel_modules = [m for m in ["dns", "ports"] if m in selected_modules]
    sequential_modules = [m for m in ["headers", "ssl", "tech", "vulns"] if m in selected_modules]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(run_module, module_map[m][0], module_map[m][1], url): m
            for m in parallel_modules
        }
        for future in concurrent.futures.as_completed(futures):
            mod_key = futures[future]
            results[mod_key] = future.result()

    for m in sequential_modules:
        name, func = module_map[m]
        results[m] = run_module(name, func, url)

    # Collect all issues
    all_issues = []
    for mod_result in results.values():
        for issue in mod_result.get("issues", []):
            issue_with_module = {**issue, "source_module": mod_result.get("module", "unknown")}
            all_issues.append(issue_with_module)

    # Sort by severity
    all_issues.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info").lower(), 99))

    risk = calculate_risk_score(all_issues)

    report = {
        "meta": {
            "tool": "security-scanner",
            "version": "1.0.0",
            "url": url,
            "hostname": parsed.hostname,
            "scheme": parsed.scheme,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "modules_run": selected_modules,
        },
        "risk_summary": risk,
        "all_issues": all_issues,
        "modules": {
            "http_headers": results.get("headers"),
            "ssl_tls": results.get("ssl"),
            "dns": results.get("dns"),
            "port_scan": results.get("ports"),
            "technologies": results.get("tech"),
            "vulnerabilities": results.get("vulns"),
        },
    }

    return report


def print_summary(report: dict) -> None:
    """Print a human-readable summary to stdout."""
    risk = report["risk_summary"]
    meta = report["meta"]

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE: {meta['url']}")
    print(f"{'='*60}")
    print(f"  Risk Level : {risk['risk_level'].upper()}")
    print(f"  Risk Score : {risk['score']}/100")
    print(f"  Total Issues: {risk['total_issues']}")
    print(f"    Critical  : {risk['issue_counts']['critical']}")
    print(f"    High      : {risk['issue_counts']['high']}")
    print(f"    Medium    : {risk['issue_counts']['medium']}")
    print(f"    Low       : {risk['issue_counts']['low']}")
    print(f"    Info      : {risk['issue_counts']['info']}")

    critical_high = [i for i in report["all_issues"] if i.get("severity") in ("critical", "high")]
    if critical_high:
        print(f"\n  Top Critical/High Issues:")
        for i, issue in enumerate(critical_high[:5], 1):
            print(f"    {i}. [{issue['severity'].upper()}] {issue['message']}")

    print(f"\n  Report saved to: {meta.get('output_file', '(see --output)')}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Security scanner - analyzes a URL and generates a JSON report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path for the JSON report (default: <hostname>_report_<timestamp>.json)",
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        help="Comma-separated list of modules to run: headers,ssl,dns,ports,tech,vulns (default: all)",
    )

    args = parser.parse_args()

    all_modules = ["headers", "ssl", "dns", "ports", "tech", "vulns"]

    if args.modules.lower() == "all":
        selected = all_modules
    else:
        selected = [m.strip().lower() for m in args.modules.split(",")]
        invalid = [m for m in selected if m not in all_modules]
        if invalid:
            print(f"Error: Unknown module(s): {', '.join(invalid)}")
            print(f"Valid modules: {', '.join(all_modules)}")
            sys.exit(1)

    # Determine output filename
    url = normalize_url(args.url)
    parsed = urlparse(url)
    hostname = parsed.hostname or "unknown"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output or f"{hostname}_report_{timestamp}.json"

    report = scan(url, selected)
    report["meta"]["output_file"] = output_file

    # Save report
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print_summary(report)
    print(f"JSON report saved to: {output_file}")


if __name__ == "__main__":
    main()
