"""HTML report generator for security scan results.

Consolidates HTTP scanner, email authentication, and Cloudflare data
into a single email-compatible HTML report.
"""

from typing import Any

from .templates import (
    REPORT_TEMPLATE,
    SEVERITY_COLORS,
    SEVERITY_BG_COLORS,
    RISK_LEVEL_STYLES,
    TARGET_LIST_TEMPLATE,
    TARGET_ROW_TEMPLATE,
    HTTP_FINDINGS_SECTION_TEMPLATE,
    HTTP_NO_DATA_TEMPLATE,
    EMAIL_AUTH_SECTION_TEMPLATE,
    EMAIL_NO_DATA_TEMPLATE,
    CLOUDFLARE_SECTION_TEMPLATE,
    CLOUDFLARE_NO_DATA_TEMPLATE,
    CLOUDFLARE_ERROR_TEMPLATE,
    WAF_ACTION_ROW_TEMPLATE,
    RATE_LIMIT_ROW_TEMPLATE,
    RATE_LIMIT_NONE_TEMPLATE,
    ISSUES_TABLE_TEMPLATE,
    ISSUE_ROW_TEMPLATE,
    ISSUES_NO_DATA_TEMPLATE,
    # Comparison templates
    NEW_BADGE,
    FIXED_BADGE,
    TREND_IMPROVED,
    TREND_DEGRADED,
    TREND_STABLE,
    COMPARISON_SUMMARY_TEMPLATE,
    FIXED_ISSUES_SECTION_TEMPLATE,
    FIXED_ISSUE_ROW_TEMPLATE,
    # GitHub templates
    GITHUB_SECTION_TEMPLATE,
    GITHUB_ISSUE_ROW_TEMPLATE,
    GITHUB_LABEL_TEMPLATE,
    GITHUB_NO_DATA_TEMPLATE,
    GITHUB_ERROR_TEMPLATE,
    # Sentry templates
    SENTRY_SECTION_TEMPLATE,
    SENTRY_PROJECT_TEMPLATE,
    SENTRY_ISSUE_ROW_TEMPLATE,
    SENTRY_NO_DATA_TEMPLATE,
    SENTRY_ERROR_TEMPLATE,
    # Codacy templates
    CODACY_SECTION_TEMPLATE,
    CODACY_CATEGORY_ROW_TEMPLATE,
    CODACY_ISSUE_ROW_TEMPLATE,
    CODACY_NO_DATA_TEMPLATE,
    CODACY_ERROR_TEMPLATE,
)


# Severity ordering for sorting
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "warning": 2, "error": 1}


def generate_report(data: dict[str, Any]) -> str:
    """Generate HTML security report from consolidated data.

    Args:
        data: Report data structure with keys:
            - environment: str (staging/production)
            - scan_date: str (ISO timestamp)
            - targets: list[str] (target URLs)
            - http_results: dict[url -> scanner result] (from scanner.scan())
            - email_auth: dict[domain -> analysis result] (from email_auth.analyze_domain())
            - cloudflare: dict (from cloudflare_api.collect_cloudflare_data())
            - github: dict (from github_issues.get_github_issues())
            - sentry: dict (from sentry_issues.get_sentry_issues())
            - comparison: dict (optional, from compare_scans())

    Returns:
        Complete HTML report as string
    """
    environment = data.get("environment", "unknown")
    scan_date = data.get("scan_date", "")
    
    # Support both old format (targets/http_results) and new format (apps)
    targets = data.get("targets", [])
    http_results = data.get("http_results", {})
    
    # If apps format is used, convert to http_results format
    apps = data.get("apps", {})
    if apps and not http_results:
        domain = data.get("domain", "")
        for app_name, app_data in apps.items():
            if isinstance(app_data, dict):
                url = f"https://{app_name}.{domain}"
                targets.append(url)
                http_results[url] = app_data
    
    email_auth = data.get("email_auth", {})
    cloudflare = data.get("cloudflare", {})
    
    # Support both github/sentry and github_issues/sentry_issues keys
    github = data.get("github") or data.get("github_issues", {})
    sentry = data.get("sentry") or data.get("sentry_issues", {})
    codacy = data.get("codacy") or data.get("codacy_issues", {})
    
    # Transform github_issues format to expected github format
    if github and "total" in github and "open_count" not in github:
        github = {
            "open_count": github.get("total", 0),
            "repo_url": f"https://github.com/{github.get('repo', '')}",
            "issues": github.get("issues", []),
            "error": github.get("error"),
        }
    
    comparison = data.get("comparison")

    # Aggregate data across all sources
    aggregate = _aggregate_data(http_results, email_auth, cloudflare)

    # Determine risk level style
    risk_level = aggregate["risk_level"]
    risk_level_style = RISK_LEVEL_STYLES.get(risk_level, RISK_LEVEL_STYLES["none"])

    # Build set of new issue keys for badge rendering
    new_issue_keys = set()
    if comparison:
        for issue in comparison.get("new_issues", []):
            key = (
                issue.get("source_module", ""),
                issue.get("severity", ""),
                issue.get("message", ""),
            )
            new_issue_keys.add(key)

    # Render sections
    targets_html = _render_targets(targets)
    http_findings_html = _render_http_findings(http_results)
    email_auth_html = _render_email_auth(email_auth)
    cloudflare_html = _render_cloudflare(cloudflare)
    github_html = _render_github(github)
    sentry_html = _render_sentry(sentry)
    codacy_html = _render_codacy(codacy)
    issues_table_html = _render_issues_table(aggregate["all_issues"], new_issue_keys)
    
    # Add comparison section and fixed issues if comparison data present
    comparison_html = _render_comparison_summary(comparison)
    fixed_issues_html = _render_fixed_issues(comparison)

    # Build final report
    html = REPORT_TEMPLATE.format(
        environment=environment,
        scan_date=scan_date,
        risk_score=aggregate["risk_score"],
        risk_level=risk_level,
        risk_level_style=risk_level_style,
        critical_count=aggregate["issue_counts"].get("critical", 0),
        high_count=aggregate["issue_counts"].get("high", 0),
        medium_count=aggregate["issue_counts"].get("medium", 0),
        low_count=aggregate["issue_counts"].get("low", 0),
        info_count=aggregate["issue_counts"].get("info", 0),
        total_issues=aggregate["total_issues"],
        targets_html=targets_html + comparison_html,
        http_findings_html=http_findings_html,
        email_auth_html=email_auth_html,
        cloudflare_html=cloudflare_html,
        github_html=github_html,
        sentry_html=sentry_html,
        codacy_html=codacy_html,
        issues_table_html=issues_table_html + fixed_issues_html,
    )

    return html


def _aggregate_data(
    http_results: dict[str, Any],
    email_auth: dict[str, Any],
    cloudflare: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate risk scores and issues from all data sources.

    Returns:
        Dict with keys: risk_score, risk_level, issue_counts, total_issues, all_issues
    """
    all_issues = []
    total_score = 0
    issue_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Collect from HTTP results
    for url, result in http_results.items():
        if isinstance(result, dict) and "all_issues" in result:
            for issue in result.get("all_issues", []):
                issue_copy = dict(issue)
                issue_copy["source"] = _extract_hostname(url)
                all_issues.append(issue_copy)

        if isinstance(result, dict) and "risk_summary" in result:
            risk = result["risk_summary"]
            total_score += risk.get("score", 0)
            for sev, count in risk.get("issue_counts", {}).items():
                if sev in issue_counts:
                    issue_counts[sev] += count

    # Collect from email auth
    for domain, result in email_auth.items():
        if isinstance(result, dict) and "issues" in result:
            for issue in result.get("issues", []):
                issue_copy = dict(issue)
                issue_copy["source"] = f"email:{domain}"
                # Map severity (email uses "warning", "error")
                sev = issue.get("severity", "info")
                if sev == "warning":
                    issue_copy["severity"] = "medium"
                    issue_counts["medium"] += 1
                elif sev == "error":
                    issue_copy["severity"] = "high"
                    issue_counts["high"] += 1
                else:
                    issue_counts.get(sev, "info")
                    if sev in issue_counts:
                        issue_counts[sev] += 1
                all_issues.append(issue_copy)

    # Note: Cloudflare data is operational metrics, not security issues
    # We could add issues for high blocked percentage, etc. but keeping it simple

    # Calculate aggregate risk level
    total_issues = sum(issue_counts.values())

    # Cap score at 100
    risk_score = min(total_score, 100)

    # Determine risk level based on score
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 40:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    # Sort issues by severity
    all_issues.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 99))

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "issue_counts": issue_counts,
        "total_issues": total_issues,
        "all_issues": all_issues,
    }


def _extract_hostname(url: str) -> str:
    """Extract hostname from URL."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _render_targets(targets: list[str]) -> str:
    """Render the targets list section."""
    if not targets:
        return "<p style='color: #64748b; font-size: 14px; margin: 0;'>No targets scanned.</p>"

    rows = "".join(TARGET_ROW_TEMPLATE.format(target=target) for target in targets)
    return TARGET_LIST_TEMPLATE.format(rows=rows)


def _render_http_findings(http_results: dict[str, Any]) -> str:
    """Render the HTTP scanner findings section."""
    if not http_results:
        return HTTP_NO_DATA_TEMPLATE

    sections = []
    for url, result in http_results.items():
        if not isinstance(result, dict):
            continue

        risk = result.get("risk_summary", {})
        score = risk.get("score", 0)
        risk_level = risk.get("risk_level", "none")
        counts = risk.get("issue_counts", {})

        risk_style = RISK_LEVEL_STYLES.get(risk_level, RISK_LEVEL_STYLES["none"])

        sections.append(
            HTTP_FINDINGS_SECTION_TEMPLATE.format(
                target=url,
                score=score,
                risk_level=risk_level.upper(),
                risk_style=risk_style,
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                info=counts.get("info", 0),
            )
        )

    return "".join(sections) if sections else HTTP_NO_DATA_TEMPLATE


def _render_email_auth(email_auth: dict[str, Any]) -> str:
    """Render the email authentication section."""
    if not email_auth:
        return EMAIL_NO_DATA_TEMPLATE

    sections = []
    for domain, result in email_auth.items():
        if not isinstance(result, dict):
            continue

        # SPF
        spf = result.get("spf", {})
        spf_valid = spf.get("valid", False)
        spf_status = "VALID" if spf_valid else "INVALID"
        spf_style = RISK_LEVEL_STYLES["none"] if spf_valid else RISK_LEVEL_STYLES["high"]
        spf_lookups = spf.get("dns_lookups")
        spf_details = ""
        if spf_lookups is not None:
            spf_details = f'<span style="color: #64748b; font-size: 11px; margin-left: 5px;">({spf_lookups} DNS lookups)</span>'

        # DKIM
        dkim = result.get("dkim", {})
        dkim_selectors = dkim.get("selectors", {})
        dkim_valid = any(dkim_selectors.values()) if dkim_selectors else False
        dkim_status = "VALID" if dkim_valid else "NONE"
        dkim_style = RISK_LEVEL_STYLES["none"] if dkim_valid else RISK_LEVEL_STYLES["medium"]

        # DMARC
        dmarc = result.get("dmarc", {})
        dmarc_valid = dmarc.get("valid", False)
        dmarc_policy = dmarc.get("policy", "none")
        dmarc_status = f"VALID ({dmarc_policy})" if dmarc_valid else "INVALID"
        dmarc_style = RISK_LEVEL_STYLES["none"] if dmarc_valid else RISK_LEVEL_STYLES["high"]
        dmarc_details = ""
        if dmarc_policy == "none":
            dmarc_details = '<span style="color: #ffc107; font-size: 11px; margin-left: 5px;">(monitoring only)</span>'

        # CAA
        caa = result.get("caa", {})
        caa_valid = caa.get("valid", False)
        caa_status = "VALID" if caa_valid else "NONE"
        caa_style = RISK_LEVEL_STYLES["none"] if caa_valid else RISK_LEVEL_STYLES["low"]

        sections.append(
            EMAIL_AUTH_SECTION_TEMPLATE.format(
                domain=domain,
                spf_status=spf_status,
                spf_style=spf_style,
                spf_details=spf_details,
                dkim_status=dkim_status,
                dkim_style=dkim_style,
                dmarc_status=dmarc_status,
                dmarc_style=dmarc_style,
                dmarc_details=dmarc_details,
                caa_status=caa_status,
                caa_style=caa_style,
            )
        )

    return "".join(sections) if sections else EMAIL_NO_DATA_TEMPLATE


def _render_cloudflare(cloudflare: dict[str, Any]) -> str:
    """Render the Cloudflare security section."""
    if not cloudflare:
        return CLOUDFLARE_NO_DATA_TEMPLATE

    # Check for errors
    security_events = cloudflare.get("security_events", {})
    traffic_analytics = cloudflare.get("traffic_analytics", {})

    if isinstance(security_events, dict) and "error" in security_events:
        return CLOUDFLARE_ERROR_TEMPLATE.format(error=security_events["error"])

    if isinstance(traffic_analytics, dict) and "error" in traffic_analytics:
        return CLOUDFLARE_ERROR_TEMPLATE.format(error=traffic_analytics["error"])

    # WAF events
    waf_total = security_events.get("total_events", 0) if isinstance(security_events, dict) else 0
    by_action = security_events.get("by_action", {}) if isinstance(security_events, dict) else {}
    waf_actions_html = ""
    for action, count in by_action.items():
        waf_actions_html += WAF_ACTION_ROW_TEMPLATE.format(action=action.capitalize(), count=count)

    # Traffic analytics
    total_requests = traffic_analytics.get("total_requests", 0) if isinstance(traffic_analytics, dict) else 0
    blocked_percentage = traffic_analytics.get("blocked_percentage", 0.0) if isinstance(traffic_analytics, dict) else 0.0

    # Rate limiting rules
    rate_limit_rules = cloudflare.get("rate_limit_rules", [])
    if rate_limit_rules:
        rate_limit_html = '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">'
        for rule in rate_limit_rules:
            action = rule.get("action", "unknown")
            expression = rule.get("expression", "")
            # Truncate long expressions
            description = expression[:60] + "..." if len(expression) > 60 else expression
            rate_limit_html += RATE_LIMIT_ROW_TEMPLATE.format(action=action, description=description)
        rate_limit_html += "</table>"
    else:
        rate_limit_html = RATE_LIMIT_NONE_TEMPLATE

    return CLOUDFLARE_SECTION_TEMPLATE.format(
        waf_total=waf_total,
        waf_actions_html=waf_actions_html,
        total_requests=f"{total_requests:,}",
        blocked_percentage=f"{blocked_percentage:.1f}",
        rate_limit_html=rate_limit_html,
    )


def _render_issues_table(all_issues: list[dict[str, Any]], new_issue_keys: set | None = None) -> str:
    """Render the issues table section.
    
    Args:
        all_issues: List of all issues to display
        new_issue_keys: Set of (source_module, severity, message) tuples for new issues
    """
    if new_issue_keys is None:
        new_issue_keys = set()
    
    if not all_issues:
        return ISSUES_NO_DATA_TEMPLATE

    rows = ""
    for issue in all_issues:
        severity = issue.get("severity", "info").lower()
        # Normalize severity
        if severity == "warning":
            severity = "medium"
        elif severity == "error":
            severity = "high"

        source = issue.get("source", issue.get("source_module", "unknown"))
        message = issue.get("message", "No description")

        bg_color = SEVERITY_BG_COLORS.get(severity, SEVERITY_BG_COLORS["info"])
        text_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])

        # Check if this is a new issue
        issue_key = (
            issue.get("source_module", ""),
            issue.get("severity", ""),
            issue.get("message", ""),
        )
        new_badge = NEW_BADGE if issue_key in new_issue_keys else ""

        rows += ISSUE_ROW_TEMPLATE.format(
            severity=severity.upper(),
            bg_color=bg_color,
            text_color=text_color,
            source=source,
            message=message + new_badge,
        )

    return ISSUES_TABLE_TEMPLATE.format(rows=rows)


def _render_comparison_summary(comparison: dict | None) -> str:
    """Render the comparison summary section."""
    if not comparison:
        return ""
    
    risk_trend = comparison.get("risk_trend", "stable")
    score_delta = comparison.get("score_delta", 0)
    new_count = comparison.get("new_count", 0)
    fixed_count = comparison.get("fixed_count", 0)
    
    # Generate trend indicator
    if risk_trend == "improved":
        trend_indicator = TREND_IMPROVED.format(delta=score_delta)
    elif risk_trend == "degraded":
        trend_indicator = TREND_DEGRADED.format(delta=score_delta)
    else:
        trend_indicator = TREND_STABLE
    
    return COMPARISON_SUMMARY_TEMPLATE.format(
        trend_indicator=trend_indicator,
        new_count=new_count,
        fixed_count=fixed_count,
    )


def _render_fixed_issues(comparison: dict | None) -> str:
    """Render the fixed issues section."""
    if not comparison:
        return ""
    
    fixed_issues = comparison.get("fixed_issues", [])
    if not fixed_issues:
        return ""
    
    rows = ""
    for issue in fixed_issues:
        severity = issue.get("severity", "info").lower()
        if severity == "warning":
            severity = "medium"
        elif severity == "error":
            severity = "high"
        
        source = issue.get("source_module", "unknown")
        message = issue.get("message", "No description")
        
        rows += FIXED_ISSUE_ROW_TEMPLATE.format(
            severity=severity.upper(),
            fixed_badge=FIXED_BADGE,
            source=source,
            message=message,
        )
    
    return FIXED_ISSUES_SECTION_TEMPLATE.format(rows=rows)


def _render_github(github: dict[str, Any]) -> str:
    """Render the GitHub issues section."""
    if not github:
        return GITHUB_NO_DATA_TEMPLATE

    # Check for errors
    if github.get("error"):
        return GITHUB_ERROR_TEMPLATE.format(error=github["error"])

    issues = github.get("issues", [])
    open_count = github.get("open_count", len(issues))
    repo_url = github.get("repo_url", "https://github.com")

    if not issues and open_count == 0:
        return GITHUB_NO_DATA_TEMPLATE

    # Render up to 10 issues
    issues_html = ""
    for issue in issues[:10]:
        title = issue.get("title", "Untitled")
        number = issue.get("number", 0)
        url = issue.get("url", "#")
        created_at = _format_relative_time(issue.get("created_at", ""))
        labels = issue.get("labels", [])

        # Render labels
        labels_html = ""
        for label in labels[:3]:  # Max 3 labels
            label_color = label.get("color", "e1e4e8")
            label_name = label.get("name", "")
            # Determine text color based on background brightness
            text_color = _get_contrast_color(label_color)
            labels_html += GITHUB_LABEL_TEMPLATE.format(
                color=label_color,
                text_color=text_color,
                name=label_name,
            )

        # Determine border color (use first label color or default)
        label_color = f"#{labels[0]['color']}" if labels else "#6c757d"

        issues_html += GITHUB_ISSUE_ROW_TEMPLATE.format(
            title=title[:80] + "..." if len(title) > 80 else title,
            number=number,
            url=url,
            created_at=created_at,
            labels_html=labels_html,
            label_color=label_color,
        )

    if open_count > 10:
        issues_html += f'<p style="color: #64748b; font-size: 12px; margin: 8px 0 0 0;">... and {open_count - 10} more issues</p>'

    return GITHUB_SECTION_TEMPLATE.format(
        open_count=open_count,
        repo_url=repo_url,
        issues_html=issues_html,
    )


def _render_sentry(sentry: dict[str, Any]) -> str:
    """Render the Sentry issues section."""
    if not sentry:
        return SENTRY_NO_DATA_TEMPLATE

    # Check for errors
    if sentry.get("error"):
        return SENTRY_ERROR_TEMPLATE.format(error=sentry["error"])

    total = sentry.get("total", 0)
    environment = sentry.get("environment", "production")
    projects = sentry.get("projects", {})

    if total == 0:
        return SENTRY_NO_DATA_TEMPLATE

    # Sentry level colors
    level_colors = {
        "fatal": {"color": "#dc3545", "bg": "#f8d7da"},
        "error": {"color": "#dc3545", "bg": "#f8d7da"},
        "warning": {"color": "#ffc107", "bg": "#fff3cd"},
        "info": {"color": "#17a2b8", "bg": "#d1ecf1"},
        "debug": {"color": "#6c757d", "bg": "#e9ecef"},
    }

    # Render each project
    projects_html = ""
    for project_slug, project_data in projects.items():
        project_name = project_data.get("name", project_slug)
        count = project_data.get("count", 0)
        issues = project_data.get("issues", [])

        # Render up to 5 issues per project
        issues_html = ""
        for issue in issues[:5]:
            title = issue.get("title", "Untitled")
            level = issue.get("level", "error")
            culprit = issue.get("culprit", "")
            event_count = issue.get("count", 1)
            last_seen = _format_relative_time(issue.get("last_seen", ""))
            url = issue.get("url", "#")

            level_style = level_colors.get(level, level_colors["error"])

            issues_html += SENTRY_ISSUE_ROW_TEMPLATE.format(
                title=title[:70] + "..." if len(title) > 70 else title,
                level=level,
                level_color=level_style["color"],
                level_bg=level_style["bg"],
                culprit=culprit[:40] + "..." if len(culprit) > 40 else culprit,
                count=event_count,
                last_seen=last_seen,
                url=url,
            )

        if count > 5:
            issues_html += f'<p style="color: #64748b; font-size: 11px; margin: 4px 0 0 0;">... and {count - 5} more</p>'

        projects_html += SENTRY_PROJECT_TEMPLATE.format(
            project_name=project_name,
            count=count,
            issues_html=issues_html,
        )

    return SENTRY_SECTION_TEMPLATE.format(
        total_count=total,
        environment=environment,
        projects_html=projects_html,
    )


def _format_relative_time(iso_timestamp: str) -> str:
    """Format ISO timestamp as relative time (e.g., '2 days ago')."""
    if not iso_timestamp:
        return "unknown"

    from datetime import datetime, timezone

    try:
        # Parse ISO timestamp
        if iso_timestamp.endswith("Z"):
            iso_timestamp = iso_timestamp[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_timestamp)
        now = datetime.now(timezone.utc)

        # Make dt timezone-aware if it isn't
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        delta = now - dt
        seconds = delta.total_seconds()

        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            mins = int(seconds / 60)
            return f"{mins}m ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours}h ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days}d ago"
        elif seconds < 2592000:
            weeks = int(seconds / 604800)
            return f"{weeks}w ago"
        else:
            return dt.strftime("%b %d")
    except Exception:
        return "unknown"


def _get_contrast_color(hex_color: str) -> str:
    """Get contrasting text color (black or white) for a background color."""
    try:
        hex_color = hex_color.lstrip("#")
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        # Calculate luminance
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
        return "#000" if luminance > 0.5 else "#fff"
    except Exception:
        return "#000"


def _render_codacy(codacy: dict[str, Any]) -> str:
    """Render the Codacy code quality section."""
    if not codacy:
        return CODACY_NO_DATA_TEMPLATE

    # Check for errors
    if codacy.get("error"):
        return CODACY_ERROR_TEMPLATE.format(error=codacy["error"])

    total = codacy.get("total", 0)
    if total == 0:
        return CODACY_NO_DATA_TEMPLATE

    by_level = codacy.get("by_level", {})
    by_category = codacy.get("by_category", {})
    issues = codacy.get("issues", [])
    organization = codacy.get("organization", "")
    repository = codacy.get("repository", "")

    # Level colors
    level_colors = {
        "Error": {"color": "#dc3545", "bg": "#f8d7da"},
        "High": {"color": "#fd7e14", "bg": "#ffe5d0"},
        "Warning": {"color": "#ffc107", "bg": "#fff3cd"},
        "Info": {"color": "#17a2b8", "bg": "#d1ecf1"},
    }

    # Render categories
    categories_html = ""
    for category, count in sorted(by_category.items(), key=lambda x: -x[1]):
        categories_html += CODACY_CATEGORY_ROW_TEMPLATE.format(
            category=category,
            count=count,
        )

    # Render sample issues (top 10)
    issues_html = ""
    if issues:
        issues_html = '<p style="margin: 15px 0 8px 0; color: #475569; font-size: 12px; font-weight: 600;">Recent Issues:</p>'
        for issue in issues[:10]:
            level = issue.get("level", "Warning")
            level_style = level_colors.get(level, level_colors["Warning"])
            
            file_path = issue.get("file_path", "")
            # Truncate long paths
            if len(file_path) > 40:
                file_path = "..." + file_path[-37:]
            
            issues_html += CODACY_ISSUE_ROW_TEMPLATE.format(
                title=issue.get("title", "Unknown issue")[:70],
                level=level,
                level_color=level_style["color"],
                level_bg=level_style["bg"],
                file_path=file_path,
                line=issue.get("line", "?"),
                tool=issue.get("tool", "unknown"),
            )

    return CODACY_SECTION_TEMPLATE.format(
        total_count=total,
        organization=organization,
        repository=repository,
        error_count=by_level.get("Error", 0),
        high_count=by_level.get("High", 0),
        warning_count=by_level.get("Warning", 0),
        info_count=by_level.get("Info", 0),
        categories_html=categories_html,
        issues_html=issues_html,
    )
