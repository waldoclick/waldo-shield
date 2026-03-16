"""HTML templates for security report generation.

Designed for email client compatibility:
- Table-based layout (works in all email clients)
- All CSS is inline (no external stylesheets, no <style> blocks)
- Max-width 600px for mobile-friendly viewing
- Color coding: critical=red, high=orange, medium=yellow, low=blue, info=gray
"""

# Severity colors (inline CSS)
SEVERITY_COLORS = {
    "critical": "#dc3545",  # Red
    "high": "#fd7e14",      # Orange
    "medium": "#ffc107",    # Yellow
    "low": "#17a2b8",       # Blue
    "info": "#6c757d",      # Gray
    "none": "#28a745",      # Green
    "error": "#dc3545",     # Red (for error severity in email auth issues)
    "warning": "#ffc107",   # Yellow (for warning severity)
}

# Background colors for severity badges (lighter versions)
SEVERITY_BG_COLORS = {
    "critical": "#f8d7da",
    "high": "#ffe5d0",
    "medium": "#fff3cd",
    "low": "#d1ecf1",
    "info": "#e9ecef",
    "none": "#d4edda",
    "error": "#f8d7da",
    "warning": "#fff3cd",
}

# Risk level pill colors
RISK_LEVEL_STYLES = {
    "critical": "background-color: #dc3545; color: white;",
    "high": "background-color: #fd7e14; color: white;",
    "medium": "background-color: #ffc107; color: black;",
    "low": "background-color: #17a2b8; color: white;",
    "none": "background-color: #28a745; color: white;",
}

# Main report template
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {environment}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f5f5f5;">
        <tr>
            <td style="padding: 20px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="background-color: #1a1a2e; padding: 30px; border-radius: 8px 8px 0 0; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">Security Report</h1>
                            <p style="margin: 10px 0 0 0; color: #94a3b8; font-size: 14px;">Environment: {environment} | {scan_date}</p>
                        </td>
                    </tr>

                    <!-- Executive Summary -->
                    <tr>
                        <td style="padding: 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Executive Summary</h2>
                            
                            <!-- Risk Score Box -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 20px;">
                                <tr>
                                    <td style="background-color: #f8fafc; padding: 20px; border-radius: 8px; text-align: center;">
                                        <p style="margin: 0 0 5px 0; color: #64748b; font-size: 12px; text-transform: uppercase;">Risk Score</p>
                                        <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 48px; font-weight: 700;">{risk_score}</p>
                                        <span style="{risk_level_style} padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase;">{risk_level}</span>
                                    </td>
                                </tr>
                            </table>

                            <!-- Issue Counts -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 20px;">
                                <tr>
                                    <td style="text-align: center; padding: 10px;">
                                        <p style="margin: 0; color: #dc3545; font-size: 24px; font-weight: 700;">{critical_count}</p>
                                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 11px; text-transform: uppercase;">Critical</p>
                                    </td>
                                    <td style="text-align: center; padding: 10px;">
                                        <p style="margin: 0; color: #fd7e14; font-size: 24px; font-weight: 700;">{high_count}</p>
                                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 11px; text-transform: uppercase;">High</p>
                                    </td>
                                    <td style="text-align: center; padding: 10px;">
                                        <p style="margin: 0; color: #ffc107; font-size: 24px; font-weight: 700;">{medium_count}</p>
                                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 11px; text-transform: uppercase;">Medium</p>
                                    </td>
                                    <td style="text-align: center; padding: 10px;">
                                        <p style="margin: 0; color: #17a2b8; font-size: 24px; font-weight: 700;">{low_count}</p>
                                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 11px; text-transform: uppercase;">Low</p>
                                    </td>
                                    <td style="text-align: center; padding: 10px;">
                                        <p style="margin: 0; color: #6c757d; font-size: 24px; font-weight: 700;">{info_count}</p>
                                        <p style="margin: 5px 0 0 0; color: #64748b; font-size: 11px; text-transform: uppercase;">Info</p>
                                    </td>
                                </tr>
                            </table>

                            <!-- Targets -->
                            <h3 style="margin: 20px 0 10px 0; color: #475569; font-size: 14px;">Targets Scanned</h3>
                            {targets_html}
                        </td>
                    </tr>

                    <!-- HTTP Scanner Findings -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">HTTP Scanner Findings</h2>
                            {http_findings_html}
                        </td>
                    </tr>

                    <!-- Email Security -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Email Security</h2>
                            {email_auth_html}
                        </td>
                    </tr>

                    <!-- Cloudflare Security -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Cloudflare Security</h2>
                            {cloudflare_html}
                        </td>
                    </tr>

                    <!-- GitHub Issues -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">GitHub Issues</h2>
                            {github_html}
                        </td>
                    </tr>

                    <!-- Sentry Errors -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">Sentry Errors</h2>
                            {sentry_html}
                        </td>
                    </tr>

                    <!-- All Issues Table -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a2e; font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px;">All Issues ({total_issues})</h2>
                            {issues_table_html}
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8fafc; padding: 20px 30px; border-radius: 0 0 8px 8px; text-align: center;">
                            <p style="margin: 0; color: #64748b; font-size: 12px;">Generated by waldo-shield | {scan_date}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

# Section templates
TARGET_LIST_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
{rows}
</table>"""

TARGET_ROW_TEMPLATE = """<tr>
    <td style="padding: 5px 0;">
        <span style="color: #3b82f6; font-size: 14px;">{target}</span>
    </td>
</tr>"""

# HTTP findings section
HTTP_FINDINGS_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 15px;">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">{target}</p>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                    <td style="padding: 2px 0;">
                        <span style="color: #64748b; font-size: 12px;">Risk Score:</span>
                        <span style="color: #1a1a2e; font-size: 12px; font-weight: 600; margin-left: 5px;">{score}</span>
                        <span style="{risk_style} padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; margin-left: 8px;">{risk_level}</span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 2px 0;">
                        <span style="color: #64748b; font-size: 12px;">Issues:</span>
                        <span style="color: #dc3545; font-size: 12px; margin-left: 5px;">{critical}C</span>
                        <span style="color: #fd7e14; font-size: 12px; margin-left: 5px;">{high}H</span>
                        <span style="color: #ffc107; font-size: 12px; margin-left: 5px;">{medium}M</span>
                        <span style="color: #17a2b8; font-size: 12px; margin-left: 5px;">{low}L</span>
                        <span style="color: #6c757d; font-size: 12px; margin-left: 5px;">{info}I</span>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>"""

HTTP_NO_DATA_TEMPLATE = """<p style="color: #64748b; font-size: 14px; margin: 0;">No HTTP scan results available.</p>"""

# Email auth section
EMAIL_AUTH_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 15px;">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">{domain}</p>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                    <td style="padding: 4px 0; width: 80px; vertical-align: top;">
                        <span style="color: #64748b; font-size: 12px;">SPF:</span>
                    </td>
                    <td style="padding: 4px 0;">
                        <span style="{spf_style} padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600;">{spf_status}</span>
                        {spf_details}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 0; width: 80px; vertical-align: top;">
                        <span style="color: #64748b; font-size: 12px;">DKIM:</span>
                    </td>
                    <td style="padding: 4px 0;">
                        <span style="{dkim_style} padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600;">{dkim_status}</span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 0; width: 80px; vertical-align: top;">
                        <span style="color: #64748b; font-size: 12px;">DMARC:</span>
                    </td>
                    <td style="padding: 4px 0;">
                        <span style="{dmarc_style} padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600;">{dmarc_status}</span>
                        {dmarc_details}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 0; width: 80px; vertical-align: top;">
                        <span style="color: #64748b; font-size: 12px;">CAA:</span>
                    </td>
                    <td style="padding: 4px 0;">
                        <span style="{caa_style} padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600;">{caa_status}</span>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>"""

EMAIL_NO_DATA_TEMPLATE = """<p style="color: #64748b; font-size: 14px; margin: 0;">No email authentication data available.</p>"""

# Cloudflare section
CLOUDFLARE_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <!-- WAF Events -->
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">WAF Events (Last 24h)</p>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 15px;">
                <tr>
                    <td style="padding: 2px 0;">
                        <span style="color: #64748b; font-size: 12px;">Total Events:</span>
                        <span style="color: #1a1a2e; font-size: 12px; font-weight: 600; margin-left: 5px;">{waf_total}</span>
                    </td>
                </tr>
                {waf_actions_html}
            </table>

            <!-- Traffic Analytics -->
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">Traffic Analytics</p>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 15px;">
                <tr>
                    <td style="padding: 2px 0;">
                        <span style="color: #64748b; font-size: 12px;">Total Requests:</span>
                        <span style="color: #1a1a2e; font-size: 12px; font-weight: 600; margin-left: 5px;">{total_requests}</span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 2px 0;">
                        <span style="color: #64748b; font-size: 12px;">Blocked:</span>
                        <span style="color: #dc3545; font-size: 12px; font-weight: 600; margin-left: 5px;">{blocked_percentage}%</span>
                    </td>
                </tr>
            </table>

            <!-- Rate Limiting -->
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">Rate Limiting Rules</p>
            {rate_limit_html}
        </td>
    </tr>
</table>"""

CLOUDFLARE_NO_DATA_TEMPLATE = """<p style="color: #64748b; font-size: 14px; margin: 0;">No Cloudflare data available.</p>"""

CLOUDFLARE_ERROR_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8d7da; padding: 15px; border-radius: 8px;">
            <p style="margin: 0; color: #721c24; font-size: 14px;">Error retrieving Cloudflare data: {error}</p>
        </td>
    </tr>
</table>"""

WAF_ACTION_ROW_TEMPLATE = """<tr>
    <td style="padding: 2px 0;">
        <span style="color: #64748b; font-size: 12px;">{action}:</span>
        <span style="color: #1a1a2e; font-size: 12px; font-weight: 600; margin-left: 5px;">{count}</span>
    </td>
</tr>"""

RATE_LIMIT_ROW_TEMPLATE = """<tr>
    <td style="padding: 4px 0;">
        <span style="background-color: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #475569;">{action}</span>
        <span style="color: #64748b; font-size: 11px; margin-left: 5px;">{description}</span>
    </td>
</tr>"""

RATE_LIMIT_NONE_TEMPLATE = """<p style="color: #64748b; font-size: 12px; margin: 0;">No rate limiting rules configured.</p>"""

# Issues table
ISSUES_TABLE_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="font-size: 12px;">
    <tr style="background-color: #f1f5f9;">
        <td style="padding: 8px; font-weight: 600; color: #475569; width: 70px;">Severity</td>
        <td style="padding: 8px; font-weight: 600; color: #475569; width: 80px;">Source</td>
        <td style="padding: 8px; font-weight: 600; color: #475569;">Issue</td>
    </tr>
    {rows}
</table>"""

ISSUE_ROW_TEMPLATE = """<tr style="border-bottom: 1px solid #e5e7eb;">
    <td style="padding: 8px; vertical-align: top;">
        <span style="background-color: {bg_color}; color: {text_color}; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase;">{severity}</span>
    </td>
    <td style="padding: 8px; color: #64748b; vertical-align: top;">{source}</td>
    <td style="padding: 8px; color: #1a1a2e; vertical-align: top;">{message}</td>
</tr>"""

ISSUES_NO_DATA_TEMPLATE = """<p style="color: #28a745; font-size: 14px; margin: 0; text-align: center; padding: 20px;">No issues found - great job!</p>"""

# Comparison/trend templates
NEW_BADGE = """<span style="background-color: #dc3545; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; margin-left: 8px;">NEW</span>"""

FIXED_BADGE = """<span style="background-color: #28a745; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; margin-left: 8px;">FIXED</span>"""

TREND_IMPROVED = """<span style="color: #28a745; font-size: 14px;">↓ Improved ({delta})</span>"""
TREND_DEGRADED = """<span style="color: #dc3545; font-size: 14px;">↑ Degraded (+{delta})</span>"""
TREND_STABLE = """<span style="color: #6c757d; font-size: 14px;">→ Stable</span>"""

COMPARISON_SUMMARY_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 20px;">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <p style="margin: 0 0 10px 0; color: #1a1a2e; font-size: 14px; font-weight: 600;">Comparison with Previous Scan</p>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                    <td style="padding: 4px 0;">
                        <span style="color: #64748b; font-size: 12px;">Trend:</span>
                        <span style="margin-left: 8px;">{trend_indicator}</span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 0;">
                        <span style="color: #64748b; font-size: 12px;">New Issues:</span>
                        <span style="color: #dc3545; font-size: 12px; font-weight: 600; margin-left: 5px;">{new_count}</span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 4px 0;">
                        <span style="color: #64748b; font-size: 12px;">Fixed Issues:</span>
                        <span style="color: #28a745; font-size: 12px; font-weight: 600; margin-left: 5px;">{fixed_count}</span>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>"""

FIXED_ISSUES_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 20px;">
    <tr>
        <td style="padding: 0;">
            <h3 style="margin: 20px 0 10px 0; color: #28a745; font-size: 14px;">Recently Fixed Issues</h3>
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="font-size: 12px;">
                {rows}
            </table>
        </td>
    </tr>
</table>"""

FIXED_ISSUE_ROW_TEMPLATE = """<tr style="border-bottom: 1px solid #e5e7eb;">
    <td style="padding: 8px; vertical-align: top;">
        <span style="background-color: #d4edda; color: #28a745; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; text-transform: uppercase;">{severity}</span>
        {fixed_badge}
    </td>
    <td style="padding: 8px; color: #64748b; vertical-align: top;">{source}</td>
    <td style="padding: 8px; color: #1a1a2e; vertical-align: top; text-decoration: line-through;">{message}</td>
</tr>"""

# GitHub Issues section
GITHUB_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 10px;">
                <tr>
                    <td>
                        <span style="color: #1a1a2e; font-size: 14px; font-weight: 600;">Open Issues:</span>
                        <span style="color: #fd7e14; font-size: 14px; font-weight: 700; margin-left: 5px;">{open_count}</span>
                    </td>
                    <td style="text-align: right;">
                        <a href="{repo_url}/issues" style="color: #3b82f6; font-size: 12px; text-decoration: none;">View all &rarr;</a>
                    </td>
                </tr>
            </table>
            {issues_html}
        </td>
    </tr>
</table>"""

GITHUB_ISSUE_ROW_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 8px;">
    <tr>
        <td style="padding: 8px; background-color: #fff; border-radius: 4px; border-left: 3px solid {label_color};">
            <a href="{url}" style="color: #1a1a2e; font-size: 13px; text-decoration: none; font-weight: 500;">{title}</a>
            <p style="margin: 4px 0 0 0; color: #64748b; font-size: 11px;">
                #{number} opened {created_at} {labels_html}
            </p>
        </td>
    </tr>
</table>"""

GITHUB_LABEL_TEMPLATE = """<span style="background-color: #{color}; color: {text_color}; padding: 1px 6px; border-radius: 10px; font-size: 10px; margin-left: 4px;">{name}</span>"""

GITHUB_NO_DATA_TEMPLATE = """<p style="color: #28a745; font-size: 14px; margin: 0;">No open issues - great job!</p>"""

GITHUB_ERROR_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8d7da; padding: 15px; border-radius: 8px;">
            <p style="margin: 0; color: #721c24; font-size: 14px;">Error fetching GitHub issues: {error}</p>
        </td>
    </tr>
</table>"""

# Sentry Issues section
SENTRY_SECTION_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8fafc; padding: 15px; border-radius: 8px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 10px;">
                <tr>
                    <td>
                        <span style="color: #1a1a2e; font-size: 14px; font-weight: 600;">Unresolved Issues:</span>
                        <span style="color: #dc3545; font-size: 14px; font-weight: 700; margin-left: 5px;">{total_count}</span>
                        <span style="color: #64748b; font-size: 12px; margin-left: 5px;">({environment})</span>
                    </td>
                </tr>
            </table>
            {projects_html}
        </td>
    </tr>
</table>"""

SENTRY_PROJECT_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 12px;">
    <tr>
        <td style="padding-bottom: 6px;">
            <span style="color: #475569; font-size: 13px; font-weight: 600;">{project_name}</span>
            <span style="color: #64748b; font-size: 12px; margin-left: 5px;">({count} issues)</span>
        </td>
    </tr>
    <tr>
        <td>
            {issues_html}
        </td>
    </tr>
</table>"""

SENTRY_ISSUE_ROW_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-bottom: 6px;">
    <tr>
        <td style="padding: 8px; background-color: #fff; border-radius: 4px; border-left: 3px solid {level_color};">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                    <td>
                        <a href="{url}" style="color: #1a1a2e; font-size: 12px; text-decoration: none;">{title}</a>
                    </td>
                    <td style="text-align: right; width: 60px;">
                        <span style="background-color: {level_bg}; color: {level_color}; padding: 2px 6px; border-radius: 10px; font-size: 10px; text-transform: uppercase;">{level}</span>
                    </td>
                </tr>
                <tr>
                    <td colspan="2">
                        <p style="margin: 4px 0 0 0; color: #64748b; font-size: 11px;">{culprit} &middot; {count}x &middot; Last seen {last_seen}</p>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>"""

SENTRY_NO_DATA_TEMPLATE = """<p style="color: #28a745; font-size: 14px; margin: 0;">No unresolved issues - great job!</p>"""

SENTRY_ERROR_TEMPLATE = """<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
    <tr>
        <td style="background-color: #f8d7da; padding: 15px; border-radius: 8px;">
            <p style="margin: 0; color: #721c24; font-size: 14px;">Error fetching Sentry issues: {error}</p>
        </td>
    </tr>
</table>"""
