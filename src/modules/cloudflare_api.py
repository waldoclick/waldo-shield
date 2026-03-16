"""Cloudflare API client for security events, traffic analytics, and rate limiting rules.

Uses the official Cloudflare Python SDK and GraphQL API for data retrieval.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from cloudflare import Cloudflare


class CloudflareClient:
    """Wrapper for Cloudflare API operations."""

    def __init__(self, token: str):
        """Initialize Cloudflare client with API token.

        Args:
            token: Cloudflare API token with required permissions
                   (Zone:Read, Analytics:Read, Firewall Services:Read)
        """
        self._client = Cloudflare(api_token=token, max_retries=2)

    def get_security_events(self, zone_id: str, hours: int = 24) -> dict[str, Any]:
        """Retrieve WAF/firewall events for the last N hours.

        Args:
            zone_id: Cloudflare zone ID
            hours: Number of hours to look back (default 24)

        Returns:
            Dict with keys: zone_id, period_hours, total_events, events, by_action, by_source
            On error: Dict with 'error' key containing error message
        """
        try:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

            query = """
            query SecurityEvents($zoneTag: String!, $since: String!) {
                viewer {
                    zones(filter: {zoneTag: $zoneTag}) {
                        firewallEventsAdaptive(
                            limit: 1000
                            filter: {datetime_gt: $since}
                            orderBy: [datetime_DESC]
                        ) {
                            action
                            clientIP
                            datetime
                            source
                            ruleId
                        }
                    }
                }
            }
            """

            response = self._client.graphql.post(
                body={"query": query, "variables": {"zoneTag": zone_id, "since": since}}
            )

            zones = response.data.get("viewer", {}).get("zones", [])
            if not zones:
                return self._empty_security_events(zone_id, hours)

            events = zones[0].get("firewallEventsAdaptive", [])

            # Aggregate by action
            by_action: dict[str, int] = {}
            by_source: dict[str, int] = {}
            for event in events:
                action = event.get("action", "unknown")
                source = event.get("source", "unknown")
                by_action[action] = by_action.get(action, 0) + 1
                by_source[source] = by_source.get(source, 0) + 1

            return {
                "zone_id": zone_id,
                "period_hours": hours,
                "total_events": len(events),
                "events": events,
                "by_action": by_action,
                "by_source": by_source,
            }

        except Exception as e:
            return {"error": str(e), "zone_id": zone_id, "period_hours": hours}

    def get_traffic_analytics(self, zone_id: str, hours: int = 24) -> dict[str, Any]:
        """Retrieve traffic analytics (requests, cached, blocked).

        Args:
            zone_id: Cloudflare zone ID
            hours: Number of hours to look back (default 24)

        Returns:
            Dict with keys: zone_id, period_hours, total_requests, cached_requests,
                          blocked_requests, blocked_percentage
            On error: Dict with 'error' key containing error message
        """
        try:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

            query = """
            query TrafficAnalytics($zoneTag: String!, $since: String!) {
                viewer {
                    zones(filter: {zoneTag: $zoneTag}) {
                        httpRequestsAdaptiveGroups(
                            limit: 1
                            filter: {datetime_gt: $since}
                        ) {
                            sum {
                                requests
                                cachedRequests
                            }
                        }
                        firewallEventsAdaptiveGroups(
                            limit: 1
                            filter: {datetime_gt: $since}
                        ) {
                            count
                        }
                    }
                }
            }
            """

            response = self._client.graphql.post(
                body={"query": query, "variables": {"zoneTag": zone_id, "since": since}}
            )

            zones = response.data.get("viewer", {}).get("zones", [])
            if not zones:
                return self._empty_traffic_analytics(zone_id, hours)

            zone_data = zones[0]

            # Get request stats
            http_groups = zone_data.get("httpRequestsAdaptiveGroups", [])
            if http_groups:
                sums = http_groups[0].get("sum", {})
                total_requests = sums.get("requests", 0)
                cached_requests = sums.get("cachedRequests", 0)
            else:
                total_requests = 0
                cached_requests = 0

            # Get blocked stats
            firewall_groups = zone_data.get("firewallEventsAdaptiveGroups", [])
            if firewall_groups:
                blocked_requests = firewall_groups[0].get("count", 0)
            else:
                blocked_requests = 0

            # Calculate blocked percentage
            blocked_percentage = (
                (blocked_requests / total_requests * 100) if total_requests > 0 else 0.0
            )

            return {
                "zone_id": zone_id,
                "period_hours": hours,
                "total_requests": total_requests,
                "cached_requests": cached_requests,
                "blocked_requests": blocked_requests,
                "blocked_percentage": round(blocked_percentage, 2),
            }

        except Exception as e:
            return {"error": str(e), "zone_id": zone_id, "period_hours": hours}

    def get_rate_limit_rules(self, zone_id: str) -> list[dict[str, Any]]:
        """Retrieve configured rate limiting rules.

        Args:
            zone_id: Cloudflare zone ID

        Returns:
            List of rule dicts with keys: id, expression, action, period, requests_per_period
            On error: Returns empty list (rate limiting is optional feature)
        """
        try:
            rulesets = self._client.rulesets.list(zone_id=zone_id)

            rules = []
            for ruleset in rulesets:
                # Only process http_ratelimit phase rulesets
                if getattr(ruleset, "phase", None) != "http_ratelimit":
                    continue

                for rule in getattr(ruleset, "rules", []) or []:
                    ratelimit = getattr(rule, "ratelimit", None)
                    rule_data = {
                        "id": getattr(rule, "id", ""),
                        "expression": getattr(rule, "expression", ""),
                        "action": getattr(rule, "action", ""),
                    }
                    if ratelimit:
                        rule_data["period"] = getattr(ratelimit, "period", None)
                        rule_data["requests_per_period"] = getattr(
                            ratelimit, "requests_per_period", None
                        )
                    rules.append(rule_data)

            return rules

        except Exception:
            # Rate limiting rules are optional - return empty list on error
            return []

    def _empty_security_events(self, zone_id: str, hours: int) -> dict[str, Any]:
        """Return empty security events structure."""
        return {
            "zone_id": zone_id,
            "period_hours": hours,
            "total_events": 0,
            "events": [],
            "by_action": {},
            "by_source": {},
        }

    def _empty_traffic_analytics(self, zone_id: str, hours: int) -> dict[str, Any]:
        """Return empty traffic analytics structure."""
        return {
            "zone_id": zone_id,
            "period_hours": hours,
            "total_requests": 0,
            "cached_requests": 0,
            "blocked_requests": 0,
            "blocked_percentage": 0.0,
        }


def collect_cloudflare_data(token: str, zone_id: str) -> dict[str, Any]:
    """Collect all Cloudflare data for a zone. Single entry point for Phase 3.

    Args:
        token: Cloudflare API token
        zone_id: Cloudflare zone ID

    Returns:
        Dict with keys: security_events, traffic_analytics, rate_limit_rules
    """
    client = CloudflareClient(token)
    return {
        "security_events": client.get_security_events(zone_id),
        "traffic_analytics": client.get_traffic_analytics(zone_id),
        "rate_limit_rules": client.get_rate_limit_rules(zone_id),
    }
