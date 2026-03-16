"""Tests for Cloudflare API module."""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


class TestCloudflareClientInit:
    """Test CloudflareClient initialization."""

    def test_client_initializes_with_token(self):
        """CloudflareClient(token) initializes client with token."""
        from modules.cloudflare_api import CloudflareClient

        with patch("modules.cloudflare_api.Cloudflare") as mock_cf:
            client = CloudflareClient("test_token_123")

            mock_cf.assert_called_once_with(api_token="test_token_123", max_retries=2)


class TestGetSecurityEvents:
    """Test get_security_events method."""

    def test_returns_structured_dict(self, mock_cloudflare_graphql):
        """get_security_events returns dict with events, total_events, by_action."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_security_events("zone_123", hours=24)

        assert "zone_id" in result
        assert "period_hours" in result
        assert "total_events" in result
        assert "events" in result
        assert "by_action" in result
        assert result["zone_id"] == "zone_123"
        assert result["period_hours"] == 24

    def test_empty_events_handled_gracefully(self, mock_cloudflare_graphql_empty):
        """Empty events list is handled gracefully."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_security_events("zone_123")

        assert result["total_events"] == 0
        assert result["events"] == []
        assert result["by_action"] == {}

    def test_api_error_returns_error_dict(self, mock_cloudflare_graphql_error):
        """API errors are caught and return error dict (not raise)."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_security_events("zone_123")

        assert "error" in result
        assert isinstance(result["error"], str)


class TestGetTrafficAnalytics:
    """Test get_traffic_analytics method."""

    def test_returns_traffic_stats(self, mock_cloudflare_graphql):
        """get_traffic_analytics returns dict with total_requests, blocked_requests, blocked_percentage."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_traffic_analytics("zone_123", hours=24)

        assert "zone_id" in result
        assert "period_hours" in result
        assert "total_requests" in result
        assert "blocked_requests" in result
        assert "blocked_percentage" in result
        assert result["zone_id"] == "zone_123"


class TestGetRateLimitRules:
    """Test get_rate_limit_rules method."""

    def test_returns_list_of_rules(self, mock_cloudflare_rulesets):
        """get_rate_limit_rules returns list of rule dicts."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_rate_limit_rules("zone_123")

        assert isinstance(result, list)
        if len(result) > 0:
            rule = result[0]
            assert "id" in rule
            assert "expression" in rule
            assert "action" in rule

    def test_empty_rules_returns_empty_list(self, mock_cloudflare_rulesets_empty):
        """Empty rules returns empty list."""
        from modules.cloudflare_api import CloudflareClient

        client = CloudflareClient("test_token")
        result = client.get_rate_limit_rules("zone_123")

        assert result == []


class TestCollectCloudflareData:
    """Test collect_cloudflare_data helper function."""

    def test_collects_all_data(self, mock_cloudflare_full):
        """collect_cloudflare_data returns all three data types."""
        from modules.cloudflare_api import collect_cloudflare_data

        result = collect_cloudflare_data("test_token", "zone_123")

        assert "security_events" in result
        assert "traffic_analytics" in result
        assert "rate_limit_rules" in result


# Fixtures for mocking Cloudflare SDK

@pytest.fixture
def mock_cloudflare_graphql():
    """Mock Cloudflare client with GraphQL responses for security events and analytics."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        # Mock GraphQL response for security events
        mock_graphql_response = MagicMock()
        mock_graphql_response.data = {
            "viewer": {
                "zones": [{
                    "firewallEventsAdaptive": [
                        {
                            "action": "block",
                            "clientIP": "1.2.3.4",
                            "datetime": "2026-03-16T12:00:00Z",
                            "source": "waf",
                            "ruleId": "rule_1"
                        },
                        {
                            "action": "challenge",
                            "clientIP": "5.6.7.8",
                            "datetime": "2026-03-16T13:00:00Z",
                            "source": "firewall_rules",
                            "ruleId": "rule_2"
                        }
                    ],
                    "httpRequestsAdaptiveGroups": [
                        {
                            "sum": {"requests": 10000, "cachedRequests": 7000}
                        }
                    ],
                    "firewallEventsAdaptiveGroups": [
                        {
                            "count": 150
                        }
                    ]
                }]
            }
        }
        mock_client.graphql.post.return_value = mock_graphql_response

        yield mock_client


@pytest.fixture
def mock_cloudflare_graphql_empty():
    """Mock Cloudflare client with empty GraphQL responses."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        mock_graphql_response = MagicMock()
        mock_graphql_response.data = {
            "viewer": {
                "zones": [{
                    "firewallEventsAdaptive": [],
                    "httpRequestsAdaptiveGroups": [
                        {"sum": {"requests": 0, "cachedRequests": 0}}
                    ],
                    "firewallEventsAdaptiveGroups": [
                        {"count": 0}
                    ]
                }]
            }
        }
        mock_client.graphql.post.return_value = mock_graphql_response

        yield mock_client


@pytest.fixture
def mock_cloudflare_graphql_error():
    """Mock Cloudflare client that raises an exception."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        mock_client.graphql.post.side_effect = Exception("API Error: Invalid token")

        yield mock_client


@pytest.fixture
def mock_cloudflare_rulesets():
    """Mock Cloudflare client with rulesets response."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        # Mock rulesets.list response
        mock_ruleset = MagicMock()
        mock_ruleset.id = "ruleset_1"
        mock_ruleset.phase = "http_ratelimit"
        mock_ruleset.rules = [
            MagicMock(
                id="rule_1",
                expression='(http.request.uri.path contains "/api/")',
                action="block",
                ratelimit=MagicMock(
                    period=60,
                    requests_per_period=100
                )
            )
        ]

        mock_client.rulesets.list.return_value = [mock_ruleset]

        yield mock_client


@pytest.fixture
def mock_cloudflare_rulesets_empty():
    """Mock Cloudflare client with no rulesets."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        mock_client.rulesets.list.return_value = []

        yield mock_client


@pytest.fixture
def mock_cloudflare_full():
    """Mock Cloudflare client for full data collection."""
    with patch("modules.cloudflare_api.Cloudflare") as mock_cf_class:
        mock_client = MagicMock()
        mock_cf_class.return_value = mock_client

        # Mock GraphQL response
        mock_graphql_response = MagicMock()
        mock_graphql_response.data = {
            "viewer": {
                "zones": [{
                    "firewallEventsAdaptive": [
                        {"action": "block", "clientIP": "1.2.3.4", "datetime": "2026-03-16T12:00:00Z", "source": "waf", "ruleId": "rule_1"}
                    ],
                    "httpRequestsAdaptiveGroups": [
                        {"sum": {"requests": 5000, "cachedRequests": 3000}}
                    ],
                    "firewallEventsAdaptiveGroups": [
                        {"count": 50}
                    ]
                }]
            }
        }
        mock_client.graphql.post.return_value = mock_graphql_response

        # Mock rulesets
        mock_client.rulesets.list.return_value = []

        yield mock_client
