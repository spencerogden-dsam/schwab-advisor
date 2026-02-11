"""Tests for Schwab Advisor client."""

import pytest
from schwab_advisor import __version__
from schwab_advisor.client import SchwabAdvisorClient


def test_version():
    assert __version__ == "0.1.0"


def test_client_requires_auth_or_token():
    """Client must have either auth or access_token."""
    with pytest.raises(ValueError, match="Either auth or access_token"):
        SchwabAdvisorClient()


def test_client_with_access_token():
    """Client can be created with direct access token."""
    client = SchwabAdvisorClient(access_token="test_token")
    assert client._access_token == "test_token"
    assert client.base_url == "https://sandbox.schwabapi.com/as-integration/bulk/v2"


def test_client_with_production_environment():
    """Client uses production URL when specified."""
    client = SchwabAdvisorClient(access_token="test_token", environment="production")
    assert client.base_url == "https://api.schwabapi.com/as-integration/bulk/v2"


def test_client_with_custom_base_url():
    """Client accepts custom base URL."""
    client = SchwabAdvisorClient(
        access_token="test_token", base_url="https://custom.example.com"
    )
    assert client.base_url == "https://custom.example.com"


def test_client_headers():
    """Client generates correct headers."""
    client = SchwabAdvisorClient(access_token="test_token", resource_version=2)
    headers = client._get_headers()

    assert headers["Authorization"] == "Bearer test_token"
    assert "Schwab-Client-CorrelId" in headers
    assert headers["Schwab-Resource-Version"] == "2"
    assert headers["Accept"] == "application/json"


def test_client_correlation_id_unique():
    """Each request gets a unique correlation ID."""
    client = SchwabAdvisorClient(access_token="test_token")
    headers1 = client._get_headers()
    headers2 = client._get_headers()

    assert headers1["Schwab-Client-CorrelId"] != headers2["Schwab-Client-CorrelId"]
