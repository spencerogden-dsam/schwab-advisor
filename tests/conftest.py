"""Shared test fixtures and configuration."""

import os

import httpx
import pytest

from schwab_advisor import SchwabAdvisorClient


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "sandbox: tests that hit the live Schwab sandbox API"
    )
    config.addinivalue_line(
        "markers",
        "production: tests that hit the live Schwab production API "
        "(gated by SCHWAB_ALLOW_PROD_TESTS=1)",
    )


@pytest.fixture
def sandbox_client():
    """Create a client authenticated against the Schwab sandbox."""
    return SchwabAdvisorClient()


@pytest.fixture
def prod_client():
    """Create a client authenticated against the Schwab production API.

    Pulls a fresh access token from the schwab-oauth.fly.dev broker so this
    test process never holds or refreshes the refresh_token. Skips entirely
    unless SCHWAB_ALLOW_PROD_TESTS=1 is set, to avoid accidental prod hits.

    Required env:
        SCHWAB_ALLOW_PROD_TESTS=1
        SCHWAB_OAUTH_BROKER_URL  (default https://schwab-oauth.fly.dev)
        SCHWAB_OAUTH_BROKER_KEY  (the broker's API_KEY secret)
    """
    if os.environ.get("SCHWAB_ALLOW_PROD_TESTS") != "1":
        pytest.skip("SCHWAB_ALLOW_PROD_TESTS=1 not set; skipping prod test")

    broker_url = os.environ.get(
        "SCHWAB_OAUTH_BROKER_URL", "https://schwab-oauth.fly.dev"
    )
    broker_key = os.environ.get("SCHWAB_OAUTH_BROKER_KEY")
    if not broker_key:
        pytest.skip("SCHWAB_OAUTH_BROKER_KEY not set; cannot fetch prod token")

    resp = httpx.get(
        f"{broker_url}/oauth/access_token",
        params={"key": broker_key},
        timeout=10.0,
    )
    if resp.status_code != 200:
        pytest.skip(
            f"Broker returned {resp.status_code}: {resp.text[:200]}; "
            "ensure prod OAuth has been completed"
        )
    access_token = resp.json()["access_token"]

    return SchwabAdvisorClient(access_token=access_token, environment="production")
