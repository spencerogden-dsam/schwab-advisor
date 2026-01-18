"""Tests for Schwab Advisor client."""

from schwab_advisor import __version__
from schwab_advisor.client import SchwabAdvisorClient


def test_version():
    assert __version__ == "0.1.0"


def test_client_init():
    client = SchwabAdvisorClient()
    assert client.base_url is None


def test_client_with_base_url():
    client = SchwabAdvisorClient(base_url="https://example.com")
    assert client.base_url == "https://example.com"
