"""Shared test fixtures and configuration."""

import pytest

from schwab_advisor import SchwabAdvisorClient


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "sandbox: tests that hit the live Schwab sandbox API"
    )


@pytest.fixture
def sandbox_client():
    """Create a client authenticated against the Schwab sandbox."""
    return SchwabAdvisorClient()
