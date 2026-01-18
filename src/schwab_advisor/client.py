"""Schwab Advisor API client."""

import httpx


class SchwabAdvisorClient:
    """Client for interacting with Schwab Advisor Services API."""

    def __init__(self, base_url: str | None = None):
        """Initialize the client.

        Args:
            base_url: Base URL for the API. Defaults to None (to be configured).
        """
        self.base_url = base_url
        self._client: httpx.Client | None = None

    def __enter__(self):
        self._client = httpx.Client(base_url=self.base_url)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            self._client.close()
