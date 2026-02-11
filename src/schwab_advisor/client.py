"""Schwab Advisor API client."""

import os
import uuid
from typing import Literal

import httpx

from .auth import SchwabAuth
from .models import AccountProfilesResponse

BASE_URLS = {
    "sandbox": "https://sandbox.schwabapi.com/as-integration/bulk/v2",
    "production": "https://api.schwabapi.com/as-integration/bulk/v2",
}


class SchwabAdvisorClient:
    """Client for interacting with Schwab Advisor Services API."""

    def __init__(
        self,
        auth: SchwabAuth | None = None,
        access_token: str | None = None,
        environment: Literal["sandbox", "production"] = "sandbox",
        base_url: str | None = None,
        resource_version: int = 1,
    ):
        """Initialize the client.

        Args:
            auth: SchwabAuth instance for token management.
            access_token: Direct access token (alternative to auth).
            environment: API environment, "sandbox" or "production".
            base_url: Override base URL (optional).
            resource_version: Schwab-Resource-Version header value.
        """
        if auth is None and access_token is None:
            raise ValueError("Either auth or access_token must be provided")

        self.auth = auth
        self._access_token = access_token
        self.base_url = base_url or BASE_URLS[environment]
        self.resource_version = resource_version
        self._client: httpx.Client | None = None

    @classmethod
    def from_env(cls) -> "SchwabAdvisorClient":
        """Create client from environment variables.

        Environment variables:
            SCHWAB_CLIENT_ID: OAuth client ID
            SCHWAB_CLIENT_SECRET: OAuth client secret
            SCHWAB_REDIRECT_URI: Redirect URI (default: https://127.0.0.1)
            SCHWAB_TOKEN_FILE: Token file path (default: ~/.schwab_tokens.json)
            SCHWAB_ENVIRONMENT: "sandbox" or "production" (default: sandbox)
        """
        auth = SchwabAuth.from_env()
        environment = os.environ.get("SCHWAB_ENVIRONMENT", "sandbox")
        if environment not in ("sandbox", "production"):
            raise ValueError(
                "SCHWAB_ENVIRONMENT must be 'sandbox' or 'production', "
                f"got {environment}"
            )
        return cls(auth=auth, environment=environment)

    def _get_access_token(self) -> str:
        """Get access token from auth or direct token."""
        if self.auth:
            return self.auth.get_access_token()
        return self._access_token

    def _get_headers(self) -> dict[str, str]:
        """Generate headers for API request."""
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Schwab-Client-CorrelId": str(uuid.uuid4()),
            "Schwab-Resource-Version": str(self.resource_version),
            "Accept": "application/json",
        }

    def __enter__(self):
        self._client = httpx.Client(base_url=self.base_url)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> httpx.Response:
        """Make an authenticated request to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (e.g., "/account-profiles")
            params: Query parameters
            json_data: JSON body data

        Returns:
            httpx.Response object
        """
        headers = self._get_headers()

        if self._client:
            response = self._client.request(
                method, path, params=params, json=json_data, headers=headers
            )
        else:
            url = f"{self.base_url}{path}"
            response = httpx.request(
                method, url, params=params, json=json_data, headers=headers
            )

        response.raise_for_status()
        return response

    def get_account_profiles(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
        include_total_count: bool = False,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountProfilesResponse:
        """Retrieve account profile information.

        Args:
            page_cursor: Cursor for pagination (from previous response).
            page_limit: Maximum number of records to return (default 1000).
            include_total_count: Include total record count in response.
            show_account: "Mask" to mask account numbers, "Show" to display full.

        Returns:
            AccountProfilesResponse with account profiles.
        """
        params = {
            "page[limit]": page_limit,
            "showAccount": show_account,
        }
        if page_cursor:
            params["page[cursor]"] = page_cursor
        if include_total_count:
            params["includeTotalCount"] = "true"

        response = self._request("GET", "/account-profiles", params=params)
        return AccountProfilesResponse.from_dict(response.json())
