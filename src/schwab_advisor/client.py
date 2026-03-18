"""Schwab Advisor API client."""

import os
import uuid
from typing import Literal

import httpx

from .auth import SchwabAuth
from .models import (
    AccountHoldersResponse,
    AccountProfile,
    AccountProfilesResponse,
    AlertsResponse,
    PreferencesAndAuthorizationsResponse,
    StandingInstructionsResponse,
    TransactionsResponse,
)

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
        if auth is None and access_token is None:
            raise ValueError("Either auth or access_token must be provided")

        self.auth = auth
        self._access_token = access_token
        self.base_url = base_url or BASE_URLS[environment]
        self.resource_version = resource_version
        self._client: httpx.Client | None = None

    @classmethod
    def from_env(cls) -> "SchwabAdvisorClient":
        auth = SchwabAuth.from_env()
        environment = os.environ.get("SCHWAB_ENVIRONMENT", "sandbox")
        if environment not in ("sandbox", "production"):
            raise ValueError(
                "SCHWAB_ENVIRONMENT must be 'sandbox' or 'production', "
                f"got {environment}"
            )
        return cls(auth=auth, environment=environment)

    def _get_access_token(self) -> str:
        if self.auth:
            return self.auth.get_access_token()
        return self._access_token

    def _get_headers(self) -> dict[str, str]:
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

    def _paginated_params(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> dict:
        params: dict = {"page[limit]": page_limit}
        if page_cursor:
            params["page[cursor]"] = page_cursor
        return params

    # --- AS Account ---

    def get_account_profiles(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
        include_total_count: bool = False,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountProfilesResponse:
        """Retrieve account profiles for all authorized accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if include_total_count:
            params["includeTotalCount"] = "true"
        response = self._request("GET", "/account-profiles", params=params)
        return AccountProfilesResponse.from_dict(response.json())

    def get_all_account_profiles(
        self,
        show_account: Literal["Mask", "Show"] = "Show",
    ) -> list[AccountProfile]:
        """Fetch all account profiles across all pages."""
        all_profiles = []
        cursor = None
        while True:
            resp = self.get_account_profiles(
                page_cursor=cursor, show_account=show_account
            )
            all_profiles.extend(resp.profiles)
            if not resp.next_cursor:
                break
            cursor = resp.next_cursor
        return all_profiles

    # --- Alerts ---

    def get_alerts(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> AlertsResponse:
        """Retrieve alerts for all authorized master accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/alerts", params=params)
        return AlertsResponse.from_dict(response.json())

    def get_alert_detail(self, alert_id: str) -> dict:
        """Get full detail for a single alert."""
        response = self._request("GET", f"/alerts/detail/{alert_id}")
        return response.json()

    def archive_alerts(self, alert_ids: list[str]) -> dict:
        """Archive one or more alerts."""
        body = {
            "data": {
                "type": "alerts-archive",
                "attributes": {"alertIds": alert_ids},
            }
        }
        response = self._request("POST", "/alerts/archive", json_data=body)
        return response.json()

    def update_alert(self, alert_id: str, updates: dict) -> dict:
        """Update an alert (e.g. mark as read)."""
        body = {
            "data": {
                "type": "alerts",
                "id": alert_id,
                "attributes": updates,
            }
        }
        response = self._request("PATCH", f"/alerts/{alert_id}", json_data=body)
        return response.json()

    # --- Transactions ---

    def get_transactions(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> TransactionsResponse:
        """Retrieve transactions for all authorized accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/transactions", params=params)
        return TransactionsResponse.from_dict(response.json())

    def get_transaction_detail(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> TransactionsResponse:
        """Retrieve detailed transaction info."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/transactions/detail", params=params)
        return TransactionsResponse.from_dict(response.json())

    # --- Standing Instructions (SLOA) ---

    def get_standing_instructions(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> StandingInstructionsResponse:
        """Retrieve standing instructions (SLOA) for authorized accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/standing-instructions", params=params)
        return StandingInstructionsResponse.from_dict(response.json())

    def get_standing_instruction_detail(self, instruction_id: str) -> dict:
        """Get full detail for a single standing instruction."""
        response = self._request(
            "GET", f"/standing-instructions/{instruction_id}"
        )
        return response.json()

    # --- Profiles ---

    def get_account_holders(
        self,
        page_cursor: str | None = None,
        page_limit: int = 1000,
    ) -> AccountHoldersResponse:
        """Retrieve account holder info (names, addresses, DOB)."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/profiles/account-holders", params=params)
        return AccountHoldersResponse.from_dict(response.json())

    def get_profiles_list(self, formatted_accounts: list[str]) -> dict:
        """Retrieve profiles for specific accounts."""
        body = {
            "data": {
                "type": "profiles",
                "attributes": {"formattedAccounts": formatted_accounts},
            }
        }
        response = self._request("POST", "/profiles/list", json_data=body)
        return response.json()

    # --- Account Preferences and Authorizations ---

    def get_preferences_and_authorizations(
        self, formatted_accounts: list[str]
    ) -> PreferencesAndAuthorizationsResponse:
        """Retrieve preferences and authorizations (MoneyLink, IA authority, etc.)."""
        body = {
            "data": {
                "type": "preferences-and-authorizations",
                "attributes": {"formattedAccounts": formatted_accounts},
            }
        }
        response = self._request(
            "POST", "/preferences-and-authorizations/list", json_data=body
        )
        return PreferencesAndAuthorizationsResponse.from_dict(response.json())
