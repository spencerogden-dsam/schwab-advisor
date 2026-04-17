"""Schwab Advisor API client."""

import uuid
from typing import Literal

import httpx

from .auth import SchwabAuth
from .models import (
    AccountHoldersResponse,
    AccountProfile,
    AccountProfilesResponse,
    AlertArchiveResponse,
    AlertDetailResponse,
    AlertsResponse,
    AlertUpdateResponse,
    PreferencesAndAuthorizationsResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopicsResponse,
    StandingInstructionsResponse,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
    TransactionsResponse,
)

# Each Schwab API product uses a different base path segment.
# AS Account uses "bulk"; AS Alerts, Service Request, Status use "accounts".
_API_SEGMENTS = {
    "sandbox": "https://sandbox.schwabapi.com/as-integration/{segment}/v2",
    "production": "https://api.schwabapi.com/as-integration/{segment}/v2",
}


class SchwabAdvisorClient:
    """Client for interacting with Schwab Advisor Services API."""

    def __init__(
        self,
        auth: SchwabAuth | None = None,
        access_token: str | None = None,
        environment: Literal["sandbox", "production"] | None = None,
        base_url: str | None = None,
        resource_version: int = 1,
    ):
        if auth is None and access_token is None:
            auth = SchwabAuth.from_env()

        if environment is None:
            environment = getattr(auth, "environment", "sandbox") if auth else "sandbox"

        self.auth = auth
        self._access_token = access_token
        self.environment = environment
        self.base_url = base_url  # override for all requests if set
        self.resource_version = resource_version
        self._client: httpx.Client | None = None

    def _base_url(self, segment: str = "bulk") -> str:
        """Get the base URL for a given API segment."""
        if self.base_url:
            return self.base_url
        return _API_SEGMENTS[self.environment].format(segment=segment)

    def _get_access_token(self) -> str:
        if self.auth:
            return self.auth.get_access_token()
        return self._access_token

    def _get_headers(
        self,
        has_body: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Schwab-Client-CorrelId": str(uuid.uuid4()),
            "Schwab-Resource-Version": str(self.resource_version),
            "Accept": "application/vnd.api+json",
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def __enter__(self):
        self._client = httpx.Client()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_data: dict | list | None = None,
        segment: Literal["bulk", "accounts"] = "bulk",
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers = self._get_headers(
            has_body=json_data is not None,
            extra_headers=extra_headers,
        )
        url = f"{self._base_url(segment)}{path}"
        timeout = httpx.Timeout(10.0, read=30.0)

        if self._client:
            response = self._client.request(
                method, url, params=params, json=json_data,
                headers=headers, timeout=timeout,
            )
        else:
            response = httpx.request(
                method, url, params=params, json=json_data,
                headers=headers, timeout=timeout,
            )

        response.raise_for_status()
        return response

    def _paginated_params(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,  # max supported by Schwab API
    ) -> dict:
        params: dict = {"page[limit]": page_limit}
        if page_cursor:
            params["page[cursor]"] = page_cursor
        return params

    # --- AS Account ---

    def get_account_profiles(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
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

    # --- Alerts (segment: accounts) ---

    def get_alerts(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        filter_types: list[str] | None = None,
        filter_subjects: list[str] | None = None,
        filter_start_date: str | None = None,
        filter_end_date: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AlertsResponse:
        """Retrieve alerts for all authorized master accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_types:
            params["filter[types]"] = ", ".join(filter_types)
        if filter_subjects:
            params["filter[subjects]"] = ", ".join(filter_subjects)
        if filter_start_date:
            params["filter[startDate]"] = filter_start_date
        if filter_end_date:
            params["filter[endDate]"] = filter_end_date
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
        response = self._request("GET", "/alerts", params=params, segment="accounts")
        return AlertsResponse.from_dict(response.json())

    def get_alert_detail(
        self,
        alert_id: int | str,
        master_account: str | None = None,
    ) -> AlertDetailResponse:
        """Get full detail for a single alert.

        Requires Schwab-Client-Ids header with masterAccount.
        """
        extra = None
        if master_account:
            extra = {"Schwab-Client-Ids": f"masterAccount={master_account}"}
        response = self._request(
            "GET",
            f"/alerts/detail/{alert_id}",
            segment="accounts",
            extra_headers=extra,
        )
        return AlertDetailResponse.from_dict(response.json())

    def archive_alerts(self, alert_ids: list[int]) -> AlertArchiveResponse:
        """Archive one or more alerts."""
        body = {"alertIds": alert_ids}
        response = self._request(
            "POST", "/alerts/archive", json_data=body, segment="accounts"
        )
        return AlertArchiveResponse.from_dict(response.json())

    def update_alert(
        self,
        alert_id: int | str,
        updates: dict,
    ) -> AlertUpdateResponse:
        """Update an alert (e.g. mark as read). Returns 204 on success."""
        body = {
            "data": {
                "type": "alert",
                "id": alert_id,
                "attributes": updates,
            }
        }
        response = self._request(
            "PATCH", f"/alerts/{alert_id}", json_data=body, segment="accounts"
        )
        if response.status_code == 204:
            return AlertUpdateResponse(id=str(alert_id), raw_data=None)
        return AlertUpdateResponse.from_dict(response.json())

    # --- Transactions ---

    def get_transactions(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> TransactionsResponse:
        """Retrieve transactions for all authorized accounts."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/transactions", params=params)
        return TransactionsResponse.from_dict(response.json())

    def get_transaction_detail(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> TransactionsResponse:
        """Retrieve detailed transaction info."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request("GET", "/transactions/detail", params=params)
        return TransactionsResponse.from_dict(response.json())

    # --- Standing Instructions (SLOA) ---

    def get_standing_instructions(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
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
        page_limit: int = 500,
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

    # --- Service Requests (segment: accounts) ---

    def get_service_request_topics(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> ServiceRequestTopicsResponse:
        """Retrieve available service request topics and subtopics."""
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request(
            "GET", "/service-requests", params=params, segment="accounts"
        )
        return ServiceRequestTopicsResponse.from_dict(response.json())

    def create_service_request(
        self,
        topic_name: str,
        sub_topic_name: str,
        description: str,
        master_account: str | None = None,
        sub_account: str | None = None,
        attachments: list[dict] | None = None,
    ) -> ServiceRequestCreateResponse:
        """Submit a new service request.

        Either master_account or sub_account is required.
        Use get_service_request_topics() to discover valid topic/subtopic names.
        Some topics require attachments.
        """
        body: dict = {
            "TopicName": topic_name,
            "SubTopicName": sub_topic_name,
            "Description": description,
        }
        if master_account:
            body["MasterAccount"] = master_account
        if sub_account:
            body["SubAccount"] = sub_account
        if attachments:
            body["Attachments"] = attachments
        response = self._request(
            "POST", "/service-requests", json_data=body, segment="accounts"
        )
        return ServiceRequestCreateResponse.from_dict(response.json())

    # --- Status Feed / Events (segment: accounts) ---

    def create_status_feed(
        self,
        status: list[str],
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> StatusFeedCreateResponse:
        """Create a status feed query.

        Args:
            status: List of status values to filter by (e.g. ["New", "Resolved"]).
            show_account: Whether to mask or show account numbers.
        """
        body: dict = {
            "Status": status,
            "ShowAccount": show_account,
        }
        response = self._request(
            "POST", "/status-feed", json_data=body, segment="accounts"
        )
        return StatusFeedCreateResponse.from_dict(response.json())

    def get_status_feed(self, feed_id: str) -> StatusFeedResponse:
        """Get status objects for a previously created feed."""
        response = self._request(
            "GET", f"/status-feed/{feed_id}", segment="accounts"
        )
        return StatusFeedResponse.from_dict(response.json())

    def get_status_events(
        self,
        feed_id: str,
        object_id: str,
    ) -> StatusEventsResponse:
        """Get status events for a specific object in a feed."""
        response = self._request(
            "GET",
            f"/status-feed/{feed_id}/status-objects/{object_id}/status-events",
            segment="accounts",
        )
        return StatusEventsResponse.from_dict(response.json())

    def post_status_events(
        self,
        myq_case_id: str,
        master_account: str,
        message: str | None = None,
        documents: list[dict] | None = None,
        status_object_id: str | None = None,
    ) -> StatusEventsPostResponse:
        """Post a status event to an existing case.

        Either message or documents must be provided.
        """
        body: dict = {
            "myqCaseId": myq_case_id,
            "masterAccount": master_account,
        }
        if message:
            body["message"] = message
        if documents:
            body["documents"] = documents
        if status_object_id:
            body["statusObjectId"] = status_object_id
        response = self._request(
            "POST", "/status-events", json_data=body, segment="accounts"
        )
        return StatusEventsPostResponse.from_dict(response.json())
