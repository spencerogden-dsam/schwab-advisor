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

_DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=30.0)

# AS Account endpoints live under "bulk"; AS Alerts/Service-Request/Status
# under "accounts". Each public method on the client picks a segment.
_API_SEGMENTS = {
    "sandbox": "https://sandbox.schwabapi.com/as-integration/{segment}/v2",
    "production": "https://api.schwabapi.com/as-integration/{segment}/v2",
}


def schwab_error_code(exc: httpx.HTTPStatusError) -> str | None:
    """Extract the Schwab error code (e.g. SEC-0001) from a failed response."""
    try:
        errors = exc.response.json().get("errors") or []
        if errors:
            return errors[0].get("code")
    except Exception:
        pass
    return None


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
        self.base_url = base_url
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
        correl_id: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Schwab-Client-CorrelId": (
                correl_id if correl_id is not None else str(uuid.uuid4())
            ),
            "Schwab-Resource-Version": str(self.resource_version),
            "Accept": "application/vnd.api+json",
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        return headers

    @staticmethod
    def _format_client_ids(client_ids: dict[str, str]) -> str:
        """Format Schwab-Client-Ids header value from a dict.

        Example: {"masterAccount": "8174295"} -> "masterAccount=8174295"
        {"masterAccount": "X", "account": "Y"} -> "masterAccount=X,account=Y"

        Multiple keys joined with "," (no space) — Schwab rejects whitespace
        between pairs with a 400 Bad Request.
        """
        return ",".join(f"{k}={v}" for k, v in client_ids.items() if v)

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
        correl_id: str | None = None,
    ) -> httpx.Response:
        headers = self._get_headers(
            has_body=json_data is not None,
            extra_headers=extra_headers,
            correl_id=correl_id,
        )
        url = f"{self._base_url(segment)}{path}"

        if self._client:
            response = self._client.request(
                method, url, params=params, json=json_data,
                headers=headers, timeout=_DEFAULT_TIMEOUT,
            )
        else:
            response = httpx.request(
                method, url, params=params, json=json_data,
                headers=headers, timeout=_DEFAULT_TIMEOUT,
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
        sort_by: Literal[
            "AccountName", "CreatedDate", "FormattedAccount",
            "FormattedMasterAccount", "Priority", "ReplyType",
            "Status", "Subject", "Type",
        ] | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        show_account: Literal["Mask", "Show"] = "Mask",
        filter_status: list[str] | None = None,
        filter_is_archived: bool | None = None,
        filter_origin_type: Literal["Original", "Copied"] | None = None,
        schwab_client_ids: dict[str, str] | None = None,
        correl_id: str | None = None,
    ) -> AlertsResponse:
        """Retrieve alerts for all authorized master accounts.

        Args:
            schwab_client_ids: Optional dict like {"account": "..."} or
                {"masterAccount": "..."} — sent as Schwab-Client-Ids header
                to scope alerts to specific accounts.
            filter_status: Optional list of status values — "New", "Viewed",
                "ResponseSent".
            filter_is_archived: Optional bool filter.
            correl_id: Optional override for Schwab-Client-CorrelId (empty
                string reproduces the 400 error).
        """
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
        if filter_status:
            params["filter[status]"] = ", ".join(filter_status)
        if filter_is_archived is not None:
            params["filter[isArchived]"] = "true" if filter_is_archived else "false"
        if filter_origin_type:
            params["filter[originType]"] = filter_origin_type
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
        extra = None
        if schwab_client_ids:
            extra = {"Schwab-Client-Ids": self._format_client_ids(schwab_client_ids)}
        response = self._request(
            "GET", "/alerts", params=params, segment="accounts",
            extra_headers=extra, correl_id=correl_id,
        )
        return AlertsResponse.from_dict(response.json())

    def get_alert_detail(
        self,
        alert_id: int | str,
        master_account: str | None = None,
        account: str | None = None,
        show_account: Literal["Mask", "Show"] = "Mask",
        correl_id: str | None = None,
    ) -> AlertDetailResponse:
        """Get full detail for a single alert.

        Args:
            alert_id: The alert id.
            master_account: Master account scope for Schwab-Client-Ids header.
            account: Sub-account scope — combined with master_account the header
                becomes ``masterAccount=X,account=Y``.
            show_account: Mask (default) or Show.

        Schwab requires the Schwab-Client-Ids header; callers should always
        pass at least ``master_account``. Omitting it returns 400.
        """
        extra = None
        ids: dict[str, str] = {}
        if master_account:
            ids["masterAccount"] = master_account
        if account:
            ids["account"] = account
        if ids:
            extra = {"Schwab-Client-Ids": self._format_client_ids(ids)}
        response = self._request(
            "GET",
            f"/alerts/detail/{alert_id}",
            params={"showAccount": show_account},
            segment="accounts",
            extra_headers=extra,
            correl_id=correl_id,
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
        action: Literal["Unarchive", "Unread"],
        correl_id: str | None = None,
    ) -> AlertUpdateResponse:
        """Unarchive an alert or mark it as unread.

        Returns 204 on success.

        Args:
            alert_id: The alert id.
            action: "Unarchive" to unarchive, "Unread" to mark as unread.
        """
        body = {"action": action}
        response = self._request(
            "PATCH", f"/alerts/{alert_id}", json_data=body, segment="accounts",
            correl_id=correl_id,
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
        master_accounts: list[str] | None = None,
        accounts: list[str] | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        time_frame: Literal["CreatedDate", "LastUpdatedDate"] | None = None,
        categories: list[str] | None = None,
        myq_case_id: str | None = None,
        service_request_confirmation_id: str | None = None,
        action_center_envelope_id: str | None = None,
        include_all_events: bool | None = None,
        first_page_only: bool | None = None,
        correl_id: str | None = None,
    ) -> StatusFeedCreateResponse:
        """Create a status feed query.

        Args:
            status: List of status values (e.g. ["New", "Resolved"]).
            show_account: Whether to mask or show account numbers.
            master_accounts: Scope to specific master accounts.
            accounts: Scope to specific sub-accounts.
            start_date: Earliest date (default 90 days prior).
            end_date: Latest date (default current date).
            time_frame: "CreatedDate" (default) or "LastUpdatedDate".
            categories: Filter by category (e.g. "Account Maintenance",
                "Move Money", "Digital Envelope").
            myq_case_id: Filter to a specific MyQ case (e.g. "WI-123456").
            service_request_confirmation_id: Filter to a service request
                (e.g. "SR813637257").
            action_center_envelope_id: Filter to an Action Center envelope
                (e.g. "842993565").
            include_all_events: If True, include all events per object.
            first_page_only: If True, returns 1000 events; else 2000.
        """
        # camelCase per AS Status OpenAPI v2.0.0 spec
        # (sandbox also accepts PascalCase but production may enforce spec strictly)
        body: dict = {
            "status": status,
            "showAccount": show_account,
        }
        if master_accounts:
            body["masterAccounts"] = master_accounts
        if accounts:
            body["accounts"] = accounts
        if start_date:
            body["startDate"] = start_date
        if end_date:
            body["endDate"] = end_date
        if time_frame:
            body["timeFrame"] = time_frame
        if categories:
            body["categories"] = categories
        if myq_case_id:
            body["myqCaseId"] = myq_case_id
        if service_request_confirmation_id:
            body["serviceRequestConfirmationId"] = service_request_confirmation_id
        if action_center_envelope_id:
            body["actionCenterEnvelopeId"] = action_center_envelope_id
        if include_all_events is not None:
            body["includeAllEvents"] = include_all_events
        if first_page_only is not None:
            body["firstPageOnly"] = first_page_only
        response = self._request(
            "POST", "/status-feed", json_data=body, segment="accounts",
            correl_id=correl_id,
        )
        return StatusFeedCreateResponse.from_dict(response.json())

    def get_status_feed(
        self,
        feed_id: str,
        page_limit: int | None = None,
        show_account: Literal["Mask", "Show"] | None = None,
        correl_id: str | None = None,
    ) -> StatusFeedResponse:
        """Get status objects for a previously created feed.

        Per the AS Status OpenAPI spec, this endpoint accepts page[limit]
        (default 1000) and showAccount query params.
        """
        params: dict = {}
        if page_limit is not None:
            params["page[limit]"] = page_limit
        if show_account is not None:
            params["showAccount"] = show_account
        response = self._request(
            "GET", f"/status-feed/{feed_id}",
            params=params or None, segment="accounts",
            correl_id=correl_id,
        )
        return StatusFeedResponse.from_dict(response.json())

    def get_status_events(
        self,
        feed_id: str,
        object_id: str,
        correl_id: str | None = None,
    ) -> StatusEventsResponse:
        """Get status events for a specific object in a feed."""
        response = self._request(
            "GET",
            f"/status-feed/{feed_id}/status-objects/{object_id}/status-events",
            segment="accounts",
            correl_id=correl_id,
        )
        return StatusEventsResponse.from_dict(response.json())

    def post_status_events(
        self,
        myq_case_id: str,
        master_account: str | None = None,
        account: str | None = None,
        message: str | None = None,
        documents: list[dict] | None = None,
        status_object_id: str | None = None,
        show_account: Literal["Mask", "Show"] | None = None,
        correl_id: str | None = None,
    ) -> StatusEventsPostResponse:
        """Post a status event to an existing case.

        Either message or documents must be provided.

        Args:
            myq_case_id: Required MyQ case id (e.g. "WI-123456").
            master_account: Optional master account scope.
            account: Optional sub-account scope.
            message: Plain-text update to append to the case.
            documents: Attachments, each ``{"name": "...", "base64EncodedFileContent": "..."}``.
            status_object_id: Optional existing status object id.
            show_account: Mask/Show in the response.
        """
        body: dict = {"myqCaseId": myq_case_id}
        if master_account:
            body["masterAccount"] = master_account
        if account:
            body["account"] = account
        if message:
            body["message"] = message
        if documents:
            body["documents"] = documents
        if status_object_id:
            body["statusObjectId"] = status_object_id
        if show_account:
            body["showAccount"] = show_account
        response = self._request(
            "POST", "/status-events", json_data=body, segment="accounts",
            correl_id=correl_id,
        )
        return StatusEventsPostResponse.from_dict(response.json())
