"""Schwab Advisor API client."""

import uuid
from typing import Literal

import httpx

from .auth import SchwabAuth
from .models import (
    AccountHoldersResponse,
    AccountInfo,
    AccountOwnerListResponse,
    AccountProfile,
    AccountProfilesResponse,
    AccountRmdResponse,
    AccountRolesResponse,
    AccountsResponse,
    AccountSyncResponse,
    AddressChangesResponse,
    AlertArchiveResponse,
    AlertDetailResponse,
    AlertsResponse,
    AlertUpdateResponse,
    BalanceDetailResponse,
    BalanceListResponse,
    ClientInquiryResponse,
    CostBasisRglResponse,
    CostBasisUglResponse,
    DocumentPreferencesResponse,
    MasterAccountsResponse,
    PositionDetailResponse,
    PositionListResponse,
    PreferencesAndAuthorizationsResponse,
    ProfilesListResponse,
    ReportsResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopicsResponse,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
    TransactionsResponse,
    UploadResponse,
)

# Each Schwab API product uses a different base path segment.
# AS Account uses "bulk"; AS Alerts, Service Request, Status use "accounts".
_DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=30.0)

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

    # =====================================================================
    # AS Account (segment: bulk)
    # =====================================================================

    def get_account_profiles(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        include_total_count: bool = False,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountProfilesResponse:
        """Retrieve account profiles for all authorized accounts.

        Sandbox: VERIFIED - returns real data with all fields populated.
        """
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
        """Fetch all account profiles across all pages.

        Sandbox: VERIFIED - pagination loop tested.
        """
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

    def get_account_roles(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountRolesResponse:
        """Retrieve account roles for all authorized accounts.

        Sandbox: VERIFIED - returns roles with holder details.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request("GET", "/account-roles", params=params)
        return AccountRolesResponse.from_dict(response.json())

    def get_account_rmd(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountRmdResponse:
        """Retrieve RMD (Required Minimum Distribution) data for retirement accounts.

        Sandbox: VERIFIED - returns RMD data, though all amounts are 0 in sandbox.
        Model fields may need refinement when real RMD amounts are present.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request("GET", "/account-rmd", params=params)
        return AccountRmdResponse.from_dict(response.json())

    # =====================================================================
    # AS Account Inquiry (segment: accounts)
    # =====================================================================

    def get_master_accounts(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> MasterAccountsResponse:
        """Retrieve master accounts.

        Sandbox: VERIFIED - returns master account details.
        """
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request(
            "GET", "/master-accounts", params=params, segment="accounts"
        )
        return MasterAccountsResponse.from_dict(response.json())

    def get_accounts(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountsResponse:
        """Retrieve all accounts under authorized master accounts.

        Sandbox: VERIFIED - returns 84 accounts with pagination.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/accounts", params=params, segment="accounts"
        )
        return AccountsResponse.from_dict(response.json())

    def search_account_owners(
        self,
        first_name: str | None = None,
        last_name: str | None = None,
        organization_name: str | None = None,
        client_id: int | None = None,
    ) -> AccountOwnerListResponse:
        """Search for account owners by name or client ID.

        Sandbox: VERIFIED - returns owner data with account links.
        """
        body: dict = {}
        if first_name:
            body["firstName"] = first_name
        if last_name:
            body["lastName"] = last_name
        if organization_name:
            body["organizationName"] = organization_name
        if client_id:
            body["clientId"] = client_id
        response = self._request(
            "POST", "/account-owners/list", json_data=body, segment="accounts"
        )
        return AccountOwnerListResponse.from_dict(response.json())

    # =====================================================================
    # AS Account Synchronization (segment: bulk)
    # =====================================================================

    def get_account_sync(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountSyncResponse:
        """Retrieve account synchronization data.

        Sandbox: VERIFIED - returns sync records with client IDs.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request("GET", "/account-sync", params=params)
        return AccountSyncResponse.from_dict(response.json())

    # =====================================================================
    # AS Accounts Preferences and Authorizations (segment: accounts)
    # =====================================================================

    def get_preferences_and_authorizations(
        self, formatted_accounts: list[str]
    ) -> PreferencesAndAuthorizationsResponse:
        """Retrieve preferences and authorizations (MoneyLink, IA authority, etc.).

        Sandbox: VERIFIED - returns nested preferencesAndAuthorizations array.
        Note: uses flat body {"Accounts": [...]}, not JSON:API format.
        """
        body = {"Accounts": formatted_accounts}
        response = self._request(
            "POST", "/preferences-and-authorizations/list",
            json_data=body, segment="accounts",
        )
        return PreferencesAndAuthorizationsResponse.from_dict(response.json())

    # =====================================================================
    # AS Address Change (segment: accounts)
    # =====================================================================

    def get_address_changes(
        self,
        filter_status: str | None = None,
        filter_last_updated_date: str | None = None,
        include_customer: bool = False,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AddressChangesResponse:
        """Retrieve address changes across all authorized accounts.

        Sandbox: VERIFIED (high confidence) - returns 200, model fields
        match documented schema exactly. Empty in sandbox (no changes exist),
        but field names are from Schwab's documented example response.
        No Schwab-Client-Ids header needed (firm-level endpoint).
        Supports JSON:API relationships and include=customer sideloading.

        Args:
            filter_status: One of Completed, Draft, PendingClientApproval,
                SubmittedToSchwab, SubmittedToSchwabException, Voided.
            filter_last_updated_date: ISO date string. Must be within last
                6 days (Schwab enforced). Default is 6 days prior.
            include_customer: If True, includes related customer data via
                JSON:API sideloading in response.included.
        """
        params: dict = {"showAccount": show_account}
        if filter_status:
            params["filter[status]"] = filter_status
        if filter_last_updated_date:
            params["filter[lastUpdatedDate]"] = filter_last_updated_date
        if include_customer:
            params["include"] = "customer"
        response = self._request(
            "GET", "/address-changes", params=params, segment="accounts",
        )
        return AddressChangesResponse.from_dict(response.json())

    def get_address_change(
        self,
        action_id: str,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> dict:
        """Retrieve a specific address change by action ID.

        Sandbox: NOT VERIFIED - no address change data exists in sandbox
        to obtain a valid action_id.
        """
        params = {"showAccount": show_account}
        response = self._request(
            "GET", f"/address-changes/{action_id}", params=params,
            segment="accounts",
        )
        return response.json()

    def create_address_change(
        self,
        master_account: int,
        user_entered_addresses: list[dict],
        customer_search_criteria: dict | None = None,
        envelope_id: str | None = None,
    ) -> dict:
        """Submit an address change request.

        Sandbox: NOT VERIFIED - endpoint times out / returns 500 in sandbox.
        Body schema is from Schwab docs. Should work in production.

        Args:
            master_account: Master account number (integer).
            user_entered_addresses: List of new address dicts with keys:
                addressLine1, city, state, zipCode, country, and optionally
                addressLine2-4, zipSuffix.
            customer_search_criteria: Dict with firstName, lastName, and
                optionally taxpayerId, dateOfBirth to identify the customer.
            envelope_id: Optional Action Center envelope ID.
        """
        body: dict = {
            "masterAccount": master_account,
            "userEnteredAddresses": user_entered_addresses,
        }
        if customer_search_criteria:
            body["customerSearchCriteria"] = customer_search_criteria
        if envelope_id:
            body["envelopeId"] = envelope_id
        response = self._request(
            "POST", "/address-changes", json_data=body, segment="accounts"
        )
        return response.json()

    # =====================================================================
    # AS Alerts (segment: accounts)
    # =====================================================================

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
        """Retrieve alerts for all authorized master accounts.

        Sandbox: VERIFIED - returns 825 alerts with full data. All filters,
        sort options (CreatedDate, Status, Type, Subject, Priority), and
        pagination tested. Max page[limit] is 500.
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

        Sandbox: VERIFIED - returns detailed alert with HTML detailText,
        statusHistory, and audit fields. Requires Schwab-Client-Ids header
        with masterAccount= format (unique to this endpoint).
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
        """Archive one or more alerts.

        Sandbox: VERIFIED - archives alerts and returns per-alert status.
        Uses flat body {"alertIds": [int]} (not JSON:API). IDs are integers.
        """
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
        """Update an alert (e.g. mark as read).

        Sandbox: VERIFIED - returns 204 No Content on success. Accepts
        status, isArchived, isRead, priority updates without validation errors.
        """
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

    # =====================================================================
    # AS Balances (segment: accounts)
    # =====================================================================

    def get_balance_detail(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> BalanceDetailResponse:
        """Retrieve detailed balance info for a specific account.

        Sandbox: VERIFIED - returns full balance breakdown (50+ fields).
        Occasionally returns 500 (sandbox instability, not a code issue).
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/balances/detail", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return BalanceDetailResponse.from_dict(response.json())

    def get_balances_list(
        self,
        accounts: list[str],
    ) -> BalanceListResponse:
        """Retrieve balances for multiple accounts.

        Sandbox: VERIFIED - returns nested balances array.
        Uses flat body {"Accounts": [...]}.
        """
        body = {"Accounts": accounts}
        response = self._request(
            "POST", "/balances/list", json_data=body, segment="accounts"
        )
        return BalanceListResponse.from_dict(response.json())

    # =====================================================================
    # AS Client Inquiry (segment: accounts)
    # =====================================================================

    def search_clients(
        self,
        first_name: str | None = None,
        last_name: str | None = None,
        organization_name: str | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> ClientInquiryResponse:
        """Search for clients by name.

        Sandbox: VERIFIED - returns client info with IDs. Search criteria goes
        in the Schwab-Client-Ids header (e.g. "firstName=TEST,lastName=DOE"),
        not in query params. This is unique to this endpoint.

        At least one of first_name, last_name, or organization_name is required.
        """
        parts = []
        if first_name:
            parts.append(f"firstName={first_name}")
        if last_name:
            parts.append(f"lastName={last_name}")
        if organization_name:
            parts.append(f"organizationName={organization_name}")
        if not parts:
            raise ValueError("At least one of first_name, last_name, or organization_name is required")
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request(
            "GET", "/client-inquiries", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": ",".join(parts)},
        )
        return ClientInquiryResponse.from_dict(response.json())

    # =====================================================================
    # AS Cost Basis (segment: accounts)
    # =====================================================================

    def get_cost_basis_account_preferences(
        self,
        account: str,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> dict:
        """Retrieve cost basis account preferences.

        Sandbox: PARTIALLY VERIFIED - returns 200 with preference structure,
        but sandbox account has no cost basis elections configured.
        Need real cost basis settings to verify all response fields.
        """
        params = {"showAccount": show_account}
        response = self._request(
            "GET", "/cost-basis/account-preferences", params=params,
            segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return response.json()

    def get_cost_basis_rgl_transactions(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 100,  # cost-basis max is 100, not 500
    ) -> CostBasisRglResponse:
        """Retrieve realized gain/loss transactions.

        Sandbox: PARTIALLY VERIFIED - returns 200 with empty transactions array.
        Need sandbox accounts with realized gains to verify transaction field
        mapping. Model fields are guessed from doc model names.
        Note: max page[limit] is 100 (lower than the 500 limit on other endpoints).
        """
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request(
            "GET", "/cost-basis/rgl-transactions", params=params,
            segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return CostBasisRglResponse.from_dict(response.json())

    def get_cost_basis_ugl_positions(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 100,  # cost-basis max is 100, not 500
    ) -> CostBasisUglResponse:
        """Retrieve unrealized gain/loss positions.

        Sandbox: PARTIALLY VERIFIED - returns 200 with empty positions array.
        Need sandbox accounts with open positions with cost basis to verify
        position field mapping. Model fields are guessed from doc model names.
        Note: max page[limit] is 100.
        """
        params = self._paginated_params(page_cursor, page_limit)
        response = self._request(
            "GET", "/cost-basis/ugl-positions", params=params,
            segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return CostBasisUglResponse.from_dict(response.json())

    # =====================================================================
    # AS Document Preferences (segment: accounts)
    # =====================================================================

    def get_document_preferences(
        self,
        accounts: list[str],
    ) -> DocumentPreferencesResponse:
        """Retrieve document delivery preferences for accounts.

        Sandbox: VERIFIED - returns delivery preferences, report preferences,
        and issuer communications settings.
        """
        body = {"Accounts": accounts}
        response = self._request(
            "POST", "/document-preferences/list", json_data=body, segment="accounts"
        )
        return DocumentPreferencesResponse.from_dict(response.json())

    # =====================================================================
    # AS Man Fees File Upload (segment: accounts)
    # =====================================================================

    def upload_manfees(
        self,
        base64_file_content: str,
    ) -> UploadResponse:
        """Upload management fees file (base64-encoded .mfa file).

        Sandbox: NOT VERIFIED - requires a real .mfa file with correct format.
        Sandbox returns 400 "File either does not have .mfa extension or is
        missing version details" for test data.
        """
        body = {"Base64EncodedFileContent": base64_file_content}
        response = self._request(
            "POST", "/upload-manfees", json_data=body, segment="accounts"
        )
        return UploadResponse.from_dict(response.json())

    # =====================================================================
    # AS Positions (segment: accounts)
    # =====================================================================

    def get_position_detail(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> PositionDetailResponse:
        """Retrieve detailed position info for a specific account.

        Sandbox: VERIFIED - returns positions with market values, quantities.
        Response is a single-item wrapper with nested positions array and
        totalPositions summary. Occasionally returns 500 (sandbox instability).
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/positions/detail", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return PositionDetailResponse.from_dict(response.json())

    def get_positions_list(
        self,
        accounts: list[str],
    ) -> PositionListResponse:
        """Retrieve positions for multiple accounts.

        Sandbox: VERIFIED - returns positions across multiple accounts.
        """
        body = {"Accounts": accounts}
        response = self._request(
            "POST", "/positions/list", json_data=body, segment="accounts"
        )
        return PositionListResponse.from_dict(response.json())

    # =====================================================================
    # AS Profiles (segment: accounts)
    # =====================================================================

    def get_account_holders(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountHoldersResponse:
        """Retrieve account holder info (names, addresses, DOB).

        Sandbox: NOT VERIFIED - returns 400 "Invalid Schwab-Client-Ids" for
        both account= and masterAccount= formats. The correct header format
        for this endpoint is unknown. May work differently in production.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/profiles/account-holders", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return AccountHoldersResponse.from_dict(response.json())

    def get_profiles(
        self,
        accounts: list[str],
    ) -> ProfilesListResponse:
        """Retrieve detailed profiles for specific accounts.

        Sandbox: VERIFIED - returns full profile with address, registration type,
        email, phone numbers. Uses flat body {"Accounts": [...]}.
        """
        body = {"Accounts": accounts}
        response = self._request(
            "POST", "/profiles/list", json_data=body, segment="accounts"
        )
        return ProfilesListResponse.from_dict(response.json())

    # =====================================================================
    # AS Reports (segment: accounts)
    # =====================================================================

    def get_reports(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> ReportsResponse:
        """Retrieve reports for a specific account.

        Sandbox: VERIFIED - returns report metadata including reportId,
        reportName, reportType, reportSubtype, preparedByDate.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/reports", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return ReportsResponse.from_dict(response.json())

    def get_report_pdf(
        self,
        account: str,
        report_id: str,
        report_type: str,
    ) -> dict:
        """Retrieve a report PDF by ID and type.

        Sandbox: NOT VERIFIED - returns 400 requiring reportType, but valid
        reportType values beyond "Statements" (from report metadata) are unknown.
        Need to discover valid reportType enum values.

        Args:
            report_type: e.g. "Statements" (from get_reports().reports[].reportType)
        """
        params = {"reportId": report_id, "reportType": report_type}
        response = self._request(
            "GET", "/reports/pdf", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return response.json()

    # =====================================================================
    # AS Service Request (segment: accounts)
    # =====================================================================

    def get_service_request_topics(
        self,
        page_cursor: str | None = None,
        page_limit: int = 500,
    ) -> ServiceRequestTopicsResponse:
        """Retrieve available service request topics and subtopics.

        Sandbox: VERIFIED - returns 15 topics with subtopics, attachment
        requirements, and max file sizes.
        """
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

        Sandbox: VERIFIED - creates SR and returns confirmation with ID.
        Uses PascalCase flat body (not JSON:API). Either master_account or
        sub_account is required. Some topics require attachments but the
        attachment field format is unknown (all attempts rejected).

        Use get_service_request_topics() to discover valid topic/subtopic names.
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

    # =====================================================================
    # AS Status (segment: accounts)
    # =====================================================================

    def create_status_feed(
        self,
        status: list[str],
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> StatusFeedCreateResponse:
        """Create a status feed query.

        Sandbox: VERIFIED - returns 100+ status objects with nested events.
        Known valid status values: "New", "Resolved". Uses PascalCase flat body.

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
        """Get status objects for a previously created feed.

        Sandbox: VERIFIED - returns all status objects as JSON:API array.
        Does NOT support pagination (page[limit] causes empty results).
        """
        response = self._request(
            "GET", f"/status-feed/{feed_id}", segment="accounts"
        )
        return StatusFeedResponse.from_dict(response.json())

    def get_status_events(
        self,
        feed_id: str,
        object_id: str,
    ) -> StatusEventsResponse:
        """Get status events for a specific object in a feed.

        Sandbox: VERIFIED - returns event history for status objects.
        """
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

        Sandbox: NOT VERIFIED - requires a valid myqCaseId (max 16 chars)
        from the MyQ case management system. No way to create/obtain case IDs
        via the API. Need a real case ID to test.

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

    # =====================================================================
    # AS Transactions (segment: accounts)
    # =====================================================================

    def get_transactions(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> TransactionsResponse:
        """Retrieve transactions for a specific account.

        Sandbox: VERIFIED - returns transactions with action, amounts, dates.
        Transaction field names differ from docs (e.g. typeCode not
        transactionType, settleDate not settlementDate).

        Args:
            account: Account number for Schwab-Client-Ids header.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/transactions", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return TransactionsResponse.from_dict(response.json())

    def get_transaction_detail(
        self,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> TransactionsResponse:
        """Retrieve detailed transaction info for a specific account.

        Sandbox: VERIFIED - returns same structure as get_transactions
        but may include additional detail fields.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/transactions/detail", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return TransactionsResponse.from_dict(response.json())
