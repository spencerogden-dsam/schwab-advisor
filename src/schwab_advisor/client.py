"""Schwab Advisor API client."""

import uuid
from typing import Literal

import httpx

from .auth import SchwabAuth
from .models import (
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
    CostBasisPreferencesResponse,
    CostBasisRglResponse,
    CostBasisUglResponse,
    UglPositionLotsResponse,
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
    "sandbox": "https://sandbox.schwabapi.com/as-integration/{segment}",
    "production": "https://api.schwabapi.com/as-integration/{segment}",
}

# Segment paths per API product (discovered from OpenAPI specs + sandbox testing)
SEGMENTS = {
    "bulk": "bulk/v2",
    "accounts": "accounts/v2",
    "transfers": "transfers/v1",
    "trading": "trading/v1",
    "trading_upload": "trading/v2",
    "users": "users/v2",
    "irebal": "irebal/v1",
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
        seg_path = SEGMENTS.get(segment, segment)
        return _API_SEGMENTS[self.environment].format(segment=seg_path)

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
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client()
        return self._client

    def close(self) -> None:
        """Close the HTTP client and release connections."""
        if self._client:
            self._client.close()
            self._client = None

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_data: dict | list | None = None,
        segment: str = "bulk",
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers = self._get_headers(
            has_body=json_data is not None,
            extra_headers=extra_headers,
        )
        url = f"{self._base_url(segment)}{path}"

        client = self._ensure_client()
        response = client.request(
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
        filter_age: str | None = None,
        filter_rmd_remaining: bool | None = None,
        filter_account_type: str | None = None,
        include_total_count: bool = False,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AccountRmdResponse:
        """Retrieve RMD (Required Minimum Distribution) data for retirement accounts.

        Sandbox: PARTIALLY VERIFIED - returns data but all RMD dollar amounts
        are 0.0 in sandbox.

        Args:
            filter_age: One of RMDAge, NotRMDAge, FirstRMDDueThisYear.
            filter_rmd_remaining: Filter by accounts with remaining RMD.
            filter_account_type: One of RothIRA, InheritedIRA, OtherIRA.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_age:
            params["filter[age]"] = filter_age
        if filter_rmd_remaining is not None:
            params["filter[rmdRemaining]"] = str(filter_rmd_remaining).lower()
        if filter_account_type:
            params["filter[accountType]"] = filter_account_type
        if include_total_count:
            params["includeTotalCount"] = "true"
        response = self._request("GET", "/account-rmd", params=params)
        return AccountRmdResponse.from_dict(response.json())

    # =====================================================================
    # AS Account Inquiry (segment: accounts)
    # =====================================================================

    def get_master_accounts(
        self,
        filter_master_account_type: str | None = None,
        filter_authority: str | None = None,
        filter_is_iip: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> MasterAccountsResponse:
        """Retrieve master accounts.

        Sandbox: VERIFIED - returns master account details.

        Args:
            filter_master_account_type: One of FA, BT, SL.
            filter_authority: One of Read, Upload, Download, Trade, MoveMoney.
            filter_is_iip: One of IIPOnly, NonIIP.
            sort_by: One of MasterAccount, MasterAccountType.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_master_account_type:
            params["filter[masterAccountType]"] = filter_master_account_type
        if filter_authority:
            params["filter[authority]"] = filter_authority
        if filter_is_iip:
            params["filter[isIip]"] = filter_is_iip
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
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
        filter_last_updated_date: str | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
        show_dob: Literal["Mask", "Show"] = "Mask",
        show_tax_id: Literal["Mask", "Show"] = "Mask",
    ) -> AccountSyncResponse:
        """Retrieve account synchronization data.

        Sandbox: VERIFIED - returns sync records with client IDs.

        Args:
            filter_last_updated_date: ISO datetime for delta sync. Returns
                only accounts updated after this date/time. This is the
                primary use case for this endpoint.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        params["showDOB"] = show_dob
        params["showTaxID"] = show_tax_id
        if filter_last_updated_date:
            params["filter[lastUpdatedDate]"] = filter_last_updated_date
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

        Sandbox: PARTIALLY VERIFIED - returns 200 but always empty data.
        No address changes exist in sandbox to verify field mapping against
        real data. Field names are from Schwab's documented example response
        but have not been seen in a live API response.
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
        filter_status: str | None = None,
        filter_is_archived: bool | None = None,
        filter_origin_type: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> AlertsResponse:
        """Retrieve alerts for all authorized master accounts.

        Sandbox: VERIFIED - returns 825 alerts with full data.

        Args:
            filter_status: One of New, Viewed, ResponseSent.
            filter_is_archived: Filter by archived status.
            filter_origin_type: One of Original, Copied.
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
            params["filter[status]"] = filter_status
        if filter_is_archived is not None:
            params["filter[isArchived]"] = str(filter_is_archived).lower()
        if filter_origin_type:
            params["filter[originType]"] = filter_origin_type
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
        action: str,
    ) -> AlertUpdateResponse:
        """Update an alert status.

        Sandbox: VERIFIED - returns 204 No Content on success.
        Per OpenAPI spec, body is flat {"action": value}.

        Args:
            action: One of "Unarchive", "Unread".
        """
        body = {"action": action}
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
        include_open_orders: bool = False,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> BalanceDetailResponse:
        """Retrieve detailed balance info for a specific account.

        Sandbox: VERIFIED - returns full balance breakdown (50+ fields).

        Args:
            include_open_orders: Include open order amounts in balances.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if include_open_orders:
            params["includeOpenOrders"] = "true"
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
    def get_cost_basis_ugl_position_lots(
        self,
        account: int | str,
        position_ids: list[str],
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> UglPositionLotsResponse:
        """Retrieve unrealized gain/loss lot-level detail for specific positions.

        Sandbox: VERIFIED - returns lot-level data with holdingPeriod,
        costPerShare, acquiredDate. Values are formatted strings ("N/A" for
        unavailable). Response includes invalidPositions for unknown IDs.

        Args:
            account: Account number as integer.
            position_ids: List of positionId strings from get_cost_basis_ugl_positions().
        """
        body = {
            "account": account,
            "positionIds": position_ids,
            "showAccount": show_account,
        }
        response = self._request(
            "POST", "/cost-basis/ugl-position-lots/list",
            json_data=body, segment="accounts",
        )
        return UglPositionLotsResponse.from_dict(response.json())

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
        account: str | None = None,
        master_account: str | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> CostBasisPreferencesResponse:
        """Retrieve cost basis account preferences.

        Sandbox: VERIFIED - masterAccount= returns 25 accounts with full
        preference data (accountingMethod, initialCostBasisSource, etc.).
        Supports both account= (single) and masterAccount= (all under master).

        Args:
            account: Single account number (Schwab-Client-Ids: account=X).
            master_account: Master account (Schwab-Client-Ids: masterAccount=X).
                Returns preferences for all accounts under the master.
                One of account or master_account is required.
        """
        if master_account:
            client_ids = f"masterAccount={master_account}"
        elif account:
            client_ids = f"account={account}"
        else:
            raise ValueError("Either account or master_account is required")
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/cost-basis/account-preferences", params=params,
            segment="accounts",
            extra_headers={"Schwab-Client-Ids": client_ids},
        )
        return CostBasisPreferencesResponse.from_dict(response.json())

    def get_cost_basis_rgl_transactions(
        self,
        account: str,
        filter_start_date: str | None = None,
        filter_end_date: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 100,  # RGL max is 100
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> CostBasisRglResponse:
        """Retrieve realized gain/loss transactions.

        Sandbox: VERIFIED - returns 3 RGL transactions for account 93319284
        with AMD, GSAT, PYPL. Values are formatted strings with parentheses
        for negatives (e.g. "($349.02)"). Includes transactionLots.
        Max page[limit] is 100.

        Args:
            filter_start_date: Transactions closed on/after this date.
                Requires filter_end_date. Default is Jan 1 two years back.
            filter_end_date: Transactions closed on/before this date.
                Requires filter_start_date. Default is today.
            sort_by: e.g. "Symbol"
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_start_date:
            params["filter[startDate]"] = filter_start_date
        if filter_end_date:
            params["filter[endDate]"] = filter_end_date
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
        response = self._request(
            "GET", "/cost-basis/rgl-transactions", params=params,
            segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return CostBasisRglResponse.from_dict(response.json())

    def get_cost_basis_ugl_positions(
        self,
        account: str,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,  # UGL max is 500 (unlike RGL's 100)
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> CostBasisUglResponse:
        """Retrieve unrealized gain/loss positions.

        Sandbox: VERIFIED - returns 5 UGL positions for account 14217596.
        Values are formatted strings (e.g. "$257,525.32", "Missing").
        Max page[limit] is 500 (higher than RGL's 100).

        Args:
            sort_by: One of CostBasis, MarketValue, Quantity, SecurityName,
                Symbol, UnrealizedGainLossDollar, UnrealizedGainLossPercent.
                Default: Symbol.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
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
    ) -> None:
        """Upload management fees file (base64-encoded fee file).

        Sandbox: VERIFIED - uploads successfully, returns 204.
        File format is CSV: account_number,fee_amount,name per line.

        Args:
            base64_file_content: Base64-encoded fee file content.
        """
        body = {"Base64EncodedFileContent": base64_file_content}
        self._request(
            "POST", "/upload-manfees", json_data=body, segment="accounts"
        )

    # =====================================================================
    # AS Positions (segment: accounts)
    # =====================================================================

    def get_position_detail(
        self,
        account: str,
        filter_security_type: str | None = None,
        filter_symbol: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> PositionDetailResponse:
        """Retrieve detailed position info for a specific account.

        Sandbox: VERIFIED - returns positions with market values, quantities.

        Args:
            filter_security_type: One of Equity, MutualFunds, Options,
                FixedIncome, Other.
            filter_symbol: Filter by ticker/CUSIP.
            sort_by: One of AreCapitalGainsReinvested, AreDividendsReinvested,
                DayChange, MarketValue, Quantity, SecurityName, SecurityType, Symbol.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_security_type:
            params["filter[securityType]"] = filter_security_type
        if filter_symbol:
            params["filter[symbol]"] = filter_symbol
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
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

    def get_account_holder(
        self,
        account: str,
        account_holder_id: str,
        show_account: Literal["Mask", "Show"] = "Mask",
        show_dob: Literal["Mask", "Show"] = "Mask",
        show_tax_id: Literal["Mask", "Show"] = "Mask",
    ) -> dict:
        """Retrieve detailed profile for a specific account holder.

        Sandbox: VERIFIED - returns full holder profile with employment,
        citizenship, addresses. Requires BOTH account and accountHolderId
        in the Schwab-Client-Ids header (comma-separated).
        Get accountHolderIds from search_account_owners() or get_account_roles().

        Args:
            account: Account number.
            account_holder_id: Holder ID (from account owners/roles).
            show_dob: Mask or show date of birth.
            show_tax_id: Mask or show taxpayer ID.
        """
        params = {
            "showAccount": show_account,
            "showDOB": show_dob,
            "showTaxID": show_tax_id,
        }
        response = self._request(
            "GET", "/profiles/account-holders", params=params, segment="accounts",
            extra_headers={
                "Schwab-Client-Ids": f"account={account},accountHolderId={account_holder_id}"
            },
        )
        return response.json()

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
        report_type: Literal["Statements", "Confirmations", "TaxReports"] = "Statements",
        filter_start_date: str | None = None,
        filter_end_date: str | None = None,
        filter_tax_year: int | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> ReportsResponse:
        """Retrieve reports for a specific account.

        Sandbox: VERIFIED - returns report metadata including reportId,
        reportName, reportType, reportSubtype, preparedByDate.

        Args:
            report_type: Statements (default), Confirmations, or TaxReports.
            filter_start_date: Reports from this date (default 3 months back, max 10 years).
            filter_end_date: Reports through this date (default today).
            filter_tax_year: For TaxReports only (default previous year).
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        params["filter[reportType]"] = report_type
        if filter_start_date:
            params["filter[startDate]"] = filter_start_date
        if filter_end_date:
            params["filter[endDate]"] = filter_end_date
        if filter_tax_year:
            params["filter[taxYear]"] = filter_tax_year
        if sort_direction:
            params["sortDirection"] = sort_direction
        response = self._request(
            "GET", "/reports", params=params, segment="accounts",
            extra_headers={"Schwab-Client-Ids": f"account={account}"},
        )
        return ReportsResponse.from_dict(response.json())

    def get_report_pdf(
        self,
        account: str,
        report_id: str,
        report_type: Literal["Statements", "Confirmations", "TaxReports"] = "Statements",
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> dict:
        """Retrieve a report PDF by ID and type.

        Sandbox: VERIFIED - returns base64-encoded PDF content (270KB+).
        Response includes data.attributes.pdfFile (base64 string).

        Args:
            report_id: From get_reports().reports[].reportId.
            report_type: One of Statements, Confirmations, TaxReports.
        """
        params = {"reportId": report_id, "reportType": report_type, "showAccount": show_account}
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
        account: str | None = None,
        name: str | None = None,
        schwab_case_id: str | None = None,
        cc_email: bool | None = None,
        files: list[dict] | None = None,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> ServiceRequestCreateResponse:
        """Submit a new service request.

        Sandbox: VERIFIED - creates SR and returns confirmation with ID.

        Args:
            name: Title for the SR (max 60 chars). Separate from description.
            schwab_case_id: Merge into existing Schwab case.
            cc_email: Send email copy to registered email.
            files: Attachments as [{"name": "file.pdf",
                "base64EncodedFileContent": "..."}]. Per OpenAPI spec.

        Use get_service_request_topics() to discover valid topic/subtopic names.
        """
        body: dict = {
            "topicName": topic_name,
            "subTopicName": sub_topic_name,
            "description": description,
            "showAccount": show_account,
        }
        if master_account:
            body["masterAccount"] = master_account
        if account:
            body["account"] = account
        if name:
            body["name"] = name
        if schwab_case_id:
            body["schwabCaseId"] = schwab_case_id
        if cc_email is not None:
            body["ccEmail"] = cc_email
        if files:
            body["files"] = files
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
        filter_start_date: str | None = None,
        filter_end_date: str | None = None,
        filter_type: str | None = None,
        filter_symbol: str | None = None,
        sort_by: str | None = None,
        sort_direction: Literal["Asc", "Desc"] | None = None,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> TransactionsResponse:
        """Retrieve transactions for a specific account.

        Sandbox: VERIFIED - returns transactions with action, amounts, dates.

        Args:
            account: Account number for Schwab-Client-Ids header.
            filter_type: One of Adjustments, AtmActivity, BillPay, Checks,
                CorporateActions, Deposits, DividendsAndCapitalGains,
                ElectronicTransfers, Fees, Interest, Misc, SecurityTransfers,
                SweepTransfers, Taxes, Trades, VisaDebitCard, Withdrawals.
            filter_symbol: Filter by ticker or options symbol.
            sort_by: One of Action, Amount, Date, Description, FeesAndComm,
                Price, Quantity, Symbol.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        if filter_start_date:
            params["filter[startDate]"] = filter_start_date
        if filter_end_date:
            params["filter[endDate]"] = filter_end_date
        if filter_type:
            params["filter[type]"] = filter_type
        if filter_symbol:
            params["filter[symbol]"] = filter_symbol
        if sort_by:
            params["sortBy"] = sort_by
        if sort_direction:
            params["sortDirection"] = sort_direction
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

    # =====================================================================
    # AS Standing Authorizations (segment: transfers)
    # =====================================================================

    def get_standing_instructions(
        self,
        master_account: str,
        account: str,
        page_cursor: str | None = None,
        page_limit: int = 500,
        show_account: Literal["Mask", "Show"] = "Mask",
    ) -> dict:
        """Retrieve standing authorization templates.

        Sandbox: PARTIALLY VERIFIED - returns 200 but empty (no standing
        instructions configured). Uses transfers/v1 segment. Requires
        BOTH masterAccount and account in Schwab-Client-Ids header.
        """
        params = self._paginated_params(page_cursor, page_limit)
        params["showAccount"] = show_account
        response = self._request(
            "GET", "/standing-instructions", params=params, segment="transfers",
            extra_headers={
                "Schwab-Client-Ids": f"masterAccount={master_account},account={account}"
            },
        )
        return response.json()

    # =====================================================================
    # AS Feature Enrollment (segment: users)
    # =====================================================================

    def get_data_delivery_enrollment(self) -> dict:
        """Get data delivery enrollment status for the firm.

        Sandbox: VERIFIED - returns enrolled: true/false.
        Uses users/v2 segment. No Schwab-Client-Ids needed (firm-level).
        """
        response = self._request(
            "GET", "/data-delivery-enrollments", segment="users"
        )
        return response.json()

    def update_data_delivery_enrollment(self, enrolled: bool) -> None:
        """Update data delivery enrollment. Returns 204 on success.

        Sandbox: VERIFIED - toggles enrollment and change persists.
        """
        body = {"enrolled": enrolled}
        self._request(
            "PUT", "/data-delivery-enrollments", json_data=body, segment="users"
        )

    # =====================================================================
    # AS User Authorization (segment: users)
    # =====================================================================

    def get_user_authorizations(self) -> dict:
        """Get current user's authorization levels.

        Sandbox: VERIFIED - returns 22 authorization types with isAuthorized
        flags and isUserFsa (firm security admin) status.
        Uses users/v2 segment. No Schwab-Client-Ids needed.
        """
        response = self._request(
            "GET", "/authorizations", segment="users"
        )
        return response.json()

    # =====================================================================
    # AS Trading File Upload (segment: trading_upload)
    # =====================================================================

    # =====================================================================
    # AS Trading (segment: trading)
    # =====================================================================

    def submit_orders(
        self,
        equity_order_items: list[dict] | None = None,
        mutual_fund_order_items: list[dict] | None = None,
        validate_only: bool = True,
        should_override_warnings: bool = False,
    ) -> dict:
        """Submit or validate trading orders.

        Sandbox: VERIFIED - validate_only=True returns validation results.
        Uses trading/v1 segment. No Schwab-Client-Ids needed (account in body).

        Each equity order item requires: clientOrderIdentifier (UUID),
        masterAccount (int), account (int), quantity (int),
        securityIdentifier: {type: "Symbol"|"CUSIP", value: str},
        transactionType: {type: "Buy"|"Sell"|"SellShort"},
        orderType: {type: "Market"|"Limit"|"Stop"|"StopLimit"|"TrailingStop",
                    market: {duration: "Day"|"GoodTillCancel"|...}}.

        Args:
            validate_only: If True (default), validate without submitting.
                Set to False to actually submit orders.
        """
        body: dict = {
            "validateOnly": validate_only,
            "shouldOverrideWarnings": should_override_warnings,
        }
        if equity_order_items:
            body["equityOrderItems"] = equity_order_items
        if mutual_fund_order_items:
            body["mutualFundOrderItems"] = mutual_fund_order_items
        response = self._request(
            "POST", "/orders", json_data=body, segment="trading"
        )
        return response.json()

    def get_order_status(
        self,
        account: int | str,
        from_date: str,
        to_date: str,
        master_account: int | str | None = None,
        order_status: str = "All",
    ) -> dict:
        """Get status of trading orders.

        Sandbox: LOW - returns 500. May need specific order data.

        Args:
            order_status: One of All, Open, Filled, Canceled, Expired, Pending.
        """
        body: dict = {
            "account": int(account),
            "fromDate": from_date,
            "toDate": to_date,
            "orderStatus": order_status,
        }
        if master_account:
            body["masterAccount"] = int(master_account)
        response = self._request(
            "POST", "/orders/status", json_data=body, segment="trading"
        )
        return response.json()

    # =====================================================================
    # AS Trading File Upload (segment: trading_upload)
    # =====================================================================

    def upload_blotters(self, base64_file_content: str) -> None:
        """Upload trade blotter file. Returns 204 on success.

        Sandbox: LOW - endpoint accepts requests but needs real trade file.
        Uses trading/v2 segment.
        """
        body = {"base64EncodedFileContent": base64_file_content}
        self._request(
            "POST", "/upload-blotters", json_data=body, segment="trading_upload"
        )

    def upload_allocations(
        self,
        base64_file_content: str,
        master_account: int | str,
    ) -> None:
        """Upload allocation file. Returns 204 on success.

        Sandbox: LOW - endpoint accepts requests but needs real allocation file.
        Uses trading/v2 segment.
        """
        body = {
            "base64EncodedFileContent": base64_file_content,
            "masterAccount": master_account,
        }
        self._request(
            "POST", "/upload-allocations", json_data=body, segment="trading_upload"
        )
