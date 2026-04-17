"""Tests for Schwab Advisor client."""

from unittest.mock import MagicMock, patch

import pytest
from schwab_advisor import __version__
from schwab_advisor.client import SchwabAdvisorClient
import httpx

from schwab_advisor.models import (
    AccountHoldersResponse,
    AccountProfilesResponse,
    AccountRmdResponse,
    AccountRolesResponse,
    AccountsResponse,
    AccountSyncResponse,
    AlertArchiveResponse,
    AlertDetailResponse,
    AlertsResponse,
    AlertUpdateResponse,
    BalanceDetailResponse,
    BalanceListResponse,
    MasterAccountsResponse,
    PositionDetailResponse,
    PositionListResponse,
    PreferencesAndAuthorizationsResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopicsResponse,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
    TransactionsResponse,
)


def test_version():
    assert __version__ == "0.1.0"


def test_client_defaults_to_env_auth():
    """Client defaults to SchwabAuth.from_env() when no auth provided."""
    with patch.dict("os.environ", {"SCHWAB_TOKEN_FILE": "/tmp/test_tokens.json"}, clear=False):
        client = SchwabAdvisorClient()
        assert client.auth is not None
        assert client.environment == "sandbox"


def test_client_inherits_environment_from_auth():
    """Client infers environment from auth object."""
    from schwab_advisor.auth import SchwabAuth
    auth = SchwabAuth(
        client_id="id", client_secret="secret",
        redirect_uri="https://example.com", environment="production",
    )
    client = SchwabAdvisorClient(auth=auth)
    assert client.environment == "production"


def test_client_access_token_only_defaults_sandbox():
    """Client with only access_token defaults to sandbox environment."""
    client = SchwabAdvisorClient(access_token="test_token")
    assert client.environment == "sandbox"
    assert client.auth is None


def test_client_with_access_token():
    """Client can be created with direct access token."""
    client = SchwabAdvisorClient(access_token="test_token")
    assert client._access_token == "test_token"
    assert client._base_url("bulk") == "https://sandbox.schwabapi.com/as-integration/bulk/v2"
    assert client._base_url("accounts") == "https://sandbox.schwabapi.com/as-integration/accounts/v2"


def test_client_with_production_environment():
    """Client uses production URL when specified."""
    client = SchwabAdvisorClient(access_token="test_token", environment="production")
    assert client._base_url("bulk") == "https://api.schwabapi.com/as-integration/bulk/v2"
    assert client._base_url("accounts") == "https://api.schwabapi.com/as-integration/accounts/v2"


def test_client_with_custom_base_url():
    """Client accepts custom base URL (overrides segment routing)."""
    client = SchwabAdvisorClient(
        access_token="test_token", base_url="https://custom.example.com"
    )
    assert client._base_url("bulk") == "https://custom.example.com"
    assert client._base_url("accounts") == "https://custom.example.com"


def test_client_headers_no_body():
    """GET requests should not include Content-Type."""
    client = SchwabAdvisorClient(access_token="test_token", resource_version=2)
    headers = client._get_headers(has_body=False)
    assert headers["Authorization"] == "Bearer test_token"
    assert headers["Accept"] == "application/vnd.api+json"
    assert headers["Schwab-Resource-Version"] == "2"
    assert "Content-Type" not in headers


def test_client_headers_with_body():
    """POST requests should include Content-Type."""
    client = SchwabAdvisorClient(access_token="test_token")
    headers = client._get_headers(has_body=True)
    assert headers["Content-Type"] == "application/json"


def test_client_correlation_id_unique():
    """Each request gets a unique correlation ID."""
    client = SchwabAdvisorClient(access_token="test_token")
    headers1 = client._get_headers()
    headers2 = client._get_headers()
    assert headers1["Schwab-Client-CorrelId"] != headers2["Schwab-Client-CorrelId"]


def _mock_response(json_data, status_code=200):
    """Create a mock httpx response."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.status_code = status_code
    mock.raise_for_status.return_value = None
    return mock


# --- Alerts ---


class TestAlerts:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_alerts(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [
                {"id": 15157510, "type": "alert", "attributes": {
                    "formattedMasterAccount": "8174295",
                    "type": "User Alert", "status": "New",
                }},
            ],
            "meta": {"paging": {"nextCursor": "3"}, "count": {"actual": 1, "total": 825}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_alerts(page_limit=5)
        assert isinstance(resp, AlertsResponse)
        assert len(resp.alerts) == 1
        assert resp.alerts[0].id == 15157510
        assert resp.alerts[0].alert_type == "User Alert"
        assert resp.next_cursor == "3"
        # Verify it uses accounts segment
        url = mock_request.call_args[1].get("url", mock_request.call_args[0][1])
        assert "/accounts/v2/alerts" in url

    @patch("schwab_advisor.client.httpx.request")
    def test_get_alerts_with_filters(self, mock_request):
        mock_request.return_value = _mock_response({"data": [], "meta": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        client.get_alerts(
            filter_types=["UserAlert", "Trading"],
            sort_by="CreatedDate",
            sort_direction="Desc",
            show_account="Show",
        )
        params = mock_request.call_args[1]["params"]
        assert params["filter[types]"] == "UserAlert, Trading"
        assert params["sortBy"] == "CreatedDate"
        assert params["showAccount"] == "Show"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_alert_detail(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": 15157510, "type": "alert-detail", "attributes": {
                "type": "User Alert", "detailText": "<html>...</html>",
                "statusHistory": [{"status": "New"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_alert_detail(15157510, master_account="8174295")
        assert isinstance(resp, AlertDetailResponse)
        assert resp.alert.id == 15157510
        # Verify Schwab-Client-Ids header
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "masterAccount=8174295"

    @patch("schwab_advisor.client.httpx.request")
    def test_archive_alerts(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": "uuid", "type": "alerts-archive", "attributes": {
                "areAllArchived": True,
                "archiveDetails": [
                    {"alertId": 15157526, "hasArchivedStatusChanged": True,
                     "noArchivedStatusChangeReason": ""},
                ],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.archive_alerts([15157526])
        assert isinstance(resp, AlertArchiveResponse)
        assert resp.are_all_archived is True
        assert resp.archive_details[0].alert_id == 15157526
        # Verify flat body (not JSON:API)
        body = mock_request.call_args[1]["json"]
        assert body == {"alertIds": [15157526]}

    @patch("schwab_advisor.client.httpx.request")
    def test_update_alert_204(self, mock_request):
        mock_request.return_value = _mock_response({}, status_code=204)
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.update_alert(15157510, "Unread")
        assert isinstance(resp, AlertUpdateResponse)
        assert resp.id == "15157510"
        assert resp.raw_data is None
        body = mock_request.call_args[1]["json"]
        assert body == {"action": "Unread"}


# --- Service Requests ---


class TestServiceRequests:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_topics(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [
                {"id": "55df8198", "type": "service-request-topic", "attributes": {
                    "name": "Open New Account", "order": 1,
                    "subTopics": [
                        {"name": "Brokerage", "isAttachmentAllowed": True,
                         "isAttachmentRequired": True, "maxAttachmentSize": 30},
                    ],
                }},
            ],
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_service_request_topics()
        assert isinstance(resp, ServiceRequestTopicsResponse)
        assert len(resp.topics) == 1
        assert resp.topics[0].name == "Open New Account"
        assert resp.topics[0].sub_topics[0].name == "Brokerage"

    @patch("schwab_advisor.client.httpx.request")
    def test_create_service_request(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": "SR378912733804863", "type": "service-request",
                     "attributes": {
                         "topicName": "Money Movement",
                         "subTopicName": "Other",
                         "description": "Test",
                         "creator": "dock_CERT1",
                     }},
        }, status_code=201)
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.create_service_request(
            topic_name="Money Movement",
            sub_topic_name="Other",
            description="Test",
            master_account="8174295",
        )
        assert isinstance(resp, ServiceRequestCreateResponse)
        assert resp.id == "SR378912733804863"
        body = mock_request.call_args[1]["json"]
        assert body["topicName"] == "Money Movement"
        assert body["masterAccount"] == "8174295"


# --- Status ---


class TestStatus:
    @patch("schwab_advisor.client.httpx.request")
    def test_create_status_feed(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": "feed-uuid", "type": "status-feed", "attributes": {
                "statusObjects": [
                    {"statusObjectId": "obj-1", "category": "Envelope",
                     "title": "Test", "statusEvents": []},
                ],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.create_status_feed(status=["New"])
        assert isinstance(resp, StatusFeedCreateResponse)
        assert resp.feed_id == "feed-uuid"
        assert len(resp.status_objects) == 1
        # Verify body format
        body = mock_request.call_args[1]["json"]
        assert body["Status"] == ["New"]
        assert body["ShowAccount"] == "Mask"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_status_feed(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [
                {"id": "obj-1", "type": "status-object", "attributes": {
                    "category": "Digital Envelope", "title": "AC Open",
                    "formattedMasterAccount": "***4295",
                    "statusEvents": [
                        {"id": "evt-1", "type": "status-event",
                         "attributes": {"status": "New"}},
                    ],
                }},
            ],
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_status_feed("feed-uuid")
        assert isinstance(resp, StatusFeedResponse)
        assert len(resp.status_objects) == 1
        assert resp.status_objects[0].category == "Digital Envelope"
        assert len(resp.status_objects[0].status_events) == 1

    @patch("schwab_advisor.client.httpx.request")
    def test_get_status_events(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [
                {"id": "evt-1", "type": "status-event", "attributes": {
                    "statusObjectId": "obj-1", "status": "New",
                    "currentStatus": "Draft", "assignmentGroup": "Advisor",
                }},
            ],
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_status_events("feed-1", "obj-1")
        assert isinstance(resp, StatusEventsResponse)
        assert len(resp.events) == 1
        assert resp.events[0].status == "New"
        assert resp.events[0].assignment_group == "Advisor"
        # Verify URL
        url = mock_request.call_args[1].get("url", mock_request.call_args[0][1])
        assert "status-feed/feed-1/status-objects/obj-1/status-events" in url

    @patch("schwab_advisor.client.httpx.request")
    def test_post_status_events(self, mock_request):
        mock_request.return_value = _mock_response({"data": {"id": "batch-1"}})
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.post_status_events(
            myq_case_id="CASE123",
            master_account="8174295",
            message="Test event",
        )
        assert isinstance(resp, StatusEventsPostResponse)
        body = mock_request.call_args[1]["json"]
        assert body["myqCaseId"] == "CASE123"
        assert body["masterAccount"] == "8174295"
        assert body["message"] == "Test event"


# --- AS Account (bulk segment) ---


class TestAccountProfiles:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_profiles(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"attributes": {
                "formattedAccount": "1234-5678",
                "formattedMasterAccount": "MASTER-1",
                "accountRegistrationType": "Individual",
            }}],
            "meta": {"paging": {"nextCursor": "2"}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_account_profiles(page_limit=10, show_account="Show")
        assert isinstance(resp, AccountProfilesResponse)
        assert len(resp.profiles) == 1
        assert resp.profiles[0].formatted_account == "1234-5678"
        assert resp.next_cursor == "2"
        # Verify bulk segment
        call_kwargs = mock_request.call_args
        url = call_kwargs.kwargs.get("url", call_kwargs.args[1] if len(call_kwargs.args) > 1 else "")
        assert "/bulk/v2/account-profiles" in url
        params = mock_request.call_args[1]["params"]
        assert params["showAccount"] == "Show"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_profiles_with_total_count(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [],
            "meta": {"paging": {}, "count": {"actual": 0}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        client.get_account_profiles(include_total_count=True)
        params = mock_request.call_args[1]["params"]
        assert params["includeTotalCount"] == "true"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_all_account_profiles_pagination(self, mock_request):
        """Tests the pagination loop accumulates results and terminates."""
        mock_request.side_effect = [
            _mock_response({
                "data": [{"attributes": {"formattedAccount": "1111"}}],
                "meta": {"paging": {"nextCursor": "page2"}, "count": {"actual": 1}},
            }),
            _mock_response({
                "data": [{"attributes": {"formattedAccount": "2222"}}],
                "meta": {"paging": {}, "count": {"actual": 1}},
            }),
        ]
        client = SchwabAdvisorClient(access_token="test_token")
        profiles = client.get_all_account_profiles()
        assert len(profiles) == 2
        assert profiles[0].formatted_account == "1111"
        assert profiles[1].formatted_account == "2222"
        assert mock_request.call_count == 2

    @patch("schwab_advisor.client.httpx.request")
    def test_get_all_account_profiles_single_page(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"attributes": {"formattedAccount": "1111"}}],
            "meta": {"paging": {}, "count": {}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        profiles = client.get_all_account_profiles()
        assert len(profiles) == 1
        assert mock_request.call_count == 1

    @patch("schwab_advisor.client.httpx.request")
    def test_get_all_account_profiles_empty(self, mock_request):
        mock_request.return_value = _mock_response({"data": [], "meta": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        profiles = client.get_all_account_profiles()
        assert profiles == []


class TestTransactions:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_transactions(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "t1", "attributes": {"action": "MoneyLink Transfer", "amount": 100}}],
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_transactions("93319284")
        assert isinstance(resp, TransactionsResponse)
        assert len(resp.transactions) == 1
        # Verify Schwab-Client-Ids header
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "account=93319284"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_transaction_detail(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "t1", "attributes": {"action": "BUY"}}],
            "meta": {},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_transaction_detail("93319284")
        assert isinstance(resp, TransactionsResponse)


class TestAccountHolders:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_holder(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": "15568272", "type": "account-holder", "attributes": {
                "role": "LPOA", "name": "TEST LPOA",
                "formattedDateOfBirth": "1983-12-10",
                "citizenship": "US",
                "employment": {"employmentStatus": "EMPLOYED"},
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_account_holder("10001015", "15568272")
        assert resp["data"]["attributes"]["role"] == "LPOA"
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "account=10001015,accountHolderId=15568272"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_profiles(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "profiles", "attributes": {
                "profiles": [{"formattedAccount": "1234"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_profiles(["1234", "5678"])
        body = mock_request.call_args[1]["json"]
        assert body["Accounts"] == ["1234", "5678"]
        assert len(resp.profiles) == 1


class TestPreferences:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_preferences_and_authorizations(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"attributes": {"formattedAccount": "1234"}}],
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_preferences_and_authorizations(["1234"])
        assert isinstance(resp, PreferencesAndAuthorizationsResponse)
        assert len(resp.items) == 1
        body = mock_request.call_args[1]["json"]
        assert body["Accounts"] == ["1234"]


class TestNewEndpoints:
    @patch("schwab_advisor.client.httpx.request")
    def test_get_master_accounts(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "8174295", "type": "master-account", "attributes": {
                "masterAccountName": "TEST FIRM", "masterAccountType": "FA",
            }}],
            "meta": {"paging": {}, "count": {"actual": 1, "total": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_master_accounts()
        assert isinstance(resp, MasterAccountsResponse)
        assert resp.master_accounts[0].id == "8174295"
        assert resp.master_accounts[0].master_account_name == "TEST FIRM"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_accounts(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "10001015", "type": "account", "attributes": {
                "formattedMasterAccount": "8174295",
                "accountRegistrationType": "Indiv",
                "firstName": "TEST",
                "lastName": "USER",
                "clientIds": [803134686],
            }}],
            "meta": {"paging": {"nextCursor": "2"}, "count": {"actual": 1, "total": 84}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_accounts(show_account="Show")
        assert isinstance(resp, AccountsResponse)
        assert resp.accounts[0].first_name == "TEST"
        assert resp.next_cursor == "2"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_roles(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "abc", "attributes": {
                "formattedAccount": "1234", "formattedMasterAccount": "8174",
                "roles": [{"role": "CONTB", "firstName": "TEST"}],
            }}],
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_account_roles()
        assert len(resp.account_roles) == 1
        assert len(resp.account_roles[0].roles) == 1

    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_rmd(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "abc", "attributes": {
                "formattedAccount": "1234", "isRothIra": False,
                "rmdCurrentYear": 5000.0, "currentYear": 2026,
            }}],
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_account_rmd()
        assert resp.rmds[0].rmd_current_year == 5000.0

    @patch("schwab_advisor.client.httpx.request")
    def test_get_account_sync(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "uuid", "attributes": {
                "formattedAccount": "1234", "firstName": "TEST",
                "clientId": 803134686,
            }}],
            "meta": {"paging": {}, "count": {"actual": 1, "total": 88}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_account_sync()
        assert resp.records[0].client_id == 803134686

    @patch("schwab_advisor.client.httpx.request")
    def test_get_balance_detail(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": "uuid", "type": "balance-detail", "attributes": {
                "formattedAccount": "9284", "totalAccountValue": 1853622.91,
                "cash": 1768.46, "isMarginEnabled": False,
            }}],
            "meta": {},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_balance_detail("93319284")
        assert resp.balances[0].total_account_value == 1853622.91
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "account=93319284"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_balances_list(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "balances", "attributes": {
                "balances": [{"formattedAccount": "9284", "totalAccountValue": 100}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_balances_list(["93319284"])
        assert len(resp.balances) == 1
        body = mock_request.call_args[1]["json"]
        assert body["Accounts"] == ["93319284"]

    @patch("schwab_advisor.client.httpx.request")
    def test_get_position_detail(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "position-detail", "attributes": {
                "positions": [{"symbol": "AAPL", "quantity": 100}],
                "totalPositions": {"totalMarketValue": 15000},
            }},
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_position_detail("93319284")
        assert len(resp.positions) == 1
        assert resp.total_positions["totalMarketValue"] == 15000

    @patch("schwab_advisor.client.httpx.request")
    def test_get_positions_list(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "positions", "attributes": {
                "positions": [{"symbol": "AAPL"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_positions_list(["93319284"])
        assert len(resp.positions) == 1

    @patch("schwab_advisor.client.httpx.request")
    def test_get_reports(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "account-reports", "attributes": {
                "reports": [{"reportName": "Monthly Statement", "reportType": "Statements"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_reports("93319284")
        assert len(resp.reports) == 1
        assert resp.reports[0]["reportName"] == "Monthly Statement"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_cost_basis_account_preferences_master(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "account-preferences", "attributes": {
                "summary": {"formattedMasterAccount": "8174295", "statementType": "Compact"},
                "details": [
                    {"formattedAccount": "14217596", "accountTitle": "PETER",
                     "accountingMethod": "HCLOT", "initialCostBasisSource": "Schwab",
                     "isNonTaxableAccount": True, "onGainLossTab": False},
                ],
            }},
            "meta": {"paging": {}, "count": {"actual": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_cost_basis_account_preferences(master_account="8174295")
        assert resp.summary["statementType"] == "Compact"
        assert len(resp.details) == 1
        assert resp.details[0].accounting_method == "HCLOT"
        assert resp.details[0].is_non_taxable_account is True
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "masterAccount=8174295"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_cost_basis_rgl(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "rgl-transactions", "attributes": {
                "summary": {}, "transactions": [],
            }},
            "meta": {"paging": {}, "count": {"actual": 0}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_cost_basis_rgl_transactions("93319284")
        assert resp.transactions == []
        # Verify page_limit default is 100 (not 500)
        params = mock_request.call_args[1]["params"]
        assert params["page[limit]"] == 100

    @patch("schwab_advisor.client.httpx.request")
    def test_get_cost_basis_ugl(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "ugl-positions", "attributes": {
                "summary": {}, "positions": [],
            }},
            "meta": {},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_cost_basis_ugl_positions("93319284")
        assert resp.positions == []

    @patch("schwab_advisor.client.httpx.request")
    def test_search_clients(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{"id": 123, "type": "client-info", "attributes": {
                "firstName": "TEST", "lastName": "USER",
                "accountName": "Test Account",
            }}],
            "meta": {"count": {"actual": 1, "total": 1}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.search_clients(first_name="TEST")
        assert len(resp.clients) == 1
        assert resp.clients[0].first_name == "TEST"
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "firstName=TEST"

    @patch("schwab_advisor.client.httpx.request")
    def test_search_clients_combined(self, mock_request):
        mock_request.return_value = _mock_response({"data": [], "meta": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        client.search_clients(first_name="A", last_name="B")
        headers = mock_request.call_args[1]["headers"]
        assert headers["Schwab-Client-Ids"] == "firstName=A,lastName=B"

    def test_search_clients_requires_name(self):
        client = SchwabAdvisorClient(access_token="test_token")
        with pytest.raises(ValueError, match="At least one"):
            client.search_clients()

    @patch("schwab_advisor.client.httpx.request")
    def test_search_account_owners(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "account-owners", "attributes": {
                "accountOwners": [{"firstName": "TEST", "formattedAccount": "1234"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.search_account_owners(first_name="TEST")
        assert len(resp.account_owners) == 1
        body = mock_request.call_args[1]["json"]
        assert body["firstName"] == "TEST"

    @patch("schwab_advisor.client.httpx.request")
    def test_get_document_preferences(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"type": "document-preferences", "attributes": {
                "documentPreferences": [{"formattedAccount": "1234"}],
            }},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_document_preferences(["93319284"])
        assert len(resp.document_preferences) == 1

    @patch("schwab_advisor.client.httpx.request")
    def test_get_address_changes(self, mock_request):
        mock_request.return_value = _mock_response({"data": [], "included": []})
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_address_changes()
        assert resp.changes == []
        assert resp.included == []
        # No Schwab-Client-Ids header (firm-level endpoint)
        headers = mock_request.call_args[1]["headers"]
        assert "Schwab-Client-Ids" not in headers

    @patch("schwab_advisor.client.httpx.request")
    def test_get_address_changes_with_data(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": [{
                "id": "abc-uuid",
                "type": "address-change",
                "attributes": {
                    "actionSource": "ActionCenter",
                    "actionStatus": "Completed",
                    "createdDate": "2020-02-20T16:46:02.984",
                    "originalCustomerAddresses": [{"addressLine1": "123 Main"}],
                    "updatedCustomerAddresses": [{"addressLine1": "456 New St"}],
                },
                "relationships": {"firm": {"data": {"id": "71525", "type": "Firm"}}},
            }],
            "included": [{"id": "162669664", "type": "customer", "attributes": {"firstName": "John"}}],
        })
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.get_address_changes(filter_status="Completed", include_customer=True)
        assert len(resp.changes) == 1
        assert resp.changes[0].action_status == "Completed"
        assert resp.changes[0].original_customer_addresses[0]["addressLine1"] == "123 Main"
        assert resp.changes[0].relationships["firm"]["data"]["id"] == "71525"
        assert len(resp.included) == 1
        params = mock_request.call_args[1]["params"]
        assert params["filter[status]"] == "Completed"
        assert params["include"] == "customer"

    @patch("schwab_advisor.client.httpx.request")
    def test_upload_manfees(self, mock_request):
        mock_request.return_value = _mock_response({"data": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.upload_manfees("dGVzdA==")
        body = mock_request.call_args[1]["json"]
        assert body["Base64EncodedFileContent"] == "dGVzdA=="


# --- Context manager ---


class TestContextManager:
    @patch("schwab_advisor.client.httpx.Client")
    def test_enter_creates_client(self, mock_client_cls):
        client = SchwabAdvisorClient(access_token="test_token")
        assert client._client is None
        with client:
            assert client._client is not None
        mock_client_cls.return_value.close.assert_called_once()

    @patch("schwab_advisor.client.httpx.Client")
    def test_request_uses_persistent_client(self, mock_client_cls):
        mock_inner = MagicMock()
        mock_inner.request.return_value = _mock_response({"data": [], "meta": {}})
        mock_client_cls.return_value = mock_inner

        client = SchwabAdvisorClient(access_token="test_token")
        with client:
            client.get_alerts()
        mock_inner.request.assert_called_once()


# --- Error handling ---


class TestErrorHandling:
    @patch("schwab_advisor.client.httpx.request")
    def test_http_error_raises(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized", request=MagicMock(), response=mock_resp
        )
        mock_request.return_value = mock_resp

        client = SchwabAdvisorClient(access_token="test_token")
        with pytest.raises(httpx.HTTPStatusError):
            client.get_alerts()

    @patch("schwab_advisor.client.httpx.request")
    def test_update_alert_non_204_parses_json(self, mock_request):
        mock_request.return_value = _mock_response(
            {"data": {"id": "alert-1", "type": "alert"}}, status_code=200
        )
        client = SchwabAdvisorClient(access_token="test_token")
        resp = client.update_alert(123, "Unarchive")
        assert resp.id == "alert-1"
        assert resp.raw_data is not None


# --- Optional parameters on create methods ---


class TestOptionalParams:
    @patch("schwab_advisor.client.httpx.request")
    def test_create_service_request_with_account(self, mock_request):
        mock_request.return_value = _mock_response(
            {"data": {"id": "sr-1", "attributes": {}}}, status_code=201
        )
        client = SchwabAdvisorClient(access_token="test_token")
        client.create_service_request(
            topic_name="T", sub_topic_name="S", description="D",
            account="9999",
        )
        body = mock_request.call_args[1]["json"]
        assert body["account"] == "9999"

    @patch("schwab_advisor.client.httpx.request")
    def test_create_service_request_with_files(self, mock_request):
        mock_request.return_value = _mock_response(
            {"data": {"id": "sr-1", "attributes": {}}}, status_code=201
        )
        client = SchwabAdvisorClient(access_token="test_token")
        client.create_service_request(
            topic_name="T", sub_topic_name="S", description="D",
            master_account="1234",
            files=[{"name": "doc.pdf", "base64EncodedFileContent": "base64..."}],
        )
        body = mock_request.call_args[1]["json"]
        assert len(body["files"]) == 1
        assert body["files"][0]["name"] == "doc.pdf"

    @patch("schwab_advisor.client.httpx.request")
    def test_post_status_events_with_documents(self, mock_request):
        mock_request.return_value = _mock_response({"data": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        client.post_status_events(
            myq_case_id="CASE1", master_account="1234",
            documents=[{"name": "doc.pdf"}],
            status_object_id="obj-1",
        )
        body = mock_request.call_args[1]["json"]
        assert body["documents"] == [{"name": "doc.pdf"}]
        assert body["statusObjectId"] == "obj-1"
        assert "message" not in body

    @patch("schwab_advisor.client.httpx.request")
    def test_get_alert_detail_without_master_account(self, mock_request):
        mock_request.return_value = _mock_response({
            "data": {"id": 123, "attributes": {}},
        })
        client = SchwabAdvisorClient(access_token="test_token")
        client.get_alert_detail(123)
        headers = mock_request.call_args[1]["headers"]
        assert "Schwab-Client-Ids" not in headers

    @patch("schwab_advisor.client.httpx.request")
    def test_get_alerts_with_all_filters(self, mock_request):
        mock_request.return_value = _mock_response({"data": [], "meta": {}})
        client = SchwabAdvisorClient(access_token="test_token")
        client.get_alerts(
            filter_types=["UserAlert"],
            filter_subjects=["User ID Activation"],
            filter_start_date="2026-04-01",
            filter_end_date="2026-04-15",
            sort_by="CreatedDate",
            sort_direction="Asc",
            show_account="Show",
            page_limit=10,
        )
        params = mock_request.call_args[1]["params"]
        assert params["filter[subjects]"] == "User ID Activation"
        assert params["filter[startDate]"] == "2026-04-01"
        assert params["filter[endDate]"] == "2026-04-15"
        assert params["sortDirection"] == "Asc"
        assert params["page[limit]"] == 10


# --- Extra header merging ---


class TestExtraHeaders:
    def test_extra_headers_merge(self):
        client = SchwabAdvisorClient(access_token="test_token")
        headers = client._get_headers(
            extra_headers={"Schwab-Client-Ids": "masterAccount=123"}
        )
        assert headers["Schwab-Client-Ids"] == "masterAccount=123"
        assert "Authorization" in headers
