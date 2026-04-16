"""Tests for Schwab Advisor client."""

from unittest.mock import MagicMock, patch

import pytest
from schwab_advisor import __version__
from schwab_advisor.client import SchwabAdvisorClient
from schwab_advisor.models import (
    AlertArchiveResponse,
    AlertDetailResponse,
    AlertsResponse,
    AlertUpdateResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopicsResponse,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
)


def test_version():
    assert __version__ == "0.1.0"


def test_client_requires_auth_or_token():
    """Client must have either auth or access_token."""
    with pytest.raises(ValueError, match="Either auth or access_token"):
        SchwabAdvisorClient()


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
        resp = client.update_alert(15157510, {"isRead": True})
        assert isinstance(resp, AlertUpdateResponse)
        assert resp.id == "15157510"
        assert resp.raw_data is None


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
        assert resp.topic_name == "Money Movement"
        # Verify PascalCase flat body
        body = mock_request.call_args[1]["json"]
        assert body["TopicName"] == "Money Movement"
        assert body["MasterAccount"] == "8174295"
        assert "data" not in body  # not JSON:API wrapped


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
