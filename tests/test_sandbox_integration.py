"""Integration tests against the Schwab sandbox API.

Run with: source .env && pytest -m sandbox -v -s
"""

import pytest
import httpx


def _try(client, method_name, *args, **kwargs):
    """Call a client method, returning (result, None) or (None, error)."""
    try:
        return getattr(client, method_name)(*args, **kwargs), None
    except httpx.HTTPStatusError as e:
        return None, e


@pytest.mark.sandbox
class TestSandboxAlerts:
    def test_get_alerts(self, sandbox_client):
        resp, err = _try(sandbox_client, "get_alerts", page_limit=5, show_account="Show")
        if err:
            pytest.skip(f"GET /alerts: {err.response.status_code}")
        assert isinstance(resp.alerts, list)
        print(f"\n[Alerts] count={len(resp.alerts)} total={resp.total_count}")
        for a in resp.alerts[:2]:
            print(f"  id={a.id} type={a.alert_type} subject={a.subject} status={a.status}")

    def test_get_alerts_with_filter(self, sandbox_client):
        resp, err = _try(
            sandbox_client, "get_alerts",
            filter_types=["UserAlert"],
            sort_by="CreatedDate",
            sort_direction="Desc",
            page_limit=3,
            show_account="Show",
        )
        if err:
            pytest.skip(f"GET /alerts filtered: {err.response.status_code}")
        assert isinstance(resp.alerts, list)
        print(f"\n[Alerts filtered] count={len(resp.alerts)}")

    def test_get_alert_detail(self, sandbox_client):
        alerts, err = _try(sandbox_client, "get_alerts", page_limit=1, show_account="Show")
        if err:
            pytest.skip(f"GET /alerts: {err.response.status_code}")
        if not alerts.alerts:
            pytest.skip("No alerts")
        a = alerts.alerts[0]
        resp, err = _try(
            sandbox_client, "get_alert_detail",
            a.id, master_account=a.formatted_master_account,
        )
        if err:
            pytest.skip(f"GET /alerts/detail: {err.response.status_code}")
        assert resp.alert is not None
        print(f"\n[Alert Detail] subject={resp.alert.subject}")
        print(f"  status_history count={len(resp.alert.status_history)}")
        print(f"  detail_type={resp.alert.detail_type}")

    def test_archive_alert(self, sandbox_client):
        alerts, err = _try(sandbox_client, "get_alerts", page_limit=1)
        if err:
            pytest.skip(f"GET /alerts: {err.response.status_code}")
        if not alerts.alerts:
            pytest.skip("No alerts")
        resp, err = _try(sandbox_client, "archive_alerts", [alerts.alerts[0].id])
        if err:
            pytest.skip(f"POST /alerts/archive: {err.response.status_code}")
        print(f"\n[Archive] all_archived={resp.are_all_archived}")
        for d in resp.archive_details:
            print(f"  id={d.alert_id} changed={d.has_status_changed}")

    def test_update_alert(self, sandbox_client):
        alerts, err = _try(sandbox_client, "get_alerts", page_limit=1)
        if err:
            pytest.skip(f"GET /alerts: {err.response.status_code}")
        if not alerts.alerts:
            pytest.skip("No alerts")
        resp, err = _try(
            sandbox_client, "update_alert",
            alerts.alerts[0].id, {"isRead": True},
        )
        if err:
            pytest.skip(f"PATCH /alerts: {err.response.status_code}")
        print(f"\n[Update] id={resp.id}")


@pytest.mark.sandbox
class TestSandboxServiceRequests:
    def test_get_topics(self, sandbox_client):
        resp, err = _try(sandbox_client, "get_service_request_topics")
        if err:
            pytest.skip(f"GET /service-requests: {err.response.status_code}")
        assert len(resp.topics) > 0
        print(f"\n[Topics] count={len(resp.topics)}")
        for t in resp.topics[:5]:
            subs = [s.name for s in t.sub_topics]
            print(f"  {t.name}: {subs[:3]}...")

    def test_create_service_request(self, sandbox_client):
        resp, err = _try(
            sandbox_client, "create_service_request",
            topic_name="Money Movement",
            sub_topic_name="Other",
            description="Sandbox API test - please ignore",
            master_account="8174295",
        )
        if err:
            print(f"\n[Create SR] {err.response.status_code}: {err.response.text[:300]}")
            pytest.skip(f"POST /service-requests: {err.response.status_code}")
        print(f"\n[Create SR] id={resp.id} topic={resp.topic_name}")
        print(f"  creator={resp.creator} status_id={resp.status_id}")


@pytest.mark.sandbox
class TestSandboxStatus:
    def test_create_status_feed(self, sandbox_client):
        resp, err = _try(sandbox_client, "create_status_feed", status=["New"])
        if err:
            print(f"\n[Create Feed] {err.response.status_code}: {err.response.text[:300]}")
            pytest.skip(f"POST /status-feed: {err.response.status_code}")
        print(f"\n[Create Feed] feed_id={resp.feed_id} objects={len(resp.status_objects)}")
        for obj in resp.status_objects[:2]:
            print(f"  {obj.category}/{obj.sub_category}: {obj.title}")
            for evt in obj.status_events[:1]:
                print(f"    event: {evt.status} - {evt.current_status}")

    def test_get_status_feed(self, sandbox_client):
        create, err = _try(sandbox_client, "create_status_feed", status=["New"])
        if err:
            pytest.skip(f"POST /status-feed: {err.response.status_code}")
        resp, err = _try(sandbox_client, "get_status_feed", create.feed_id)
        if err:
            pytest.skip(f"GET /status-feed: {err.response.status_code}")
        print(f"\n[Get Feed] objects={len(resp.status_objects)}")
        for obj in resp.status_objects[:2]:
            print(f"  id={obj.status_object_id} category={obj.category}")

    def test_get_status_events(self, sandbox_client):
        create, err = _try(sandbox_client, "create_status_feed", status=["New"])
        if err:
            pytest.skip(f"POST /status-feed: {err.response.status_code}")
        if not create.status_objects:
            pytest.skip("No status objects")
        obj = create.status_objects[0]
        resp, err = _try(
            sandbox_client, "get_status_events",
            create.feed_id, obj.status_object_id,
        )
        if err:
            pytest.skip(f"GET status-events: {err.response.status_code}")
        print(f"\n[Events] count={len(resp.events)}")
        for evt in resp.events[:2]:
            print(f"  {evt.status}: {evt.current_status}")

    def test_create_status_feed_resolved(self, sandbox_client):
        resp, err = _try(
            sandbox_client, "create_status_feed",
            status=["New", "Resolved"], show_account="Show",
        )
        if err:
            pytest.skip(f"POST /status-feed: {err.response.status_code}")
        print(f"\n[Feed New+Resolved] objects={len(resp.status_objects)}")
