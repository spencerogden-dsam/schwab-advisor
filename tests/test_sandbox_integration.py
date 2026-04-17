"""Integration tests against the Schwab sandbox API.

Run with: source .env && pytest -m sandbox -v -s
"""

import pytest
import httpx


def _call_or_skip(client, method_name, *args, **kwargs):
    """Call a client method, skipping the test on HTTP errors."""
    try:
        return getattr(client, method_name)(*args, **kwargs)
    except httpx.HTTPStatusError as e:
        pytest.skip(f"{method_name}: {e.response.status_code}")


@pytest.mark.sandbox
class TestSandboxAlerts:
    def test_get_alerts(self, sandbox_client):
        resp = _call_or_skip(sandbox_client, "get_alerts", page_limit=5, show_account="Show")
        assert isinstance(resp.alerts, list)
        print(f"\n[Alerts] count={len(resp.alerts)} total={resp.total_count}")
        for a in resp.alerts[:2]:
            print(f"  id={a.id} type={a.alert_type} subject={a.subject} status={a.status}")

    def test_get_alerts_with_filter(self, sandbox_client):
        resp = _call_or_skip(
            sandbox_client, "get_alerts",
            filter_types=["UserAlert"],
            sort_by="CreatedDate",
            sort_direction="Desc",
            page_limit=3,
            show_account="Show",
        )
        assert isinstance(resp.alerts, list)
        print(f"\n[Alerts filtered] count={len(resp.alerts)}")

    def test_get_alert_detail(self, sandbox_client):
        alerts = _call_or_skip(sandbox_client, "get_alerts", page_limit=1, show_account="Show")
        if not alerts.alerts:
            pytest.skip("No alerts")
        a = alerts.alerts[0]
        resp = _call_or_skip(
            sandbox_client, "get_alert_detail",
            a.id, master_account=a.formatted_master_account,
        )
        assert resp.alert is not None
        print(f"\n[Alert Detail] subject={resp.alert.subject}")
        print(f"  status_history count={len(resp.alert.status_history)}")
        print(f"  detail_type={resp.alert.detail_type}")

    def test_archive_alert(self, sandbox_client):
        alerts = _call_or_skip(sandbox_client, "get_alerts", page_limit=1)
        if not alerts.alerts:
            pytest.skip("No alerts")
        resp = _call_or_skip(sandbox_client, "archive_alerts", [alerts.alerts[0].id])
        print(f"\n[Archive] all_archived={resp.are_all_archived}")
        for d in resp.archive_details:
            print(f"  id={d.alert_id} changed={d.has_status_changed}")

    def test_update_alert(self, sandbox_client):
        alerts = _call_or_skip(sandbox_client, "get_alerts", page_limit=1)
        if not alerts.alerts:
            pytest.skip("No alerts")
        resp = _call_or_skip(
            sandbox_client, "update_alert",
            alerts.alerts[0].id, "Unread",
        )
        print(f"\n[Update] id={resp.id}")


@pytest.mark.sandbox
class TestSandboxServiceRequests:
    def test_get_topics(self, sandbox_client):
        resp = _call_or_skip(sandbox_client, "get_service_request_topics")
        assert len(resp.topics) > 0
        print(f"\n[Topics] count={len(resp.topics)}")
        for t in resp.topics[:5]:
            subs = [s.name for s in t.sub_topics]
            print(f"  {t.name}: {subs[:3]}...")

    def test_create_service_request(self, sandbox_client):
        resp = _call_or_skip(
            sandbox_client, "create_service_request",
            topic_name="Money Movement",
            sub_topic_name="Other",
            description="Sandbox API test - please ignore",
            master_account="8174295",
        )
        print(f"\n[Create SR] id={resp.id} topic={resp.topic_name}")
        print(f"  creator={resp.creator} status_id={resp.status_id}")


@pytest.mark.sandbox
class TestSandboxStatus:
    def test_create_status_feed(self, sandbox_client):
        resp = _call_or_skip(sandbox_client, "create_status_feed", status=["New"])
        print(f"\n[Create Feed] feed_id={resp.feed_id} objects={len(resp.status_objects)}")
        for obj in resp.status_objects[:2]:
            print(f"  {obj.category}/{obj.sub_category}: {obj.title}")
            for evt in obj.status_events[:1]:
                print(f"    event: {evt.status} - {evt.current_status}")

    def test_get_status_feed(self, sandbox_client):
        create = _call_or_skip(sandbox_client, "create_status_feed", status=["New"])
        resp = _call_or_skip(sandbox_client, "get_status_feed", create.feed_id)
        print(f"\n[Get Feed] objects={len(resp.status_objects)}")
        for obj in resp.status_objects[:2]:
            print(f"  id={obj.status_object_id} category={obj.category}")

    def test_get_status_events(self, sandbox_client):
        create = _call_or_skip(sandbox_client, "create_status_feed", status=["New"])
        if not create.status_objects:
            pytest.skip("No status objects")
        obj = create.status_objects[0]
        resp = _call_or_skip(
            sandbox_client, "get_status_events",
            create.feed_id, obj.status_object_id,
        )
        print(f"\n[Events] count={len(resp.events)}")
        for evt in resp.events[:2]:
            print(f"  {evt.status}: {evt.current_status}")

    def test_create_status_feed_resolved(self, sandbox_client):
        resp = _call_or_skip(
            sandbox_client, "create_status_feed",
            status=["New", "Resolved"], show_account="Show",
        )
        print(f"\n[Feed New+Resolved] objects={len(resp.status_objects)}")


@pytest.mark.sandbox
class TestSandboxEdgeCases:
    """Edge cases and error behavior discovered during API exploration."""

    def test_alerts_max_page_size_is_500(self, sandbox_client):
        """page[limit] > 500 silently returns 0 results."""
        resp = _call_or_skip(sandbox_client, "get_alerts", page_limit=500)
        assert len(resp.alerts) > 0, "Expected alerts with limit=500"
        print(f"\n[Page limit] limit=500: {len(resp.alerts)} alerts, total={resp.total_count}")

    def test_alerts_pagination_no_overlap(self, sandbox_client):
        """Paginated pages don't return duplicate alerts."""
        page1 = _call_or_skip(sandbox_client, "get_alerts", page_limit=5)
        assert page1.next_cursor is not None
        page2 = _call_or_skip(
            sandbox_client, "get_alerts",
            page_limit=5, page_cursor=page1.next_cursor,
        )
        ids1 = {a.id for a in page1.alerts}
        ids2 = {a.id for a in page2.alerts}
        assert ids1.isdisjoint(ids2), f"Duplicate IDs across pages: {ids1 & ids2}"
        print(f"\n[Pagination] Page 1 IDs: {sorted(ids1)}, Page 2 IDs: {sorted(ids2)}")

    def test_alert_detail_requires_client_ids(self, sandbox_client):
        """GET /alerts/detail/{id} without Schwab-Client-Ids returns 400."""
        alerts = _call_or_skip(sandbox_client, "get_alerts", page_limit=1)
        if not alerts.alerts:
            pytest.skip("No alerts")
        try:
            sandbox_client.get_alert_detail(alerts.alerts[0].id)
            pytest.fail("Expected 400 without master_account")
        except httpx.HTTPStatusError as e:
            assert e.response.status_code == 400
            print(f"\n[Client-Ids required] Correctly got 400 without master_account")

    def test_invalid_alert_id_returns_404(self, sandbox_client):
        """Non-existent alert ID returns 404 SEC-0200."""
        try:
            sandbox_client.get_alert_detail(
                99999999, master_account="8174295"
            )
            pytest.fail("Expected 404 for invalid alert ID")
        except httpx.HTTPStatusError as e:
            assert e.response.status_code == 404
            print(f"\n[Invalid ID] Correctly got 404")

    def test_archive_empty_list_returns_400(self, sandbox_client):
        """Archiving empty list returns 400."""
        try:
            sandbox_client.archive_alerts([])
            pytest.fail("Expected 400 for empty archive list")
        except httpx.HTTPStatusError as e:
            assert e.response.status_code == 400
            print(f"\n[Empty archive] Correctly got 400")

    def test_alerts_date_filter(self, sandbox_client):
        """Date range filtering works on alerts."""
        resp = _call_or_skip(
            sandbox_client, "get_alerts",
            filter_start_date="2026-04-01",
            filter_end_date="2026-04-16",
            page_limit=5,
        )
        assert isinstance(resp.alerts, list)
        print(f"\n[Date filter] {len(resp.alerts)} alerts in date range")

    def test_alerts_all_sort_options(self, sandbox_client):
        """All documented sort fields work."""
        for sort_by in ["CreatedDate", "Status", "Type", "Subject", "Priority"]:
            resp = _call_or_skip(
                sandbox_client, "get_alerts",
                sort_by=sort_by, sort_direction="Desc", page_limit=1,
            )
            assert isinstance(resp.alerts, list)
        print(f"\n[Sort] All 5 sort fields accepted")

    def test_status_feed_get_returns_all_without_pagination(self, sandbox_client):
        """GET /status-feed/{id} returns all objects (no pagination support)."""
        create = _call_or_skip(sandbox_client, "create_status_feed", status=["New"])
        feed = _call_or_skip(sandbox_client, "get_status_feed", create.feed_id)
        assert len(feed.status_objects) == len(create.status_objects)
        print(f"\n[Feed GET] POST returned {len(create.status_objects)}, GET returned {len(feed.status_objects)}")
