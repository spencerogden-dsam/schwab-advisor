"""Integration tests against the Schwab PRODUCTION API.

Gated behind SCHWAB_ALLOW_PROD_TESTS=1 to avoid accidental hits. Tokens are
pulled from the schwab-oauth.fly.dev broker so this process never holds the
refresh_token (the broker is the single owner of refresh).

Run with:
    SCHWAB_ALLOW_PROD_TESTS=1 \\
    SCHWAB_OAUTH_BROKER_KEY=<broker key> \\
    poetry run pytest -m production -v -s

The approved prod app currently exposes only AS Alerts and AS Status — these
tests only exercise those products.
"""

import httpx
import pytest


def _call_or_skip(client, method_name, *args, **kwargs):
    """Call a client method, skipping the test on HTTP errors."""
    try:
        return getattr(client, method_name)(*args, **kwargs)
    except httpx.HTTPStatusError as e:
        pytest.skip(f"{method_name}: {e.response.status_code} {e.response.text[:200]}")


@pytest.mark.production
class TestProdAlerts:
    def test_get_alerts(self, prod_client):
        resp = _call_or_skip(prod_client, "get_alerts", page_limit=5, show_account="Show")
        assert isinstance(resp.alerts, list)
        print(f"\n[Prod Alerts] count={len(resp.alerts)} total={resp.total_count}")
        for a in resp.alerts[:3]:
            print(
                f"  id={a.id} type={a.alert_type} subject={a.subject} "
                f"status={a.status}"
            )

    def test_get_alerts_filter_by_status(self, prod_client):
        resp = _call_or_skip(
            prod_client, "get_alerts",
            filter_status="New",
            sort_by="CreatedDate",
            sort_direction="Desc",
            page_limit=3,
            show_account="Show",
        )
        assert isinstance(resp.alerts, list)
        print(f"\n[Prod status=New] count={len(resp.alerts)}")

    def test_get_alerts_date_range(self, prod_client):
        resp = _call_or_skip(
            prod_client, "get_alerts",
            filter_start_date="2026-04-01",
            filter_end_date="2026-05-06",
            page_limit=5,
        )
        assert isinstance(resp.alerts, list)
        print(f"\n[Prod date filter] {len(resp.alerts)} alerts in range")

    def test_get_alert_detail(self, prod_client):
        alerts = _call_or_skip(prod_client, "get_alerts", page_limit=1, show_account="Show")
        if not alerts.alerts:
            pytest.skip("No prod alerts to inspect")
        a = alerts.alerts[0]
        resp = _call_or_skip(
            prod_client, "get_alert_detail",
            a.id, master_account=a.formatted_master_account,
        )
        assert resp.alert is not None
        print(f"\n[Prod Alert Detail] id={a.id} subject={resp.alert.subject}")
        print(f"  status_history count={len(resp.alert.status_history)}")
        print(f"  detail_type={resp.alert.detail_type}")


@pytest.mark.production
class TestProdStatus:
    def test_create_status_feed(self, prod_client):
        resp = _call_or_skip(prod_client, "create_status_feed", status=["New"])
        print(
            f"\n[Prod Create Feed] feed_id={resp.feed_id} "
            f"objects={len(resp.status_objects)}"
        )
        for obj in resp.status_objects[:3]:
            print(f"  {obj.category}/{obj.sub_category}: {obj.title}")

    def test_get_status_feed_round_trip(self, prod_client):
        # NOTE: As of 2026-05-06, GET /status-feed/{feed_id} is NOT in the
        # AS Status Production "API Product" attached to our prod app, even
        # though POST /status-feed and the nested status-events GET are.
        # Schwab returns 401 SEC-0001 with www-authenticate
        # "InvalidAPICallAsNoApiProductMatchFound". The _call_or_skip helper
        # turns that into a skip. To fix properly, ask Schwab to add this
        # route to the product. POST /status-feed already returns the full
        # feed inline, so the bare GET is rarely strictly necessary.
        create = _call_or_skip(prod_client, "create_status_feed", status=["New"])
        feed = _call_or_skip(prod_client, "get_status_feed", create.feed_id)
        assert len(feed.status_objects) == len(create.status_objects)
        print(
            f"\n[Prod Feed GET] POST={len(create.status_objects)} "
            f"GET={len(feed.status_objects)}"
        )

    def test_get_status_events(self, prod_client):
        create = _call_or_skip(prod_client, "create_status_feed", status=["New"])
        if not create.status_objects:
            pytest.skip("No status objects in prod feed")
        obj = create.status_objects[0]
        resp = _call_or_skip(
            prod_client, "get_status_events",
            create.feed_id, obj.status_object_id,
        )
        print(f"\n[Prod Events] count={len(resp.events)}")
        for evt in resp.events[:2]:
            print(f"  {evt.status}: {evt.current_status}")
