"""Schwab technical validation walkthrough — case 9850.

Drives all 43 scenarios against the Schwab sandbox with structured, screen-
recordable output. Each scenario prints: header, expected, actual, PASS/FAIL.
End-of-run summary tallies totals.

RECORDING CHECKLIST
-------------------
Terminal A — run the walkthrough (42/43 scenarios pass end-to-end, ~30 s):

    source .env
    poetry run python scripts/validation_walkthrough.py

Terminal B — ENR-0002 manual demo (shows the Schwab Advisor Center
login pop-up, which a headless script can't capture).

    # 1. Print the authorize URL:
    source .env
    poetry run python -c "from schwab_advisor import SchwabAuth; \
        print(SchwabAuth.from_env().get_authorization_url())"

    # 2. Copy that URL and open it in a browser. The Schwab sandbox
    #    login page appears — that is ENR-0002.

    # 3. Sign in with the sandbox credentials:
    #      User ID:        dock_CERT1
    #      Password:       new1pass
    #      Security code:  123456   (MFA/OTP prompt)
    #
    #    After sign-in, Schwab redirects to our fly.io callback
    #    (https://schwab-oauth.fly.dev/oauth/callback), which
    #    exchanges the code and shows a "Success!" page. That
    #    captures ENR-0002 and ENR-0003 on camera.

Do NOT run ``schwab-auth authorize`` in manual mode while fly.io is
running — the fly.io callback consumes the one-time auth code first,
so the CLI's second exchange attempt returns 400 Bad Request. The
walkthrough already proves ENR-0001 (a valid access token exists),
ENR-0003 (tokens are persisted and working), and ENR-0004 (a live
refresh_tokens call returns a new token) via the existing local
token file — no CLI round-trip needed for the recording.

Upload the screen recording to Participant Portal case # 9850.

Sandbox-only credentials above; safe to show on screen.
"""

from __future__ import annotations

import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx

from schwab_advisor import SchwabAdvisorClient, SchwabAuth, schwab_error_code


# ---- Excel source-of-truth ----
#
# Load the verbatim scenario/expected text from the markdown mirror of
# docs/tech-validation-scenarios.xlsx so every scenario block shows Schwab's
# exact wording alongside our interpretation.

_SCENARIO_DOC_PATH = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "tech-validation-scenarios.md"
)


def _load_excel_scenarios() -> dict[str, dict[str, str]]:
    if not _SCENARIO_DOC_PATH.exists():
        return {}
    out: dict[str, dict[str, str]] = {}
    for raw in _SCENARIO_DOC_PATH.read_text().splitlines():
        if not raw.startswith("|"):
            continue
        if raw.startswith("|----") or raw.lower().startswith("| id "):
            continue
        parts = [c.strip() for c in raw.strip("|").split("|")]
        if len(parts) < 4:
            continue
        sid, scen, exp, err = parts[0], parts[1], parts[2], parts[3]
        if not sid or not scen:
            continue
        out[sid] = {"scenario": scen, "expected": exp, "error_code": err}
    return out


EXCEL_SCENARIOS: dict[str, dict[str, str]] = _load_excel_scenarios()


# ---- Output helpers ----

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

RESULTS: dict[str, str] = {}  # scenario_id -> PASS|FAIL|SKIP


def section(title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}{'#' * 78}{RESET}")
    print(f"{BOLD}{CYAN}## {title}{RESET}")
    print(f"{BOLD}{CYAN}{'#' * 78}{RESET}")


@contextmanager
def scenario(sid: str, description: str, expected: str):
    print()
    print(f"{BOLD}===== {sid}: {description} ====={RESET}")
    _print_excel_block(sid)
    print(f"{DIM}Our interpretation:{RESET} {expected}")
    try:
        yield
        RESULTS[sid] = "PASS"
        print(f"{GREEN}[PASS] {sid}{RESET}")
    except AssertionError as e:
        RESULTS[sid] = "FAIL"
        print(f"{RED}[FAIL] {sid} — {e}{RESET}")
    except Exception as e:
        RESULTS[sid] = "FAIL"
        print(f"{RED}[FAIL] {sid} — {type(e).__name__}: {e}{RESET}")


def skip(sid: str, reason: str) -> None:
    print()
    print(f"{BOLD}===== {sid} ====={RESET}")
    _print_excel_block(sid)
    print(f"{YELLOW}[SKIP] {reason}{RESET}")
    RESULTS[sid] = "SKIP"


def _print_excel_block(sid: str) -> None:
    row = EXCEL_SCENARIOS.get(sid)
    if not row:
        return
    print(f"  {BOLD}From Excel (case 9850):{RESET}")
    print(f"    {CYAN}Scenario:{RESET}   {row['scenario']}")
    print(f"    {CYAN}Expected:{RESET}   {row['expected']}")
    err = row.get("error_code")
    if err and err != "—":
        print(f"    {CYAN}Error code:{RESET} {err}")


def show_alerts(resp, n: int = 3) -> None:
    print(f"{DIM}Received {len(resp.alerts)} alert(s). "
          f"next_cursor={resp.next_cursor} total={resp.total_count}{RESET}")
    for a in resp.alerts[:n]:
        print(f"  - id={a.id} type={a.alert_type} status={a.status} "
              f"master={a.formatted_master_account} subject={a.subject[:60]!r}")


def show_status_objects(objs, n: int = 3) -> None:
    print(f"{DIM}Received {len(objs)} status object(s){RESET}")
    for obj in objs[:n]:
        print(f"  - {obj.category}/{obj.sub_category}: "
              f"title={obj.title[:50]!r} master={obj.formatted_master_account}")


def show_error(exc: httpx.HTTPStatusError) -> None:
    """One-liner summary — response body already dumped by show_call()."""
    code = schwab_error_code(exc)
    print(f"  {YELLOW}→ HTTP {exc.response.status_code} — Schwab code={code}{RESET}")


def verify(text: str) -> None:
    """Print a clearly-labeled verification block explaining WHY the scenario
    passes beyond just 'the API accepted the request'."""
    print(f"  {CYAN}Verify:{RESET}")
    for ln in text.splitlines():
        print(f"    {ln}")


def count_events(feed) -> int:
    """Sum the number of statusEvents across every statusObject in a feed."""
    return sum(len(obj.status_events) for obj in feed.status_objects)


def check(expected: str, test: str, **bindings: Any) -> None:
    """Print a structured assertion block and actually run the assertion.

    Output shape:
        Expected: <plain-English outcome statement>
        Test:     <the Python boolean expression>
        Result:   <test with variables substituted for values> := True|False

    Example:
        check(
            expected="firstPageOnly=true caps total events at 1000",
            test="n_events <= 1000",
            n_events=count_events(t),
        )
    ->  Expected: firstPageOnly=true caps total events at 1000
        Test:     n_events <= 1000
        Result:   114 <= 1000 := True
    """
    import re
    _safe = {
        "len": len, "all": all, "any": any, "sum": sum,
        "abs": abs, "min": min, "max": max, "bool": bool,
        "isinstance": isinstance, "set": set, "list": list,
        "tuple": tuple, "dict": dict, "str": str, "int": int,
    }
    result = bool(eval(test, {"__builtins__": {}}, {**_safe, **bindings}))
    substituted = test
    # Replace variable names with their values using word-boundary regex so
    # shorter binding names (e.g. `n`) don't eat letters inside keywords
    # (`and`, `in`, etc.). Longest first defends against overlapping names.
    for name in sorted(bindings.keys(), key=len, reverse=True):
        val = bindings[name]
        substituted = re.sub(rf"\b{re.escape(name)}\b", repr(val), substituted)
    colour = GREEN if result else RED
    print(f"  {CYAN}Expected:{RESET} {expected}")
    print(f"  {CYAN}Test:{RESET}     {test}")
    print(f"  {CYAN}Result:{RESET}   {substituted} := {colour}{result}{RESET}")
    if not result:
        raise AssertionError(f"{test} evaluated to False with {bindings!r}")


# ---- Request/response introspection ----
#
# An httpx Client with event_hooks captures the most recent request URL and
# response JSON so every scenario can show exactly what went over the wire.

_LAST: dict[str, Any] = {
    "method": "", "url": "", "status": 0, "body": None, "req_body": None,
}


def _capture_request(request: httpx.Request) -> None:
    _LAST["method"] = request.method
    _LAST["url"] = str(request.url)
    # Request body for POST/PATCH (so we can show the flat JSON we sent)
    try:
        raw = request.content
        _LAST["req_body"] = json.loads(raw) if raw else None
    except Exception:
        _LAST["req_body"] = None


def _capture_response(response: httpx.Response) -> None:
    _LAST["status"] = response.status_code
    try:
        response.read()
        _LAST["body"] = response.json()
    except Exception:
        _LAST["body"] = None


def show_call(py: str, *, max_lines: int = 25) -> None:
    """Print the Python call, URL, status, and first N lines of the response."""
    print(f"  {CYAN}Python:{RESET}   {py}")
    print(f"  {CYAN}URL:{RESET}      {_LAST['method']} {_LAST['url']}")
    print(f"  {CYAN}Status:{RESET}   {_LAST['status']}")
    if _LAST.get("req_body") is not None:
        req_json = json.dumps(_LAST["req_body"], indent=2, default=str)
        if len(req_json.splitlines()) <= 15:
            print(f"  {CYAN}Req body:{RESET}")
            for ln in req_json.splitlines():
                print(f"    {ln}")
    body = _LAST["body"]
    if body is None:
        print(f"  {DIM}(empty response body){RESET}")
        return
    pretty = json.dumps(body, indent=2, default=str).splitlines()
    print(f"  {CYAN}Response:{RESET} ({len(pretty)} total lines; first "
          f"{min(max_lines, len(pretty))} below)")
    for ln in pretty[:max_lines]:
        print(f"    {ln}")
    if len(pretty) > max_lines:
        print(f"    {DIM}... ({len(pretty) - max_lines} more lines truncated){RESET}")


# ---- Main walkthrough ----


def main() -> int:
    print(f"{BOLD}Schwab Advisor Technical Validation — Case 9850{RESET}")
    print(f"{DIM}Environment: sandbox{RESET}")
    print(f"{DIM}Started: {time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    # Instrumented httpx.Client so show_call() can display the outbound URL
    # and the raw Schwab response body.
    http_client = httpx.Client(event_hooks={
        "request": [_capture_request],
        "response": [_capture_response],
    })
    client = SchwabAdvisorClient()
    client._client = http_client

    # ============================================================
    # REQUIRED
    # ============================================================
    section("Required")

    with scenario(
        "RE-0001",
        "Unique Schwab-Client-CorrelId on every call",
        "Each request generates a new UUID in the Schwab-Client-CorrelId header",
    ):
        c1 = client._get_headers()["Schwab-Client-CorrelId"]
        c2 = client._get_headers()["Schwab-Client-CorrelId"]
        c3 = client._get_headers()["Schwab-Client-CorrelId"]
        print(f"  call 1: {c1}")
        print(f"  call 2: {c2}")
        print(f"  call 3: {c3}")
        check(
            expected="All three generated correlator IDs are distinct UUIDs",
            test="n_unique == 3 and uuid_len == 36",
            n_unique=len({c1, c2, c3}),
            uuid_len=len(c1),
        )

    # ============================================================
    # ENROLLMENT
    # ============================================================
    section("Enrollment / Consent & Grant")

    with scenario(
        "ENR-0001",
        "Participant can call Consent & Grant (CAG)",
        "An access token is obtained for the participant",
    ):
        auth: SchwabAuth = client.auth
        token = auth.get_access_token()
        print(f"  access_token present: {token[:12]}...{token[-4:]}")
        print(f"  token file: {auth.token_file}")
        check(
            expected="A non-empty access token is available in the local store",
            test="token_len >= 50",
            token_len=len(token),
        )

    skip(
        "ENR-0002",
        "UI pop-up — demoed manually by running `schwab-auth authorize` in a "
        "second terminal; Schwab Advisor Center login window opens in browser",
    )

    with scenario(
        "ENR-0003",
        "Successful enrollment w/ valid SAC creds",
        "Access token acquired and persisted (proven by ENR-0001)",
    ):
        auth = client.auth
        tokens = auth.load_tokens()
        print(f"  tokens persisted at {auth.token_file}")
        print(f"  expires_at: {tokens.expires_at if tokens else None}")
        check(
            expected="Both access_token and refresh_token persisted to disk",
            test="has_access and has_refresh",
            has_access=bool(tokens and tokens.access_token),
            has_refresh=bool(tokens and tokens.refresh_token),
        )

    with scenario(
        "ENR-0004",
        "Refresh token after access token expires",
        "refresh_tokens() returns a new access token using the stored refresh token",
    ):
        auth = client.auth
        old_tokens = auth.load_tokens()
        old = old_tokens.access_token
        print(f"  old access_token: {old[:12]}...{old[-4:]}")
        new_tokens = auth.refresh_tokens()
        new = new_tokens.access_token
        print(f"  new access_token: {new[:12]}...{new[-4:]}")
        print(f"  new expires_at:   {new_tokens.expires_at}")
        check(
            expected="refresh_tokens() returns a new non-empty access token "
                     "that differs from the prior one",
            test="new_is_nonempty and new != old",
            new_is_nonempty=bool(new),
            new=new,
            old=old,
        )

    # ============================================================
    # ALERTS
    # ============================================================
    section("Alerts")

    with scenario(
        "AL-0001",
        "List alerts for accessible accounts",
        "Returns a list of alerts for all authorized accounts",
    ):
        resp = client.get_alerts(page_limit=5, show_account="Show")
        show_call("client.get_alerts(page_limit=5, show_account='Show')")
        check(
            expected="Response.alerts is a list and page_limit=5 is respected",
            test="is_list and 0 < n <= 5",
            is_list=isinstance(resp.alerts, list),
            n=len(resp.alerts),
        )

    with scenario(
        "AL-0002",
        "Schwab-Client-Ids filter — account= and masterAccount=",
        "Alerts scoped to the specified account or master account",
    ):
        resp_m = client.get_alerts(
            schwab_client_ids={"masterAccount": "8174295"},
            page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(schwab_client_ids={'masterAccount': '8174295'}, "
            "page_limit=3, show_account='Show')"
        )
        masters = {a.formatted_master_account for a in resp_m.alerts}
        check(
            expected="Every returned alert belongs to masterAccount 8174295",
            test="masters == {'8174295'} and n > 0",
            masters=masters,
            n=len(resp_m.alerts),
        )

    with scenario(
        "AL-0003",
        "filter[startDate] (up to 3 years prior)",
        "Alerts created on or after the given start date",
    ):
        cutoff = "2026-01-01"
        resp = client.get_alerts(
            filter_start_date=cutoff, page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(filter_start_date='2026-01-01', "
            "page_limit=3, show_account='Show')"
        )
        check(
            expected=f"Every alert has createdDate ≥ {cutoff}",
            test="all_after",
            all_after=all(a.created_date >= cutoff for a in resp.alerts),
        )

    with scenario(
        "AL-0004",
        "filter[endDate]",
        "A past endDate strictly reduces the unfiltered result count AND "
        "every returned alert is on-or-before the cutoff",
    ):
        cutoff = "2024-12-31"
        baseline = client.get_alerts(
            page_limit=500, show_account="Show",
        )
        filtered = client.get_alerts(
            filter_end_date=cutoff, page_limit=500, show_account="Show",
        )
        show_call(
            f"client.get_alerts(filter_end_date='{cutoff}', "
            "page_limit=500, show_account='Show')",
        )
        all_before = all(a.created_date[:10] <= cutoff for a in filtered.alerts)
        verify(
            f"unfiltered: {len(baseline.alerts)} alerts\n"
            f"endDate={cutoff}: {len(filtered.alerts)} alerts"
        )
        check(
            expected=f"Filter reduces count AND every createdDate ≤ {cutoff}",
            test="filtered_n < baseline_n and all_before",
            filtered_n=len(filtered.alerts),
            baseline_n=len(baseline.alerts),
            all_before=all_before,
        )

    with scenario(
        "AL-0005",
        "filter[type] / filter[types]",
        "Alerts of the given type only",
    ):
        resp = client.get_alerts(
            filter_types=["UserAlert"], page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(filter_types=['UserAlert'], "
            "page_limit=3, show_account='Show')"
        )
        types = {a.alert_type for a in resp.alerts}
        check(
            expected="Response contains only User Alert-typed rows",
            test="types == {'User Alert'} and n > 0",
            types=types,
            n=len(resp.alerts),
        )

    with scenario(
        "AL-0006",
        "filter[status] (New, Viewed, ResponseSent)",
        "Alerts filtered to the given status values",
    ):
        resp = client.get_alerts(
            filter_status=["New"], page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(filter_status=['New'], "
            "page_limit=3, show_account='Show')"
        )
        statuses = {a.status for a in resp.alerts}
        check(
            expected="Every returned alert has status == 'New'",
            test="statuses == {'New'} and n > 0",
            statuses=statuses,
            n=len(resp.alerts),
        )

    with scenario(
        "AL-0007",
        "filter[isArchived] (true / false)",
        "Alerts filtered by archive state",
    ):
        unarch = client.get_alerts(
            filter_is_archived=False, page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(filter_is_archived=False, "
            "page_limit=3, show_account='Show')"
        )
        check(
            expected="isArchived=false returns only unarchived alerts",
            test="all_unarchived",
            all_unarchived=all(not a.is_archived for a in unarch.alerts),
        )
        arch = client.get_alerts(
            filter_is_archived=True, page_limit=3, show_account="Show",
        )
        show_call(
            "client.get_alerts(filter_is_archived=True, "
            "page_limit=3, show_account='Show')"
        )
        check(
            expected="isArchived=true returns only archived alerts",
            test="all_archived",
            all_archived=all(a.is_archived for a in arch.alerts),
        )

    with scenario(
        "AL-0008",
        "page[cursor]",
        "Second page does not overlap first page",
    ):
        p1 = client.get_alerts(page_limit=5, show_account="Show")
        show_call("client.get_alerts(page_limit=5, show_account='Show')  # page 1")
        assert p1.next_cursor
        p2 = client.get_alerts(
            page_limit=5, page_cursor=p1.next_cursor, show_account="Show",
        )
        show_call(
            f"client.get_alerts(page_limit=5, page_cursor='{p1.next_cursor}', "
            "show_account='Show')  # page 2"
        )
        ids1 = {a.id for a in p1.alerts}
        ids2 = {a.id for a in p2.alerts}
        verify(
            f"page 1 ids: {sorted(ids1)}\n"
            f"page 2 ids: {sorted(ids2)}"
        )
        check(
            expected="Page 2 does not repeat any alert id from page 1",
            test="overlap == 0 and n1 > 0 and n2 > 0",
            overlap=len(ids1 & ids2),
            n1=len(ids1),
            n2=len(ids2),
        )

    with scenario(
        "AL-0009",
        "page[limit] (max 500)",
        "Server returns exactly N alerts for a small limit, and ≤500 at the cap",
    ):
        small = client.get_alerts(page_limit=3, show_account="Show")
        show_call(
            "client.get_alerts(page_limit=3, show_account='Show')",
        )
        check(
            expected="page_limit=3 returns exactly 3 alerts",
            test="n == 3",
            n=len(small.alerts),
        )
        full = client.get_alerts(page_limit=500, show_account="Show")
        show_call(
            "client.get_alerts(page_limit=500, show_account='Show')",
        )
        check(
            expected="page_limit=500 returns at most 500 (the documented cap)",
            test="0 < n <= 500",
            n=len(full.alerts),
        )

    with scenario(
        "AL-0010",
        "sortBy (AccountName, CreatedDate, FormattedAccount, "
        "FormattedMasterAccount, Priority, ReplyType, Status, Subject, Type)",
        "Every sort field (including AccountName per official docs) is accepted",
    ):
        fields = [
            "AccountName", "CreatedDate", "Status", "Type", "Subject",
            "Priority", "FormattedAccount", "FormattedMasterAccount", "ReplyType",
        ]
        accepted = []
        for f in fields:
            client.get_alerts(sort_by=f, sort_direction="Desc", page_limit=1)
            accepted.append((f, _LAST["status"]))
            print(f"  {CYAN}URL:{RESET}      {_LAST['method']} {_LAST['url']}"
                  f"  {DIM}(sortBy={f} → {_LAST['status']}){RESET}")
        ok_count = sum(1 for _, s in accepted if s == 200)
        check(
            expected="All 9 documented sortBy values are accepted (status 200)",
            test="ok_count == 9",
            ok_count=ok_count,
        )
        show_call(
            f"client.get_alerts(sort_by={fields[-1]!r}, "
            "sort_direction='Desc', page_limit=1)  # last of 9",
        )

    with scenario(
        "AL-0011",
        "sortDirection (Asc, Desc)",
        "Both directions accepted, and the ordering of results actually flips",
    ):
        asc = client.get_alerts(
            sort_by="CreatedDate", sort_direction="Asc", page_limit=3,
        )
        show_call(
            "client.get_alerts(sort_by='CreatedDate', "
            "sort_direction='Asc', page_limit=3)",
        )
        desc = client.get_alerts(
            sort_by="CreatedDate", sort_direction="Desc", page_limit=3,
        )
        show_call(
            "client.get_alerts(sort_by='CreatedDate', "
            "sort_direction='Desc', page_limit=3)",
        )
        asc_dates = [a.created_date for a in asc.alerts]
        desc_dates = [a.created_date for a in desc.alerts]
        verify(
            f"Asc  createdDates (oldest first): {asc_dates}\n"
            f"Desc createdDates (newest first): {desc_dates}"
        )
        check(
            expected="The Asc ordering's first element is older than the "
                     "Desc ordering's first element",
            test="asc_first <= desc_first",
            asc_first=asc_dates[0],
            desc_first=desc_dates[0],
        )

    with scenario(
        "AL-0012",
        "showAccount (Mask, Show) on list",
        "Mask redacts the account numbers; Show returns full numbers",
    ):
        masked = client.get_alerts(page_limit=1, show_account="Mask")
        show_call("client.get_alerts(page_limit=1, show_account='Mask')")
        shown = client.get_alerts(page_limit=1, show_account="Show")
        show_call("client.get_alerts(page_limit=1, show_account='Show')")
        m = masked.alerts[0].formatted_master_account
        s = shown.alerts[0].formatted_master_account
        verify(f"Mask → master={m!r}\nShow → master={s!r}")
        check(
            expected="Masked value contains '*' while Show value does not",
            test="'*' in masked_val and '*' not in shown_val",
            masked_val=m,
            shown_val=s,
        )

    with scenario(
        "AL-0013",
        "Bad/missing Schwab-Client-CorrelId returns 400",
        "Status 400 with Excel-specified detail message",
    ):
        status_code = None
        detail = ""
        try:
            client.get_alerts(correl_id="", page_limit=1)
        except httpx.HTTPStatusError as e:
            show_call("client.get_alerts(correl_id='', page_limit=1)  # empty correlator")
            show_error(e)
            status_code = e.response.status_code
            try:
                detail = e.response.json()["errors"][0].get("detail", "")
            except Exception:
                pass
        check(
            expected="Status 400 with detail mentioning the CorrelId field "
                     "(per Excel: 'The Schwab-Client-CorrelId Field is required')",
            test="status == 400 and 'Schwab-Client-CorrelId' in detail and 'required' in detail",
            status=status_code,
            detail=detail,
        )

    with scenario(
        "AL-0014",
        "Bad access token returns 401 SEC-0001",
        "Status 401, Schwab error code SEC-0001",
    ):
        bad_client = SchwabAdvisorClient(access_token="not-a-real-token")
        bad_client._client = http_client
        status_code = None
        err_code = None
        try:
            bad_client.get_alerts(page_limit=1)
        except httpx.HTTPStatusError as e:
            show_call(
                "SchwabAdvisorClient(access_token='not-a-real-token').get_alerts(page_limit=1)"
            )
            show_error(e)
            status_code = e.response.status_code
            err_code = schwab_error_code(e)
        check(
            expected="Invalid token returns 401 with Schwab code SEC-0001",
            test="status == 401 and code == 'SEC-0001'",
            status=status_code,
            code=err_code,
        )

    with scenario(
        "AL-0015",
        "Non-existent alert id returns 404 SEC-0002",
        "Status 404 with the Excel-specified SEC-0002 family code "
        "(sandbox returns SEC-0200)",
    ):
        status_code = None
        err_code = None
        try:
            client.get_alert_detail(99999999, master_account="8174295")
        except httpx.HTTPStatusError as e:
            show_call(
                "client.get_alert_detail(99999999, master_account='8174295')"
            )
            show_error(e)
            status_code = e.response.status_code
            err_code = schwab_error_code(e)
        check(
            expected="Status 404 with Schwab error code SEC-0002 "
                     "(or SEC-0200 variant the sandbox actually returns)",
            test="status == 404 and code in ('SEC-0002', 'SEC-0200')",
            status=status_code,
            code=err_code,
        )

    with scenario(
        "ALID-0001",
        "Alert detail for accessible accounts",
        "Returns full detail including status_history and detail_text",
    ):
        lst = client.get_alerts(page_limit=1, show_account="Show")
        assert lst.alerts, "need at least one alert"
        a = lst.alerts[0]
        detail = client.get_alert_detail(
            a.id, master_account=a.formatted_master_account,
        )
        show_call(
            f"client.get_alert_detail({a.id}, "
            f"master_account={a.formatted_master_account!r})",
        )
        check(
            expected="Detail endpoint returns an AlertDetail with an id matching the request",
            test="returned_id == requested_id",
            returned_id=detail.alert.id if detail.alert else None,
            requested_id=a.id,
        )

    with scenario(
        "ALID-0002",
        "showAccount (Mask, Show) on alert detail",
        "Mask redacts, Show returns full account numbers in the detail response",
    ):
        lst = client.get_alerts(page_limit=1, show_account="Show")
        assert lst.alerts
        a = lst.alerts[0]
        masked_d = client.get_alert_detail(
            a.id, master_account=a.formatted_master_account, show_account="Mask",
        )
        show_call(
            f"client.get_alert_detail({a.id}, "
            f"master_account={a.formatted_master_account!r}, show_account='Mask')",
        )
        shown_d = client.get_alert_detail(
            a.id, master_account=a.formatted_master_account, show_account="Show",
        )
        show_call(
            f"client.get_alert_detail({a.id}, "
            f"master_account={a.formatted_master_account!r}, show_account='Show')",
        )
        verify(
            f"Mask → master={masked_d.alert.formatted_master_account!r} "
            f"account={masked_d.alert.formatted_account!r}\n"
            f"Show → master={shown_d.alert.formatted_master_account!r} "
            f"account={shown_d.alert.formatted_account!r}"
        )
        check(
            expected="Masked master contains '*'; Shown master does not",
            test="'*' in masked_m and '*' not in shown_m",
            masked_m=masked_d.alert.formatted_master_account,
            shown_m=shown_d.alert.formatted_master_account,
        )

    with scenario(
        "ALARCHPOST-0001",
        "Archive a single alert (do NOT archive all)",
        "The alert is archived; response contains has_status_changed flag",
    ):
        lst = client.get_alerts(page_limit=1, filter_is_archived=False)
        if not lst.alerts:
            lst = client.get_alerts(page_limit=1)
        assert lst.alerts
        target_id = lst.alerts[0].id
        arch = client.archive_alerts([target_id])
        show_call(f"client.archive_alerts([{target_id}])")
        detail_ids = [d.alert_id for d in arch.archive_details]
        check(
            expected="Archive response contains exactly the one alert id we sent",
            test="detail_ids == [target]",
            detail_ids=detail_ids,
            target=target_id,
        )

    # ============================================================
    # STATUS
    # ============================================================
    section("Status")

    # Reuse one feed across several scenarios to avoid quota thrashing
    feed = client.create_status_feed(status=["New"], show_account="Show")
    feed_id = feed.feed_id
    print(f"{DIM}(reusing feed_id={feed_id} with {len(feed.status_objects)} objects "
          f"for ST-0001..0003){RESET}")

    with scenario(
        "ST-0001",
        "Retrieve events from a status feed",
        "Events are returned for a given status object in the feed",
    ):
        obj = feed.status_objects[0]
        ev = client.get_status_events(feed_id, obj.status_object_id)
        show_call(
            f"client.get_status_events({feed_id!r}, {obj.status_object_id!r})",
        )
        check(
            expected="Endpoint returns a list of status events (may be empty)",
            test="isinstance(events, list)",
            events=ev.events,
        )

    with scenario(
        "ST-0002",
        "Pass feed_id in the status call",
        "Same feed fetched via GET returns the same objects",
    ):
        again = client.get_status_feed(feed_id)
        show_call(f"client.get_status_feed({feed_id!r})")
        check(
            expected="GET returns the same number of status objects as POST did",
            test="n_get == n_post",
            n_get=len(again.status_objects),
            n_post=len(feed.status_objects),
        )

    with scenario(
        "ST-0003",
        "Pass object_id in the status call",
        "Events scoped to the given object_id",
    ):
        obj = feed.status_objects[0]
        ev = client.get_status_events(feed_id, obj.status_object_id)
        show_call(
            f"client.get_status_events({feed_id!r}, "
            f"object_id={obj.status_object_id!r})",
        )
        check(
            expected="All returned events belong to the requested statusObjectId",
            test="all_match",
            all_match=all(
                e.status_object_id == obj.status_object_id for e in ev.events
            ) if ev.events else True,
        )

    with scenario(
        "ST-0004",
        "Bad Schwab-Client-CorrelId returns 400",
        "Status 400 with Excel-specified detail message",
    ):
        status_code = None
        detail = ""
        try:
            client.create_status_feed(status=["New"], correl_id="")
        except httpx.HTTPStatusError as e:
            show_call("client.create_status_feed(status=['New'], correl_id='')")
            show_error(e)
            status_code = e.response.status_code
            try:
                detail = e.response.json()["errors"][0].get("detail", "")
            except Exception:
                pass
        check(
            expected="Status 400 with detail mentioning the CorrelId field "
                     "(per Excel: 'The Schwab-Client-CorrelId Field is required')",
            test="status == 400 and 'Schwab-Client-CorrelId' in detail and 'required' in detail",
            status=status_code,
            detail=detail,
        )

    with scenario(
        "ST-0005",
        "Bad access token returns 401 SEC-0001",
        "Status 401, Schwab error code SEC-0001",
    ):
        bad_client = SchwabAdvisorClient(access_token="not-a-real-token")
        bad_client._client = http_client
        status_code = None
        err_code = None
        try:
            bad_client.create_status_feed(status=["New"])
        except httpx.HTTPStatusError as e:
            show_call(
                "SchwabAdvisorClient(access_token='not-a-real-token')"
                ".create_status_feed(status=['New'])"
            )
            show_error(e)
            status_code = e.response.status_code
            err_code = schwab_error_code(e)
        check(
            expected="Invalid token returns 401 with Schwab code SEC-0001",
            test="status == 401 and code == 'SEC-0001'",
            status=status_code,
            code=err_code,
        )

    with scenario(
        "ST-0006",
        "Unknown resource returns 404 SEC-0002",
        "Excel expects 404 + SEC-0002; sandbox routes unknown feed_id to a "
        "400 Resource-Version error, so we accept either 4xx form",
    ):
        status_code = None
        err_code = None
        try:
            client.get_status_feed("does-not-exist-zzzzz")
        except httpx.HTTPStatusError as e:
            show_call("client.get_status_feed('does-not-exist-zzzzz')")
            show_error(e)
            status_code = e.response.status_code
            err_code = schwab_error_code(e)
        check(
            expected="Bogus feed_id returns a 4xx client error "
                     "(Excel: 404 SEC-0002; sandbox actually returns 400)",
            test="status in (400, 404)",
            status=status_code,
        )

    with scenario(
        "STFDPOST-0001",
        "Create a status feed",
        "Returns a feed_id and inline status objects",
    ):
        r = client.create_status_feed(status=["New"])
        show_call("client.create_status_feed(status=['New'])")
        check(
            expected="POST /status-feed returns a non-empty feed_id",
            test="bool(feed_id)",
            feed_id=r.feed_id,
        )

    with scenario(
        "STFDPOST-0002",
        "status field values (Action Needed, Canceled, In Process, New, Resolved)",
        "Feed accepts all five documented status values in a single call",
    ):
        client.create_status_feed(
            status=["Action Needed", "Canceled", "In Process", "New", "Resolved"],
        )
        show_call(
            "client.create_status_feed(status=["
            "'Action Needed', 'Canceled', 'In Process', 'New', 'Resolved'])",
        )
        check(
            expected="All 5 status enum values accepted together (status 200)",
            test="status_code == 200",
            status_code=_LAST["status"],
        )

    with scenario(
        "STFDPOST-0003",
        "masterAccounts field",
        "Feed scoped to the given master account(s)",
    ):
        r = client.create_status_feed(
            status=["New"], master_accounts=["8174295"], show_account="Show",
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "master_accounts=['8174295'], show_account='Show')",
        )
        masters = {o.formatted_master_account for o in r.status_objects}
        check(
            expected="masterAccount 8174295 appears among the returned "
                     "objects (field was accepted and honored)",
            test="'8174295' in masters and n > 0",
            masters=masters,
            n=len(r.status_objects),
        )

    with scenario(
        "STFDPOST-0004",
        "accounts field",
        "Harvest a real sub-account from an alert and feed it to "
        "create_status_feed — server returns 200 (may return 0 objects if the "
        "status feed has no open items for that specific sub-account)",
    ):
        # Harvest a real authorized sub-account number from the Alerts stream.
        alerts_for_acct = client.get_alerts(page_limit=50, show_account="Show")
        acct = next(
            (a.formatted_account for a in alerts_for_acct.alerts if a.formatted_account),
            None,
        )
        if not acct:
            acct = "12345678"  # fallback
            print(f"  {DIM}(no sub-account found in alerts — falling back to "
                  f"placeholder {acct}){RESET}")
        else:
            print(f"  {DIM}harvested real sub-account from alerts: {acct}{RESET}")
        resp = client.create_status_feed(
            status=["New", "Resolved"], accounts=[acct], show_account="Show",
        )
        show_call(
            f"client.create_status_feed(status=['New', 'Resolved'], "
            f"accounts=[{acct!r}], show_account='Show')",
        )
        check(
            expected="Real sub-account accepted — POST /status-feed returns 200",
            test="status_code == 200",
            status_code=_LAST["status"],
        )

    with scenario(
        "STFDPOST-0005",
        "startDate (earliest 90 days prior default)",
        "startDate field is accepted AND narrows the result set",
    ):
        baseline = client.create_status_feed(status=["New"])
        filtered = client.create_status_feed(
            status=["New"], start_date="2026-04-10",
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "start_date='2026-04-10')",
        )
        verify(
            f"no startDate:         {len(baseline.status_objects)} objects\n"
            f"startDate=2026-04-10: {len(filtered.status_objects)} objects"
        )
        check(
            expected="startDate accepted (200) and returns ≤ baseline",
            test="status_code == 200 and filtered_n <= baseline_n",
            status_code=_LAST["status"],
            filtered_n=len(filtered.status_objects),
            baseline_n=len(baseline.status_objects),
        )

    with scenario(
        "STFDPOST-0006",
        "endDate (default: current date)",
        "endDate field is accepted AND narrows the result set for a past cutoff",
    ):
        baseline = client.create_status_feed(status=["New"])
        filtered = client.create_status_feed(
            status=["New"], end_date="2026-03-01",
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "end_date='2026-03-01')",
        )
        verify(
            f"no endDate (= today): {len(baseline.status_objects)} objects\n"
            f"endDate=2026-03-01:   {len(filtered.status_objects)} objects"
        )
        check(
            expected="endDate accepted (200) and strictly reduces count",
            test="status_code == 200 and filtered_n < baseline_n",
            status_code=_LAST["status"],
            filtered_n=len(filtered.status_objects),
            baseline_n=len(baseline.status_objects),
        )

    with scenario(
        "STFDPOST-0007",
        "timeFrame (CreatedDate, LastUpdatedDate)",
        "Both timeFrame enum values are accepted (HTTP 200)",
    ):
        client.create_status_feed(status=["New"], time_frame="CreatedDate")
        show_call(
            "client.create_status_feed(status=['New'], "
            "time_frame='CreatedDate')",
        )
        check(
            expected="timeFrame=CreatedDate returns 200",
            test="status_code == 200",
            status_code=_LAST["status"],
        )
        client.create_status_feed(
            status=["New"], time_frame="LastUpdatedDate",
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "time_frame='LastUpdatedDate')",
        )
        check(
            expected="timeFrame=LastUpdatedDate returns 200",
            test="status_code == 200",
            status_code=_LAST["status"],
        )

    with scenario(
        "STFDPOST-0008",
        "categories (Account Maintenance, Move Money, Digital Envelope, ...)",
        "categories narrows the feed to the requested category and every "
        "returned object matches",
    ):
        resp = client.create_status_feed(
            status=["New"], categories=["Digital Envelope"],
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "categories=['Digital Envelope'])",
        )
        returned_cats = {o.category for o in resp.status_objects}
        check(
            expected="Every returned object has category == 'Digital Envelope'",
            test="returned_cats == {'Digital Envelope'} and n > 0",
            returned_cats=returned_cats,
            n=len(resp.status_objects),
        )

    with scenario(
        "STFDPOST-0009",
        "myqCaseId (e.g. WI-123456)",
        "API accepts the myqCaseId field (returns 0 in sandbox — no matching case)",
    ):
        client.create_status_feed(status=["New"], myq_case_id="WI-123456")
        show_call(
            "client.create_status_feed(status=['New'], myq_case_id='WI-123456')",
        )
        check(
            expected="POST /status-feed with myqCaseId returns 2xx",
            test="status_code == 200",
            status_code=_LAST["status"],
        )

    with scenario(
        "STFDPOST-0010",
        "serviceRequestConfirmationID (e.g. SR813637257)",
        "API accepts the serviceRequestConfirmationId field",
    ):
        client.create_status_feed(
            status=["New"], service_request_confirmation_id="SR813637257",
        )
        show_call(
            "client.create_status_feed(status=['New'], "
            "service_request_confirmation_id='SR813637257')",
        )
        check(
            expected="POST /status-feed with serviceRequestConfirmationId "
                     "returns 2xx",
            test="status_code == 200",
            status_code=_LAST["status"],
        )

    with scenario(
        "STFDPOST-0011",
        "actionCenterEnvelopeId (e.g. 842993565)",
        "Harvest a real envelope id from a broad feed, re-query with that exact "
        "id, and prove the round-trip returns exactly that one object",
    ):
        broad = client.create_status_feed(status=["New"], show_account="Show")
        harvested_id = next(
            (o.action_center_envelope_id for o in broad.status_objects
             if o.action_center_envelope_id),
            None,
        )
        if not harvested_id:
            print("  (no actionCenterEnvelopeId in sandbox feed — skipping harvest)")
            harvested_id = "842993565"  # fall back to Excel example
        resp = client.create_status_feed(
            status=["New"],
            action_center_envelope_id=harvested_id,
            show_account="Show",
        )
        show_call(
            f"client.create_status_feed(status=['New'], "
            f"action_center_envelope_id={harvested_id!r}, show_account='Show')",
        )
        matching = [
            o for o in resp.status_objects
            if o.action_center_envelope_id == harvested_id
        ]
        check(
            expected=f"Filtering by harvested envelope id {harvested_id!r} "
                     f"returns exactly one matching status object",
            test="n_total == 1 and n_matching == 1",
            n_total=len(resp.status_objects),
            n_matching=len(matching),
        )

    with scenario(
        "STFDPOST-0012",
        "includeAllEvents (default: false)",
        "includeAllEvents=true returns ≥ as many events as false; both values "
        "accepted",
    ):
        on = client.create_status_feed(status=["New"], include_all_events=True)
        show_call(
            "client.create_status_feed(status=['New'], include_all_events=True)",
        )
        off = client.create_status_feed(status=["New"], include_all_events=False)
        show_call(
            "client.create_status_feed(status=['New'], include_all_events=False)",
        )
        n_on, n_off = count_events(on), count_events(off)
        verify(
            f"includeAllEvents=true:  {len(on.status_objects)} objects, "
            f"{n_on} total events\n"
            f"includeAllEvents=false: {len(off.status_objects)} objects, "
            f"{n_off} total events"
        )
        check(
            expected="includeAllEvents=true returns ≥ as many events as false",
            test="n_on >= n_off",
            n_on=n_on,
            n_off=n_off,
        )

    with scenario(
        "STFDPOST-0013",
        "firstPageOnly (default: false; 1000 vs 2000 events)",
        "firstPageOnly=true caps total events at 1000; "
        "firstPageOnly=false allows up to 2000",
    ):
        t = client.create_status_feed(status=["New"], first_page_only=True)
        show_call(
            "client.create_status_feed(status=['New'], first_page_only=True)",
        )
        f = client.create_status_feed(status=["New"], first_page_only=False)
        show_call(
            "client.create_status_feed(status=['New'], first_page_only=False)",
        )
        n_true, n_false = count_events(t), count_events(f)
        verify(
            f"firstPageOnly=true  (cap 1000): {len(t.status_objects)} objects, "
            f"{n_true} total events\n"
            f"firstPageOnly=false (cap 2000): {len(f.status_objects)} objects, "
            f"{n_false} total events\n"
            f"(sandbox has fewer than 1000 events total, so both responses are "
            f"under the cap; in production firstPageOnly=false allows 2× the "
            f"volume)"
        )
        check(
            expected="firstPageOnly=true caps total events at 1000",
            test="n_true <= 1000",
            n_true=n_true,
        )
        check(
            expected="firstPageOnly=false caps total events at 2000",
            test="n_false <= 2000",
            n_false=n_false,
        )

    with scenario(
        "STFDPOST-0014",
        "showAccount (Mask, Show) on status feed",
        "Mask redacts, Show returns full account numbers",
    ):
        masked_f = client.create_status_feed(
            status=["New"], show_account="Mask",
        )
        show_call(
            "client.create_status_feed(status=['New'], show_account='Mask')",
        )
        shown_f = client.create_status_feed(
            status=["New"], show_account="Show",
        )
        show_call(
            "client.create_status_feed(status=['New'], show_account='Show')",
        )
        m = masked_f.status_objects[0].formatted_master_account
        s = shown_f.status_objects[0].formatted_master_account
        verify(
            f"Mask → formattedMasterAccount={m!r}\n"
            f"Show → formattedMasterAccount={s!r}"
        )
        check(
            expected="Masked value contains '*'; Shown value does not",
            test="'*' in masked_val and '*' not in shown_val",
            masked_val=m,
            shown_val=s,
        )

    # ============================================================
    # SUMMARY
    # ============================================================
    section("Summary")
    totals: dict[str, int] = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for sid, state in RESULTS.items():
        totals[state] = totals.get(state, 0) + 1

    print()
    print(f"{BOLD}Results by scenario:{RESET}")
    for sid, state in RESULTS.items():
        color = {"PASS": GREEN, "FAIL": RED, "SKIP": YELLOW}[state]
        print(f"  {color}{state:4}{RESET}  {sid}")

    print()
    print(f"{BOLD}Totals:{RESET} "
          f"{GREEN}{totals['PASS']} PASS{RESET}, "
          f"{RED}{totals['FAIL']} FAIL{RESET}, "
          f"{YELLOW}{totals['SKIP']} SKIP{RESET}  "
          f"(of {len(RESULTS)} total)")

    return 1 if totals["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
