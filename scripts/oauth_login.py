"""Guided Schwab sandbox OAuth login — end-to-end.

Uses the fly.io callback (the only redirect URI Schwab will accept for this
app) and, after you complete the login in the browser, syncs the resulting
tokens down to your local SCHWAB_TOKEN_FILE so the walkthrough picks them up.

Usage
-----
    source .env
    export API_KEY='<fly.io /oauth/tokens key>'
    poetry run python scripts/oauth_login.py

The API_KEY matches the ``API_KEY`` secret configured on the fly.io app
(``fly secrets list -a schwab-oauth`` shows its digest). If you don't have it
locally, grab it from 1Password or from ``fly secrets unset API_KEY && fly
secrets set API_KEY=<new>`` then redeploy.

Flow
----
1. Confirms fly.io server is reachable and prints current ``/oauth/status``.
2. Prints the authorize URL and opens it in the default browser.
3. Polls ``/oauth/status`` every 2 s for up to 3 minutes, watching for the
   ``expires_at`` timestamp to advance (= fly.io successfully exchanged a
   fresh code).
4. Pulls the new tokens via ``/oauth/tokens`` (API_KEY protected) and writes
   them to ``SCHWAB_TOKEN_FILE`` with 0o600 permissions.
5. Validates by constructing a ``SchwabAdvisorClient`` and pulling one alert.

Sandbox credentials for the Schwab login page:
    User ID:       dock_CERT1
    Password:      new1pass
    Security code: 123456
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime

import httpx

from schwab_advisor import SchwabAdvisorClient, SchwabAuth
from schwab_advisor.models import TokenResponse

GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"
CYAN = "\033[36m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

FLY_BASE = "https://schwab-oauth.fly.dev"
POLL_INTERVAL_S = 2
POLL_TIMEOUT_S = 180


def info(msg: str) -> None:
    print(f"{CYAN}[info]{RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{GREEN}[ok]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[warn]{RESET} {msg}")


def err(msg: str) -> None:
    print(f"{RED}[err]{RESET} {msg}")


def status() -> dict:
    """Return /oauth/status JSON from fly.io."""
    r = httpx.get(f"{FLY_BASE}/oauth/status", timeout=15)
    r.raise_for_status()
    return r.json()


def fetch_tokens(api_key: str) -> dict:
    """Fetch the token payload via the API-key-protected endpoint."""
    r = httpx.get(f"{FLY_BASE}/oauth/tokens", params={"key": api_key}, timeout=15)
    r.raise_for_status()
    return r.json()


def main() -> int:
    print(f"{BOLD}Schwab Sandbox OAuth — guided login{RESET}")
    print(f"{DIM}Started: {datetime.now().isoformat(timespec='seconds')}{RESET}")
    print()

    # 1. Require the fly.io API key up-front.
    api_key = os.environ.get("SCHWAB_OAUTH_API_KEY") or os.environ.get("API_KEY")
    if not api_key:
        err("SCHWAB_OAUTH_API_KEY (or API_KEY) environment variable not set.")
        print("  Add the fly.io /oauth/tokens key to .env:")
        print("      export SCHWAB_OAUTH_API_KEY='<value>'")
        print("  (Same as the API_KEY secret on the schwab-oauth fly app.)")
        return 2

    # 2. Probe fly.io.
    try:
        s0 = status()
    except httpx.HTTPError as e:
        err(f"Cannot reach fly.io /oauth/status: {e}")
        return 2
    ok(f"fly.io reachable; current auth: authenticated={s0['authenticated']} "
       f"expired={s0['expired']} expires_at={s0['expires_at']}")
    baseline_expires_at = s0.get("expires_at")

    # 3. Build the authorize URL and open it.
    auth = SchwabAuth.from_env()
    authorize_url = auth.get_authorization_url()
    info("Authorize URL:")
    print(f"  {authorize_url}")
    print()
    print(f"  {BOLD}Sandbox login:{RESET}  dock_CERT1 / new1pass   (MFA: 123456)")
    print()

    # Best-effort browser launch — macOS uses `open`, Linux `xdg-open`.
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    try:
        subprocess.run([opener, authorize_url], check=False)
        info(f"Opened authorize URL in browser via `{opener}`.")
    except FileNotFoundError:
        warn(f"`{opener}` not found; open the URL manually.")

    # 4. Poll /oauth/status until expires_at advances past the baseline.
    info(f"Polling {FLY_BASE}/oauth/status every {POLL_INTERVAL_S}s "
         f"(up to {POLL_TIMEOUT_S}s)…")
    deadline = time.time() + POLL_TIMEOUT_S
    new_status: dict | None = None
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL_S)
        try:
            s = status()
        except httpx.HTTPError as e:
            warn(f"  /oauth/status error ({e}) — retrying")
            continue
        exp = s.get("expires_at")
        authed = s.get("authenticated")
        expired = s.get("expired")
        print(f"  expires_at={exp}  expired={expired}")
        if authed and not expired and exp and exp != baseline_expires_at:
            new_status = s
            break
    if new_status is None:
        err("Timed out waiting for fly.io to exchange a fresh auth code.")
        print("  Possible causes:")
        print("   - Didn't complete the browser login.")
        print("   - Browser error page (code consumed twice, etc.).")
        print("   - fly.io app lacks the right SCHWAB_CLIENT_* secrets.")
        return 3
    ok(f"fly.io acquired fresh tokens. expires_at={new_status['expires_at']}")

    # 5. Pull tokens down.
    try:
        tokens_json = fetch_tokens(api_key)
    except httpx.HTTPError as e:
        err(f"/oauth/tokens fetch failed: {e}")
        return 4

    if not auth.token_file:
        err("SCHWAB_TOKEN_FILE not set in local env.")
        return 4
    auth.save_tokens(TokenResponse.from_dict(tokens_json))
    ok(f"Tokens written to {auth.token_file} (0600).")

    # 6. Sanity-check with a real API call.
    try:
        client = SchwabAdvisorClient()
        resp = client.get_alerts(page_limit=1, show_account="Show")
    except Exception as e:
        err(f"Client sanity call failed: {e}")
        return 5
    count = len(resp.alerts)
    ok(f"Client call succeeded — get_alerts returned {count} alert(s).")
    print()
    print(f"{GREEN}{BOLD}All good.{RESET}  Your local token file is fresh and the")
    print("walkthrough script (scripts/validation_walkthrough.py) can be run now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
