"""OAuth callback server for Schwab API authentication."""

import hmac
import html
import os
from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from .auth import SchwabAuth

app = FastAPI(title="Schwab OAuth Server")

API_KEY = os.environ.get("API_KEY", "")


@lru_cache
def get_auth() -> SchwabAuth:
    return SchwabAuth.from_env()


def _verify_api_key(key: str = Query(...)) -> str:
    if not API_KEY or not hmac.compare_digest(key, API_KEY):
        raise HTTPException(status_code=401, detail="unauthorized")
    return key


@app.get("/oauth/start")
def oauth_start(_: str = Depends(_verify_api_key)):
    return {"authorize_url": get_auth().get_authorization_url()}


@app.get("/oauth/callback", response_class=HTMLResponse)
def oauth_callback(code: str = Query(...)):
    try:
        tokens = get_auth().exchange_code(code)
        return HTMLResponse(
            "<html><body><h1>Success!</h1>"
            f"<p>Authenticated. Token expires at {tokens.expires_at.isoformat()}.</p>"
            "</body></html>"
        )
    except Exception as e:
        return HTMLResponse(
            "<html><body><h1>Error</h1>"
            f"<p>{html.escape(str(e))}</p></body></html>",
            status_code=500,
        )


@app.get("/oauth/status")
def oauth_status():
    tokens = get_auth().tokens
    if tokens is None:
        return {"authenticated": False, "expired": None, "expires_at": None}
    return {
        "authenticated": True,
        "expired": tokens.is_expired(),
        "expires_at": tokens.expires_at.isoformat(),
    }


@app.get("/oauth/tokens")
def oauth_tokens(_: str = Depends(_verify_api_key)):
    """Export tokens (API key protected) for syncing to local dev."""
    tokens = get_auth().tokens
    if tokens is None:
        return JSONResponse({"error": "no tokens"}, status_code=404)
    return tokens.to_dict()


@app.get("/oauth/access_token")
def oauth_access_token(_: str = Depends(_verify_api_key)):
    """Return a fresh access token, auto-refreshing if expired.

    This endpoint is the single owner of refresh; downstream services call it
    instead of holding the refresh_token themselves so a refresh-token rotation
    can never produce a race between two refreshers.
    """
    auth = get_auth()
    # Reload from disk in case another worker/process refreshed.
    auth.load_tokens()
    try:
        access_token = auth.get_access_token(auto_refresh=True)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=404)
    tokens = auth.tokens
    return {
        "access_token": access_token,
        "expires_at": tokens.expires_at.isoformat() if tokens else None,
    }
