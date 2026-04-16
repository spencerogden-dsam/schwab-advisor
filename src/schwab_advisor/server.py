"""OAuth callback server for Schwab API authentication."""

import hmac
import html
import os
from functools import lru_cache

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

from .auth import SchwabAuth

app = FastAPI(title="Schwab OAuth Server")

API_KEY = os.environ.get("API_KEY", "")


@lru_cache
def get_auth() -> SchwabAuth:
    return SchwabAuth.from_env()


@app.get("/oauth/start")
def oauth_start(key: str = Query(...)):
    if not API_KEY or not hmac.compare_digest(key, API_KEY):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
def oauth_tokens(key: str = Query(...)):
    """Export tokens (API key protected) for syncing to local dev."""
    if not API_KEY or not hmac.compare_digest(key, API_KEY):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    tokens = get_auth().tokens
    if tokens is None:
        return JSONResponse({"error": "no tokens"}, status_code=404)
    return tokens.to_dict()
