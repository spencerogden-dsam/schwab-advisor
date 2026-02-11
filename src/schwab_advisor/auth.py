"""OAuth 2.0 authentication for Schwab Advisor API."""

import base64
import json
import os
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import httpx

from .models import TokenResponse

OAUTH_AUTHORIZE_URLS = {
    "sandbox": "https://sandbox.schwabapi.com/v1/oauth/authorize",
    "production": "https://api.schwabapi.com/v1/oauth/authorize",
}
OAUTH_TOKEN_URLS = {
    "sandbox": "https://sandbox.schwabapi.com/v1/oauth/token",
    "production": "https://api.schwabapi.com/v1/oauth/token",
}


class SchwabAuth:
    """Handle OAuth 2.0 authentication for Schwab API."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        token_file: str | Path | None = None,
        environment: Literal["sandbox", "production"] = "sandbox",
    ):
        """Initialize authentication handler.

        Args:
            client_id: OAuth client ID from Schwab Developer Portal.
            client_secret: OAuth client secret from Schwab Developer Portal.
            redirect_uri: Registered redirect URI for OAuth callback.
            token_file: Optional path to file for persisting tokens.
            environment: API environment, "sandbox" or "production".
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.token_file = Path(token_file).expanduser() if token_file else None
        self.environment = environment
        self._tokens: TokenResponse | None = None

    @property
    def authorize_url(self) -> str:
        """Get the OAuth authorize URL for current environment."""
        return OAUTH_AUTHORIZE_URLS[self.environment]

    @property
    def token_url(self) -> str:
        """Get the OAuth token URL for current environment."""
        return OAUTH_TOKEN_URLS[self.environment]

    @classmethod
    def from_env(cls) -> "SchwabAuth":
        """Create SchwabAuth from environment variables.

        Environment variables:
            SCHWAB_CLIENT_ID: OAuth client ID
            SCHWAB_CLIENT_SECRET: OAuth client secret
            SCHWAB_REDIRECT_URI: Redirect URI (default: https://127.0.0.1)
            SCHWAB_TOKEN_FILE: Token file path (default: ~/.schwab_tokens.json)
            SCHWAB_ENVIRONMENT: "sandbox" or "production" (default: sandbox)
        """
        client_id = os.environ.get("SCHWAB_CLIENT_ID")
        client_secret = os.environ.get("SCHWAB_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError(
                "SCHWAB_CLIENT_ID and SCHWAB_CLIENT_SECRET environment variables "
                "must be set"
            )
        environment = os.environ.get("SCHWAB_ENVIRONMENT", "sandbox")
        if environment not in ("sandbox", "production"):
            raise ValueError(
                "SCHWAB_ENVIRONMENT must be 'sandbox' or 'production', "
                f"got {environment}"
            )
        return cls(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=os.environ.get("SCHWAB_REDIRECT_URI", "https://127.0.0.1"),
            token_file=os.environ.get("SCHWAB_TOKEN_FILE", "~/.schwab_tokens.json"),
            environment=environment,
        )

    def get_authorization_url(self) -> str:
        """Generate the authorization URL for user to visit.

        Returns:
            URL to redirect user to for Schwab login and consent.
        """
        # Schwab only uses client_id and redirect_uri (no scope or response_type)
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
        }
        return f"{self.authorize_url}?{urllib.parse.urlencode(params)}"

    def _get_basic_auth_header(self) -> str:
        """Generate Basic auth header value."""
        credentials = f"{self.client_id}:{self.client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def exchange_code(self, authorization_code: str) -> TokenResponse:
        """Exchange authorization code for access and refresh tokens.

        Args:
            authorization_code: Code received from OAuth callback.

        Returns:
            TokenResponse with access and refresh tokens.
        """
        headers = {
            "Authorization": self._get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self.redirect_uri,
        }

        response = httpx.post(self.token_url, headers=headers, data=data)
        response.raise_for_status()

        token_data = response.json()
        tokens = self._parse_token_response(token_data)
        self._tokens = tokens

        if self.token_file:
            self.save_tokens(tokens)

        return tokens

    def refresh_tokens(self, refresh_token: str | None = None) -> TokenResponse:
        """Refresh the access token using the refresh token.

        Args:
            refresh_token: Refresh token to use. If not provided, uses stored token.

        Returns:
            TokenResponse with new access and refresh tokens.
        """
        if refresh_token is None:
            if self._tokens is None:
                self._tokens = self.load_tokens()
            if self._tokens is None:
                raise ValueError("No refresh token available")
            refresh_token = self._tokens.refresh_token

        headers = {
            "Authorization": self._get_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        response = httpx.post(self.token_url, headers=headers, data=data)
        response.raise_for_status()

        token_data = response.json()
        tokens = self._parse_token_response(token_data)
        self._tokens = tokens

        if self.token_file:
            self.save_tokens(tokens)

        return tokens

    def _parse_token_response(self, data: dict) -> TokenResponse:
        """Parse token response from API."""
        expires_in = data.get("expires_in", 1800)
        expires_at = datetime.now() + timedelta(seconds=expires_in)

        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=expires_in,
            scope=data.get("scope", ""),
            expires_at=expires_at,
        )

    def load_tokens(self) -> TokenResponse | None:
        """Load tokens from file.

        Returns:
            TokenResponse if file exists and is valid, None otherwise.
        """
        if self.token_file is None:
            return None

        try:
            with open(self.token_file) as f:
                data = json.load(f)
            self._tokens = TokenResponse.from_dict(data)
            return self._tokens
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None

    def save_tokens(self, tokens: TokenResponse) -> None:
        """Save tokens to file with restricted permissions.

        Args:
            tokens: TokenResponse to persist.
        """
        if self.token_file is None:
            return

        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.token_file, "w") as f:
            json.dump(tokens.to_dict(), f, indent=2)
        # Set restrictive permissions (owner read/write only)
        self.token_file.chmod(0o600)

    def get_access_token(self, auto_refresh: bool = True) -> str:
        """Get a valid access token, refreshing if needed.

        Args:
            auto_refresh: If True, automatically refresh expired tokens.

        Returns:
            Valid access token string.

        Raises:
            ValueError: If no valid token is available.
        """
        if self._tokens is None:
            self._tokens = self.load_tokens()

        if self._tokens is None:
            raise ValueError(
                "No tokens available. Run schwab-auth to authenticate first."
            )

        if self._tokens.is_expired() and auto_refresh:
            self.refresh_tokens()

        return self._tokens.access_token

    @property
    def tokens(self) -> TokenResponse | None:
        """Get current tokens, loading from file if needed."""
        if self._tokens is None:
            self._tokens = self.load_tokens()
        return self._tokens
