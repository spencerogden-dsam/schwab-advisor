"""Tests for the FastAPI OAuth callback server."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from schwab_advisor.models import TokenResponse


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.get_authorization_url.return_value = "https://schwab.com/authorize?client_id=test"
    auth.tokens = None
    return auth


@pytest.fixture
def client(mock_auth):
    with patch.dict("os.environ", {"API_KEY": "test-api-key"}, clear=False):
        # Must import after env is set so API_KEY picks up the value
        import importlib
        import schwab_advisor.server as server_module
        importlib.reload(server_module)

        with patch.object(server_module, "get_auth", return_value=mock_auth):
            yield TestClient(server_module.app)


class TestOAuthStart:
    def test_start_with_valid_key(self, client, mock_auth):
        resp = client.get("/oauth/start?key=test-api-key")
        assert resp.status_code == 200
        assert "authorize_url" in resp.json()

    def test_start_with_invalid_key(self, client):
        resp = client.get("/oauth/start?key=wrong-key")
        assert resp.status_code == 401

    def test_start_missing_key(self, client):
        resp = client.get("/oauth/start")
        assert resp.status_code == 422  # FastAPI validation error


class TestOAuthCallback:
    def test_callback_success(self, client, mock_auth):
        mock_auth.exchange_code.return_value = TokenResponse(
            access_token="new_token", refresh_token="new_refresh",
            token_type="Bearer", expires_in=1800, scope="api",
            expires_at=datetime.now() + timedelta(seconds=1800),
        )
        resp = client.get("/oauth/callback?code=auth_code_123")
        assert resp.status_code == 200
        assert "Success" in resp.text
        mock_auth.exchange_code.assert_called_once_with("auth_code_123")

    def test_callback_error(self, client, mock_auth):
        mock_auth.exchange_code.side_effect = Exception("Token exchange failed")
        resp = client.get("/oauth/callback?code=bad_code")
        assert resp.status_code == 500
        assert "Error" in resp.text
        assert "Token exchange failed" in resp.text

    def test_callback_xss_protection(self, client, mock_auth):
        mock_auth.exchange_code.side_effect = Exception("<script>alert('xss')</script>")
        resp = client.get("/oauth/callback?code=xss")
        assert "<script>" not in resp.text
        assert "&lt;script&gt;" in resp.text


class TestOAuthStatus:
    def test_status_no_tokens(self, client, mock_auth):
        mock_auth.tokens = None
        resp = client.get("/oauth/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is False

    def test_status_with_valid_tokens(self, client, mock_auth):
        mock_auth.tokens = TokenResponse(
            access_token="t", refresh_token="r",
            token_type="Bearer", expires_in=1800, scope="api",
            expires_at=datetime.now() + timedelta(seconds=1800),
        )
        resp = client.get("/oauth/status")
        data = resp.json()
        assert data["authenticated"] is True
        assert data["expired"] is False

    def test_status_with_expired_tokens(self, client, mock_auth):
        mock_auth.tokens = TokenResponse(
            access_token="t", refresh_token="r",
            token_type="Bearer", expires_in=1800, scope="api",
            expires_at=datetime.now() - timedelta(seconds=100),
        )
        resp = client.get("/oauth/status")
        data = resp.json()
        assert data["authenticated"] is True
        assert data["expired"] is True


class TestOAuthTokens:
    def test_tokens_with_valid_key(self, client, mock_auth):
        mock_auth.tokens = TokenResponse(
            access_token="export_token", refresh_token="export_refresh",
            token_type="Bearer", expires_in=1800, scope="api",
            expires_at=datetime.now() + timedelta(seconds=1800),
        )
        resp = client.get("/oauth/tokens?key=test-api-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "export_token"

    def test_tokens_with_invalid_key(self, client):
        resp = client.get("/oauth/tokens?key=wrong")
        assert resp.status_code == 401

    def test_tokens_none(self, client, mock_auth):
        mock_auth.tokens = None
        resp = client.get("/oauth/tokens?key=test-api-key")
        assert resp.status_code == 404


class TestOAuthAccessToken:
    def test_access_token_with_valid_key(self, client, mock_auth):
        expires = datetime.now() + timedelta(seconds=1800)
        mock_auth.get_access_token.return_value = "fresh_access_token"
        mock_auth.tokens = TokenResponse(
            access_token="fresh_access_token", refresh_token="r",
            token_type="Bearer", expires_in=1800, scope="api",
            expires_at=expires,
        )
        resp = client.get("/oauth/access_token?key=test-api-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "fresh_access_token"
        assert data["expires_at"] == expires.isoformat()
        mock_auth.load_tokens.assert_called_once()
        mock_auth.get_access_token.assert_called_once_with(auto_refresh=True)

    def test_access_token_with_invalid_key(self, client):
        resp = client.get("/oauth/access_token?key=wrong")
        assert resp.status_code == 401

    def test_access_token_no_tokens(self, client, mock_auth):
        mock_auth.get_access_token.side_effect = ValueError("No tokens available")
        resp = client.get("/oauth/access_token?key=test-api-key")
        assert resp.status_code == 404
        assert "No tokens" in resp.json()["error"]
