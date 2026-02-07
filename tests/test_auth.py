"""Tests for Schwab OAuth authentication."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from schwab_advisor.auth import OAUTH_AUTHORIZE_URLS, OAUTH_TOKEN_URLS, SchwabAuth
from schwab_advisor.models import TokenResponse


class TestSchwabAuth:
    """Tests for SchwabAuth class."""

    def test_init(self):
        """Test basic initialization."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        assert auth.client_id == "test_id"
        assert auth.client_secret == "test_secret"
        assert auth.redirect_uri == "https://127.0.0.1"
        assert auth.token_file is None
        assert auth.environment == "sandbox"

    def test_init_with_token_file(self):
        """Test initialization with token file path."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
            token_file="~/.schwab_tokens.json",
        )
        assert auth.token_file == Path.home() / ".schwab_tokens.json"

    def test_init_with_environment(self):
        """Test initialization with production environment."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
            environment="production",
        )
        assert auth.environment == "production"
        assert auth.authorize_url == OAUTH_AUTHORIZE_URLS["production"]
        assert auth.token_url == OAUTH_TOKEN_URLS["production"]

    def test_sandbox_uses_sandbox_oauth_urls(self):
        """Test sandbox environment uses sandbox OAuth URLs."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
            environment="sandbox",
        )
        assert "sandbox.schwabapi.com" in auth.authorize_url
        assert "sandbox.schwabapi.com" in auth.token_url

    def test_from_env_missing_vars(self):
        """Test from_env raises when env vars missing."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="SCHWAB_CLIENT_ID"):
                SchwabAuth.from_env()

    def test_from_env_success(self):
        """Test from_env with all vars set."""
        env = {
            "SCHWAB_CLIENT_ID": "env_client_id",
            "SCHWAB_CLIENT_SECRET": "env_client_secret",
            "SCHWAB_REDIRECT_URI": "https://callback.example.com",
            "SCHWAB_TOKEN_FILE": "/tmp/tokens.json",
            "SCHWAB_ENVIRONMENT": "production",
        }
        with patch.dict("os.environ", env, clear=True):
            auth = SchwabAuth.from_env()
            assert auth.client_id == "env_client_id"
            assert auth.client_secret == "env_client_secret"
            assert auth.redirect_uri == "https://callback.example.com"
            assert auth.token_file == Path("/tmp/tokens.json")
            assert auth.environment == "production"

    def test_from_env_defaults(self):
        """Test from_env uses defaults for optional vars."""
        env = {
            "SCHWAB_CLIENT_ID": "test_id",
            "SCHWAB_CLIENT_SECRET": "test_secret",
        }
        with patch.dict("os.environ", env, clear=True):
            auth = SchwabAuth.from_env()
            assert auth.redirect_uri == "https://127.0.0.1"
            assert auth.token_file == Path.home() / ".schwab_tokens.json"
            assert auth.environment == "sandbox"


class TestAuthorizationUrl:
    """Tests for authorization URL generation."""

    def test_get_authorization_url(self):
        """Test authorization URL is correctly formatted."""
        auth = SchwabAuth(
            client_id="my_client_id",
            client_secret="my_secret",
            redirect_uri="https://127.0.0.1",
        )
        url = auth.get_authorization_url()

        # Default sandbox environment uses sandbox URL
        assert url.startswith(OAUTH_AUTHORIZE_URLS["sandbox"])
        assert "response_type=code" in url
        assert "client_id=my_client_id" in url
        assert "redirect_uri=https%3A%2F%2F127.0.0.1" in url

    def test_get_authorization_url_encodes_redirect(self):
        """Test redirect URI with port is properly encoded."""
        auth = SchwabAuth(
            client_id="test",
            client_secret="secret",
            redirect_uri="https://127.0.0.1:8443/callback",
        )
        url = auth.get_authorization_url()
        assert "redirect_uri=https%3A%2F%2F127.0.0.1%3A8443%2Fcallback" in url


class TestBasicAuth:
    """Tests for Basic authentication header."""

    def test_basic_auth_header(self):
        """Test Basic auth header is correctly encoded."""
        auth = SchwabAuth(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        header = auth._get_basic_auth_header()

        # "test_client:test_secret" base64 encoded
        import base64

        expected = base64.b64encode(b"test_client:test_secret").decode()
        assert header == f"Basic {expected}"


class TestTokenExchange:
    """Tests for token exchange."""

    def test_exchange_code_success(self):
        """Test successful code exchange."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "scope": "api",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            tokens = auth.exchange_code("auth_code_123")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == auth.token_url
            assert call_args.kwargs["data"]["grant_type"] == "authorization_code"
            assert call_args.kwargs["data"]["code"] == "auth_code_123"

            assert tokens.access_token == "new_access_token"
            assert tokens.refresh_token == "new_refresh_token"
            assert tokens.token_type == "Bearer"
            assert tokens.expires_in == 1800

    def test_refresh_tokens_success(self):
        """Test successful token refresh."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "refreshed_access",
            "refresh_token": "refreshed_refresh",
            "token_type": "Bearer",
            "expires_in": 1800,
            "scope": "api",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            tokens = auth.refresh_tokens("old_refresh_token")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == auth.token_url
            assert call_args.kwargs["data"]["grant_type"] == "refresh_token"

            assert tokens.access_token == "refreshed_access"


class TestTokenPersistence:
    """Tests for token save/load."""

    def test_save_and_load_tokens(self):
        """Test tokens can be saved and loaded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = Path(tmpdir) / "tokens.json"
            auth = SchwabAuth(
                client_id="test_id",
                client_secret="test_secret",
                redirect_uri="https://127.0.0.1",
                token_file=str(token_file),
            )

            tokens = TokenResponse(
                access_token="saved_access",
                refresh_token="saved_refresh",
                token_type="Bearer",
                expires_in=1800,
                scope="api",
                expires_at=datetime.now() + timedelta(seconds=1800),
            )

            auth.save_tokens(tokens)
            assert token_file.exists()

            # Check file permissions (Unix only)
            mode = token_file.stat().st_mode
            assert mode & 0o777 == 0o600

            # Load tokens
            loaded = auth.load_tokens()
            assert loaded is not None
            assert loaded.access_token == "saved_access"
            assert loaded.refresh_token == "saved_refresh"

    def test_load_tokens_file_not_found(self):
        """Test load_tokens returns None when file missing."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
            token_file="/nonexistent/path/tokens.json",
        )
        assert auth.load_tokens() is None

    def test_load_tokens_no_file_configured(self):
        """Test load_tokens returns None when no file configured."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        assert auth.load_tokens() is None


class TestGetAccessToken:
    """Tests for get_access_token method."""

    def test_get_access_token_no_tokens(self):
        """Test error when no tokens available."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        with pytest.raises(ValueError, match="No tokens available"):
            auth.get_access_token()

    def test_get_access_token_valid(self):
        """Test returns token when valid."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        auth._tokens = TokenResponse(
            access_token="valid_token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=1800,
            scope="api",
            expires_at=datetime.now() + timedelta(seconds=1800),
        )

        assert auth.get_access_token() == "valid_token"

    def test_get_access_token_auto_refresh(self):
        """Test auto-refresh when token expired."""
        auth = SchwabAuth(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="https://127.0.0.1",
        )
        auth._tokens = TokenResponse(
            access_token="expired_token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=1800,
            scope="api",
            expires_at=datetime.now() - timedelta(seconds=100),  # Expired
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
            "token_type": "Bearer",
            "expires_in": 1800,
            "scope": "api",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response):
            token = auth.get_access_token(auto_refresh=True)
            assert token == "new_token"


class TestTokenResponse:
    """Tests for TokenResponse model."""

    def test_is_expired_false(self):
        """Test is_expired returns False for valid token."""
        token = TokenResponse(
            access_token="token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=1800,
            scope="api",
            expires_at=datetime.now() + timedelta(seconds=1800),
        )
        assert token.is_expired() is False

    def test_is_expired_true(self):
        """Test is_expired returns True for expired token."""
        token = TokenResponse(
            access_token="token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=1800,
            scope="api",
            expires_at=datetime.now() - timedelta(seconds=100),
        )
        assert token.is_expired() is True

    def test_to_dict_and_from_dict(self):
        """Test serialization round-trip."""
        expires_at = datetime.now() + timedelta(seconds=1800)
        token = TokenResponse(
            access_token="token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=1800,
            scope="api",
            expires_at=expires_at,
        )

        data = token.to_dict()
        restored = TokenResponse.from_dict(data)

        assert restored.access_token == token.access_token
        assert restored.refresh_token == token.refresh_token
        assert restored.token_type == token.token_type
        assert restored.expires_in == token.expires_in
        assert restored.scope == token.scope
        # Datetime comparison (may have microsecond differences)
        assert abs((restored.expires_at - token.expires_at).total_seconds()) < 1
