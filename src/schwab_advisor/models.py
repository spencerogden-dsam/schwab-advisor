"""Data models for Schwab Advisor API responses."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class TokenResponse:
    """OAuth token response from Schwab API."""

    access_token: str
    refresh_token: str
    token_type: str  # "Bearer"
    expires_in: int  # seconds
    scope: str
    expires_at: datetime  # calculated from expires_in

    def is_expired(self) -> bool:
        """Check if the access token has expired."""
        return datetime.now() >= self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenResponse":
        """Create TokenResponse from dictionary."""
        return cls(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            token_type=data["token_type"],
            expires_in=data["expires_in"],
            scope=data["scope"],
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


@dataclass
class AccountProfile:
    """Account profile information."""

    account_number: str
    account_type: str | None = None
    account_status: str | None = None
    account_name: str | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountProfile":
        """Create AccountProfile from API response dictionary."""
        return cls(
            account_number=data.get("accountNumber", ""),
            account_type=data.get("accountType"),
            account_status=data.get("accountStatus"),
            account_name=data.get("accountName"),
            raw_data=data,
        )


@dataclass
class AccountProfilesResponse:
    """Response from account-profiles endpoint."""

    profiles: list[AccountProfile]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountProfilesResponse":
        """Create AccountProfilesResponse from API response."""
        profiles = [
            AccountProfile.from_dict(p) for p in data.get("data", [])
        ]
        meta = data.get("meta", {})
        pagination = meta.get("pagination", {})
        return cls(
            profiles=profiles,
            next_cursor=pagination.get("nextCursor"),
            total_count=meta.get("totalCount"),
        )
