"""Data models for Schwab Advisor API responses."""

from dataclasses import dataclass, field
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


# --- Pagination helpers ---


def _parse_meta(data: dict) -> tuple[str | None, int | None]:
    """Extract next_cursor and count from JSON:API meta."""
    meta = data.get("meta", {})
    paging = meta.get("paging", {})
    count = meta.get("count", {})
    return paging.get("nextCursor"), count.get("actual")


# --- Account Profiles (AS Account) ---


@dataclass
class Address:
    """Mailing or physical address."""

    address_line1: str = ""
    address_line2: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    country: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Address":
        return cls(
            address_line1=data.get("addressLine1", ""),
            address_line2=data.get("addressLine2", ""),
            city=data.get("city", ""),
            state=data.get("state", ""),
            zip_code=data.get("zipCode", ""),
            country=data.get("country", ""),
        )


@dataclass
class AccountProfile:
    """Account profile from /account-profiles."""

    formatted_account: str = ""
    formatted_master_account: str = ""
    master_accounts: list[dict] = field(default_factory=list)
    registration_type: str = ""
    title1: str = ""
    title2: str = ""
    title3: str = ""
    established_date: str = ""
    last_updated_date: str = ""
    email: str = ""
    home_phone: str = ""
    business_phone: str = ""
    mailing_address: Address | None = None
    is_money_link_enabled: bool = False
    is_margin_enabled: bool = False
    is_fee_payment_authorized: bool = False
    restriction_codes: list[str] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountProfile":
        """Create from JSON:API data item (with id/type/attributes)."""
        attrs = data.get("attributes", data)
        addr = attrs.get("mailingAddress")
        return cls(
            formatted_account=attrs.get("formattedAccount", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            master_accounts=attrs.get("masterAccounts", []),
            registration_type=attrs.get("accountRegistrationType", ""),
            title1=attrs.get("accountTitle1", ""),
            title2=attrs.get("accountTitle2", ""),
            title3=attrs.get("accountTitle3", ""),
            established_date=attrs.get("establishedDate", ""),
            last_updated_date=attrs.get("lastUpdatedDate", ""),
            email=attrs.get("emailAddress", ""),
            home_phone=attrs.get("homePhone", ""),
            business_phone=attrs.get("businessPhone", ""),
            mailing_address=Address.from_dict(addr) if addr else None,
            is_money_link_enabled=attrs.get("isMoneyLinkEnabled", False),
            is_margin_enabled=attrs.get("isMarginEnabled", False),
            is_fee_payment_authorized=attrs.get(
                "isFeePaymentAuthorizationEnabled", False
            ),
            restriction_codes=attrs.get("restrictionCodes", []),
            raw_data=data,
        )


@dataclass
class AccountProfilesResponse:
    """Response from /account-profiles."""

    profiles: list[AccountProfile]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountProfilesResponse":
        profiles = [AccountProfile.from_dict(p) for p in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(profiles=profiles, next_cursor=next_cursor, total_count=count)


# --- Alerts ---


@dataclass
class Alert:
    """Alert from /alerts."""

    id: str = ""
    formatted_account: str = ""
    formatted_master_account: str = ""
    alert_type: str = ""
    status: str = ""
    description: str = ""
    created_date: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            alert_type=attrs.get("alertType", ""),
            status=attrs.get("status", ""),
            description=attrs.get("description", ""),
            created_date=attrs.get("createdDate", ""),
            raw_data=data,
        )


@dataclass
class AlertsResponse:
    """Response from /alerts."""

    alerts: list[Alert]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertsResponse":
        alerts = [Alert.from_dict(a) for a in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(alerts=alerts, next_cursor=next_cursor, total_count=count)


# --- Transactions ---


@dataclass
class Transaction:
    """Transaction from /transactions."""

    id: str = ""
    formatted_account: str = ""
    transaction_type: str = ""
    description: str = ""
    trade_date: str = ""
    settlement_date: str = ""
    amount: float = 0.0
    symbol: str = ""
    quantity: float = 0.0
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            transaction_type=attrs.get("transactionType", ""),
            description=attrs.get("description", ""),
            trade_date=attrs.get("tradeDate", ""),
            settlement_date=attrs.get("settlementDate", ""),
            amount=float(attrs.get("amount", 0)),
            symbol=attrs.get("symbol", ""),
            quantity=float(attrs.get("quantity", 0)),
            raw_data=data,
        )


@dataclass
class TransactionsResponse:
    """Response from /transactions."""

    transactions: list[Transaction]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "TransactionsResponse":
        txns = [Transaction.from_dict(t) for t in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(transactions=txns, next_cursor=next_cursor, total_count=count)


# --- Standing Instructions (SLOA) ---


@dataclass
class StandingInstruction:
    """Standing instruction from /standing-instructions."""

    id: str = ""
    formatted_account: str = ""
    instruction_type: str = ""
    status: str = ""
    counter_party: dict | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StandingInstruction":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            instruction_type=attrs.get("instructionType", ""),
            status=attrs.get("status", ""),
            counter_party=attrs.get("counterParty"),
            raw_data=data,
        )


@dataclass
class StandingInstructionsResponse:
    """Response from /standing-instructions."""

    instructions: list[StandingInstruction]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StandingInstructionsResponse":
        items = [StandingInstruction.from_dict(i) for i in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(instructions=items, next_cursor=next_cursor, total_count=count)


# --- Profiles (account holders) ---


@dataclass
class AccountHolder:
    """Account holder from /profiles/account-holders."""

    formatted_account: str = ""
    first_name: str = ""
    middle_name: str = ""
    last_name: str = ""
    date_of_birth: str = ""
    mailing_address: Address | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountHolder":
        attrs = data.get("attributes", data)
        addr = attrs.get("mailingAddress")
        return cls(
            formatted_account=attrs.get("formattedAccount", ""),
            first_name=attrs.get("firstName", ""),
            middle_name=attrs.get("middleName", ""),
            last_name=attrs.get("lastName", ""),
            date_of_birth=attrs.get("formattedDateOfBirth", ""),
            mailing_address=Address.from_dict(addr) if addr else None,
            raw_data=data,
        )


@dataclass
class AccountHoldersResponse:
    """Response from /profiles/account-holders."""

    holders: list[AccountHolder]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountHoldersResponse":
        holders = [AccountHolder.from_dict(h) for h in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(holders=holders, next_cursor=next_cursor, total_count=count)


# --- Preferences and Authorizations ---


@dataclass
class PreferencesAndAuthorizations:
    """Account preferences from /preferences-and-authorizations/list."""

    formatted_account: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "PreferencesAndAuthorizations":
        attrs = data.get("attributes", data)
        return cls(
            formatted_account=attrs.get("formattedAccount", ""),
            raw_data=data,
        )


@dataclass
class PreferencesAndAuthorizationsResponse:
    """Response from /preferences-and-authorizations/list."""

    items: list[PreferencesAndAuthorizations]

    @classmethod
    def from_dict(cls, data: dict) -> "PreferencesAndAuthorizationsResponse":
        items = [
            PreferencesAndAuthorizations.from_dict(i) for i in data.get("data", [])
        ]
        return cls(items=items)
