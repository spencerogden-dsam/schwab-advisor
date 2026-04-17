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


def _parse_alert_attrs(data: dict) -> dict:
    """Parse common alert fields from a JSON:API item."""
    attrs = data.get("attributes", data)
    return {
        "id": data.get("id", ""),
        "formatted_account": attrs.get("formattedAccount", ""),
        "formatted_master_account": attrs.get("formattedMasterAccount", ""),
        "account_title": attrs.get("accountTitle", ""),
        "category": attrs.get("category", ""),
        "type_code": attrs.get("typeCode", ""),
        "alert_type": attrs.get("type", ""),
        "subject": attrs.get("subject", ""),
        "text": attrs.get("text", ""),
        "status": attrs.get("status", ""),
        "created_date": attrs.get("createdDate", ""),
        "source": attrs.get("source", ""),
        "from_name": attrs.get("fromName", ""),
        "priority": attrs.get("priority", ""),
        "reply_type": attrs.get("replyType", ""),
        "destination": attrs.get("destination", ""),
        "viewed_date": attrs.get("viewedDate", ""),
        "transfer_status": attrs.get("transferStatus", ""),
        "transfer_status_date": attrs.get("transferStatusDate", ""),
        "is_archived": attrs.get("isArchived", False),
        "is_restricted": attrs.get("isRestricted", False),
        "is_copied": attrs.get("isCopied", False),
        "raw_data": data,
    }


@dataclass
class Alert:
    """Alert from /alerts."""

    id: int | str = ""
    formatted_account: str = ""
    formatted_master_account: str = ""
    account_title: str = ""
    category: str = ""
    type_code: str = ""
    alert_type: str = ""
    subject: str = ""
    text: str = ""
    status: str = ""
    created_date: str = ""
    source: str = ""
    from_name: str = ""
    priority: str = ""
    reply_type: str = ""
    destination: str = ""
    viewed_date: str = ""
    transfer_status: str = ""
    transfer_status_date: str = ""
    is_archived: bool = False
    is_restricted: bool = False
    is_copied: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(**_parse_alert_attrs(data))


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


# --- Alert Detail / Archive / Update responses ---


@dataclass
class AlertDetail:
    """Detailed alert from /alerts/detail/{alert_id}."""

    id: int | str = ""
    formatted_master_account: str = ""
    account_title: str = ""
    account_description: str = ""
    category: str = ""
    type_code: str = ""
    alert_type: str = ""
    subject: str = ""
    text: str = ""
    detail_text: str = ""
    detail_type: str = ""
    status: str = ""
    created_date: str = ""
    source: str = ""
    from_name: str = ""
    priority: str = ""
    reply_type: str = ""
    destination: str = ""
    viewed_date: str = ""
    transfer_status: str = ""
    transfer_status_date: str = ""
    is_archived: bool = False
    is_restricted: bool = False
    is_copied: bool = False
    status_history: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertDetail":
        attrs = data.get("attributes", data)
        common = _parse_alert_attrs(data)
        common.pop("formatted_account", None)
        common["account_description"] = attrs.get("accountDescription", "")
        common["detail_text"] = attrs.get("detailText", "")
        common["detail_type"] = attrs.get("detailType", "")
        common["status_history"] = attrs.get("statusHistory", [])
        return cls(**common)


@dataclass
class AlertDetailResponse:
    """Response from /alerts/detail/{alert_id}."""

    alert: AlertDetail | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertDetailResponse":
        d = data.get("data")
        alert = AlertDetail.from_dict(d) if d else None
        return cls(alert=alert, raw_data=data)


@dataclass
class ArchiveDetail:
    """Detail for a single archived alert."""

    alert_id: int = 0
    has_status_changed: bool = False
    no_change_reason: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ArchiveDetail":
        return cls(
            alert_id=data.get("alertId", 0),
            has_status_changed=data.get("hasArchivedStatusChanged", False),
            no_change_reason=data.get("noArchivedStatusChangeReason", ""),
        )


@dataclass
class AlertArchiveResponse:
    """Response from POST /alerts/archive."""

    are_all_archived: bool = False
    archive_details: list[ArchiveDetail] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertArchiveResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        details = [
            ArchiveDetail.from_dict(ad)
            for ad in attrs.get("archiveDetails", [])
        ]
        return cls(
            are_all_archived=attrs.get("areAllArchived", False),
            archive_details=details,
            raw_data=data,
        )


@dataclass
class AlertUpdateResponse:
    """Response from PATCH /alerts/{alert_id}."""

    id: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AlertUpdateResponse":
        d = data.get("data", {})
        return cls(id=d.get("id", ""), raw_data=data)


# --- Service Requests ---


@dataclass
class SubTopic:
    """A sub-topic within a service request topic."""

    name: str = ""
    is_attachment_allowed: bool = False
    is_attachment_required: bool = False
    max_attachment_size: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> "SubTopic":
        return cls(
            name=data.get("name", ""),
            is_attachment_allowed=data.get("isAttachmentAllowed", False),
            is_attachment_required=data.get("isAttachmentRequired", False),
            max_attachment_size=data.get("maxAttachmentSize", 0),
        )


@dataclass
class ServiceRequestTopic:
    """A service request topic from GET /service-requests."""

    id: str = ""
    name: str = ""
    order: int = 0
    sub_topics: list[SubTopic] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceRequestTopic":
        attrs = data.get("attributes", data)
        subs = [SubTopic.from_dict(s) for s in attrs.get("subTopics", [])]
        return cls(
            id=data.get("id", ""),
            name=attrs.get("name", ""),
            order=attrs.get("order", 0),
            sub_topics=subs,
            raw_data=data,
        )


@dataclass
class ServiceRequestTopicsResponse:
    """Response from GET /service-requests (returns available topics)."""

    topics: list[ServiceRequestTopic]

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceRequestTopicsResponse":
        topics = [ServiceRequestTopic.from_dict(t) for t in data.get("data", [])]
        return cls(topics=topics)


@dataclass
class ServiceRequestCreateResponse:
    """Response from POST /service-requests."""

    id: str = ""
    formatted_master_account: str = ""
    master_account_name: str = ""
    topic_name: str = ""
    sub_topic_name: str = ""
    description: str = ""
    created_date: str = ""
    creator: str = ""
    status_id: str = ""
    has_attachments: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceRequestCreateResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            id=d.get("id", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            master_account_name=attrs.get("masterAccountName", ""),
            topic_name=attrs.get("topicName", ""),
            sub_topic_name=attrs.get("subTopicName", ""),
            description=attrs.get("description", ""),
            created_date=attrs.get("createdDate", ""),
            creator=attrs.get("creator", ""),
            status_id=attrs.get("statusId", ""),
            has_attachments=attrs.get("hasAttachments", False),
            raw_data=data,
        )


# --- Status Feed / Events ---


@dataclass
class StatusEvent:
    """Status event within a status object."""

    id: str = ""
    status_object_id: str = ""
    status: str = ""
    current_status: str = ""
    current_status_detail: str = ""
    created_date: str = ""
    last_updated_date: str = ""
    assignment_group: str = ""
    source: str = ""
    source_id: str = ""
    source_user: str = ""
    can_be_deleted: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusEvent":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            status_object_id=attrs.get("statusObjectId", ""),
            status=attrs.get("status", ""),
            current_status=attrs.get("currentStatus", ""),
            current_status_detail=attrs.get("currentStatusMessageDetail", ""),
            created_date=attrs.get("createdDate", ""),
            last_updated_date=attrs.get("lastUpdatedDate", ""),
            assignment_group=attrs.get("assignmentGroup", ""),
            source=attrs.get("source", ""),
            source_id=attrs.get("sourceId", ""),
            source_user=attrs.get("sourceUser", ""),
            can_be_deleted=attrs.get("canBeDeleted", False),
            raw_data=data,
        )


@dataclass
class StatusObject:
    """Status object within a status feed."""

    status_object_id: str = ""
    bundle_id: str = ""
    created_date: str = ""
    last_updated_date: str = ""
    source: str = ""
    category: str = ""
    sub_category: str = ""
    formatted_master_account: str = ""
    title: str = ""
    description: str = ""
    action_center_envelope_id: str = ""
    is_updatable: bool = False
    is_confidential: bool = False
    status_events: list[StatusEvent] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusObject":
        attrs = data.get("attributes", data)
        events = [
            StatusEvent.from_dict(e)
            for e in attrs.get("statusEvents", [])
        ]
        return cls(
            status_object_id=data.get("id", attrs.get("statusObjectId", "")),
            bundle_id=attrs.get("bundleId", ""),
            created_date=attrs.get("createdDate", ""),
            last_updated_date=attrs.get("lastUpdatedDate", ""),
            source=attrs.get("source", ""),
            category=attrs.get("category", ""),
            sub_category=attrs.get("subCategory", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            title=attrs.get("title", ""),
            description=attrs.get("description", ""),
            action_center_envelope_id=attrs.get("actionCenterEnvelopeId", ""),
            is_updatable=attrs.get("isUpdatable", False),
            is_confidential=attrs.get("isConfidential", False),
            status_events=events,
            raw_data=data,
        )


@dataclass
class StatusFeedCreateResponse:
    """Response from POST /status-feed.

    The POST response inlines statusObjects with their events.
    """

    feed_id: str = ""
    status_objects: list[StatusObject] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusFeedCreateResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        objects = [
            StatusObject.from_dict(o)
            for o in attrs.get("statusObjects", [])
        ]
        return cls(
            feed_id=d.get("id", attrs.get("feedId", "")),
            status_objects=objects,
            raw_data=data,
        )


@dataclass
class StatusFeedResponse:
    """Response from GET /status-feed/{feed_id}.

    Returns a list of status objects (JSON:API array).
    """

    status_objects: list[StatusObject] = field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusFeedResponse":
        raw = data.get("data")
        if isinstance(raw, list):
            objects = [StatusObject.from_dict(o) for o in raw]
        elif isinstance(raw, dict):
            objects = [StatusObject.from_dict(raw)]
        else:
            objects = []
        next_cursor, count = _parse_meta(data)
        return cls(
            status_objects=objects,
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


@dataclass
class StatusEventsResponse:
    """Response from GET /status-feed/{feed_id}/status-objects/{object_id}/status-events."""

    events: list[StatusEvent]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusEventsResponse":
        events = [StatusEvent.from_dict(e) for e in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(events=events, next_cursor=next_cursor, total_count=count)


@dataclass
class StatusEventsPostResponse:
    """Response from POST /status-events."""

    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "StatusEventsPostResponse":
        return cls(raw_data=data)
