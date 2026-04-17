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
    type_code: str = ""
    action: str = ""
    description: str = ""
    security_type: str = ""
    cusip_number: str = ""
    trade_date: str = ""
    settle_date: str = ""
    executed_date: str = ""
    published_date: str = ""
    quantity: float = 0.0
    price: float = 0.0
    amount: float = 0.0
    net_amount: float = 0.0
    fees_and_comm: float = 0.0
    is_intraday: bool = False
    has_details: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            type_code=attrs.get("typeCode", ""),
            action=attrs.get("action", ""),
            description=attrs.get("description", ""),
            security_type=attrs.get("securityType", ""),
            cusip_number=attrs.get("cusipNumber", ""),
            trade_date=attrs.get("tradeDate", ""),
            settle_date=attrs.get("settleDate", ""),
            executed_date=attrs.get("executedDate", ""),
            published_date=attrs.get("publishedDate", ""),
            quantity=float(attrs.get("quantity", 0)),
            price=float(attrs.get("price", 0)),
            amount=float(attrs.get("amount", 0)),
            net_amount=float(attrs.get("netAmount", 0)),
            fees_and_comm=float(attrs.get("feesAndComm", 0)),
            is_intraday=attrs.get("isIntraday", False),
            has_details=attrs.get("hasDetails", False),
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
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "PreferencesAndAuthorizationsResponse":
        # Response can be JSON:API array OR single-item with nested list
        raw = data.get("data", [])
        if isinstance(raw, list):
            items = [PreferencesAndAuthorizations.from_dict(i) for i in raw]
        elif isinstance(raw, dict):
            attrs = raw.get("attributes", raw)
            nested = attrs.get("preferencesAndAuthorizations", [])
            items = [PreferencesAndAuthorizations.from_dict(i) for i in nested]
        else:
            items = []
        return cls(items=items, raw_data=data)


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


# --- Account Inquiry ---


@dataclass
class MasterAccount:
    """Master account from /master-accounts."""

    id: str = ""
    master_account_name: str = ""
    master_account_type: str = ""
    is_fee_payment_authorized: bool = False
    is_iip: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "MasterAccount":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            master_account_name=attrs.get("masterAccountName", ""),
            master_account_type=attrs.get("masterAccountType", ""),
            is_fee_payment_authorized=attrs.get("isFeePaymentAuthorizationEnabled", False),
            is_iip=attrs.get("isIip", False),
            raw_data=data,
        )


@dataclass
class MasterAccountsResponse:
    """Response from GET /master-accounts."""

    master_accounts: list[MasterAccount]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "MasterAccountsResponse":
        items = [MasterAccount.from_dict(m) for m in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(master_accounts=items, next_cursor=next_cursor, total_count=count)


@dataclass
class AccountInfo:
    """Account from /accounts."""

    id: str = ""
    formatted_master_account: str = ""
    registration_type: str = ""
    title1: str = ""
    title2: str = ""
    title3: str = ""
    linked_to_master_date: str = ""
    established_date: str = ""
    first_name: str = ""
    last_name: str = ""
    organization_name: str = ""
    formatted_taxpayer_id: str = ""
    taxpayer_id_type: str = ""
    is_iip: bool = False
    client_ids: list[int] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountInfo":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            registration_type=attrs.get("accountRegistrationType", ""),
            title1=attrs.get("accountTitle1", ""),
            title2=attrs.get("accountTitle2", ""),
            title3=attrs.get("accountTitle3", ""),
            linked_to_master_date=attrs.get("linkedToMasterDate", ""),
            established_date=attrs.get("establishedDate", ""),
            first_name=attrs.get("firstName", ""),
            last_name=attrs.get("lastName", ""),
            organization_name=attrs.get("organizationName", ""),
            formatted_taxpayer_id=attrs.get("formattedTaxpayerId", ""),
            taxpayer_id_type=attrs.get("taxpayerIdType", ""),
            is_iip=attrs.get("isIip", False),
            client_ids=attrs.get("clientIds", []),
            raw_data=data,
        )


@dataclass
class AccountsResponse:
    """Response from GET /accounts."""

    accounts: list[AccountInfo]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountsResponse":
        items = [AccountInfo.from_dict(a) for a in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(accounts=items, next_cursor=next_cursor, total_count=count)


# --- Account Roles ---


@dataclass
class AccountRole:
    """Account role entry from /account-roles."""

    id: str = ""
    formatted_account: str = ""
    formatted_master_account: str = ""
    roles: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountRole":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            roles=attrs.get("roles", []),
            raw_data=data,
        )


@dataclass
class AccountRolesResponse:
    """Response from GET /account-roles."""

    account_roles: list[AccountRole]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountRolesResponse":
        items = [AccountRole.from_dict(r) for r in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(account_roles=items, next_cursor=next_cursor, total_count=count)


# --- Account RMD ---


@dataclass
class AccountRmd:
    """Account RMD data from /account-rmd."""

    id: str = ""
    formatted_account: str = ""
    formatted_master_account: str = ""
    registration_type: str = ""
    is_roth_ira: bool = False
    title1: str = ""
    first_name: str = ""
    last_name: str = ""
    current_year: int = 0
    prior_year: int = 0
    rmd_current_year: float = 0.0
    rmd_prior_year: float = 0.0
    prior_year_end_value: float = 0.0
    life_expectancy_factor: float = 0.0
    rmd_required_beginning_date: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountRmd":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            registration_type=attrs.get("accountRegistrationType", ""),
            is_roth_ira=attrs.get("isRothIra", False),
            title1=attrs.get("accountTitle1", ""),
            first_name=attrs.get("firstName", ""),
            last_name=attrs.get("lastName", ""),
            current_year=attrs.get("currentYear", 0),
            prior_year=attrs.get("priorYear", 0),
            rmd_current_year=float(attrs.get("rmdCurrentYear", 0)),
            rmd_prior_year=float(attrs.get("rmdPriorYear", 0)),
            prior_year_end_value=float(attrs.get("priorYearEndValue", 0)),
            life_expectancy_factor=float(attrs.get("lifeExpectancyFactor", 0)),
            rmd_required_beginning_date=attrs.get("rmdRequiredBeginningDate", ""),
            raw_data=data,
        )


@dataclass
class AccountRmdResponse:
    """Response from GET /account-rmd."""

    rmds: list[AccountRmd]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountRmdResponse":
        items = [AccountRmd.from_dict(r) for r in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(rmds=items, next_cursor=next_cursor, total_count=count)


# --- Account Synchronization ---


@dataclass
class AccountSyncRecord:
    """Account sync record from /account-sync."""

    id: str = ""
    formatted_account: str = ""
    formatted_master_account: str = ""
    registration_type: str = ""
    title1: str = ""
    linked_to_master_date: str = ""
    established_date: str = ""
    client_id: int = 0
    first_name: str = ""
    last_name: str = ""
    organization_name: str = ""
    formatted_date_of_birth: str = ""
    zip_code: str = ""
    formatted_taxpayer_id: str = ""
    taxpayer_id_type: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountSyncRecord":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            formatted_master_account=attrs.get("formattedMasterAccount", ""),
            registration_type=attrs.get("accountRegistrationType", ""),
            title1=attrs.get("accountTitle1", ""),
            linked_to_master_date=attrs.get("linkedToMasterDate", ""),
            established_date=attrs.get("establishedDate", ""),
            client_id=attrs.get("clientId", 0),
            first_name=attrs.get("firstName", ""),
            last_name=attrs.get("lastName", ""),
            organization_name=attrs.get("organizationName", ""),
            formatted_date_of_birth=attrs.get("formattedDateOfBirth", ""),
            zip_code=attrs.get("zipCode", ""),
            formatted_taxpayer_id=attrs.get("formattedTaxpayerId", ""),
            taxpayer_id_type=attrs.get("taxpayerIdType", ""),
            raw_data=data,
        )


@dataclass
class AccountSyncResponse:
    """Response from GET /account-sync."""

    records: list[AccountSyncRecord]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountSyncResponse":
        items = [AccountSyncRecord.from_dict(r) for r in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(records=items, next_cursor=next_cursor, total_count=count)


# --- Balances ---


@dataclass
class BalanceDetail:
    """Balance detail from /balances/detail."""

    id: str = ""
    formatted_account: str = ""
    total_account_value: float = 0.0
    total_market_value: float = 0.0
    total_account_balance: float = 0.0
    total_available_to_withdraw: float = 0.0
    account_net_worth: float = 0.0
    cash: float = 0.0
    cash_and_cash_investments: float = 0.0
    cash_available_to_trade: float = 0.0
    bank_sweep: float = 0.0
    margin_balance: float = 0.0
    settled_funds: float = 0.0
    is_margin_enabled: bool = False
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "BalanceDetail":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            formatted_account=attrs.get("formattedAccount", ""),
            total_account_value=float(attrs.get("totalAccountValue", 0)),
            total_market_value=float(attrs.get("totalMarketValue", 0)),
            total_account_balance=float(attrs.get("totalAccountBalance", 0)),
            total_available_to_withdraw=float(attrs.get("totalAvailableToWithdraw", 0)),
            account_net_worth=float(attrs.get("accountNetWorth", 0)),
            cash=float(attrs.get("cash", 0)),
            cash_and_cash_investments=float(attrs.get("cashAndCashInvestments", 0)),
            cash_available_to_trade=float(attrs.get("cashAvailableToTrade", 0)),
            bank_sweep=float(attrs.get("bankSweep", 0)),
            margin_balance=float(attrs.get("marginBalance", 0)),
            settled_funds=float(attrs.get("settledFunds", 0)),
            is_margin_enabled=attrs.get("isMarginEnabled", False),
            raw_data=data,
        )


@dataclass
class BalanceDetailResponse:
    """Response from GET /balances/detail."""

    balances: list[BalanceDetail]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "BalanceDetailResponse":
        raw = data.get("data", [])
        if isinstance(raw, list):
            items = [BalanceDetail.from_dict(b) for b in raw]
        elif isinstance(raw, dict):
            items = [BalanceDetail.from_dict(raw)]
        else:
            items = []
        next_cursor, count = _parse_meta(data)
        return cls(balances=items, next_cursor=next_cursor, total_count=count)


@dataclass
class BalanceListResponse:
    """Response from POST /balances/list (single-item wrapper with nested balances)."""

    balances: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "BalanceListResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            balances=attrs.get("balances", []),
            raw_data=data,
        )


# --- Positions ---


@dataclass
class PositionDetailResponse:
    """Response from GET /positions/detail (single-item wrapper)."""

    positions: list[dict] = field(default_factory=list)
    total_positions: dict | None = None
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "PositionDetailResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        next_cursor, count = _parse_meta(data)
        return cls(
            positions=attrs.get("positions", []),
            total_positions=attrs.get("totalPositions"),
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


@dataclass
class PositionListResponse:
    """Response from POST /positions/list."""

    positions: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "PositionListResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            positions=attrs.get("positions", []),
            raw_data=data,
        )


# --- Client Inquiry ---


@dataclass
class ClientInfo:
    """Client info from /client-inquiries."""

    id: int | str = ""
    first_name: str = ""
    last_name: str = ""
    organization_name: str = ""
    city: str = ""
    state: str = ""
    month_year_of_birth: str = ""
    account_name: str = ""
    established_date: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ClientInfo":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            first_name=attrs.get("firstName", ""),
            last_name=attrs.get("lastName", ""),
            organization_name=attrs.get("organizationName", ""),
            city=attrs.get("city", ""),
            state=attrs.get("state", ""),
            month_year_of_birth=attrs.get("monthYearOfBirth", ""),
            account_name=attrs.get("accountName", ""),
            established_date=attrs.get("establishedDate", ""),
            raw_data=data,
        )


@dataclass
class ClientInquiryResponse:
    """Response from GET /client-inquiries."""

    clients: list[ClientInfo]
    next_cursor: str | None = None
    total_count: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ClientInquiryResponse":
        items = [ClientInfo.from_dict(c) for c in data.get("data", [])]
        next_cursor, count = _parse_meta(data)
        return cls(clients=items, next_cursor=next_cursor, total_count=count)


# --- Account Owners ---


@dataclass
class AccountOwnerListResponse:
    """Response from POST /account-owners/list."""

    account_owners: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AccountOwnerListResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            account_owners=attrs.get("accountOwners", []),
            raw_data=data,
        )


# --- Document Preferences ---


@dataclass
class DocumentPreferencesResponse:
    """Response from POST /document-preferences/list."""

    document_preferences: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "DocumentPreferencesResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            document_preferences=attrs.get("documentPreferences", []),
            raw_data=data,
        )


# --- Address Changes ---


@dataclass
class AddressChange:
    """Address change action from /address-changes.

    Response schema from Schwab docs - field names are known even though
    sandbox returns empty data.
    """

    id: str = ""
    action_source: str = ""
    action_status: str = ""
    created_date: str = ""
    submitted_date: str = ""
    delivered_date: str = ""
    completed_date: str = ""
    last_updated_date: str = ""
    original_customer_addresses: list[dict] = field(default_factory=list)
    updated_customer_addresses: list[dict] = field(default_factory=list)
    trust_profiles: list[dict] = field(default_factory=list)
    account_address_links: list[dict] = field(default_factory=list)
    other_account_holders: list[dict] = field(default_factory=list)
    organization_profiles: list[dict] = field(default_factory=list)
    relationships: dict | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AddressChange":
        attrs = data.get("attributes", data)
        return cls(
            id=data.get("id", ""),
            action_source=attrs.get("actionSource", ""),
            action_status=attrs.get("actionStatus", ""),
            created_date=attrs.get("createdDate", ""),
            submitted_date=attrs.get("submittedDate", ""),
            delivered_date=attrs.get("deliveredDate", ""),
            completed_date=attrs.get("completedDate", ""),
            last_updated_date=attrs.get("lastUpdatedDate", ""),
            original_customer_addresses=attrs.get("originalCustomerAddresses", []),
            updated_customer_addresses=attrs.get("updatedCustomerAddresses", []),
            trust_profiles=attrs.get("trustProfiles", []),
            account_address_links=attrs.get("accountAddressLinks", []),
            other_account_holders=attrs.get("otherAccountHolders", []),
            organization_profiles=attrs.get("organizationProfiles", []),
            relationships=data.get("relationships"),
            raw_data=data,
        )


@dataclass
class AddressChangesResponse:
    """Response from GET /address-changes.

    Supports JSON:API include=customer sideloading via the included field.
    """

    changes: list[AddressChange]
    included: list[dict] = field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "AddressChangesResponse":
        raw = data.get("data", [])
        if isinstance(raw, list):
            changes = [AddressChange.from_dict(c) for c in raw]
        elif raw:
            changes = [AddressChange.from_dict(raw)]
        else:
            changes = []
        next_cursor, count = _parse_meta(data)
        return cls(
            changes=changes,
            included=data.get("included", []),
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


# --- Profiles List ---


@dataclass
class ProfilesListResponse:
    """Response from POST /profiles/list."""

    profiles: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ProfilesListResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            profiles=attrs.get("profiles", []),
            raw_data=data,
        )


# --- Cost Basis ---


@dataclass
class CostBasisAccountPreference:
    """Individual account cost basis preference."""

    formatted_account: str = ""
    account_title: str = ""
    is_non_taxable_account: bool = False
    initial_cost_basis_source: str = ""
    accounting_method: str = ""
    average_mutual_funds: bool = False
    adjust_cost_basis_for_fixed_income: bool = False
    on_gain_loss_tab: bool = False
    has_schwab_alliance_log_on: bool = False
    cost_basis_on_statements: str = ""
    year_end_gain_loss_report: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "CostBasisAccountPreference":
        return cls(
            formatted_account=data.get("formattedAccount", ""),
            account_title=data.get("accountTitle", ""),
            is_non_taxable_account=data.get("isNonTaxableAccount", False),
            initial_cost_basis_source=data.get("initialCostBasisSource", ""),
            accounting_method=data.get("accountingMethod", ""),
            average_mutual_funds=data.get("averageMutualFunds", False),
            adjust_cost_basis_for_fixed_income=data.get("adjustCostBasisForFixedIncome", False),
            on_gain_loss_tab=data.get("onGainLossTab", False),
            has_schwab_alliance_log_on=data.get("hasSchwabAllianceLogOn", False),
            cost_basis_on_statements=data.get("costBasisOnStatements", ""),
            year_end_gain_loss_report=data.get("yearEndGainLossReport", ""),
            raw_data=data,
        )


@dataclass
class CostBasisPreferencesResponse:
    """Response from GET /cost-basis/account-preferences."""

    summary: dict = field(default_factory=dict)
    details: list[CostBasisAccountPreference] = field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "CostBasisPreferencesResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        details = [
            CostBasisAccountPreference.from_dict(det)
            for det in attrs.get("details", [])
        ]
        next_cursor, count = _parse_meta(data)
        return cls(
            summary=attrs.get("summary", {}),
            details=details,
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


@dataclass
class RglTransaction:
    """Realized gain/loss transaction from /cost-basis/rgl-transactions.

    Note: dollar/percent values are formatted strings (e.g. "($349.02)", "25.87%"),
    not floats. Negative values use parentheses.
    """

    transaction_id: str = ""
    symbol: str = ""
    security_name: str = ""
    total_realized_gain_loss_dollar: str = ""
    total_realized_gain_loss_percent: str = ""
    short_term_realized_gain_loss: str = ""
    long_term_realized_gain_loss: str = ""
    quantity: str = ""
    total_proceeds: str = ""
    cost_basis: str = ""
    acquired_or_opened_date: str = ""
    sold_or_closed_date: str = ""
    notes: str = ""
    transaction_lots: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "RglTransaction":
        return cls(
            transaction_id=data.get("transactionId", ""),
            symbol=data.get("symbol", ""),
            security_name=data.get("securityName", ""),
            total_realized_gain_loss_dollar=data.get("totalRealizedGainLossDollar", ""),
            total_realized_gain_loss_percent=data.get("totalRealizedGainLossPercent", ""),
            short_term_realized_gain_loss=data.get("shortTermRealizedGainLoss", ""),
            long_term_realized_gain_loss=data.get("longTermRealizedGainLoss", ""),
            quantity=data.get("quantity", ""),
            total_proceeds=data.get("totalProceeds", ""),
            cost_basis=data.get("costBasis", ""),
            acquired_or_opened_date=data.get("acquiredOrOpenedDate", ""),
            sold_or_closed_date=data.get("soldOrClosedDate", ""),
            notes=data.get("notes", ""),
            transaction_lots=data.get("transactionLots", []),
            raw_data=data,
        )


@dataclass
class CostBasisRglResponse:
    """Response from GET /cost-basis/rgl-transactions."""

    summary: dict = field(default_factory=dict)
    transactions: list[RglTransaction] = field(default_factory=list)
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "CostBasisRglResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        txns = [RglTransaction.from_dict(t) for t in attrs.get("transactions", [])]
        next_cursor, count = _parse_meta(data)
        return cls(
            summary=attrs.get("summary", {}),
            transactions=txns,
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


@dataclass
class UglPosition:
    """Unrealized gain/loss position from /cost-basis/ugl-positions.

    Note: dollar/percent values are formatted strings (e.g. "$257,525.32",
    "194.31%", "Missing"). Not floats.
    """

    position_id: str = ""
    symbol: str = ""
    security_name: str = ""
    unrealized_gain_loss_dollar: str = ""
    unrealized_gain_loss_percent: str = ""
    quantity: str = ""
    cost_basis: str = ""
    market_value: str = ""
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "UglPosition":
        return cls(
            position_id=data.get("positionId", ""),
            symbol=data.get("symbol", ""),
            security_name=data.get("securityName", ""),
            unrealized_gain_loss_dollar=data.get("unrealizedGainLossDollar", ""),
            unrealized_gain_loss_percent=data.get("unrealizedGainLossPercent", ""),
            quantity=data.get("quantity", ""),
            cost_basis=data.get("costBasis", ""),
            market_value=data.get("marketValue", ""),
            raw_data=data,
        )


@dataclass
class UglPositionLotsResponse:
    """Response from POST /cost-basis/ugl-position-lots/list.

    Values are formatted strings. "N/A" indicates unavailable data.
    """

    positions: list[dict] = field(default_factory=list)
    invalid_positions: list[str] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "UglPositionLotsResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        errors = attrs.get("errors", {})
        return cls(
            positions=attrs.get("positions", []),
            invalid_positions=errors.get("invalidPositions", []),
            raw_data=data,
        )


@dataclass
class CostBasisUglResponse:
    """Response from GET /cost-basis/ugl-positions."""

    summary: dict = field(default_factory=dict)
    positions: list[UglPosition] = field(default_factory=list)
    is_amortized: bool = False
    next_cursor: str | None = None
    total_count: int | None = None
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "CostBasisUglResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        positions = [UglPosition.from_dict(p) for p in attrs.get("positions", [])]
        next_cursor, count = _parse_meta(data)
        return cls(
            summary=attrs.get("summary", {}),
            positions=positions,
            is_amortized=attrs.get("isAmortized", False),
            next_cursor=next_cursor,
            total_count=count,
            raw_data=data,
        )


# --- Reports ---


@dataclass
class ReportsResponse:
    """Response from GET /reports."""

    reports: list[dict] = field(default_factory=list)
    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ReportsResponse":
        d = data.get("data", {})
        attrs = d.get("attributes", d)
        return cls(
            reports=attrs.get("reports", []),
            raw_data=data,
        )


# --- Upload ManFees ---


@dataclass
class UploadResponse:
    """Response from POST /upload-manfees."""

    raw_data: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "UploadResponse":
        return cls(raw_data=data)
