"""Python client for Schwab Advisor Services API."""

from .auth import SchwabAuth
from .client import SchwabAdvisorClient, schwab_error_code
from .models import (
    AccountProfile,
    AccountProfilesResponse,
    AlertArchiveResponse,
    AlertDetail,
    AlertDetailResponse,
    AlertsResponse,
    AlertUpdateResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopic,
    ServiceRequestTopicsResponse,
    StatusEvent,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
    StatusObject,
    SubTopic,
    TokenResponse,
)

__version__ = "0.1.0"

__all__ = [
    "SchwabAdvisorClient",
    "SchwabAuth",
    "schwab_error_code",
    "TokenResponse",
    "AccountProfile",
    "AccountProfilesResponse",
    "AlertArchiveResponse",
    "AlertDetail",
    "AlertDetailResponse",
    "AlertsResponse",
    "AlertUpdateResponse",
    "ServiceRequestCreateResponse",
    "ServiceRequestTopic",
    "ServiceRequestTopicsResponse",
    "StatusEvent",
    "StatusEventsPostResponse",
    "StatusEventsResponse",
    "StatusFeedCreateResponse",
    "StatusFeedResponse",
    "StatusObject",
    "SubTopic",
]
