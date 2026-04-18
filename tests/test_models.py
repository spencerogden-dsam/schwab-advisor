"""Tests for data model from_dict parsing."""

from schwab_advisor.models import (
    AccountHolder,
    AccountHoldersResponse,
    AccountProfile,
    AccountProfilesResponse,
    Address,
    Alert,
    AlertArchiveResponse,
    AlertDetail,
    AlertDetailResponse,
    AlertUpdateResponse,
    ArchiveDetail,
    PreferencesAndAuthorizations,
    PreferencesAndAuthorizationsResponse,
    ServiceRequestCreateResponse,
    ServiceRequestTopic,
    ServiceRequestTopicsResponse,
    StandingInstruction,
    StandingInstructionsResponse,
    StatusEvent,
    StatusEventsPostResponse,
    StatusEventsResponse,
    StatusFeedCreateResponse,
    StatusFeedResponse,
    StatusObject,
    SubTopic,
    Transaction,
    TransactionsResponse,
    _parse_meta,
)


# --- Alert ---


class TestAlert:
    def test_from_dict_with_attributes(self):
        data = {
            "id": 15157510,
            "type": "alert",
            "attributes": {
                "formattedMasterAccount": "8174295",
                "category": "ALERT",
                "typeCode": "USR-ALERT",
                "type": "User Alert",
                "subject": "User ID Reactivated",
                "status": "Viewed",
                "createdDate": "2024-10-16T17:18:55",
                "source": "MF_FILE",
                "priority": "INFO",
                "isArchived": False,
            },
        }
        alert = Alert.from_dict(data)
        assert alert.id == 15157510
        assert alert.formatted_master_account == "8174295"
        assert alert.alert_type == "User Alert"
        assert alert.type_code == "USR-ALERT"
        assert alert.subject == "User ID Reactivated"
        assert alert.status == "Viewed"
        assert alert.is_archived is False

    def test_from_dict_empty(self):
        alert = Alert.from_dict({})
        assert alert.id == ""
        assert alert.alert_type == ""

    def test_from_dict_with_new_spec_fields(self):
        """accountDescription + externalSystemRefId from official API spec."""
        data = {
            "id": 16054502,
            "type": "alert",
            "attributes": {
                "formattedAccount": "*****0120",
                "accountTitle": "GALE MORGAN BUSH-STONE",
                "accountDescription": "Gale Account",
                "externalSystemRefId": "A602",
            },
        }
        alert = Alert.from_dict(data)
        assert alert.account_description == "Gale Account"
        assert alert.external_system_ref_id == "A602"


# --- Alert Detail ---


class TestAlertDetail:
    def test_from_dict_with_attributes(self):
        data = {
            "id": 15157510,
            "type": "alert-detail",
            "attributes": {
                "formattedMasterAccount": "***4295",
                "category": "ALERT",
                "type": "User Alert",
                "subject": "User ID Reactivated",
                "status": "Viewed",
                "detailText": "<html>...</html>",
                "detailType": "HTML",
                "statusHistory": [{"status": "New", "date": "2024-10-16"}],
            },
        }
        detail = AlertDetail.from_dict(data)
        assert detail.id == 15157510
        assert detail.alert_type == "User Alert"
        assert detail.detail_text == "<html>...</html>"
        assert len(detail.status_history) == 1

    def test_from_dict_empty(self):
        detail = AlertDetail.from_dict({})
        assert detail.id == ""
        assert detail.status_history == []

    def test_from_dict_with_new_spec_fields(self):
        """Detail fields that weren't in the old model: formattedAccount,
        externalSystemRefId, audit/viewed/archived user+lastName+date."""
        data = {
            "id": 16054502,
            "type": "alert-detail",
            "attributes": {
                "formattedAccount": "*****0120",
                "formattedMasterAccount": "***3045",
                "externalSystemRefId": "AM-174788690",
                "auditUserId": "AlertsSystem",
                "auditLastName": "LANG",
                "viewedUserId": "user_1",
                "viewedLastName": "LANG",
                "archivedDate": "2022-05-13T06:37:37",
                "archivedUserId": "user_1",
                "archivedLastName": "LANG",
            },
        }
        d = AlertDetail.from_dict(data)
        assert d.formatted_account == "*****0120"
        assert d.external_system_ref_id == "AM-174788690"
        assert d.audit_user_id == "AlertsSystem"
        assert d.audit_last_name == "LANG"
        assert d.viewed_user_id == "user_1"
        assert d.viewed_last_name == "LANG"
        assert d.archived_date == "2022-05-13T06:37:37"
        assert d.archived_user_id == "user_1"
        assert d.archived_last_name == "LANG"


class TestAlertDetailResponse:
    def test_from_dict_with_data(self):
        data = {
            "data": {
                "id": 15157510,
                "type": "alert-detail",
                "attributes": {"type": "User Alert"},
            }
        }
        resp = AlertDetailResponse.from_dict(data)
        assert resp.alert is not None
        assert resp.alert.id == 15157510

    def test_from_dict_no_data(self):
        resp = AlertDetailResponse.from_dict({})
        assert resp.alert is None


class TestAlertArchiveResponse:
    def test_from_dict(self):
        data = {
            "data": {
                "id": "9d76e773-15bb-4005-8fa1-decd23d124ae",
                "type": "alerts-archive",
                "attributes": {
                    "areAllArchived": True,
                    "archiveDetails": [
                        {
                            "alertId": 15157526,
                            "hasArchivedStatusChanged": True,
                            "noArchivedStatusChangeReason": "",
                        }
                    ],
                },
            }
        }
        resp = AlertArchiveResponse.from_dict(data)
        assert resp.id == "9d76e773-15bb-4005-8fa1-decd23d124ae"
        assert resp.are_all_archived is True
        assert len(resp.archive_details) == 1
        assert resp.archive_details[0].alert_id == 15157526
        assert resp.archive_details[0].has_status_changed is True

    def test_previously_archived_reason(self):
        """Docs example: noArchivedStatusChangeReason='Previously Archived'."""
        data = {
            "data": {
                "id": "batch-uuid",
                "attributes": {
                    "areAllArchived": True,
                    "archiveDetails": [{
                        "alertId": 1556881,
                        "hasArchivedStatusChanged": False,
                        "noArchivedStatusChangeReason": "Previously Archived",
                    }],
                },
            }
        }
        resp = AlertArchiveResponse.from_dict(data)
        assert resp.archive_details[0].no_change_reason == "Previously Archived"
        assert resp.archive_details[0].has_status_changed is False

    def test_from_dict_empty(self):
        resp = AlertArchiveResponse.from_dict({})
        assert resp.id == ""
        assert resp.are_all_archived is False
        assert resp.archive_details == []


class TestAlertUpdateResponse:
    def test_from_dict(self):
        data = {"data": {"id": "alert-1", "type": "alert"}}
        resp = AlertUpdateResponse.from_dict(data)
        assert resp.id == "alert-1"

    def test_no_content(self):
        resp = AlertUpdateResponse(id="123", raw_data=None)
        assert resp.id == "123"


# --- Service Request Topics ---


class TestSubTopic:
    def test_from_dict(self):
        data = {
            "name": "Brokerage",
            "isAttachmentAllowed": True,
            "isAttachmentRequired": True,
            "maxAttachmentSize": 30,
        }
        st = SubTopic.from_dict(data)
        assert st.name == "Brokerage"
        assert st.is_attachment_required is True
        assert st.max_attachment_size == 30


class TestServiceRequestTopic:
    def test_from_dict(self):
        data = {
            "id": "55df8198",
            "type": "service-request-topic",
            "attributes": {
                "name": "Open New Account",
                "order": 1,
                "subTopics": [
                    {"name": "Brokerage", "isAttachmentAllowed": True,
                     "isAttachmentRequired": True, "maxAttachmentSize": 30},
                ],
            },
        }
        topic = ServiceRequestTopic.from_dict(data)
        assert topic.id == "55df8198"
        assert topic.name == "Open New Account"
        assert topic.order == 1
        assert len(topic.sub_topics) == 1
        assert topic.sub_topics[0].name == "Brokerage"


class TestServiceRequestTopicsResponse:
    def test_from_dict(self):
        data = {
            "data": [
                {"id": "1", "attributes": {"name": "Topic A", "order": 1, "subTopics": []}},
                {"id": "2", "attributes": {"name": "Topic B", "order": 2, "subTopics": []}},
            ]
        }
        resp = ServiceRequestTopicsResponse.from_dict(data)
        assert len(resp.topics) == 2
        assert resp.topics[0].name == "Topic A"


class TestServiceRequestCreateResponse:
    def test_from_dict(self):
        data = {
            "data": {
                "id": "SR378912733804863",
                "type": "service-request",
                "attributes": {
                    "formattedMasterAccount": "****4295",
                    "masterAccountName": "TEST FIRM",
                    "topicName": "Money Movement",
                    "subTopicName": "Other",
                    "description": "Test",
                    "createdDate": "2026-04-16T12:07:33Z",
                    "creator": "dock_CERT1",
                    "statusId": "1",
                    "hasAttachments": False,
                },
            }
        }
        resp = ServiceRequestCreateResponse.from_dict(data)
        assert resp.id == "SR378912733804863"
        assert resp.topic_name == "Money Movement"
        assert resp.creator == "dock_CERT1"

    def test_from_dict_empty(self):
        resp = ServiceRequestCreateResponse.from_dict({})
        assert resp.id == ""


# --- Status ---


class TestStatusEvent:
    def test_from_dict_with_attributes(self):
        data = {
            "id": "26068466-uuid",
            "type": "status-event",
            "attributes": {
                "statusObjectId": "b4e59d5c-uuid",
                "status": "New",
                "currentStatus": "Draft - Not ready",
                "currentStatusMessageDetail": "Draft detail",
                "createdDate": "2026-04-16T05:14:25Z",
                "assignmentGroup": "Advisor",
                "source": "AD00007188",
                "sourceUser": "Docupace Enterprise",
            },
        }
        evt = StatusEvent.from_dict(data)
        assert evt.id == "26068466-uuid"
        assert evt.status == "New"
        assert evt.current_status == "Draft - Not ready"
        assert evt.assignment_group == "Advisor"

    def test_from_dict_empty(self):
        evt = StatusEvent.from_dict({})
        assert evt.id == ""
        assert evt.status == ""


class TestStatusObject:
    def test_from_dict_from_feed_response(self):
        data = {
            "id": "b4e59d5c-uuid",
            "type": "status-object",
            "attributes": {
                "bundleId": "f595c897-uuid",
                "category": "Digital Envelope",
                "subCategory": "Account Open",
                "formattedMasterAccount": "***4295",
                "title": "AC Account Open",
                "description": "Action Center envelope",
                "isUpdatable": False,
                "statusEvents": [
                    {"id": "evt-1", "type": "status-event",
                     "attributes": {"status": "New"}},
                ],
            },
        }
        obj = StatusObject.from_dict(data)
        assert obj.status_object_id == "b4e59d5c-uuid"
        assert obj.category == "Digital Envelope"
        assert obj.title == "AC Account Open"
        assert len(obj.status_events) == 1
        assert obj.status_events[0].status == "New"

    def test_from_dict_inline(self):
        """Status objects from POST /status-feed are inline (no id/type wrapper)."""
        data = {
            "statusObjectId": "abc-123",
            "category": "Service Request",
            "title": "SR Title",
            "statusEvents": [],
        }
        obj = StatusObject.from_dict(data)
        assert obj.status_object_id == "abc-123"
        assert obj.category == "Service Request"


class TestStatusFeedCreateResponse:
    def test_from_dict(self):
        data = {
            "data": {
                "id": "feed-uuid",
                "type": "status-feed",
                "attributes": {
                    "statusObjects": [
                        {"statusObjectId": "obj-1", "category": "Envelope",
                         "title": "Test", "statusEvents": []},
                    ]
                },
            }
        }
        resp = StatusFeedCreateResponse.from_dict(data)
        assert resp.feed_id == "feed-uuid"
        assert len(resp.status_objects) == 1
        assert resp.status_objects[0].status_object_id == "obj-1"


class TestStatusFeedResponse:
    def test_from_dict_list(self):
        data = {
            "data": [
                {"id": "obj-1", "type": "status-object",
                 "attributes": {"category": "Envelope", "title": "T",
                                "statusEvents": []}},
            ],
            "meta": {"paging": {"nextCursor": "c1"}, "count": {"actual": 1}},
        }
        resp = StatusFeedResponse.from_dict(data)
        assert len(resp.status_objects) == 1
        assert resp.status_objects[0].status_object_id == "obj-1"
        assert resp.next_cursor == "c1"

    def test_from_dict_empty(self):
        resp = StatusFeedResponse.from_dict({})
        assert resp.status_objects == []


class TestStatusEventsResponse:
    def test_from_dict(self):
        data = {
            "data": [
                {"id": "evt-1", "type": "status-event",
                 "attributes": {"status": "New", "currentStatus": "Draft"}},
            ]
        }
        resp = StatusEventsResponse.from_dict(data)
        assert len(resp.events) == 1
        assert resp.events[0].status == "New"


class TestStatusEventsPostResponse:
    def test_from_dict(self):
        data = {"data": {"id": "batch-1"}}
        resp = StatusEventsPostResponse.from_dict(data)
        assert resp.raw_data == data


# --- Pagination helper ---


class TestParseMeta:
    def test_with_cursor_and_count(self):
        data = {"meta": {"paging": {"nextCursor": "101"}, "count": {"actual": 50}}}
        cursor, count = _parse_meta(data)
        assert cursor == "101"
        assert count == 50

    def test_empty_meta(self):
        cursor, count = _parse_meta({})
        assert cursor is None
        assert count is None

    def test_partial_meta(self):
        cursor, count = _parse_meta({"meta": {"paging": {}}})
        assert cursor is None
        assert count is None


# --- Address ---


class TestAddress:
    def test_from_dict(self):
        data = {
            "addressLine1": "123 Main St",
            "addressLine2": "Suite 400",
            "city": "Philadelphia",
            "state": "PA",
            "zipCode": "19103",
            "country": "US",
        }
        addr = Address.from_dict(data)
        assert addr.address_line1 == "123 Main St"
        assert addr.city == "Philadelphia"
        assert addr.zip_code == "19103"

    def test_from_dict_empty(self):
        addr = Address.from_dict({})
        assert addr.address_line1 == ""
        assert addr.country == ""


# --- Account Profile ---


class TestAccountProfile:
    def test_from_dict_with_address(self):
        data = {
            "id": "prof-1",
            "type": "account-profile",
            "attributes": {
                "formattedAccount": "1234-5678",
                "formattedMasterAccount": "MASTER-1",
                "accountRegistrationType": "Individual",
                "accountTitle1": "John Doe",
                "emailAddress": "john@example.com",
                "mailingAddress": {
                    "addressLine1": "123 Main",
                    "city": "Philly",
                    "state": "PA",
                    "zipCode": "19103",
                },
                "isMoneyLinkEnabled": True,
                "restrictionCodes": ["R1", "R2"],
            },
        }
        prof = AccountProfile.from_dict(data)
        assert prof.formatted_account == "1234-5678"
        assert prof.registration_type == "Individual"
        assert prof.title1 == "John Doe"
        assert prof.email == "john@example.com"
        assert prof.mailing_address is not None
        assert prof.mailing_address.city == "Philly"
        assert prof.is_money_link_enabled is True
        assert prof.restriction_codes == ["R1", "R2"]

    def test_from_dict_without_address(self):
        data = {"attributes": {"formattedAccount": "1234"}}
        prof = AccountProfile.from_dict(data)
        assert prof.formatted_account == "1234"
        assert prof.mailing_address is None

    def test_from_dict_empty(self):
        prof = AccountProfile.from_dict({})
        assert prof.formatted_account == ""
        assert prof.restriction_codes == []


class TestAccountProfilesResponse:
    def test_from_dict(self):
        data = {
            "data": [
                {"attributes": {"formattedAccount": "1234"}},
                {"attributes": {"formattedAccount": "5678"}},
            ],
            "meta": {"paging": {"nextCursor": "next"}, "count": {"actual": 2}},
        }
        resp = AccountProfilesResponse.from_dict(data)
        assert len(resp.profiles) == 2
        assert resp.next_cursor == "next"
        assert resp.total_count == 2

    def test_from_dict_empty(self):
        resp = AccountProfilesResponse.from_dict({"data": []})
        assert resp.profiles == []
        assert resp.next_cursor is None


# --- Transaction ---


class TestTransaction:
    def test_from_dict(self):
        data = {
            "id": "txn-1",
            "type": "transaction",
            "attributes": {
                "formattedAccount": "1234-5678",
                "transactionType": "BUY",
                "description": "Buy AAPL",
                "tradeDate": "2026-04-10",
                "settlementDate": "2026-04-12",
                "amount": "1500.50",
                "symbol": "AAPL",
                "quantity": "10",
            },
        }
        txn = Transaction.from_dict(data)
        assert txn.id == "txn-1"
        assert txn.transaction_type == "BUY"
        assert txn.amount == 1500.50
        assert txn.quantity == 10.0
        assert txn.symbol == "AAPL"

    def test_from_dict_empty(self):
        txn = Transaction.from_dict({})
        assert txn.amount == 0.0
        assert txn.quantity == 0.0

    def test_from_dict_numeric_amount(self):
        data = {"attributes": {"amount": 99.99, "quantity": 5}}
        txn = Transaction.from_dict(data)
        assert txn.amount == 99.99
        assert txn.quantity == 5.0


class TestTransactionsResponse:
    def test_from_dict(self):
        data = {
            "data": [{"id": "t1", "attributes": {"transactionType": "BUY"}}],
            "meta": {"paging": {"nextCursor": "c1"}, "count": {"actual": 1}},
        }
        resp = TransactionsResponse.from_dict(data)
        assert len(resp.transactions) == 1
        assert resp.next_cursor == "c1"

    def test_from_dict_empty(self):
        resp = TransactionsResponse.from_dict({"data": []})
        assert resp.transactions == []


# --- Standing Instruction ---


class TestStandingInstruction:
    def test_from_dict(self):
        data = {
            "id": "si-1",
            "type": "standing-instruction",
            "attributes": {
                "formattedAccount": "1234",
                "instructionType": "ACH",
                "status": "Active",
                "counterParty": {"name": "Bank of America"},
            },
        }
        si = StandingInstruction.from_dict(data)
        assert si.id == "si-1"
        assert si.instruction_type == "ACH"
        assert si.counter_party == {"name": "Bank of America"}

    def test_from_dict_empty(self):
        si = StandingInstruction.from_dict({})
        assert si.counter_party is None


class TestStandingInstructionsResponse:
    def test_from_dict(self):
        data = {
            "data": [{"id": "si-1", "attributes": {"instructionType": "ACH"}}],
            "meta": {"paging": {}, "count": {"actual": 1}},
        }
        resp = StandingInstructionsResponse.from_dict(data)
        assert len(resp.instructions) == 1


# --- Account Holder ---


class TestAccountHolder:
    def test_from_dict_with_address(self):
        data = {
            "attributes": {
                "formattedAccount": "1234",
                "firstName": "John",
                "middleName": "Q",
                "lastName": "Doe",
                "formattedDateOfBirth": "01/15/1980",
                "mailingAddress": {"addressLine1": "123 Main", "city": "Philly"},
            },
        }
        holder = AccountHolder.from_dict(data)
        assert holder.first_name == "John"
        assert holder.last_name == "Doe"
        assert holder.date_of_birth == "01/15/1980"
        assert holder.mailing_address is not None
        assert holder.mailing_address.city == "Philly"

    def test_from_dict_without_address(self):
        holder = AccountHolder.from_dict({"attributes": {"firstName": "Jane"}})
        assert holder.first_name == "Jane"
        assert holder.mailing_address is None


class TestAccountHoldersResponse:
    def test_from_dict(self):
        data = {
            "data": [{"attributes": {"firstName": "John"}}],
            "meta": {"paging": {"nextCursor": "c2"}, "count": {"actual": 1}},
        }
        resp = AccountHoldersResponse.from_dict(data)
        assert len(resp.holders) == 1
        assert resp.next_cursor == "c2"


# --- Preferences and Authorizations ---


class TestPreferencesAndAuthorizations:
    def test_from_dict(self):
        data = {
            "attributes": {"formattedAccount": "1234"},
        }
        pref = PreferencesAndAuthorizations.from_dict(data)
        assert pref.formatted_account == "1234"
        assert pref.raw_data == data


class TestPreferencesAndAuthorizationsResponse:
    def test_from_dict(self):
        data = {"data": [{"attributes": {"formattedAccount": "1234"}}]}
        resp = PreferencesAndAuthorizationsResponse.from_dict(data)
        assert len(resp.items) == 1

    def test_from_dict_empty(self):
        resp = PreferencesAndAuthorizationsResponse.from_dict({"data": []})
        assert resp.items == []


# --- Edge cases: StatusFeedResponse dict vs list ---


class TestStatusFeedResponseEdgeCases:
    def test_from_dict_single_dict(self):
        data = {
            "data": {"id": "obj-1", "attributes": {"category": "Test", "statusEvents": []}},
        }
        resp = StatusFeedResponse.from_dict(data)
        assert len(resp.status_objects) == 1
        assert resp.status_objects[0].status_object_id == "obj-1"

    def test_from_dict_null_data(self):
        resp = StatusFeedResponse.from_dict({"data": None})
        assert resp.status_objects == []
