"""Tests for data model from_dict parsing."""

from schwab_advisor.models import (
    Alert,
    AlertArchiveResponse,
    AlertDetail,
    AlertDetailResponse,
    AlertUpdateResponse,
    ArchiveDetail,
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
                "id": "some-uuid",
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
        assert resp.are_all_archived is True
        assert len(resp.archive_details) == 1
        assert resp.archive_details[0].alert_id == 15157526
        assert resp.archive_details[0].has_status_changed is True

    def test_from_dict_empty(self):
        resp = AlertArchiveResponse.from_dict({})
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
