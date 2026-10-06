"""Unit tests for person/group chat grouping."""

from app.services.artifact_group_browse import (
    apply_family_grouping,
    enrich_chat_row,
    filter_rows_for_person,
    group_message_rows_as_persons,
    resolve_group_mode,
)


def _msg(
    *,
    app: str,
    conversation: str,
    conversation_id: str,
    sender: str,
    body: str,
    ts: str,
    from_me: bool = False,
    is_group: bool = False,
    deleted: bool = False,
    recovery_state: str | None = None,
    media_name: str | None = None,
) -> dict:
    return {
        "id": f"ev-{app}-{conversation_id}-{ts}-{body[:8]}",
        "job_id": "job-1",
        "artifact_type": "chat_message",
        "title": f"{sender}: {body}",
        "source_path": f"/data/{app}.db",
        "artifact_datetime": ts,
        "tags": ["deleted"] if deleted else [],
        "parser_version": f"{app}_parse",
        "confidence": "high",
        "metadata": {
            "evidence_kind": "chat_message",
            "social_app": app,
            "conversation": conversation,
            "conversation_id": conversation_id,
            "sender": sender,
            "body": body,
            "timestamp": ts,
            "from_me": from_me,
            "is_group": is_group,
            "is_deleted": deleted,
            "recovery_state": recovery_state,
            "media_name": media_name,
            "source_artifact_id": "ART-1",
        },
    }


def test_resolve_group_mode_defaults_to_person_for_chats():
    assert resolve_group_mode("whatsapp_messages", None) == "person"
    assert resolve_group_mode("sms", "conversation") == "conversation"
    assert resolve_group_mode("pictures", None) == "album"


def test_person_merge_across_apps():
    rows = [
        _msg(
            app="whatsapp",
            conversation="Person A",
            conversation_id="wa:1",
            sender="Person A",
            body="Good morning",
            ts="2026-08-10T09:15:00Z",
        ),
        _msg(
            app="whatsapp",
            conversation="Person A",
            conversation_id="wa:1",
            sender="me",
            body="Are you coming today?",
            ts="2026-08-10T09:17:00Z",
            from_me=True,
        ),
        _msg(
            app="sms",
            conversation="Person A",
            conversation_id="sms:9",
            sender="Person A",
            body="Please call me.",
            ts="2026-08-09T18:42:00Z",
        ),
        _msg(
            app="telegram",
            conversation="Person A",
            conversation_id="tg:3",
            sender="me",
            body="Document sent",
            ts="2026-08-08T14:20:00Z",
            from_me=True,
            media_name="doc.pdf",
        ),
    ]
    people = group_message_rows_as_persons(rows, job_id="job-1")
    assert len(people) == 1
    meta = people[0]["metadata"]
    assert meta["message_count"] == 4
    assert set(meta["applications"]) >= {"WhatsApp", "SMS", "Telegram"}
    assert meta["deleted_count"] == 0
    assert meta["media_count"] >= 1


def test_deleted_filter_and_recovery_enrichment():
    rows = [
        _msg(
            app="whatsapp",
            conversation="Person A",
            conversation_id="wa:1",
            sender="Person A",
            body="Bring the documents.",
            ts="2026-08-07T11:42:00Z",
            deleted=True,
            recovery_state="sqlite_wal",
        ),
        _msg(
            app="whatsapp",
            conversation="Person A",
            conversation_id="wa:1",
            sender="Person A",
            body="Still here",
            ts="2026-08-07T12:00:00Z",
        ),
    ]
    people = group_message_rows_as_persons(rows, job_id="job-1")
    pid = people[0]["metadata"]["person_id"]
    deleted_only = filter_rows_for_person(rows, pid, message_filter="deleted")
    assert len(deleted_only) == 1
    enriched = enrich_chat_row(deleted_only[0])
    recovery = enriched["metadata"]["recovery"]
    assert recovery["classification"] == "WAL_RECOVERED"
    assert recovery["is_current"] is False
    assert enriched["metadata"]["sender_display_name"] == "Person A"
    assert "provenance" in enriched["metadata"]


def test_group_participants_and_apply_family_grouping():
    rows = [
        _msg(
            app="whatsapp",
            conversation="Project Team",
            conversation_id="wa-g:1",
            sender="Person A",
            body="Meeting at 11.",
            ts="2026-08-10T08:40:00Z",
            is_group=True,
        ),
        _msg(
            app="whatsapp",
            conversation="Project Team",
            conversation_id="wa-g:1",
            sender="Person B",
            body="Okay.",
            ts="2026-08-10T08:42:00Z",
            is_group=True,
        ),
        _msg(
            app="whatsapp",
            conversation="Project Team",
            conversation_id="wa-g:1",
            sender="me",
            body="I'll join.",
            ts="2026-08-10T08:44:00Z",
            from_me=True,
            is_group=True,
        ),
    ]
    out, mode, summary = apply_family_grouping(
        rows, job_id="job-1", family="whatsapp_messages", group_by="person"
    )
    assert mode == "person"
    assert len(out) == 1
    assert out[0]["metadata"]["is_group"] is True
    assert out[0]["metadata"]["participant_count"] >= 3
    gid = out[0]["metadata"]["person_id"]
    thread, mode2, summary2 = apply_family_grouping(
        rows,
        job_id="job-1",
        family="whatsapp_messages",
        group_by="person",
        group_id=gid,
        message_filter="all",
    )
    assert mode2 == "person"
    assert len(thread) == 3
    assert summary2 is not None
    assert summary2["message_count"] == 3
    assert "Device Owner" in summary2["participants"]


def test_chat_rows_have_stable_sha256_record_hash_for_transcript():
    row = _msg(
        app="whatsapp",
        conversation="Person A",
        conversation_id="wa:1",
        sender="Person A",
        body="Bring the documents.",
        ts="2026-08-07T11:42:00Z",
        deleted=True,
        recovery_state="sqlite_wal",
    )
    one = enrich_chat_row(row)
    two = enrich_chat_row(row)
    h1 = one["metadata"]["record_hash_sha256"]
    h2 = two["metadata"]["record_hash_sha256"]
    assert h1 == h2
    assert len(h1) == 64
    assert all(ch in "0123456789abcdef" for ch in h1)
    assert one["metadata"]["provenance"]["record_hash_sha256"] == h1
