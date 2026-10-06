"""Browse parsed WhatsApp records, including decrypted backups and text exports."""

from __future__ import annotations

import hashlib
import json

from app.db.sql_helpers import fetchall, fetchone

DELETED = ("database_deleted", "wal_recovered", "journal_recovered", "freelist_candidate", "fragment")
FAMILIES = {"whatsapp_messages", "whatsapp_chats", "whatsapp_deleted_messages"}
_CONVERSATION = "COALESCE(NULLIF(data->>'conversation_id',''),forensic->>'source_path',artifact_id)"


def _json(value):
    return json.loads(value) if isinstance(value, str) else (value or {})


def whatsapp_recovery_notice(job_id, family, db=None):
    statuses = []
    if db is not None:
        table = fetchone(db, "SELECT to_regclass('mobile_normalized_artifacts') AS t")
        if table and table.get("t"):
            rows = fetchall(db, """SELECT data,forensic FROM mobile_normalized_artifacts
                WHERE job_id=:jid AND data->>'application'='whatsapp'
                AND artifact_type='app_backup_encrypted' ORDER BY artifact_id""", {"jid": job_id})
            for row in rows:
                data = _json(row.get("data"))
                forensic = _json(row.get("forensic"))
                diag = data.get("decrypt_diagnostics") or {}
                statuses.append({"source_path": forensic.get("source_path") or data.get("path"),
                                 "state": data.get("decryption_state") or "unverified",
                                 "reason": diag.get("reason") or "not_processed",
                                 "keys_tried": diag.get("keys_tried") or 0})
    body = (
        "No readable WhatsApp records in this view yet.\n\n"
        "Supported sources: plaintext msgstore.db / ChatStorage.sqlite (with available WAL files), "
        "authenticated crypt12/14/15 backups with a matching key, structurally checked legacy crypt5/7/8, or WhatsApp TXT chat exports with their media.\n\n"
        "crypt7/8/12/14: collect files/key (typically 158 bytes) from the matching WhatsApp installation. "
        "crypt5 requires the exact original Android Google account email. Legacy CBC formats have no authentication tag. "
        "crypt15: collect files/encrypted_backup.key (raw or Java-serialized), or enter the owner's 64-character backup key. "
        "An adb run-as error saved as a key file is invalid; a backup password alone is not a local decryption key.\n\n"
        "Save a valid key under Case Intake → Decrypt keys, then choose Reprocess mobile evidence when the job is idle. "
        "Every collected key is tried against each backup. Backup status gives the reason if authentication fails.\n\n"
        "For acquisition, include private app databases/keys from an already-accessible filesystem extraction, "
        "including WhatsApp Business and Android user profiles. If the owner's phone can open WhatsApp, export each required chat "
        "with media and import the export as evidence. An ordinary shared-storage ADB/MTP pull cannot read a production app's private sandbox.\n"
        "Exports contain only the history the app exports. Deleted recovery requires surviving database rows, WAL or residual evidence; "
        "overwritten/absent messages cannot be supplied by a parser."
    )
    if statuses:
        totals = {}
        for item in statuses:
            reason = item["reason"] if item["state"] != "decrypted" else "decrypted"
            totals[reason] = totals.get(reason, 0) + 1
        body += "\n\nCollected backup results: " + "; ".join(f"{reason}: {count}" for reason, count in sorted(totals.items()))
    return {"id": f"ev-notice-{family}", "job_id": job_id, "artifact_type": "notice",
            "title": "WhatsApp recovery sources and next steps", "source_path": None,
            "metadata": {"evidence_kind": "notice", "preview_body": body, "body": body,
                         "backup_results": statuses}, "tags": ["notice", "no_chat_data"]}


def _row(record, job_id):
    from app.services.artifact_group_browse import _person_key_from_row

    data = _json(record.get("data"))
    forensic = _json(record.get("forensic"))
    state = record.get("state") or forensic.get("state") or "unverified"
    deleted = state in DELETED
    candidate = state in {"freelist_candidate", "fragment"}
    conversation = str(data.get("conversation_id") or forensic.get("source_path") or record["artifact_id"])
    title = str(data.get("conversation_name") or data.get("conversation_title") or conversation)
    body = str(data.get("body") or "")
    stamp = record.get("timestamp_utc")
    stamp = stamp.isoformat() if hasattr(stamp, "isoformat") else stamp
    meta = {**data, "evidence_kind": "whatsapp_message", "social_app": "whatsapp",
            "normalized_artifact_id": record["artifact_id"],
            "conversation_id": conversation, "conversation": title,
            "chat_jid": conversation if "@" in conversation else None,
            "is_group": conversation.endswith("@g.us"), "is_deleted": None if candidate else deleted,
            "is_deleted_candidate": candidate,
            "body": body, "timestamp": stamp or data.get("timestamp_local"),
            "source_path": forensic.get("source_path"), "source_sha256": forensic.get("source_sha256"),
            "forensic_state": state, "forensic": forensic,
            "classification": forensic.get("ui_label") or state.upper(),
            # Legacy grouping treats any recovery_state as deleted. Preserve
            # historical/exported state separately so it cannot leak into Deleted.
            "recovery_state": state if deleted else "",
            "preview_body": f"WhatsApp: {title}\nTime: {stamp or data.get('timestamp_local') or 'unspecified'}\n"
                            f"Sender: {data.get('sender') or 'unspecified'}\nState: {state}\n\n{body}\n\n"
                            f"Source: {forensic.get('source_path') or ''}\nSHA256: {forensic.get('source_sha256') or ''}"}
    row = {"id": "ev-mobile-" + record["artifact_id"], "job_id": job_id, "artifact_type": "whatsapp_message",
           "title": title, "source_path": forensic.get("source_path"), "artifact_datetime": stamp,
           "metadata": meta, "tags": ["whatsapp", state] + (["deleted"] if deleted else [])}
    person, label, group = _person_key_from_row(row)
    meta.update({"person_id": person, "base_person_id": person, "person_name": label, "is_group": group})
    return row


def _link_media(db, job_id, rows):
    names = sorted({str(row["metadata"].get("media_name") or "").lower() for row in rows} - {""})
    if not names:
        return
    files = fetchall(db, """SELECT id,file_path,file_name FROM job_artifacts
        WHERE job_id=:jid AND lower(file_name)=ANY(CAST(:names AS text[]))""", {"jid": job_id, "names": names})
    for row in rows:
        meta = row["metadata"]
        name = str(meta.get("media_name") or "").lower()
        path = str(meta.get("media_path") or "").replace("\\", "/")
        matches = [item for item in files if str(item["file_name"]).lower() == name]
        exact = [item for item in matches if str(item["file_path"]).replace("\\", "/") == path]
        match = exact[0] if len(exact) == 1 else matches[0] if len(matches) == 1 else None
        if match:
            meta["media_artifact_id"] = str(match["id"])
            meta["media_path"] = match["file_path"]


def list_whatsapp_evidence(db, job_id, *, family="whatsapp_messages", page=1, page_size=50,
                           group_by=None, group_id=None, message_filter=None, q=None):
    """Return None before normalized parsing; otherwise SQL-page complete records."""
    if family not in FAMILIES:
        return None
    table = fetchone(db, "SELECT to_regclass('mobile_normalized_artifacts') AS t")
    if not table or not table.get("t"):
        return None
    present = fetchone(db, """SELECT 1 AS found FROM mobile_normalized_artifacts
        WHERE job_id=:jid AND data->>'application'='whatsapp' AND artifact_type='app_message' LIMIT 1""", {"jid": job_id})
    if not present:
        return None
    page = max(int(page or 1), 1)
    page_size = max(1, min(int(page_size or 50), 200))
    params = {"jid": job_id, "deleted": list(DELETED), "limit": page_size, "offset": (page - 1) * page_size}
    where = "job_id=:jid AND data->>'application'='whatsapp' AND artifact_type='app_message'"
    deleted_only = family == "whatsapp_deleted_messages" or str(group_id or "").endswith("::deleted")
    if deleted_only or message_filter == "deleted":
        where += " AND state=ANY(CAST(:deleted AS text[]))"
    elif message_filter == "current":
        where += " AND state='allocated'"
    elif family != "whatsapp_deleted_messages" and not group_id:
        where += " AND NOT(state=ANY(CAST(:deleted AS text[])))"
    if message_filter == "media":
        where += " AND (data->>'has_attachment'='true' OR NULLIF(data->>'media_name','') IS NOT NULL)"
    if message_filter == "calls":
        where += " AND data->>'message_type_label' ILIKE '%call%'"
    if q:
        where += " AND strpos(lower(data::text),lower(:q))>0"
        params["q"] = str(q)
    grouped = group_by in {"person", "conversation"}
    summaries = []
    if grouped or group_id:
        base = f"SELECT *, {_CONVERSATION} AS conv FROM mobile_normalized_artifacts WHERE {where}"
        summaries = fetchall(db, f"""WITH base AS ({base}), counts AS (
            SELECT conv,count(*) AS message_count,count(*) FILTER(WHERE state='allocated') AS current_count,
                count(*) FILTER(WHERE state=ANY(CAST(:deleted AS text[]))) AS deleted_count,
                count(*) FILTER(WHERE state IN ('historical','backup_historical')) AS historical_count,
                count(*) FILTER(WHERE data->>'has_attachment'='true') AS media_count
            FROM base GROUP BY conv), latest AS (
            SELECT DISTINCT ON(conv) * FROM base ORDER BY conv,timestamp_utc DESC NULLS LAST,artifact_id DESC)
            SELECT latest.*,counts.message_count,counts.current_count,counts.deleted_count,counts.historical_count,counts.media_count
            FROM latest JOIN counts USING(conv)""", params)
    if group_id:
        want = str(group_id).removesuffix("::deleted")
        conversations = []
        for record in summaries:
            meta = _row(record, job_id)["metadata"]
            identity = meta["person_id"] if group_by == "person" else meta["conversation_id"]
            if identity == want:
                conversations.append(record["conv"])
        where += f" AND {_CONVERSATION}=ANY(CAST(:conversations AS text[]))"
        params["conversations"] = conversations
    if grouped and not group_id:
        buckets = {}
        for record in summaries:
            row = _row(record, job_id)
            meta = row["metadata"]
            identity = meta["person_id"] if group_by == "person" else meta["conversation_id"]
            if deleted_only:
                identity += "::deleted"
            if identity not in buckets:
                kind = "group" if meta["is_group"] else "person" if group_by == "person" else "conversation"
                row.update({"id": "ev-normalized-" + hashlib.sha256(identity.encode()).hexdigest()[:24], "artifact_type": kind})
                meta.update({"evidence_kind": kind, "person_id": identity, "deleted_bucket": deleted_only,
                             "applications": ["WhatsApp"], "message_count": 0, "current_count": 0,
                             "deleted_count": 0, "historical_count": 0, "media_count": 0})
                buckets[identity] = row
            bucket = buckets[identity]["metadata"]
            for key in ("message_count", "current_count", "deleted_count", "historical_count", "media_count"):
                bucket[key] += int(record.get(key) or 0)
            bucket["preview_body"] = (f"WhatsApp: {bucket['conversation']}\nMessages: {bucket['message_count']}\n"
                                      f"Current: {bucket['current_count']}\nHistorical: {bucket['historical_count']}\n"
                                      f"Deleted/recovery candidates: {bucket['deleted_count']}\nMedia references: {bucket['media_count']}")
        rows = sorted(buckets.values(), key=lambda row: str(row["title"]).casefold())
        total = len(rows)
        rows = rows[params["offset"]:params["offset"] + page_size]
        summary = None
    else:
        total = int((fetchone(db, f"SELECT count(*) AS n FROM mobile_normalized_artifacts WHERE {where}", params) or {}).get("n") or 0)
        records = fetchall(db, f"""SELECT * FROM mobile_normalized_artifacts WHERE {where}
            ORDER BY timestamp_utc NULLS LAST,forensic->>'source_path',
                CASE WHEN data->>'source_line_start' ~ '^[0-9]+$' THEN (data->>'source_line_start')::bigint END,
                artifact_id LIMIT :limit OFFSET :offset""", params)
        rows = [_row(record, job_id) for record in records]
        _link_media(db, job_id, rows)
        summary = {"person_id": group_id, "message_count": total} if group_id else None
    return {"items": rows, "total": total, "page": page, "page_size": page_size,
            "group_by": group_by, "group_id": group_id, "message_filter": message_filter or "all",
            "thread_summary": summary, "evidence_domain": "whatsapp_message", "evidence_label": family,
            "normalized_evidence": True}
