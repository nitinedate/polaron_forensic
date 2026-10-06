from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
from app.services.artifact_evidence_browse import list_evidence_items
from app.services.artifact_family_browse import filter_evidence_rows_for_family

JOB = "02bcb441-d1de-45b0-8a79-9c9139f08875"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
try:
    for fam, name in [
        ("whatsapp_chats", "WhatsApp Chats"),
        ("sms", "SMS Messages"),
        ("whatsapp_messages", "WhatsApp Messages"),
    ]:
        ev = list_evidence_items(
            db, JOB, artifact_name=name, page=1, page_size=20_000, hard_cap=20_000
        )
        rows = filter_evidence_rows_for_family(fam, list((ev or {}).get("items") or []))
        sms_src = [
            r
            for r in rows
            if "sms.db" in str(r.get("source_path") or "").lower()
            or "sms_imessage" in str(r.get("source_path") or "").lower()
        ]
        print(fam, "api_total", (ev or {}).get("total"), "filtered", len(rows), "sms_src", len(sms_src))

    row = fetchone(
        db,
        "SELECT disk_source->'mobile_inventory'->'counts' AS c FROM jobs WHERE id=:j",
        {"j": JOB},
    )
    c = row["c"] if row else {}
    print(
        "board",
        {
            k: c.get(k)
            for k in (
                "whatsapp_chats",
                "whatsapp_messages",
                "sms",
                "email_attachments",
                "deleted_social",
                "sms_attachments",
            )
        },
    )
finally:
    db.close()
