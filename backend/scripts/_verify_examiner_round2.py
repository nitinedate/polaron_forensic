from app.db.session import SessionLocal, apply_firm_search_path
from app.services.artifact_evidence_browse import list_evidence_items, _looks_like_chat_body
from app.services.artifact_family_browse import filter_evidence_rows_for_family

JOB = "02bcb441-d1de-45b0-8a79-9c9139f08875"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
try:
    checks = [
        ("whatsapp_chats", "WhatsApp Chats"),
        ("whatsapp_deleted_messages", "WhatsApp Deleted Messages"),
        ("deleted_social", "Deleted Social / Chat Data"),
        ("email_attachments", "Email Attachments"),
        ("sms_attachments", "SMS / MMS Attachments"),
    ]
    for fam, name in checks:
        ev = list_evidence_items(db, JOB, artifact_name=name, page=1, page_size=20_000, hard_cap=20_000)
        rows = filter_evidence_rows_for_family(fam, list((ev or {}).get("items") or []))
        sms = sum(1 for r in rows if "sms.db" in str(r.get("source_path") or "").lower())
        junk = sum(
            1
            for r in rows
            if "WAMessageDataItem" in str(r.get("title") or "")
            or (
                "@s.whatsapp.net" in str(r.get("title") or "")
                and " " not in str(((r.get("metadata") or {}).get("body") or ""))
            )
        )
        sample = str(rows[0].get("title") if rows else "")[:90]
        print(
            f"{fam}: total={(ev or {}).get('total')} filtered={len(rows)} sms_src={sms} junkish={junk} sample={sample!r}"
        )
    print("body filters", _looks_like_chat_body("WAMessageDataItem"), _looks_like_chat_body("hi there friend"))
finally:
    db.close()
