"""Probe live deleted-message bodies for glued JID+text."""
from __future__ import annotations

from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_evidence_browse import (
    _whatsapp_deleted_message_rows,
    _whatsapp_deleted_person_rows,
)
from app.services.chat_message_extract import _split_whatsapp_carve_text

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"


def main() -> None:
    db = SessionLocal()
    try:
        db.execute(text('SET search_path TO "firm_aetheris", public'))
        persons = _whatsapp_deleted_person_rows(db, JOB)
        hits = [
            p
            for p in persons
            if "7th" in str(p.get("title") or "").lower()
            or "common grp" in str(p.get("title") or "").lower()
            or "7th" in str((p.get("metadata") or {}).get("conversation") or "").lower()
        ]
        print("person hits", len(hits))
        for p in hits[:8]:
            print(" ", p.get("id"), "|", p.get("title"))
        target = hits[0] if hits else None
        if not target:
            print("no 7th std person; sample titles:")
            for p in persons[:15]:
                print(" ", p.get("title"))
            return
        pid = str(target.get("id") or "")
        print("using", pid, target.get("title"))
        rows = _whatsapp_deleted_message_rows(db, JOB, person_id=pid)
        print("rows", len(rows))
        glued = 0
        for r in rows[:80]:
            meta = r.get("metadata") or {}
            oc = str(meta.get("original_content") or "")
            body = str(meta.get("body") or "")
            prev = str(meta.get("preview_body") or "")
            sample = oc or body
            if "@g.us" in sample or "@lid" in sample or "@g.us" in prev:
                glued += 1
                clean, res = _split_whatsapp_carve_text(sample)
                print("---")
                print("oc:", repr(oc[:140]))
                print("body:", repr(body[:140]))
                print("split clean:", repr((clean or "")[:100]))
                print("split res:", repr((res or "")[:80]))
                if "Original content:" in prev:
                    idx = prev.index("Original content:")
                    print("preview:", repr(prev[idx : idx + 220]))
        print("glued_count_in_first_80", glued)
    finally:
        db.close()


if __name__ == "__main__":
    main()
