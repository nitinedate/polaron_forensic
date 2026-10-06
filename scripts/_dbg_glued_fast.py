"""Fast probe: load persisted cache + sanitize only (no ChatSearch enrich)."""
from __future__ import annotations

from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_evidence_browse import (
    _load_browse_cache,
    _sanitize_deleted_protocol_noise,
    _whatsapp_deleted_person_rows,
)
from app.services.chat_message_extract import _split_whatsapp_carve_text
from app.services.artifact_group_browse import _person_key_from_row, _split_person_bucket_id

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"


def main() -> None:
    db = SessionLocal()
    try:
        db.execute(text('SET search_path TO "firm_aetheris", public'))
        persons = _whatsapp_deleted_person_rows(db, JOB)
        target = next(
            (
                p
                for p in persons
                if "7th" in str(p.get("title") or "").lower()
                or "common grp" in str(p.get("title") or "").lower()
            ),
            None,
        )
        print("target", target.get("id") if target else None, target.get("title") if target else None)
        pid = str(target.get("id") or "")
        base_id, _ = _split_person_bucket_id(pid)

        full = _load_browse_cache(db, JOB, "wa_deleted_v17") or _load_browse_cache(db, JOB, "wa_deleted_v16") or _load_browse_cache(db, JOB, "wa_deleted_v15") or _load_browse_cache(db, JOB, "wa_deleted_v14") or _load_browse_cache(db, JOB, "wa_deleted_v13")
        print("cache rows", None if full is None else len(full))
        if not full:
            return
        kept = []
        for row in full:
            meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            try:
                sid, _, _ = _person_key_from_row(row)
            except Exception:
                continue
            if sid == base_id:
                kept.append(row)
        print("filtered", len(kept))

        before = 0
        samples = []
        for r in kept:
            meta = r.get("metadata") or {}
            blob = str(meta.get("original_content") or meta.get("body") or meta.get("preview_body") or "")
            if "@g.us" in blob or "@lid" in blob:
                before += 1
                if len(samples) < 3:
                    samples.append(blob[:180])
        print("before_glued", before)
        for s in samples:
            print(" SAMPLE", repr(s))
            print(" SPLIT", _split_whatsapp_carve_text(s))

        _sanitize_deleted_protocol_noise(kept)
        after = 0
        for r in kept:
            meta = r.get("metadata") or {}
            for key in ("original_content", "body", "preview_body"):
                blob = str(meta.get(key) or "")
                if "@g.us" in blob or "@lid" in blob:
                    # protocol_residue is allowed to keep @g.us
                    if key == "protocol_residue":
                        continue
                    # preview may list residue under a separate label
                    if key == "preview_body" and "Protocol residue" in blob:
                        # check Original content section only
                        if "Original content:" in blob:
                            part = blob.split("Original content:", 1)[1]
                            part = part.split("Protocol residue", 1)[0]
                            if "@g.us" in part or "@lid" in part:
                                after += 1
                                if after <= 3:
                                    print("STILL in original section:", repr(part[:160]))
                        continue
                    after += 1
                    if after <= 3:
                        print("STILL", key, repr(blob[:160]))
                    break
        print("after_glued_fields", after)
        # show one cleaned preview
        for r in kept:
            meta = r.get("metadata") or {}
            if meta.get("protocol_residue") and meta.get("original_content"):
                print("OK oc:", repr(str(meta["original_content"])[:120]))
                print("OK res:", repr(str(meta["protocol_residue"])[:80]))
                print("OK prev:", repr(str(meta.get("preview_body") or "")[:300]))
                break
    finally:
        db.close()


if __name__ == "__main__":
    main()
