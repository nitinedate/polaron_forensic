"""Time Shiny open under firm_aetheris (real schema)."""
from __future__ import annotations

import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_evidence_browse import (
    _load_whatsapp_deleted_browse_cache,
    _whatsapp_deleted_message_rows,
)
from app.services.artifact_group_browse import _person_key_from_row, _split_person_bucket_id

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
PID = "person:4ad02db5e27f5dd0::deleted"


def main() -> None:
    db = SessionLocal()
    try:
        db.execute(text("SET search_path TO firm_aetheris, public"))
        t0 = time.perf_counter()
        full = _load_whatsapp_deleted_browse_cache(db, JOB)
        t1 = time.perf_counter()
        print(f"cache_load_sec={t1 - t0:.3f} rows={0 if full is None else len(full)}")
        if full:
            base, _ = _split_person_bucket_id(PID)
            hits = 0
            shiny_keys = set()
            for row in full:
                try:
                    sid, name, _ = _person_key_from_row(row)
                except Exception:
                    continue
                if "shiny" in str(name).lower():
                    shiny_keys.add((sid, name))
                meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
                stamped = str(meta.get("base_person_id") or meta.get("person_id") or "").strip()
                stamped_base = _split_person_bucket_id(stamped)[0] if stamped else ""
                if sid == base or stamped_base == base:
                    hits += 1
            print(f"filter_hits_for_pid={hits}")
            print(f"shiny_keys={list(shiny_keys)[:8]}")
        t2 = time.perf_counter()
        rows = _whatsapp_deleted_message_rows(db, JOB, person_id=PID)
        t3 = time.perf_counter()
        print(f"person_rows_sec={t3 - t2:.3f} count={len(rows)}")
        if rows:
            m = rows[0].get("metadata") or {}
            print("sample_body", str(m.get("body") or m.get("original_content") or "")[:120])
    finally:
        db.close()


if __name__ == "__main__":
    main()
