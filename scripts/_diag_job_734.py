"""Diagnose census/carve/media for job 734dcf91."""
from __future__ import annotations

import json
from sqlalchemy import text
from app.db.session import firm_session_readonly

jid = "734dcf91-453f-4461-aeef-0ea1fefa0613"
with firm_session_readonly("firm_aetheris") as db:
    arts = db.execute(text("SELECT COUNT(*) FROM job_artifacts WHERE job_id=:j"), {"j": jid}).scalar()
    print("job_artifacts", arts)
    ds = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": jid}).scalar()
    d = ds if isinstance(ds, dict) else json.loads(ds or "{}")
    for k in (
        "media_disk_inventory",
        "document_disk_inventory",
        "lnk_disk_count",
        "signature_carve_inventory",
        "thumbcache_inventory",
    ):
        v = d.get(k)
        if isinstance(v, dict):
            print(k, {kk: v.get(kk) for kk in list(v)[:12]})
        else:
            print(k, v)

    from app.services.axiom_aligned_counts import count_axiom_catalog_artifact
    from app.services.media_inventory import media_counts_for_answer
    from app.services.signature_carve_inventory import carved_axiom_count, ensure_signature_carve_inventory

    print("media_counts_for_answer", media_counts_for_answer(db, jid))
    for name, cat in [
        ("Picture", "Media"),
        ("Video", "Media"),
        ("Photoshop Files", "Media"),
        ("Audio", "Media"),
        ("PDF Documents", "Documents"),
        ("RTF Documents", "Documents"),
        ("Outlook Emails", "Email & Calendar"),
        ("Email Attachments", "Email & Calendar"),
        ("USB Devices", "Connected Devices"),
        ("Social Media URLs", "Communication"),
        ("Web Chat URLs", "Communication"),
    ]:
        c = count_axiom_catalog_artifact(db, jid, artifact_name=name, category=cat)
        print(f"LIVE {name}: {c}")

    inv = ensure_signature_carve_inventory(db, jid)
    print(
        "carve",
        inv.get("axiom_counts"),
        "hits",
        inv.get("hit_total"),
        "urls",
        len(inv.get("url_records") or []),
        "unalloc",
        inv.get("unalloc_bytes_scanned"),
    )
