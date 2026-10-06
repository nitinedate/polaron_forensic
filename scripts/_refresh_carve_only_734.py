"""Force pagefile/hiberfil carve + persist Section B (no full census walk)."""
from __future__ import annotations

from app.db.session import firm_session
from app.services.signature_carve_inventory import clear_carve_cache, ensure_signature_carve_inventory
from app.services.browser_url_inventory import clear_browser_url_cache
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact, compute_all_aligned_count_results
from app.services.axiom_artifact_runner import _persist_axiom_inventory, clear_inventory_runtime_cache
from app.services.email_inventory import clear_email_count_cache

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
SCHEMA = "firm_aetheris"

PDF = {
    "USB Devices": 39,
    "Picture": 70580,
    "Video": 330,
    "Photoshop Files": 50,
    "PDF Documents": 400,
    "RTF Documents": 5847,
    "Outlook Emails": 216,
    "Email Attachments": 312,
    "Social Media URLs": 50,
    "Web Chat URLs": 10,
    "Audio": 594,
    "Microsoft Excel Documents": 150,
    "Microsoft Word Documents": 305,
    "Microsoft PowerPoint Documents": 21,
}

with firm_session(SCHEMA) as db:
    clear_carve_cache(JID)
    clear_browser_url_cache(JID)
    clear_inventory_runtime_cache(JID)
    clear_email_count_cache(JID)

    # Drop cached carve so force rebuild includes VD pagefile/hiberfil.
    from sqlalchemy import text
    import json

    row = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": JID}).scalar()
    ds = row if isinstance(row, dict) else json.loads(row or "{}")
    ds.pop("signature_carve_inventory", None)
    db.execute(
        text("UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:j"),
        {"ds": json.dumps(ds), "j": JID},
    )
    db.commit()

    print("=== Carve with VD pagefile/hiberfil ===")
    carve = ensure_signature_carve_inventory(db, JID, force=True)
    print(
        "axiom",
        carve.get("axiom_counts"),
        "hits",
        carve.get("hit_total"),
        "urls",
        len(carve.get("url_records") or []),
        "unalloc",
        carve.get("unalloc_bytes_scanned"),
        "ipm",
        carve.get("ipm_note_hits"),
        "sources",
        carve.get("sources_scanned"),
    )

    print("=== LIVE deltas ===")
    for name, pdf in PDF.items():
        if name in {"Picture", "Video", "Photoshop Files", "Audio"}:
            cat = "Media"
        elif "Document" in name or name.startswith("PDF") or name.startswith("RTF") or name.startswith("Microsoft"):
            cat = "Documents"
        elif "Email" in name or "Outlook" in name:
            cat = "Email & Calendar"
        elif "URL" in name:
            cat = "Communication"
        elif "USB" in name:
            cat = "Connected Devices"
        else:
            cat = "Operating System"
        app = count_axiom_catalog_artifact(db, JID, artifact_name=name, category=cat)
        print(f"{name:<32} PDF={pdf:>6} APP={app:>6} DELTA={app - pdf:+d}")

    results = compute_all_aligned_count_results(db, JID, "Windows", skip_warm=False)
    written = _persist_axiom_inventory(
        db,
        JID,
        platform="Windows",
        schema_name=SCHEMA,
        count_results=results,
        skip_section_snapshot=True,
    )
    db.commit()
    print("persisted", written)
