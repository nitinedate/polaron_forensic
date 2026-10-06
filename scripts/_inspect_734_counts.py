"""Inspect job 734 media/doc/carve + inventory rows."""
from __future__ import annotations

import json
from sqlalchemy import text
from app.db.session import firm_session

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"

with firm_session("firm_aetheris") as db:
    ds = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": JID}).scalar()
    d = ds if isinstance(ds, dict) else json.loads(ds or "{}")
    m = d.get("media_disk_inventory") or {}
    doc = d.get("document_disk_inventory") or {}
    carve = d.get("signature_carve_inventory") or {}
    print(
        "media",
        m.get("source"),
        "pic",
        m.get("picture"),
        "vid",
        m.get("video"),
        "aud",
        m.get("audio"),
        "psd",
        m.get("photoshop"),
        "thumb",
        m.get("thumbcache_entries"),
        "files",
        m.get("enumerated_files"),
    )
    print(
        "doc",
        {
            k: doc.get(k)
            for k in (
                "pdf",
                "rtf",
                "doc",
                "docx",
                "xls",
                "xlsx",
                "ppt",
                "pptx",
                "source",
                "enumerated_files",
            )
        },
    )
    print("carve axiom", carve.get("axiom_counts"))
    print(
        "carve meta",
        "hits",
        carve.get("hit_total"),
        "unalloc",
        carve.get("unalloc_bytes_scanned"),
        "urls",
        len(carve.get("url_records") or []),
    )
    rows = db.execute(
        text(
            """
            SELECT artifact_name, count
            FROM axiom_inventory
            WHERE job_id=:j
              AND artifact_name = ANY(:names)
            ORDER BY artifact_name
            """
        ),
        {
            "j": JID,
            "names": [
                "Picture",
                "Video",
                "Photoshop Files",
                "PDF Documents",
                "RTF Documents",
                "Outlook Emails",
                "Email Attachments",
                "Social Media URLs",
                "Web Chat URLs",
                "USB Devices",
                "Audio",
                "Encrypted Files",
                "Logfile Analysis",
            ],
        },
    ).fetchall()
    for r in rows:
        print("inv", r[0], r[1])

    # Video extension histogram from path samples / job_artifacts
    vids = db.execute(
        text(
            """
            SELECT lower(substring(file_path from '\\.[^.]+$')) AS ext, count(*)
            FROM job_artifacts
            WHERE job_id=:j
              AND lower(substring(file_path from '\\.[^.]+$')) = ANY(
                ARRAY['.mp4','.avi','.mkv','.mov','.wmv','.mpeg','.mpg','.flv','.m4v','.3gp','.webm','.asf','.vob','.ts','.m2ts']
              )
            GROUP BY 1 ORDER BY 2 DESC
            """
        ),
        {"j": JID},
    ).fetchall()
    print("job_artifacts video exts", vids)

    psd = db.execute(
        text(
            """
            SELECT count(*) FROM job_artifacts
            WHERE job_id=:j AND lower(file_path) LIKE '%.psd'
            """
        ),
        {"j": JID},
    ).scalar()
    print("job_artifacts psd", psd)
