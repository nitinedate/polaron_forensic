"""Locate pagefile/hiberfil and large cache sources."""
from sqlalchemy import text
from app.db.session import firm_session
from app.services.virtual_disk import enumerate_all_files, open_virtual_disk

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"

with firm_session("firm_aetheris") as db:
    rows = db.execute(
        text(
            """
            SELECT file_path, size_bytes FROM job_artifacts
            WHERE job_id=:j AND (
              lower(file_name) IN ('pagefile.sys','hiberfil.sys','swapfile.sys')
              OR file_path ILIKE '%pagefile%'
              OR file_path ILIKE '%hiberfil%'
              OR file_path ILIKE '%thumbcache%'
              OR lower(file_name)='thumbs.db'
            )
            ORDER BY size_bytes DESC NULLS LAST
            LIMIT 50
            """
        ),
        {"j": JID},
    ).fetchall()
    print("job_artifacts hits", len(rows))
    for r in rows[:30]:
        print(r[1], r[0])

    vd = open_virtual_disk(db, JID)
    found = []
    for n in enumerate_all_files(vd):
        p = (n.get("path") or "").replace("\\", "/")
        low = p.lower()
        base = low.rsplit("/", 1)[-1]
        if base in {"pagefile.sys", "hiberfil.sys", "swapfile.sys"} or "thumbcache" in base:
            found.append((n.get("size") or n.get("size_bytes"), p))
    found.sort(key=lambda x: -(x[0] or 0))
    print("vd found", len(found))
    for s, p in found[:40]:
        print(s, p)
