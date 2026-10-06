"""Find social-domain strings on the job / disk."""
from sqlalchemy import text
from app.db.session import firm_session
from app.services.artifact_live_counts import _read_job_files

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
DOMAINS = (
    b"facebook.com",
    b"instagram.com",
    b"linkedin.com",
    b"twitter.com",
    b"youtube.com",
    b"web.whatsapp.com",
    b"teams.microsoft.com",
    b"reddit.com",
)

with firm_session("firm_aetheris") as db:
    rows = db.execute(
        text(
            """
            SELECT id, file_path, size_bytes FROM job_artifacts
            WHERE job_id=:j AND (
              file_path ILIKE '%History%'
              OR file_path ILIKE '%places.sqlite%'
              OR file_path ILIKE '%Web Data%'
              OR file_path ILIKE '%Cookies%'
              OR file_path ILIKE '%.pst'
              OR lower(file_name) IN ('pagefile.sys','hiberfil.sys')
            )
            AND size_bytes > 1000
            ORDER BY size_bytes DESC NULLS LAST
            LIMIT 40
            """
        ),
        {"j": JID},
    ).mappings().all()
    print("sources", len(rows))
    for r in rows[:15]:
        print(" ", r["size_bytes"], r["file_path"][:120])

    contents = _read_job_files(db, JID, [dict(r) for r in rows], max_bytes=80_000_000)
    for r in rows:
        path = (r["file_path"] or "").replace("\\", "/")
        data = contents.get(path) or b""
        if not data:
            continue
        hits = {d.decode(): data.count(d) + data.count(d.decode().encode("utf-16le")) for d in DOMAINS}
        hits = {k: v for k, v in hits.items() if v}
        if hits:
            print(path[:100], hits)
