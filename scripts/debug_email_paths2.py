from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

patterns = [
    ("eml_any", "%eml%"),
    ("mbox", "%mbox%"),
    ("ics", "%.ics"),
    ("pst_ost", "%.pst%"),
    ("windows_mail", "%windowscommunicationsapps%"),
    ("olk", "%/Olk/%"),
    ("outlook_files", "%/Outlook Files/%"),
    ("localstate_mail", "%LocalState%Mail%"),
    ("hxoutlook", "%hxoutlook%"),
    ("store_vol", "%store.vol%"),
]
for name, p in patterns:
    r = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE :p",
        {"j": j, "p": p},
    )
    print(name, r["c"])

rows = fetchall(
    db,
    """SELECT file_path, extension, size_bytes FROM job_artifacts
       WHERE job_id=:j AND (
         file_path ILIKE '%.eml'
         OR file_path ILIKE '%.emlx'
         OR file_path ILIKE '%.mbox'
         OR file_path ILIKE '%.ics'
         OR file_path ILIKE '%/Olk/%'
         OR file_path ILIKE '%windowscommunicationsapps%LocalState%'
         OR file_path ILIKE '%/Outlook Files/%'
         OR file_path ILIKE '%store.vol%'
       )
       AND file_path NOT ILIKE '%Program Files%'
       AND file_path NOT ILIKE '%.exe'
       ORDER BY size_bytes DESC NULLS LAST LIMIT 40""",
    {"j": j},
)
print("filtered samples", len(rows))
for r in rows:
    print(r["file_path"][:120], r.get("extension"), r["size_bytes"])

db.close()
