from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files
from app.parsers.jumplist import parse_jump_list

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
rows = fetchall(
    db,
    """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
         file_path ILIKE '%.automaticDestinations-ms'
         OR file_path ILIKE '%.customDestinations-ms'
       )""",
    {"j": job},
)
contents = _read_job_files(db, job, rows)
auto_emb = custom_emb = auto_ent = 0
for row in rows:
    path = row["file_path"].replace("\\", "/")
    data = contents.get(path)
    if not data:
        continue
    for rec in parse_jump_list(data, path):
        if rec.get("record_type") != "jump_list_file":
            continue
        kind = (rec.get("jump_list_kind") or "").lower()
        if kind == "custom":
            custom_emb += int(rec.get("embedded_lnk_count") or 0)
        else:
            auto_emb += int(rec.get("embedded_lnk_count") or 0)
            auto_ent += int(rec.get("entry_count") or 0)
print("auto embedded", auto_emb, "custom embedded", custom_emb, "auto entries", auto_ent)
print("625 + auto_emb", 625 + auto_emb)
print("625 + auto_ent", 625 + auto_ent)
db.close()
