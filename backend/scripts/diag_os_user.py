from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall, fetchone
from app.services.forensic_profile_index import collect_os_facts

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")

rows = fetchall(
    db,
    """SELECT ja.file_path, apr.normalized::text AS n
       FROM job_artifacts ja
       JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
       WHERE ja.job_id=:jid AND ja.file_path ILIKE '%config/SOFTWARE%'
       LIMIT 3""",
    {"jid": JOB},
)
print("SOFTWARE parses:", len(rows))
for r in rows:
    print(" ", r["file_path"], "len", len(r["n"] or ""))
    if "product_name" in (r["n"] or "").lower() or "windows_os" in (r["n"] or ""):
        print("  HAS OS DATA")

sam = fetchall(
    db,
    """SELECT count(*) c FROM job_artifacts ja
       WHERE ja.job_id=:jid AND ja.file_path ILIKE '%/SAM'""",
    {"jid": JOB},
)
print("SAM artifacts", sam)

chunk = fetchone(
    db,
    "SELECT content, metadata FROM rag_chunks WHERE job_id=:jid AND file_path='__forensic__/windows_user_profiles'",
    {"jid": JOB},
)
if chunk:
    print("USER content:\n", chunk["content"][:1200])
    print("META users", (chunk.get("metadata") or {}).get("users") if isinstance(chunk.get("metadata"), dict) else chunk.get("metadata"))

oschunk = fetchone(
    db,
    "SELECT content, metadata FROM rag_chunks WHERE job_id=:jid AND file_path='__forensic__/windows_os'",
    {"jid": JOB},
)
print("OS chunk exists", bool(oschunk))
if oschunk:
    print(oschunk["content"][:1200])

print("collect_os_facts", collect_os_facts(db, JOB))
sw = fetchone(
    db,
    "SELECT file_path, parse_status FROM job_artifacts WHERE job_id=:jid AND file_path ILIKE '%config/SOFTWARE' LIMIT 1",
    {"jid": JOB},
)
print("SOFTWARE hive", sw)
sysrow = fetchone(
    db,
    "SELECT file_path, parse_status FROM job_artifacts WHERE job_id=:jid AND file_path ILIKE '%config/SYSTEM' LIMIT 1",
    {"jid": JOB},
)
print("SYSTEM hive", sysrow)
chunks = fetchall(
    db,
    """SELECT file_path, left(content,120) c FROM rag_chunks
       WHERE job_id=:jid AND (
         content ILIKE '%ProductName%' OR content ILIKE '%Windows 11%'
         OR content ILIKE '%CurrentBuild%' OR metadata->>'kind' = 'windows_os'
       ) LIMIT 8""",
    {"jid": JOB},
)
print("OS-related chunks", len(chunks))
for c in chunks:
    print(" ", c["file_path"], c["c"][:80])
db.close()
