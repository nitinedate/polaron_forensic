from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_evidence_browse import _load_browse_cache, _whatsapp_deleted_person_rows
from app.services.artifact_group_browse import _person_key_from_row, _split_person_bucket_id

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
db = SessionLocal()
db.execute(text('SET search_path TO "firm_aetheris", public'))
persons = _whatsapp_deleted_person_rows(db, JOB)
target = next(p for p in persons if "7th" in str(p.get("title") or "").lower())
pid = str(target["id"])
base, deleted = _split_person_bucket_id(pid)
print("pid", pid, "base", base, "deleted", deleted)
print("meta", target.get("metadata"))
full = _load_browse_cache(db, JOB, "wa_deleted_v13")
keys = {}
for r in full or []:
    meta = r.get("metadata") or {}
    conv = str(meta.get("conversation") or "")
    if "7th" in conv.lower() or "common grp" in conv.lower():
        try:
            sid, label, _ = _person_key_from_row(r)
        except Exception as e:
            sid, label = "ERR", str(e)
        keys[sid] = keys.get(sid, 0) + 1
        if keys[sid] <= 2:
            print("msg sid", sid, "label", label, "conv", conv, "jid", meta.get("chat_jid"))
print("sid counts", keys)
db.close()
