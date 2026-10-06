"""Sync existing RAG chunks to OpenSearch and ensure Windows user profile facts."""

from app.db.session import firm_session
from app.db.sql_helpers import fetchall, fetchone
from app.services.forensic_profile_index import ensure_profile_fact_chunks, discover_windows_users
from app.services.opensearch_sync import bulk_index_chunks, opensearch_available

jid = "a088f720-1da5-430a-8bbd-ae5a2d042d2b"
schema = "firm_aetheris"

with firm_session(schema) as db:
    users = discover_windows_users(db, jid)
    print("users", users)
    n = ensure_profile_fact_chunks(db, jid)
    db.commit()
    print("profile_chunks", n)

    chunks = fetchall(
        db,
        """SELECT id, job_id, file_path, content, artifact_id, chunk_type
           FROM rag_chunks WHERE job_id=:jid OR job_id IS NULL""",
        {"jid": jid},
    )
    print("db_chunks", len(chunks), "opensearch", opensearch_available())
    if opensearch_available() and chunks:
        # Index job evidence under job index; encyclopedia under encyclopedia index
        job_chunks = [c for c in chunks if c.get("job_id")]
        enc_chunks = [c for c in chunks if not c.get("job_id")]
        if job_chunks:
            print("bulk job", bulk_index_chunks([{**dict(c), "chunk_id": str(c["id"])} for c in job_chunks], job_id=jid))
        if enc_chunks:
            print(
                "bulk enc",
                bulk_index_chunks([{**dict(c), "chunk_id": str(c["id"])} for c in enc_chunks], job_id=None),
            )

    from app.retrieval.hybrid import hybrid_retrieve

    hits = hybrid_retrieve(db, jid, "provide the users list who used the laptop", top_k=8)
    print("retrieve", len(hits))
    for h in hits[:5]:
        print("-", (h.get("file_path") or "")[:80], "|", (h.get("content") or "")[:100].replace("\n", " "))
