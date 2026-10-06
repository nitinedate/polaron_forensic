"""Diagnose iOS WhatsApp inventory for the latest mobile job."""
from __future__ import annotations

from app.db.sql_helpers import fetchall, fetchone
from app.db.session import firm_session
from app.services.mobile_forensic.inventory import build_mobile_inventory_snapshot
from app.services.mobile_forensic.sqlite_counts import (
    _open_sqlite,
    _read_artifact_bytes,
    _table_names,
    analyze_whatsapp_db,
    collect_mobile_sqlite_inventory,
)

JID = "02bcb441-d1de-45b0-8a79-9c9139f08875"


def main() -> None:
    with firm_session("firm_aetheris") as db:
        inv = collect_mobile_sqlite_inventory(db, JID)
        keys = (
            "whatsapp_messages",
            "whatsapp_chats",
            "whatsapp_calls",
            "whatsapp_contacts",
            "whatsapp_groups",
            "whatsapp_media_files",
            "whatsapp_deleted_messages",
            "sms",
            "call_logs",
            "contacts",
            "emails",
        )
        print("SQLITE_INV", {k: inv.get(k) for k in keys})
        print("LIMITATIONS", inv.get("limitations"))
        print("WA_PATHS", (inv.get("whatsapp_db_paths") or [])[:8])

        rows = fetchall(
            db,
            """SELECT file_path, size_bytes, minio_uri
               FROM job_artifacts
               WHERE job_id=:jid
                 AND (
                   lower(file_path) LIKE '%chatstorage.sqlite'
                   OR lower(file_path) LIKE '%extchatdatabase%'
                   OR lower(file_path) LIKE '%chatsearch%'
                   OR lower(file_path) LIKE '%callhistory.sqlite%'
                 )
               ORDER BY size_bytes DESC NULLS LAST
               LIMIT 12""",
            {"jid": JID},
        )
        for r in rows:
            path = r["file_path"]
            data = _read_artifact_bytes(db, JID, path)
            print(
                "FILE",
                (path or "")[-90:],
                "size",
                r.get("size_bytes"),
                "read",
                None if data is None else len(data),
                "hdr",
                None if not data else data[:15],
            )
            if not data:
                continue
            analyzed = analyze_whatsapp_db(data, path)
            print("  ANALYZE", analyzed)
            conn, tmp = _open_sqlite(data)
            if conn:
                try:
                    cur = conn.cursor()
                    tables = _table_names(cur)
                    interesting = [
                        t
                        for t in tables
                        if any(
                            x in t.lower()
                            for x in ("message", "chat", "call", "contact", "group", "media")
                        )
                    ]
                    print("  TABLES", interesting[:40], "total", len(tables))
                    for t in interesting[:12]:
                        try:
                            cur.execute(f'SELECT count(*) FROM "{t}"')
                            print("   ", t, cur.fetchone()[0])
                        except Exception as exc:
                            print("   ", t, "ERR", exc)
                finally:
                    conn.close()

        snap = build_mobile_inventory_snapshot(db, JID, force=True)
        print("SNAP_COUNTS", snap.get("counts"))
        print("SNAP_LIMITS", snap.get("limitations"))
        print("TOTAL_FILES", snap.get("total_files"))


if __name__ == "__main__":
    main()
