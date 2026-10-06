"""Force-refresh mobile inventory after ChatStorage read-cap fix."""
from __future__ import annotations

import json

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.mobile_forensic.inventory import (
    clear_mobile_inventory_cache,
    persist_mobile_inventory_snapshot,
)

JID = "02bcb441-d1de-45b0-8a79-9c9139f08875"


def main() -> None:
    clear_mobile_inventory_cache(JID)
    with firm_session("firm_aetheris") as db:
        # Drop stale deleted-pipeline cache so freelist inflation is recalculated.
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": JID}) or {}
        ds = row.get("disk_source")
        if isinstance(ds, str):
            try:
                ds = json.loads(ds)
            except Exception:
                ds = {}
        if isinstance(ds, dict):
            ds.pop("mobile_deleted_pipeline", None)
            ds.pop("mobile_forensic_inventory", None)
            ds.pop("mobile_artifact_board", None)
            execute(
                db,
                "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:id",
                {"id": JID, "ds": json.dumps(ds)},
            )
            db.commit()

        # Clear incorrect is_deleted tags on live ChatStorage / msgstore.
        execute(
            db,
            """UPDATE job_artifacts
               SET metadata = metadata - 'is_deleted'
               WHERE job_id=:jid
                 AND (
                   lower(file_name) IN ('chatstorage.sqlite', 'msgstore.db', 'extchatdatabase.sqlite')
                   OR lower(file_path) LIKE '%/chatstorage.sqlite'
                   OR lower(file_path) LIKE '%/msgstore.db'
                 )
                 AND coalesce(metadata->>'is_deleted','') IN ('true','1','t')""",
            {"jid": JID},
        )
        db.commit()

        snap = persist_mobile_inventory_snapshot(db, JID, force=True)
        db.commit()
        counts = snap.get("counts") or {}
        print("TOTAL_FILES", snap.get("total_files"))
        for k in (
            "whatsapp_messages",
            "whatsapp_chats",
            "whatsapp_calls",
            "whatsapp_contacts",
            "whatsapp_groups",
            "whatsapp_media",
            "whatsapp_deleted_messages",
            "sms",
            "contacts",
            "emails",
            "pictures",
            "videos",
            "audio",
            "documents",
            "deleted_files",
            "deleted_social",
            "facebook_deleted",
        ):
            print(f"  {k}={counts.get(k)}")
        print("LIMITATIONS", snap.get("limitations"))
        print("WA_DB", (snap.get("db_paths") or {}).get("whatsapp"))


if __name__ == "__main__":
    main()
