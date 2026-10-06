"""Find glued @g.us bodies in deleted cache regardless of person filter."""
from __future__ import annotations

from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_evidence_browse import (
    _load_browse_cache,
    _sanitize_deleted_protocol_noise,
)
from app.services.chat_message_extract import _split_whatsapp_carve_text

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"


def main() -> None:
    db = SessionLocal()
    try:
        db.execute(text('SET search_path TO "firm_aetheris", public'))
        full = None
        for kind in (
            "wa_deleted_v17",
            "wa_deleted_v16",
            "wa_deleted_v15",
            "wa_deleted_v14",
            "wa_deleted_v13",
        ):
            full = _load_browse_cache(db, JOB, kind)
            if full:
                print("loaded", kind, len(full))
                break
        if not full:
            print("no cache")
            return

        glued_rows = []
        for r in full:
            meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
            for key in ("original_content", "body", "preview_body", "title"):
                blob = str(meta.get(key) if key != "title" else r.get("title") or meta.get(key) or "")
                if "@g.us" in blob:
                    glued_rows.append((r, key, blob))
                    break
        print("glued_rows", len(glued_rows))
        for r, key, blob in glued_rows[:5]:
            meta = r.get("metadata") or {}
            print("--- key", key)
            print("conv", meta.get("conversation"), "chat_jid", meta.get("chat_jid"))
            print("blob", repr(blob[:200]))
            print("split", _split_whatsapp_carve_text(blob))

        # sanitize a copy of glued subset
        subset = [r for r, _, _ in glued_rows[:20]]
        _sanitize_deleted_protocol_noise(subset)
        still = 0
        for r in subset:
            meta = r.get("metadata") or {}
            oc = str(meta.get("original_content") or "")
            body = str(meta.get("body") or "")
            prev = str(meta.get("preview_body") or "")
            bad = False
            if "@g.us" in oc or "@lid" in oc:
                bad = True
            if "@g.us" in body.split("(🚫")[0] if "(🚫" in body else body:
                # allow if only in residue section of body? body shouldn't have jid
                if "@g.us" in body:
                    bad = True
            if "Original content:" in prev:
                part = prev.split("Original content:", 1)[1].split("Protocol residue", 1)[0]
                if "@g.us" in part or "@lid" in part:
                    bad = True
                    print("BAD preview original:", repr(part[:180]))
            if bad:
                still += 1
                print("STILL oc", repr(oc[:120]), "res", repr(str(meta.get("protocol_residue") or "")[:60]))
        print("still_bad_in_sample", still, "of", len(subset))
    finally:
        db.close()


if __name__ == "__main__":
    main()
