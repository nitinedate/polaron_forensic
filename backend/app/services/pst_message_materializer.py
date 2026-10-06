"""Derived PST/OST -> EML materialization for examiner email preview.

Original mailbox bytes are never changed. When ``readpst`` is available, each
mailbox is copied to a private temporary file, converted to RFC822 ``.eml``
messages, and the derived EML messages are registered as job artifacts. The
normal MIME preview then exposes the real body and attachments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from email.parser import BytesHeaderParser
from email import policy
from pathlib import Path, PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchone

log = logging.getLogger("pst_message_materializer")


def _safe_piece(value: str, fallback: str) -> str:
    value = re.sub(r"[\\/:*?\"<>|\x00-\x1f]+", "_", value or "").strip(" ._")
    value = re.sub(r"\s+", " ", value)[:120]
    return value or fallback


def _message_subject(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            msg = BytesHeaderParser(policy=policy.default).parse(fh, headersonly=True)
        return str(msg.get("Subject") or "").strip()
    except Exception:
        return ""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _existing_count(db, job_id: str, parent_id: str) -> int:
    row = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts
           WHERE job_id=:j
             AND metadata->>'derived_mailbox_parent_id'=:p
             AND lower(coalesce(extension,''))='.eml'""",
        {"j": job_id, "p": parent_id},
    )
    return int((row or {}).get("c") or 0)


def materialize_mailbox_messages(
    db,
    job_id: str,
    mailbox_row: dict[str, Any],
    *,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Convert one PST/OST artifact to derived EML job_artifacts when possible."""
    parent_id = str(mailbox_row.get("id") or "")
    if not parent_id:
        return {"status": "skipped", "reason": "missing_parent_id", "materialized": 0}
    already = _existing_count(db, job_id, parent_id)
    if already:
        return {"status": "cached", "materialized": already}

    readpst = shutil.which("readpst")
    if not readpst:
        return {"status": "unavailable", "reason": "readpst_not_installed", "materialized": 0}

    from app.services.artifact_preview import iter_artifact_content
    from app.services.storage import put_file

    timeout = int(timeout_seconds or os.getenv("POLARON_PST_READPST_TIMEOUT_SECONDS", "900"))
    max_messages = int(os.getenv("POLARON_PST_MATERIALIZE_MAX_MESSAGES", "0") or 0)
    source_name = str(mailbox_row.get("file_name") or PurePosixPath(str(mailbox_row.get("file_path") or "mailbox.pst").replace("\\", "/")).name or "mailbox.pst")
    source_ext = PurePosixPath(source_name).suffix or ".pst"

    with tempfile.TemporaryDirectory(prefix="polaron-pst-") as tmp:
        root = Path(tmp)
        source = root / f"source{source_ext}"
        out_dir = root / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        total_bytes = 0
        with source.open("wb") as fh:
            for chunk in iter_artifact_content(db, job_id, mailbox_row, max_bytes=None):
                fh.write(chunk)
                total_bytes += len(chunk)
        if total_bytes <= 0:
            return {"status": "failed", "reason": "mailbox_content_unavailable", "materialized": 0}

        command = [readpst, "-q", "-e", "-D", "-t", "e", "-j", "2", "-o", str(out_dir), str(source)]
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            log.warning("readpst timed out job=%s mailbox=%s", job_id, mailbox_row.get("file_path"))
            return {"status": "timeout", "reason": "readpst_timeout", "materialized": 0}
        if proc.returncode != 0:
            log.warning("readpst failed job=%s rc=%s stderr=%s", job_id, proc.returncode, (proc.stderr or "")[-500:])
            return {"status": "failed", "reason": "readpst_failed", "returncode": proc.returncode, "materialized": 0}

        eml_files = sorted(p for p in out_dir.rglob("*.eml") if p.is_file())
        if max_messages > 0:
            eml_files = eml_files[:max_messages]
        if not eml_files:
            return {"status": "ok", "materialized": 0}

        mailbox_label = _safe_piece(PurePosixPath(source_name).stem, "mailbox")
        materialized = 0
        for ordinal, eml in enumerate(eml_files, start=1):
            try:
                size = eml.stat().st_size
                if size <= 0:
                    continue
                sha = _sha256(eml)
                subject = _safe_piece(_message_subject(eml), f"message-{ordinal:06d}")
                rel_parent = eml.relative_to(out_dir).parent.as_posix()
                folder = _safe_piece(rel_parent.replace("/", " - "), "Inbox")
                file_name = f"{ordinal:06d} - {subject}.eml"
                derived_path = f"Derived/Microsoft/Outlook/{mailbox_label}/{folder}/{file_name}"
                object_key = f"jobs/{job_id}/derived-mail/{parent_id}/{sha}.eml"
                uri = put_file(object_key, eml, content_type="message/rfc822")
                meta = {
                    "derived_from_mailbox": True,
                    "derived_mailbox_parent_id": parent_id,
                    "derived_mailbox_path": str(mailbox_row.get("file_path") or ""),
                    "derived_tool": "readpst",
                    "derived_format": "rfc822",
                    "resolved_content_type": "message/rfc822",
                    "content_type": "message/rfc822",
                    "content_type_label": "Email message",
                    "detected_extension": ".eml",
                    "detected_kind": "email",
                    "type_source": "parser",
                    "type_confidence": "high",
                    "normalized_filename": file_name,
                }
                execute(
                    db,
                    """INSERT INTO job_artifacts
                       (job_id, file_path, file_name, extension, size_bytes, sha256,
                        parse_status, minio_uri, metadata)
                       VALUES (:j, :path, :name, '.eml', :size, :sha, 'parsed', :uri, CAST(:meta AS jsonb))
                       ON CONFLICT (job_id, file_path) DO UPDATE SET
                         file_name=EXCLUDED.file_name,
                         extension=EXCLUDED.extension,
                         size_bytes=EXCLUDED.size_bytes,
                         sha256=EXCLUDED.sha256,
                         parse_status='parsed',
                         minio_uri=EXCLUDED.minio_uri,
                         metadata=coalesce(job_artifacts.metadata, '{}'::jsonb) || EXCLUDED.metadata,
                         updated_at=NOW()""",
                    {
                        "j": job_id,
                        "path": derived_path,
                        "name": file_name,
                        "size": size,
                        "sha": sha,
                        "uri": uri,
                        "meta": json.dumps(meta),
                    },
                )
                materialized += 1
            except Exception as exc:
                log.warning("derived EML materialize failed job=%s file=%s: %s", job_id, eml, exc)

        if materialized:
            db.commit()
            try:
                from app.services.email_mime_inventory import clear_email_mime_scan_cache
                clear_email_mime_scan_cache(job_id)
            except Exception:
                pass
        return {
            "status": "ok",
            "materialized": materialized,
            "mailbox_bytes": total_bytes,
            "derived_eml_discovered": len(eml_files),
        }
