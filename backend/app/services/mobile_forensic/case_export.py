"""Complete ZIP case package export for normalized mobile evidence.

Large collections are written as JSONL streams so an export never becomes a
preview just because a handset contains hundreds of thousands of files or
artifacts.  The small *.json files are manifests that point at their complete
JSONL companions and preserve the historic package paths consumed by the UI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.db.sql_helpers import fetchall, fetchone
from app.services.mobile_forensic.storage import ensure_mobile_case_schema, list_artifacts, timeline_rows

log = logging.getLogger("mobile_forensic.case_export")

_RECOVERED_STATES = (
    "database_deleted",
    "wal_recovered",
    "journal_recovered",
    "freelist_candidate",
    "orphaned",
    "fragment",
    "filesystem_recovered",
    "cache_derived",
    "unverified",
    "historical",
    "backup_historical",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _row_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    for key in ("data", "forensic", "meta"):
        if key in item:
            item[key] = _json_value(item.get(key))
    return item


def _inventory_rows(db, job_id: str, *, batch_size: int = 5000) -> Iterator[dict[str, Any]]:
    offset = 0
    while True:
        rows = fetchall(
            db,
            """SELECT path, size_bytes, extension, mime_hint, status, parser, error, sha256, meta
               FROM mobile_inventory_items
               WHERE job_id=:jid ORDER BY path ASC LIMIT :lim OFFSET :off""",
            {"jid": job_id, "lim": batch_size, "off": offset},
        )
        if not rows:
            break
        for row in rows:
            yield _row_dict(row)
        offset += len(rows)
        if len(rows) < batch_size:
            break


def _artifact_rows(
    db,
    job_id: str,
    *,
    state_mode: str = "all",
    batch_size: int = 5000,
) -> Iterator[dict[str, Any]]:
    offset = 0
    while True:
        rows = list_artifacts(db, job_id, limit=batch_size, offset=offset)
        if not rows:
            break
        for item in rows:
            state = str(item.get("state") or "")
            if state_mode == "allocated" and state != "allocated":
                continue
            if state_mode == "recovered" and state not in _RECOVERED_STATES:
                continue
            yield item
        offset += len(rows)
        if len(rows) < batch_size:
            break


def _timeline_rows(db, job_id: str, *, batch_size: int = 5000) -> Iterator[dict[str, Any]]:
    offset = 0
    while True:
        rows = timeline_rows(db, job_id, limit=batch_size, offset=offset)
        if not rows:
            break
        yield from rows
        offset += len(rows)
        if len(rows) < batch_size:
            break


def _count(db, sql: str, params: dict[str, Any]) -> int:
    row = fetchone(db, sql, params) or {}
    return int(row.get("c") or 0)


def build_case_package_zip(db, job_id: str, dest: Path) -> dict[str, Any]:
    """Write a complete, streaming examiner case package without modifying originals."""
    ensure_mobile_case_schema(db)
    dest.parent.mkdir(parents=True, exist_ok=True)

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    ds = ds if isinstance(ds, dict) else {}
    manifest = ds.get("evidence_manifest") if isinstance(ds.get("evidence_manifest"), dict) else {
        "source_id": f"SOURCE-{job_id[:8]}",
        "job_id": job_id,
        "note": "manifest regenerated at export",
    }

    counts = {
        "inventory_total": _count(db, "SELECT count(*)::bigint AS c FROM mobile_inventory_items WHERE job_id=:jid", {"jid": job_id}),
        "allocated_artifacts": _count(db, "SELECT count(*)::bigint AS c FROM mobile_normalized_artifacts WHERE job_id=:jid AND state='allocated'", {"jid": job_id}),
        "recovered_candidates": _count(
            db,
            "SELECT count(*)::bigint AS c FROM mobile_normalized_artifacts WHERE job_id=:jid AND state = ANY(CAST(:states AS text[]))",
            {"jid": job_id, "states": list(_RECOVERED_STATES)},
        ),
        "timeline_events": _count(db, "SELECT count(*)::bigint AS c FROM mobile_normalized_artifacts WHERE job_id=:jid AND timestamp_utc IS NOT NULL", {"jid": job_id}),
    }

    file_hashes: dict[str, str] = {}
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        def _put(name: str, obj: Any) -> None:
            raw = json.dumps(obj, indent=2, ensure_ascii=False, default=str).encode("utf-8")
            zf.writestr(name, raw)
            file_hashes[name] = _sha256_bytes(raw)

        def _put_jsonl(name: str, rows: Iterable[dict[str, Any]]) -> int:
            digest = hashlib.sha256()
            n = 0
            with zf.open(name, "w", force_zip64=True) as fp:
                for item in rows:
                    raw = (json.dumps(item, ensure_ascii=False, default=str, separators=(",", ":")) + "\n").encode("utf-8")
                    fp.write(raw)
                    digest.update(raw)
                    n += 1
            file_hashes[name] = digest.hexdigest()
            return n

        _put("manifest/evidence_manifest.json", manifest)
        _put(
            "manifest/export_meta.json",
            {
                "job_id": job_id,
                "exported_at_utc": created,
                "package_version": "2.0.0",
                "immutable_originals": True,
                "complete_mobile_artifacts": True,
                "global_export_row_cap": None,
                "record_format": "JSONL for complete record sets; JSON files are manifests",
            },
        )
        _put(
            "source/disk_source_public.json",
            {
                "formats": (manifest or {}).get("formats"),
                "mobile_os": (manifest or {}).get("mobile_os") or ds.get("mobile_os"),
                "hashes": (manifest or {}).get("hashes") or [],
                "acquisition_mode": (manifest or {}).get("acquisition_mode"),
            },
        )

        inv_written = _put_jsonl("inventory/inventory.jsonl", _inventory_rows(db, job_id))
        allocated_written = _put_jsonl("parsed/artifacts.jsonl", _artifact_rows(db, job_id, state_mode="allocated"))
        recovered_written = _put_jsonl("recovered/candidates.jsonl", _artifact_rows(db, job_id, state_mode="recovered"))
        timeline_written = _put_jsonl("reports/timeline.jsonl", _timeline_rows(db, job_id))

        _put("inventory/inventory.json", {"total": inv_written, "complete": True, "records": "inventory/inventory.jsonl"})
        _put("parsed/artifacts.json", {"total": allocated_written, "complete": True, "records": "parsed/artifacts.jsonl"})
        _put("recovered/candidates.json", {"total": recovered_written, "complete": True, "records": "recovered/candidates.jsonl"})
        _put("reports/timeline.json", {"total": timeline_written, "complete": True, "records": "reports/timeline.jsonl"})
        export_complete = (
            inv_written == counts["inventory_total"]
            and allocated_written == counts["allocated_artifacts"]
            and recovered_written == counts["recovered_candidates"]
            and timeline_written == counts["timeline_events"]
        )
        _put(
            "reports/summary.json",
            {
                **counts,
                "inventory_exported": inv_written,
                "allocated_exported": allocated_written,
                "recovered_exported": recovered_written,
                "timeline_exported": timeline_written,
                "complete": export_complete,
            },
        )
        # This file intentionally hashes every package member written before it.
        _put("hashes/package_files.sha256.json", file_hashes)

    return {
        "path": str(dest),
        "job_id": job_id,
        "files": list(file_hashes.keys()),
        "file_count": len(file_hashes),
        "exported_at_utc": created,
        "complete": export_complete,
        "counts": counts,
    }
