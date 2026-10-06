"""Encryption & Credentials artifact counts — AXIOM-style report and catalog mapping."""

from __future__ import annotations

import gc
import re
import threading
from typing import Any

from app.db.sql_helpers import fetchall, fetchone

_JOB_ENCRYPT_CACHE: dict[str, dict[str, Any]] = {}
_ENCRYPT_LOCK = threading.Lock()
_ENCRYPT_JOB_LOCKS: dict[str, threading.Lock] = {}


def _encrypt_job_lock(job_id: str) -> threading.Lock:
    with _ENCRYPT_LOCK:
        lock = _ENCRYPT_JOB_LOCKS.get(job_id)
        if lock is None:
            lock = threading.Lock()
            _ENCRYPT_JOB_LOCKS[job_id] = lock
        return lock

# Cap deep-scan candidates — full UFED/E01 corpora previously hung inventory for minutes.

_CANDIDATE_SQL = """
    SELECT file_path, size_bytes FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 64 AND size_bytes < 134217728 AND (
      lower(coalesce(extension,'')) IN (
        '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
        '.7z','.rar','.aes','.enc','.gpg','.pgp','.kdbx','.hc','.tc'
      )
      OR file_path ILIKE '%.pdf'
      OR file_path ILIKE '%.docx'
      OR file_path ILIKE '%.xlsx'
      OR file_path ILIKE '%.pptx'
    )
    AND file_path NOT ILIKE '%Program Files%'
    AND file_path NOT ILIKE '%Program Files (x86)%'
    AND file_path NOT ILIKE '%WindowsApps%'
    AND lower(coalesce(extension,'')) NOT IN ('.pas','.ufd','.ufdx')
    ORDER BY size_bytes DESC
    LIMIT 10000
"""

_ZIP_SQL = """
    SELECT file_path, size_bytes FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 100 AND size_bytes < 134217728 AND (
      lower(coalesce(extension,''))='.zip' OR file_path ILIKE '%.zip'
    )
    AND file_path NOT ILIKE '%Program Files%'
    AND file_path NOT ILIKE '%WindowsApps%'
    AND lower(coalesce(extension,'')) NOT IN ('.pas','.ufd','.ufdx')
    AND file_path NOT ILIKE '%.pas'
    AND file_path NOT ILIKE '%.ufd'
    ORDER BY size_bytes DESC
    LIMIT 3000
"""

# Path-only encrypted estimate — no content reads (inventory / UI fast path).
# Includes BitLocker recovery (.bek) and common crypto containers AXIOM flags.
_ENCRYPTED_PATH_SQL = """
    lower(coalesce(extension,'')) IN (
      '.gpg','.pgp','.kdbx','.kdb','.hc','.tc','.aes','.enc','.bek','.p12','.pfx','.asc'
    )
    OR file_path ILIKE '%.gpg'
    OR file_path ILIKE '%.pgp'
    OR file_path ILIKE '%.kdbx'
    OR file_path ILIKE '%.hc'
    OR file_path ILIKE '%.tc'
    OR file_path ILIKE '%.bek'
    OR file_path ILIKE '%.p12'
    OR file_path ILIKE '%.pfx'
    OR file_name ILIKE '%.enc'
    OR file_path ILIKE '%BitLocker%'
    OR file_path ILIKE '%TrueCrypt%'
    OR file_path ILIKE '%VeraCrypt%'
"""
_ANTIFORENSICS_SQL = """
    file_path ILIKE '%veracrypt%'
    OR file_path ILIKE '%truecrypt%'
    OR file_path ILIKE '%bleachbit%'
    OR file_path ILIKE '%ccleaner%'
    OR file_path ILIKE '%cipher.exe%'
    OR file_path ILIKE '%sdelete%'
    OR file_path ILIKE '%eraser%'
    OR file_path ILIKE '%anti-forensic%'
    OR file_name ILIKE 'VeraCrypt.exe'
    OR file_name ILIKE 'TrueCrypt.exe'
"""

# AXIOM "Windows Stored Credentials" = recoverable Credential Manager vault entries.
# Path hits alone (Policy.vpol / empty .vsch / system-profile stubs) are not counted —
# without DPAPI decryption AXIOM typically reports 0 for these.
_CREDENTIALS_SQL = """
    (
      file_path ILIKE 'Users/%/AppData/%/Microsoft/Credentials/%'
      OR file_path ILIKE 'Users/%/AppData/%/Microsoft/Vault/%'
    )
    AND file_path NOT ILIKE '%Program Files%'
    AND file_path NOT ILIKE '%Microsoft/Protect/%'
    AND file_name NOT ILIKE 'Policy.vpol'
    AND file_name NOT ILIKE 'Latest.dat'
    AND file_path NOT ILIKE '%.vsch'
    AND coalesce(size_bytes, 0) > 256
"""

_PDF_PREFIX_BYTES = 524_288


def _count_sql(db, job_id: str, where: str) -> int:
    row = fetchone(
        db,
        f"SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND ({where})",
        {"j": job_id},
    )
    return int(row["c"]) if row else 0


def _sample_sql(db, job_id: str, where: str, *, limit: int = 8) -> list[str]:
    rows = fetchall(
        db,
        f"""SELECT file_path FROM job_artifacts WHERE job_id=:j AND ({where})
            ORDER BY size_bytes DESC NULLS LAST LIMIT :lim""",
        {"j": job_id, "lim": limit},
    )
    return [r["file_path"] for r in rows]


def scan_encrypted_files(db, job_id: str) -> dict[str, Any]:
    """Header scan for password-protected / encrypted user files."""
    import concurrent.futures

    from app.services.artifact_live_counts import _job_index_map, _read_job_files
    from app.services.encryption_detect import count_encrypted_zip_entries, is_encrypted_file

    zip_rows = fetchall(db, _ZIP_SQL, {"j": job_id})
    rows = fetchall(db, _CANDIDATE_SQL, {"j": job_id})

    encrypted: list[str] = []
    zip_entry_total = 0
    scanned = 0
    schema = db.info.get("firm_schema") if hasattr(db, "info") else None

    def _scan_one_zip(row: dict) -> tuple[int, str | None]:
        path = (row.get("file_path") or "").replace("\\", "/")
        try:
            if schema:
                from app.db.session import firm_session_readonly

                with firm_session_readonly(schema) as thread_db:
                    size = max(int(row.get("size_bytes") or 0), 0)
                    # V10 read only the first 4 MB of ZIP archives. For an archive with
                    # hundreds of encrypted members that can count only the early local
                    # headers (e.g. 314) while the central directory contains more.
                    # Read the complete archive whenever it is within the bounded 256 MB
                    # candidate limit so encrypted member counts are complete.
                    read_cap = min(max(size + 4096, 4_000_000), 134_217_728)
                    contents = _read_job_files(thread_db, job_id, [row], max_bytes=read_cap)
            else:
                size = max(int(row.get("size_bytes") or 0), 0)
                read_cap = min(max(size + 4096, 4_000_000), 134_217_728)
                contents = _read_job_files(db, job_id, [row], max_bytes=read_cap)
            data = contents.get(path)
            if not data:
                return 0, None
            n = count_encrypted_zip_entries(data)
            if n > 0:
                suffix = "" if not size or len(data) >= size else " (partial archive read)"
                return n, f"{path} ({n} encrypted entries){suffix}"
        except Exception:
            return 0, None
        return 0, None

    # Parallel ZIP header checks — dominant cost on large corpora.
    workers = 2 if schema else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for n, sample in pool.map(_scan_one_zip, zip_rows):
            if n > 0 and sample:
                zip_entry_total += n
                encrypted.append(sample)

    index_map = _job_index_map(db, job_id)
    by_part: dict[str, list[dict]] = {}
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        if path.lower().endswith(".zip") or ".zip" in path.lower():
            continue
        part_uri = index_map.get(path)
        if not part_uri:
            continue
        by_part.setdefault(part_uri, []).append(row)

    for part_rows in by_part.values():
        # Keep report-time deep scanning bounded in memory while allowing far more
        # than the old 200-candidate ceiling (which could never reproduce a case
        # containing hundreds of protected files).
        for start in range(0, len(part_rows), 100):
            batch = part_rows[start:start + 100]
            contents = _read_job_files(db, job_id, batch, max_bytes=_PDF_PREFIX_BYTES)
            for row in batch:
                path = (row.get("file_path") or "").replace("\\", "/")
                data = contents.get(path)
                if not data:
                    continue
                scanned += 1
                if is_encrypted_file(data, path):
                    encrypted.append(path)
            contents.clear()
            gc.collect()

    standalone = len([p for p in encrypted if " encrypted entries)" not in p])
    count = zip_entry_total + standalone

    return {
        "count": count,
        "samples": encrypted[:8],
        "scanned": scanned,
        "candidates": len(rows),
        "zip_entry_total": zip_entry_total,
        "standalone_encrypted": standalone,
    }


def count_windows_stored_credentials(db, job_id: str) -> dict[str, Any]:
    """Windows Credential Manager vault entries (AXIOM-aligned).

    Path candidates are sampled for evidence browse, but the reported count stays
    0 unless a credential parser has produced vault records — matching AXIOM when
    DPAPI secrets are not recovered.
    """
    file_count = _count_sql(db, job_id, _CREDENTIALS_SQL)
    # Only count when we actually recovered credential records (not mere path hits).
    parsed = 0
    try:
        row = fetchone(
            db,
            """SELECT coalesce(sum(
                   CASE WHEN jsonb_typeof(apr.normalized) = 'array'
                        THEN jsonb_array_length(apr.normalized)
                        WHEN apr.normalized IS NOT NULL THEN 1
                        ELSE 0 END
               ), 0) AS c
               FROM artifact_parse_results apr
               JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
               WHERE ja.job_id=:j
                 AND (
                   apr.normalized->>'record_type' ILIKE '%credential%'
                   OR apr.normalized->>'record_type' ILIKE '%vault%'
                   OR apr.parser_name ILIKE '%credential%'
                 )""",
            {"j": job_id},
        )
        parsed = int((row or {}).get("c") or 0)
    except Exception:
        parsed = 0
    return {
        "count": parsed,
        "samples": _sample_sql(db, job_id, _CREDENTIALS_SQL),
        "store_files": file_count,
        "parsed_credentials": parsed,
    }


def count_antiforensics_tools(db, job_id: str) -> dict[str, Any]:
    count = _count_sql(db, job_id, _ANTIFORENSICS_SQL)
    return {"count": count, "samples": _sample_sql(db, job_id, _ANTIFORENSICS_SQL)}


def count_encrypted_files_by_path(db, job_id: str) -> dict[str, Any]:
    """Fast encrypted-file estimate from extensions/names (no content reads)."""
    count = _count_sql(db, job_id, _ENCRYPTED_PATH_SQL)
    return {
        "count": count,
        "samples": _sample_sql(db, job_id, _ENCRYPTED_PATH_SQL),
        "path_estimate": True,
    }


def compute_report_encryption_counts(db, job_id: str, *, scan_encrypted: bool = False) -> dict[str, int]:
    """Encryption & Credentials counts for UI / inventory.

    Default (``scan_encrypted=False``): path heuristics only — safe for inventory warm.
    Deep header scans are opt-in and capped (see ``scan_encrypted_files``).
    """
    with _encrypt_job_lock(job_id):
        cached = _JOB_ENCRYPT_CACHE.get(job_id)
        if cached and isinstance(cached.get("counts"), dict):
            if not scan_encrypted or cached.get("full_scan"):
                return dict(cached["counts"])

        cred = count_windows_stored_credentials(db, job_id)
        tools = count_antiforensics_tools(db, job_id)
        enc_detail: dict[str, Any]
        if scan_encrypted:
            enc_detail = scan_encrypted_files(db, job_id)
            enc_count = int(enc_detail.get("count") or 0)
        else:
            enc_detail = count_encrypted_files_by_path(db, job_id)
            enc_count = int(enc_detail.get("count") or 0)

        counts = {
            "encrypted files": enc_count,
            "windows stored credentials": int(cred.get("count") or 0),
            "encryption / anti-forensics tools": int(tools.get("count") or 0),
        }
        _JOB_ENCRYPT_CACHE[job_id] = {
            "counts": counts,
            "full_scan": bool(scan_encrypted),
            "detail": {"encrypted": enc_detail, "credentials": cred, "tools": tools},
        }
        return counts


def compute_all_encryption_counts(db, job_id: str, *, deep_scan: bool = False) -> dict[str, int]:
    """Inventory / catalog default is the fast path; pass ``deep_scan=True`` for header reads."""
    return compute_report_encryption_counts(db, job_id, scan_encrypted=deep_scan)


def clear_encryption_count_cache(job_id: str | None = None) -> None:
    if job_id:
        _JOB_ENCRYPT_CACHE.pop(job_id, None)
    else:
        _JOB_ENCRYPT_CACHE.clear()


def collect_encryption_artifact(db, job_id: str, title: str) -> dict[str, Any]:
    key = re.sub(r"\s+", " ", (title or "").strip().lower())
    counts = compute_all_encryption_counts(db, job_id, deep_scan=False)
    count = int(counts.get(key, 0))
    detail = (_JOB_ENCRYPT_CACHE.get(job_id) or {}).get("detail") or {}
    samples: list[str] = []
    if key == "encrypted files":
        samples = (detail.get("encrypted") or {}).get("samples") or []
    elif key == "windows stored credentials":
        samples = (detail.get("credentials") or {}).get("samples") or []
    elif "anti-forensics" in key or "anti forensics" in key:
        samples = (detail.get("tools") or {}).get("samples") or []
    return {"count": count, "samples": samples}