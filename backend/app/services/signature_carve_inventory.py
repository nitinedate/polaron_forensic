"""Signature carving for AXIOM-parity counts (unallocated + high-value containers).

AXIOM Section B often exceeds allocated filesystem extension censuses because it
recovers embedded/carved objects (images in thumb/pagefile slack, PDFs in mail
stores, PSD by magic, EML/MSG fragments). This module runs a bounded carve and
exposes counts + evidence rows for the Artifacts page.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("signature_carve_inventory")

_JOB_CACHE: dict[str, dict[str, Any]] = {}
_BUILDING: set[str] = set()
_LOCK = threading.Lock()
_BUILD_COND = threading.Condition(_LOCK)

# Cap work so inventory stays interactive on large E01s.
_MAX_SOURCE_BYTES = 64 * 1024 * 1024  # default per source file read
_MAX_PAGEFILE_BYTES = 768 * 1024 * 1024  # pagefile/hiberfil — AXIOM carves heavily here
_MAX_UNALLOC_BYTES = 4 * 1024 * 1024 * 1024  # sampled unallocated budget (4 GiB)
_MAX_HITS_PER_KIND = 80_000
_MAX_EVIDENCE_ROWS = 2_000
_STEP = 2048  # scan stride after a hit (dense enough for fragmented caches)


@dataclass(frozen=True)
class _Sig:
    kind: str
    magic: bytes
    max_size: int
    extensions: tuple[str, ...]


_SIGNATURES: tuple[_Sig, ...] = (
    _Sig("pdf", b"%PDF-", 25_000_000, (".pdf",)),
    _Sig("rtf", b"{\\rtf", 8_000_000, (".rtf",)),
    _Sig("psd", b"8BPS", 80_000_000, (".psd", ".psb")),
    _Sig("jpeg", bytes([0xFF, 0xD8, 0xFF]), 20_000_000, (".jpg", ".jpeg")),
    _Sig("png", bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), 20_000_000, (".png",)),
    _Sig("gif", b"GIF8", 12_000_000, (".gif",)),
    _Sig("bmp", b"BM", 12_000_000, (".bmp",)),
    _Sig("tiff_le", b"II*\x00", 40_000_000, (".tif", ".tiff")),
    _Sig("tiff_be", b"MM\x00*", 40_000_000, (".tif", ".tiff")),
    # ISO BMFF (mp4/m4v/mov) — magic at offset 4; scanner matches anywhere then validates.
    _Sig("mp4", b"ftyp", 200_000_000, (".mp4", ".m4v", ".mov")),
    _Sig("avi", b"AVI ", 200_000_000, (".avi",)),
    _Sig("mkv", bytes([0x1A, 0x45, 0xDF, 0xA3]), 200_000_000, (".mkv", ".webm")),
    _Sig("ole", bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]), 40_000_000, (".doc", ".msg", ".xls", ".ppt")),
    _Sig("zip_ooxml", b"PK\x03\x04", 40_000_000, (".docx", ".xlsx", ".pptx")),
    _Sig("eml_mime", b"MIME-Version:", 8_000_000, (".eml",)),
    _Sig("eml_from", b"\nFrom: ", 8_000_000, (".eml",)),
)

_KIND_TO_AXIOM: dict[str, list[str]] = {
    "pdf": ["pdf documents"],
    "rtf": ["rtf documents"],
    "psd": ["photoshop files"],
    "jpeg": ["picture", "pictures"],
    "png": ["picture", "pictures"],
    "gif": ["picture", "pictures"],
    "bmp": ["picture", "pictures"],
    "ole": ["microsoft word documents", "outlook emails", "email attachments"],
    "zip_ooxml": ["microsoft word documents", "microsoft excel documents", "microsoft powerpoint documents"],
    "eml_mime": ["eml(x) files", "outlook emails", "email attachments"],
    "eml_from": ["eml(x) files", "outlook emails"],
}

_HIGH_VALUE_PATH_SQL = """
    SELECT id, file_path, size_bytes FROM job_artifacts
    WHERE job_id=:j AND size_bytes > 4096 AND size_bytes < 2147483648 AND (
      lower(file_name) IN (
        'pagefile.sys', 'hiberfil.sys', 'swapfile.sys', '$logfile', 'windows.edb',
        'history', 'history-wal', 'history-journal', 'places.sqlite', 'web data',
        'sessionstore.jsonlz4', 'recovery.jsonlz4'
      )
      OR file_path ILIKE '%/pagefile.sys'
      OR file_path ILIKE '%/hiberfil.sys'
      OR file_path ILIKE '%/swapfile.sys'
      OR file_path ILIKE '%/$LogFile'
      OR file_path ILIKE '%.pst'
      OR file_path ILIKE '%.ost'
      OR file_path ILIKE '%.msg'
      OR file_path ILIKE '%Content.Outlook%'
      OR file_path ILIKE '%/INetCache/%'
      OR file_path ILIKE '%windowscommunicationsapps%'
      OR file_path ILIKE '%/Search%/%.edb'
      OR file_path ~* '/(History|History-wal|History-journal|places\\.sqlite|Web Data)$'
      OR file_path ILIKE '%/$Recycle.Bin/%'
      OR file_path ILIKE '%/.Trash/%'
      OR file_path ILIKE '%/Recycler/%'
      OR file_path ILIKE '%/INetCache/%'
      OR file_path ILIKE '%/WebCache/%'
      OR file_path ILIKE '%/Cache2/%'
      OR file_path ILIKE '%thumbcache%.db'
      OR file_path ILIKE '%iconcache%.db'
      OR lower(file_name) = 'thumbs.db'
      OR file_path ILIKE '%/Temp/%'
      OR file_path ILIKE '%/AppData/Local/Temp/%'
    )
    AND file_path NOT ILIKE '%Safe Browsing%'
    AND file_path NOT ILIKE '%/Code Cache/%'
    ORDER BY
      CASE
        WHEN lower(file_name) LIKE 'history%' OR file_path ILIKE '%.pst' OR file_path ILIKE '%.ost'
          OR lower(file_name) IN ('pagefile.sys', 'hiberfil.sys') THEN 0
        WHEN file_path ILIKE '%thumbcache%' OR file_path ILIKE '%INetCache%' THEN 1
        ELSE 2
      END,
      size_bytes DESC NULLS LAST
    LIMIT 200
"""

_MAIL_ADJACENT_TOKENS = (
    "content.outlook",
    ".pst",
    ".ost",
    ".msg",
    "windowscommunicationsapps",
    "inetcache",
    "mail",
    "outlook",
)

_URL_RE = re.compile(
    rb"https?://[a-zA-Z0-9][-a-zA-Z0-9.,;:_@&/=+%?#~!]{6,300}"
)


def clear_carve_cache(job_id: str | None = None) -> None:
    with _BUILD_COND:
        if job_id is None:
            _JOB_CACHE.clear()
            _BUILDING.clear()
        else:
            _JOB_CACHE.pop(job_id, None)
            _BUILDING.discard(job_id)
        _BUILD_COND.notify_all()


def _hit_id(kind: str, source: str, offset: int, head: bytes) -> str:
    digest = hashlib.sha1(f"{kind}|{source}|{offset}".encode() + head[:64]).hexdigest()[:16]
    return f"carve-{kind}-{digest}"


def _classify_ole(head: bytes) -> str:
    """Refine OLE hits into msg / doc / generic."""
    low = head[:8192]
    if b"__properties_version1.0" in low or b"IPM.Note" in low or b"OutlookMessage" in low:
        return "msg"
    if b"WordDocument" in low or b"Microsoft Office Word" in low:
        return "doc"
    if b"Workbook" in low or b"Microsoft Excel" in low:
        return "xls"
    if b"PowerPoint Document" in low:
        return "ppt"
    return "ole"


def _classify_zip(head: bytes) -> str:
    low = head[:16384]
    if b"[Content_Types].xml" not in low and b"word/" not in low and b"xl/" not in low and b"ppt/" not in low:
        return "zip_other"
    if b"word/" in low:
        return "docx"
    if b"xl/" in low:
        return "xlsx"
    if b"ppt/" in low:
        return "pptx"
    return "zip_other"


def scan_buffer_for_signatures(
    data: bytes,
    *,
    source_path: str,
    source_artifact_id: str | None = None,
    base_offset: int = 0,
) -> list[dict[str, Any]]:
    """Find signature hits in a buffer (dedupe by kind+offset)."""
    if not data or len(data) < 16:
        return []
    hits: list[dict[str, Any]] = []
    seen_local: set[str] = set()
    n = len(data)
    for sig in _SIGNATURES:
        magic = sig.magic
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            # Stride forward to avoid dense false-positive clusters
            start = idx + max(len(magic), _STEP)
            head = data[idx : idx + min(4096, n - idx)]
            kind = sig.kind
            if kind == "ole":
                refined = _classify_ole(head)
                if refined == "ole":
                    # Skip generic OLE noise (installers, thumbs compound files)
                    continue
                kind = refined
            elif kind == "zip_ooxml":
                refined = _classify_zip(head)
                if refined == "zip_other":
                    continue
                kind = refined
            elif kind == "bmp":
                # BM is common false positive — require plausible size field
                if len(head) < 14:
                    continue
                try:
                    size_le = int.from_bytes(head[2:6], "little")
                except Exception:
                    continue
                if size_le < 64 or size_le > sig.max_size:
                    continue
            elif kind == "mp4":
                # ISO BMFF: size(4) + 'ftyp' at offset 4
                if idx < 4:
                    start = idx + 4
                    continue
                # Validate brand bytes after ftyp
                brand = data[idx + 4 : idx + 8]
                if brand not in {
                    b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"MSNV",
                    b"M4V ", b"M4A ", b"qt  ", b"3gp4", b"3gp5", b"dash",
                    b"ndsc", b"ndsh", b"ndsm", b"ndsp", b"ndss", b"ndxs",
                }:
                    start = idx + 4
                    continue
            elif kind == "avi":
                # RIFF....AVI  — magic matched on 'AVI '; require RIFF 8 bytes earlier
                if idx < 8 or data[idx - 8 : idx - 4] != b"RIFF":
                    start = idx + 4
                    continue
            elif kind == "psd":
                # Photoshop: 8BPS; version 1/2 when present (some fragments omit it).
                if len(head) >= 6 and head[4:6] not in (b"\x00\x01", b"\x00\x02", b"\x00\x00"):
                    start = idx + 4
                    continue
            elif kind in {"tiff_le", "tiff_be"}:
                kind = "tiff"
            elif kind in {"eml_mime", "eml_from"}:
                kind = "eml"
                # Require another email header nearby
                window = data[idx : idx + min(2048, n - idx)].lower()
                if b"subject:" not in window and b"to:" not in window and b"date:" not in window:
                    continue

            abs_off = base_offset + idx
            hid = _hit_id(kind, source_path, abs_off, head)
            if hid in seen_local:
                continue
            seen_local.add(hid)
            hits.append(
                {
                    "id": hid,
                    "kind": kind,
                    "source_path": source_path,
                    "source_artifact_id": source_artifact_id,
                    "offset": abs_off,
                    "max_size": sig.max_size,
                    "head_sha1": hashlib.sha1(head).hexdigest()[:16],
                }
            )
            if len(hits) >= 20_000:
                return hits
    return hits


def extract_urls_from_raw_bytes(data: bytes, *, source_path: str) -> list[dict[str, Any]]:
    """Recover http(s) URLs from raw History/WAL/cache bytes when SQLite is incomplete."""
    if not data:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(data):
        try:
            url = match.group(0).decode("ascii", errors="ignore").rstrip(".,;)}]'\"")
        except Exception:
            continue
        if not url.startswith("http"):
            continue
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": url, "visit_count": 1, "source": source_path})
        if len(out) >= 20_000:
            break
    return out


def _load_disk_source(db, job_id: str) -> dict[str, Any]:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    ds = (row or {}).get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    return ds if isinstance(ds, dict) else {}


def _save_carve_inventory(db, job_id: str, inv: dict[str, Any]) -> None:
    ds = _load_disk_source(db, job_id)
    # Persist capped URL rows so chat/social counts survive process restart.
    url_rows = list(inv.get("url_records") or [])[:8_000]
    ds["signature_carve_inventory"] = {
        "by_kind": inv.get("by_kind") or {},
        "axiom_counts": inv.get("axiom_counts") or {},
        "url_record_count": len(inv.get("url_records") or []),
        "url_records": url_rows,
        "hit_total": inv.get("hit_total") or 0,
        "sources_scanned": inv.get("sources_scanned") or 0,
        "unalloc_bytes_scanned": inv.get("unalloc_bytes_scanned") or 0,
        "ipm_note_hits": int(inv.get("ipm_note_hits") or 0),
        "evidence_rows": (inv.get("evidence_rows") or [])[:_MAX_EVIDENCE_ROWS],
    }
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:j",
        {"ds": json.dumps(ds), "j": job_id},
    )


def _source_read_budget(path: str) -> int:
    pl = (path or "").lower().replace("\\", "/")
    if any(tok in pl for tok in ("pagefile.sys", "hiberfil.sys", "swapfile.sys")):
        return _MAX_PAGEFILE_BYTES
    if pl.endswith((".pst", ".ost", ".edb")):
        return min(_MAX_PAGEFILE_BYTES, 128 * 1024 * 1024)
    return _MAX_SOURCE_BYTES


def _count_ipm_note_markers(data: bytes) -> int:
    """Outlook message-class markers (ASCII + UTF-16LE) — AXIOM-style mail fragments."""
    if not data:
        return 0
    ascii_hits = data.count(b"IPM.Note")
    utf16_hits = data.count("IPM.Note".encode("utf-16le"))
    return int(ascii_hits + utf16_hits)


def _process_carve_buffer(
    data: bytes,
    *,
    path: str,
    source_artifact_id: str | None,
    hits: list[dict[str, Any]],
    urls: list[dict[str, Any]],
) -> int:
    """Scan one buffer; return IPM.Note hit count."""
    if not data:
        return 0
    budget = _source_read_budget(path)
    if len(data) > budget:
        data = data[:budget]
    hits.extend(
        scan_buffer_for_signatures(
            data, source_path=path, source_artifact_id=source_artifact_id
        )
    )
    pl = path.lower().replace("\\", "/")
    ipm = 0
    if any(
        tok in pl
        for tok in (
            "pagefile",
            "hiberfil",
            "swapfile",
            ".pst",
            ".ost",
            ".edb",
            "content.outlook",
            "windowscommunicationsapps",
            "unalloc",
        )
    ):
        ipm = _count_ipm_note_markers(data)
    if any(
        tok in pl
        for tok in (
            "history",
            "places.sqlite",
            "web data",
            "sessionstore",
            "recovery.json",
            "edb",
            "inetcache",
            "content.outlook",
            "pagefile",
            "hiberfil",
            "swapfile",
        )
    ):
        urls.extend(extract_urls_from_raw_bytes(data, source_path=path))
    return ipm


def _read_vd_file_sampled(vd, path: str, *, budget: int, window: int = 32 * 1024 * 1024) -> bytes:
    """Read evenly spaced windows across a large file (AXIOM carves full pagefile/hiberfil).

    Prefix-only reads miss most recoverable artifacts — pagefile headers are sparse.
    """
    fs = getattr(vd, "_fs_info", None)
    if fs is None:
        from app.services.virtual_disk import read_full_file_from_disk

        return read_full_file_from_disk(vd, path, max_bytes=budget) or b""

    try:
        fentry = fs.open(path.replace("\\", "/").lstrip("/"))
    except Exception:
        return b""
    size = int(getattr(getattr(fentry, "info", None), "meta", None).size or 0)
    if size <= 0:
        return b""
    if size <= budget:
        return fentry.read_random(0, size) or b""

    window = max(min(window, budget), 1_048_576)
    n_windows = max(budget // window, 1)
    # Spread windows across the whole file (include start + end).
    if n_windows == 1:
        offsets = [0]
    else:
        step = max((size - window) // (n_windows - 1), 1)
        offsets = [min(i * step, max(size - window, 0)) for i in range(n_windows)]

    chunks: list[bytes] = []
    total = 0
    for off in offsets:
        if total >= budget:
            break
        n = min(window, size - off, budget - total)
        if n <= 0:
            continue
        try:
            part = fentry.read_random(int(off), int(n))
        except Exception:
            continue
        if part:
            chunks.append(part)
            total += len(part)
    return b"".join(chunks)


def _scan_vd_pagefile_hiberfil(
    db, job_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    """Carve pagefile/hiberfil via virtual disk — often omitted from job_artifacts."""
    try:
        from app.services.virtual_disk import open_virtual_disk
    except Exception:
        return [], [], 0, 0

    # Prefer known root paths; fall back to a short name probe.
    candidates = (
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "Pagefile.sys",
        "Hiberfil.sys",
    )
    try:
        vd = open_virtual_disk(db, job_id)
    except Exception as exc:
        log.info("carve: vd open failed for pagefile job=%s: %s", job_id, exc)
        return [], [], 0, 0

    hits: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    scanned = 0
    ipm_notes = 0
    seen: set[str] = set()
    for path in candidates:
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        # Windows 10+ hiberfil is often Xpress-compressed — raw carve yields little.
        # Prefer pagefile budget; still sample hiberfil lightly for uncompressed pockets.
        budget = _MAX_PAGEFILE_BYTES
        if "hiberfil" in key:
            budget = min(budget, 256 * 1024 * 1024)
        try:
            data = _read_vd_file_sampled(vd, path, budget=budget)
        except Exception as exc:
            log.info("carve vd read failed path=%s: %s", path, exc)
            continue
        if not data or len(data) < 4096:
            continue
        scanned += 1
        ipm_notes += _process_carve_buffer(
            data, path=path, source_artifact_id=None, hits=hits, urls=urls
        )
        log.info(
            "carve vd system file job=%s path=%s bytes=%s jpeg~=%s hits_so_far=%s",
            job_id,
            path,
            len(data),
            data.count(bytes([0xFF, 0xD8, 0xFF])),
            len(hits),
        )
    return hits, urls, scanned, ipm_notes


def _scan_high_value_files(
    db, job_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    from app.services.artifact_live_counts import _read_job_files

    rows = fetchall(db, _HIGH_VALUE_PATH_SQL, {"j": job_id})
    hits: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    scanned = 0
    ipm_notes = 0

    if rows:
        # Read pagefile/hiberfil with a larger budget than ordinary History/PST slices.
        max_budget = max(_source_read_budget(str(r.get("file_path") or "")) for r in rows)
        contents = _read_job_files(db, job_id, rows, max_bytes=max_budget)
        for row in rows:
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path) or b""
            if not data:
                continue
            scanned += 1
            ipm_notes += _process_carve_buffer(
                data,
                path=path,
                source_artifact_id=str(row["id"]),
                hits=hits,
                urls=urls,
            )

    # AXIOM carves pagefile/hiberfil across the full file. Extract filters omit them
    # from job_artifacts, and prefix-only reads miss most hits — always sample via VD.
    vd_hits, vd_urls, vd_n, vd_ipm = _scan_vd_pagefile_hiberfil(db, job_id)
    hits.extend(vd_hits)
    urls.extend(vd_urls)
    scanned += vd_n
    ipm_notes += vd_ipm

    return hits, urls, scanned, ipm_notes


def _scan_unallocated(
    db, job_id: str
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]], int]:
    """Sample unallocated inodes via pytsk3 (bounded)."""
    try:
        from app.services.virtual_disk import open_virtual_disk
    except Exception:
        return [], 0, [], 0

    try:
        vd = open_virtual_disk(db, job_id)
    except Exception as exc:
        log.info("carve: virtual disk unavailable job=%s: %s", job_id, exc)
        return [], 0, [], 0

    fs = getattr(vd, "_fs_info", None)
    if fs is None:
        return [], 0, [], 0

    try:
        import pytsk3
    except Exception:
        return [], 0, [], 0

    hits: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    bytes_scanned = 0
    ipm_notes = 0
    first = int(getattr(fs.info, "first_inum", 0) or 0)
    last = int(getattr(fs.info, "last_inum", 0) or 0)
    if last <= first:
        return [], 0, [], 0

    # Pass 1: discover unalloc inodes (dense stride). Pass 2: read largest first —
    # AXIOM recovers deleted media folders; uniform stride wastes budget on tiny slack.
    span = max(last - first, 1)
    stride = max(span // 1_500_000, 1)
    unalloc_flag = getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 0x01)
    candidates: list[tuple[int, int]] = []  # (size, inum)

    for inum in range(first, last + 1, stride):
        try:
            entry = fs.open_meta(inum)
        except Exception:
            continue
        meta = getattr(entry, "info", None)
        meta = getattr(meta, "meta", None) if meta else None
        if meta is None:
            continue
        flags = int(getattr(meta, "flags", 0) or 0)
        if not (flags & unalloc_flag):
            continue
        size = int(getattr(meta, "size", 0) or 0)
        if size < 4096:
            continue
        candidates.append((size, inum))
        if len(candidates) >= 80_000:
            break

    candidates.sort(key=lambda t: t[0], reverse=True)

    for size, inum in candidates:
        if bytes_scanned >= _MAX_UNALLOC_BYTES:
            break
        try:
            entry = fs.open_meta(inum)
        except Exception:
            continue
        # Prefer larger deleted objects (docs/media); cap per-inode read.
        read_n = min(size, 8_000_000, _MAX_UNALLOC_BYTES - bytes_scanned)
        try:
            data = entry.read_random(0, read_n)
        except Exception:
            continue
        if not data:
            continue
        bytes_scanned += len(data)
        source = f"unallocated:inode:{inum}"
        hits.extend(scan_buffer_for_signatures(data, source_path=source, base_offset=0))
        if b"IPM.Note" in data or b"I\x00P\x00M\x00.\x00N\x00o\x00t\x00e\x00" in data:
            ipm_notes += _count_ipm_note_markers(data)
        if len(urls) < 8_000 and (b"http://" in data or b"https://" in data):
            urls.extend(extract_urls_from_raw_bytes(data[: min(len(data), 512_000)], source_path=source))
        if len(hits) >= _MAX_HITS_PER_KIND:
            break

    log.info(
        "carve unalloc job=%s bytes=%s hits=%s urls=%s candidates=%s stride=%s ipm=%s",
        job_id,
        bytes_scanned,
        len(hits),
        len(urls),
        len(candidates),
        stride,
        ipm_notes,
    )
    return hits, bytes_scanned, urls, ipm_notes


def _is_mail_adjacent(source_path: str) -> bool:
    pl = (source_path or "").lower().replace("\\", "/")
    return any(tok in pl for tok in _MAIL_ADJACENT_TOKENS)


def _is_thumb_cache_source(source_path: str) -> bool:
    """Thumbcache CMMM entries are counted separately — skip picture carve here."""
    pl = (source_path or "").lower().replace("\\", "/")
    return (
        "thumbcache" in pl
        or "iconcache" in pl
        or pl.endswith("/thumbs.db")
        or pl.endswith("\\thumbs.db")
    )


def _is_high_signal_carve_source(source_path: str) -> bool:
    """Office OLE/OOXML false-positives are common in Temp/caches — prefer slack sources."""
    pl = (source_path or "").lower().replace("\\", "/")
    return any(
        tok in pl
        for tok in (
            "pagefile",
            "hiberfil",
            "swapfile",
            "unallocated",
            ".pst",
            ".ost",
            "content.outlook",
            "$recycle",
            "/recycler/",
        )
    )


def _aggregate(
    hits: list[dict[str, Any]],
    urls: list[dict[str, Any]],
    *,
    ipm_note_hits: int = 0,
) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    mail_adj_by_kind: dict[str, int] = {}
    office_by_kind: dict[str, int] = {}
    dedupe: set[str] = set()
    evidence: list[dict[str, Any]] = []
    pic_kinds = {"jpeg", "png", "gif", "bmp", "tiff"}
    office_kinds = {"doc", "docx", "xls", "xlsx", "ppt", "pptx"}
    for hit in hits:
        hid = hit["id"]
        if hid in dedupe:
            continue
        dedupe.add(hid)
        kind = hit["kind"]
        src = str(hit.get("source_path") or "")
        # Avoid double-counting thumbcache CMMM catalog vs embedded JPEG carve.
        if kind in pic_kinds and _is_thumb_cache_source(src):
            continue
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if kind in office_kinds and _is_high_signal_carve_source(src):
            office_by_kind[kind] = office_by_kind.get(kind, 0) + 1
        if _is_mail_adjacent(src):
            mail_adj_by_kind[kind] = mail_adj_by_kind.get(kind, 0) + 1
        if len(evidence) < _MAX_EVIDENCE_ROWS:
            evidence.append(hit)

    # Map to AXIOM catalog names — these are carve-only uplifts (not allocated FS).
    axiom_counts: dict[str, int] = {}
    picture = (
        by_kind.get("jpeg", 0)
        + by_kind.get("png", 0)
        + by_kind.get("gif", 0)
        + by_kind.get("bmp", 0)
        + by_kind.get("tiff", 0)
    )
    axiom_counts["picture"] = picture
    axiom_counts["pictures"] = picture
    video = by_kind.get("mp4", 0) + by_kind.get("avi", 0) + by_kind.get("mkv", 0)
    axiom_counts["video"] = video
    axiom_counts["videos"] = video
    axiom_counts["photoshop files"] = by_kind.get("psd", 0)
    axiom_counts["pdf documents"] = by_kind.get("pdf", 0)
    axiom_counts["rtf documents"] = by_kind.get("rtf", 0)
    # Office: only high-signal carve sources (pagefile/unalloc/mail) to limit OLE noise.
    axiom_counts["microsoft word documents"] = office_by_kind.get("doc", 0) + office_by_kind.get(
        "docx", 0
    )
    axiom_counts["microsoft excel documents"] = office_by_kind.get("xls", 0) + office_by_kind.get(
        "xlsx", 0
    )
    axiom_counts["microsoft powerpoint documents"] = office_by_kind.get("ppt", 0) + office_by_kind.get(
        "pptx", 0
    )
    axiom_counts["eml(x) files"] = by_kind.get("eml", 0)
    carved_mail = by_kind.get("msg", 0) + by_kind.get("eml", 0)
    # IPM.Note markers in pagefile/unalloc often exceed intact MSG headers.
    axiom_counts["outlook emails"] = max(carved_mail, int(ipm_note_hits or 0))
    # Attachments: only mail-adjacent carved docs/PDF + MSG (avoid counting all disk PDFs).
    axiom_counts["email attachments"] = (
        mail_adj_by_kind.get("pdf", 0)
        + mail_adj_by_kind.get("doc", 0)
        + mail_adj_by_kind.get("docx", 0)
        + mail_adj_by_kind.get("xls", 0)
        + mail_adj_by_kind.get("xlsx", 0)
        + mail_adj_by_kind.get("ppt", 0)
        + mail_adj_by_kind.get("pptx", 0)
        + mail_adj_by_kind.get("rtf", 0)
        + by_kind.get("msg", 0)
    )

    # Dedupe URLs
    url_merged: dict[str, dict[str, Any]] = {}
    for rec in urls:
        url = str(rec.get("url") or "").strip()
        if not url:
            continue
        key = url.lower()
        prev = url_merged.get(key)
        if not prev:
            url_merged[key] = dict(rec)
        else:
            prev["visit_count"] = max(int(prev.get("visit_count") or 1), int(rec.get("visit_count") or 1))

    return {
        "by_kind": by_kind,
        "axiom_counts": axiom_counts,
        "evidence_rows": evidence,
        "url_records": list(url_merged.values()),
        "hit_total": len(dedupe),
    }


def ensure_signature_carve_inventory(
    db,
    job_id: str,
    *,
    force: bool = False,
    scan_unallocated: bool = True,
) -> dict[str, Any]:
    """Build/cache carve inventory for a job (single-flight per job)."""
    with _BUILD_COND:
        while True:
            if not force and job_id in _JOB_CACHE:
                return dict(_JOB_CACHE[job_id])
            if job_id in _BUILDING:
                _BUILD_COND.wait(timeout=1.0)
                continue
            _BUILDING.add(job_id)
            break

    try:
        if not force:
            ds = _load_disk_source(db, job_id)
            cached = ds.get("signature_carve_inventory")
            if (
                isinstance(cached, dict)
                and cached.get("by_kind") is not None
            ):
                inv = {
                    "by_kind": dict(cached.get("by_kind") or {}),
                    "axiom_counts": dict(cached.get("axiom_counts") or {}),
                    "evidence_rows": list(cached.get("evidence_rows") or []),
                    "url_records": list(cached.get("url_records") or []),
                    "hit_total": int(cached.get("hit_total") or 0),
                    "sources_scanned": int(cached.get("sources_scanned") or 0),
                    "unalloc_bytes_scanned": int(cached.get("unalloc_bytes_scanned") or 0),
                }
                with _BUILD_COND:
                    _JOB_CACHE[job_id] = inv
                return dict(inv)

        log.info("signature carve start job=%s", job_id)
        hits, urls, sources, ipm_hi = _scan_high_value_files(db, job_id)
        unalloc_bytes = 0
        ipm_un = 0
        if scan_unallocated:
            unalloc_hits, unalloc_bytes, unalloc_urls, ipm_un = _scan_unallocated(db, job_id)
            hits.extend(unalloc_hits)
            urls.extend(unalloc_urls)

        inv = _aggregate(hits, urls, ipm_note_hits=int(ipm_hi or 0) + int(ipm_un or 0))
        inv["sources_scanned"] = sources
        inv["unalloc_bytes_scanned"] = unalloc_bytes
        inv["ipm_note_hits"] = int(ipm_hi or 0) + int(ipm_un or 0)
        try:
            _save_carve_inventory(db, job_id, inv)
            db.commit()
        except Exception as exc:
            log.warning("persist carve inventory failed job=%s: %s", job_id, exc)
            try:
                db.rollback()
            except Exception:
                pass

        with _BUILD_COND:
            _JOB_CACHE[job_id] = inv
        log.info(
            "signature carve done job=%s hits=%s picture=%s pdf=%s psd=%s eml=%s urls=%s",
            job_id,
            inv.get("hit_total"),
            inv.get("axiom_counts", {}).get("picture"),
            inv.get("axiom_counts", {}).get("pdf documents"),
            inv.get("axiom_counts", {}).get("photoshop files"),
            inv.get("axiom_counts", {}).get("eml(x) files"),
            len(inv.get("url_records") or []),
        )
        return dict(inv)
    finally:
        with _BUILD_COND:
            _BUILDING.discard(job_id)
            _BUILD_COND.notify_all()


def get_cached_signature_carve_inventory(db, job_id: str) -> dict[str, Any] | None:
    """Return the cached carve inventory, building it on demand when absent.

    Virtual ``carve-*`` content/preview endpoints need the same evidence rows that
    produced the catalog count.  A previous refactor left the consumer import in
    place but removed this accessor, making carved evidence impossible to open.
    """
    with _BUILD_COND:
        cached = _JOB_CACHE.get(job_id)
        if cached is not None:
            return dict(cached)
    try:
        return ensure_signature_carve_inventory(db, job_id)
    except Exception:
        return None


def carved_axiom_count(db, job_id: str, artifact_name: str) -> int:
    from app.services.axiom_aligned_counts import _norm_axiom_name

    inv = ensure_signature_carve_inventory(db, job_id)
    name = _norm_axiom_name(artifact_name)
    return int((inv.get("axiom_counts") or {}).get(name) or 0)


def carved_url_records(db, job_id: str) -> list[dict[str, Any]]:
    """Raw http(s) URLs recovered from History-WAL / pagefile / mail binaries."""
    inv = ensure_signature_carve_inventory(db, job_id)
    return list(inv.get("url_records") or [])


def _is_direct_eml_source(path: str) -> bool:
    """True when a carved EML hit is inside an already-listable message file.

    Signature carving an allocated .eml/.emlx (or Maildir/Apple Mail message) is
    useful for validation but must not create a second EML(X) evidence row.
    """
    norm = (path or "").replace("\\", "/").lower()
    leaf = norm.rsplit("/", 1)[-1]
    if leaf.endswith((".eml", ".emlx")):
        return True
    if "/maildir/" in norm and ("/cur/" in norm or "/new/" in norm):
        return True
    if "/library/mail/" in norm and "/messages/" in norm:
        return True
    if "/containers/com.apple.mail/" in norm and "/messages/" in norm:
        return True
    return False


_AXIOM_NAME_TO_KINDS: dict[str, set[str]] = {
    "picture": {"jpeg", "png", "gif", "bmp", "tiff"},
    "pictures": {"jpeg", "png", "gif", "bmp", "tiff"},
    "video": {"mp4", "avi", "mkv"},
    "videos": {"mp4", "avi", "mkv"},
    "photoshop files": {"psd"},
    "pdf documents": {"pdf"},
    "rtf documents": {"rtf"},
    "microsoft word documents": {"doc", "docx"},
    "microsoft excel documents": {"xls", "xlsx"},
    "microsoft powerpoint documents": {"ppt", "pptx"},
    "eml(x) files": {"eml"},
    "outlook emails": {"msg", "eml"},
    "email attachments": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "msg"},
}


def list_carve_evidence(
    db,
    job_id: str,
    *,
    kinds: set[str] | None = None,
    axiom_name: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import _norm_axiom_name

    inv = ensure_signature_carve_inventory(db, job_id)
    rows = list(inv.get("evidence_rows") or [])
    norm_name = _norm_axiom_name(axiom_name) if axiom_name else ""
    if norm_name and not kinds:
        kinds = _AXIOM_NAME_TO_KINDS.get(norm_name)
    if kinds:
        rows = [r for r in rows if r.get("kind") in kinds]
        # Email attachments: prefer mail-adjacent sources for browse parity.
        if norm_name == "email attachments":
            rows = [
                r
                for r in rows
                if r.get("kind") == "msg" or _is_mail_adjacent(str(r.get("source_path") or ""))
            ]
        # Do not double-count the RFC822 signature of an allocated EML/EMLX
        # file that is already present in the canonical browse set.
        if norm_name == "eml(x) files":
            rows = [r for r in rows if not _is_direct_eml_source(str(r.get("source_path") or ""))]
    total = len(rows)
    page = max(int(page or 1), 1)
    page_size = max(min(int(page_size or 50), 200), 1)
    start = (page - 1) * page_size
    slice_rows = rows[start : start + page_size]
    items = []
    for hit in slice_rows:
        kind = hit.get("kind") or "carve"
        src = hit.get("source_path") or ""
        title = f"Carved {kind.upper()} @ {src}:{hit.get('offset', 0)}"
        items.append(
            {
                "id": hit.get("id"),
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": hit.get("source_artifact_id"),
                "artifact_type": f"carved_{kind}",
                "axiom_category": kind,
                "axiom_category_label": f"Carved {kind}",
                "axiom_sub_category": None,
                "title": title[:200],
                "source_path": src,
                "artifact_datetime": None,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "carved_signature",
                    "kind": kind,
                    "offset": hit.get("offset"),
                    "source_path": src,
                    "source_artifact_id": hit.get("source_artifact_id"),
                    "preview_body": (
                        f"Carved {kind} signature hit\n"
                        f"Source: {src}\n"
                        f"Offset: {hit.get('offset')}\n"
                        "Recovered by magic-byte scan (unallocated / container). "
                        "Open source to inspect the surrounding bytes."
                    ),
                },
                "tags": ["carved", kind],
                "examiner_comment": None,
                "parser_version": "signature_carve_inventory",
                "confidence": None,
                "created_at": "",
            }
        )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "evidence_domain": "carved_signature",
        "evidence_label": "Carved evidence",
    }
