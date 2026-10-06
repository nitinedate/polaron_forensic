"""AXIOM-aligned artifact counting (parsed records vs file occurrences).

Implements the counting contract from the AXIOM-aligned specification:
- Registry/USB/RDP/Feature Usage → parsed artifact record counts
- Documents → allocated file occurrence counts (extension + basename fallback)
- Communication URLs → visit occurrence counts (not unique-URL-only)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("axiom_aligned_counts")

_USB_DEVICE_ID = re.compile(
    r"(USBSTOR\\[^\\]+\\[^\\]+|USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\\]*)",
    re.I,
)

_LARGE_JOB_CACHE: dict[str, bool] = {}
_LARGE_JOB_FILE_THRESHOLD = 80_000


def _is_large_artifact_job(db, job_id: str) -> bool:
    """True when job_artifacts is large enough that browser/email full scans OOM or stall."""
    cached = _LARGE_JOB_CACHE.get(job_id)
    if cached is not None:
        return cached
    try:
        row = fetchone(db, "SELECT COUNT(*) AS c FROM job_artifacts WHERE job_id=:j", {"j": job_id})
        large = int((row or {}).get("c") or 0) >= _LARGE_JOB_FILE_THRESHOLD
    except Exception:
        large = False
    _LARGE_JOB_CACHE[job_id] = large
    return large

_FEATURE_USAGE_SUBKEYS = frozenset({
    "AppLaunch",
    "AppSwitched",
    "ShowJumpView",
    "AppBadgeUpdated",
    "TrayButtonClicked",
})


def _normalized_extensions(extensions: list[str]) -> list[str]:
    out: list[str] = []
    for ext in extensions:
        e = (ext or "").strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = f".{e}"
        out.append(e)
    return out


def count_document_file_occurrences(db, job_id: str, extensions: list[str]) -> int:
    """Count allocated document files by extension column or basename suffix."""
    exts = _normalized_extensions(extensions)
    if not exts:
        return 0
    row = fetchone(
        db,
        """SELECT count(*) AS c FROM job_artifacts
           WHERE job_id=:jid AND (
             lower(coalesce(extension, '')) = ANY(:exts)
             OR lower(regexp_replace(coalesce(file_name, ''), '^.*(\\.[a-z0-9]+)$', '\\1')) = ANY(:exts)
             OR lower(regexp_replace(coalesce(file_path, ''), '^.*(\\.[a-z0-9]+)$', '\\1')) = ANY(:exts)
           )""",
        {"jid": job_id, "exts": exts},
    )
    return int(row["c"]) if row else 0


def _usb_record_key(rec: dict[str, Any]) -> str:
    bus = str(rec.get("bus") or "")
    class_id = str(rec.get("class_id") or "")
    serial = str(rec.get("serial") or "")
    name = str(rec.get("device_name") or "")
    if bus.lower() == "setupapi":
        return f"setupapi|{class_id}".lower()
    return f"{bus}|{class_id}|{serial}|{name}".lower()


def _setupapi_device_key(device_id: str) -> str:
    did = (device_id or "").strip()
    m = _USB_DEVICE_ID.search(did)
    return (m.group(1) if m else did[:160]).lower()


def count_usb_device_records(db, job_id: str) -> tuple[int, list[dict[str, Any]]]:
    """USB Devices — Enum\\USB + USBSTOR registry instances + SetupAPI device IDs."""
    from app.parsers.registry import parse_registry_hive
    from app.parsers.setupapi import parse_setupapi_log
    from app.services.artifact_live_counts import _read_job_files

    devices: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(rec: dict[str, Any]) -> None:
        if rec.get("record_type") != "usb_device":
            return
        key = _usb_record_key(rec)
        if key in seen:
            return
        seen.add(key)
        devices.append(rec)

    # Parsed records + live hive/SetupAPI — AXIOM USB ≈ Enum\USB + USBSTOR + SetupAPI.
    # Do not early-return on a small parse set (previously capped at 8 and missed devices).
    _usb_devices_from_parse_results(db, job_id, seen, devices)

    hive_rows = fetchall(
        db,
        """SELECT file_path, size_bytes, sha256 FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 4096
             AND (file_path ILIKE '%/SYSTEM' OR lower(file_name) = 'system')
           ORDER BY size_bytes DESC LIMIT 64""",
        {"j": job_id},
    )
    if hive_rows:
        contents = _read_job_files(db, job_id, hive_rows, max_bytes=8_000_000)
        seen_hive_hashes: set[str] = set()
        for row in hive_rows:
            digest = str(row.get("sha256") or "").strip().lower()
            if digest and digest in seen_hive_hashes:
                continue
            if digest:
                seen_hive_hashes.add(digest)
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            try:
                for rec in parse_registry_hive(data, path):
                    _add(rec)
            except Exception:
                continue

    setup_rows = fetchall(
        db,
        """SELECT file_path, size_bytes, sha256 FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 32 AND (
             lower(file_name) LIKE 'setupapi.dev%'
             OR file_path ILIKE '%setupapi.dev.log%'
           )
           ORDER BY size_bytes DESC LIMIT 64""",
        {"j": job_id},
    )
    if setup_rows:
        contents = _read_job_files(db, job_id, setup_rows, max_bytes=4_000_000)
        seen_setup_hashes: set[str] = set()
        for row in setup_rows:
            digest = str(row.get("sha256") or "").strip().lower()
            if digest and digest in seen_setup_hashes:
                continue
            if digest:
                seen_setup_hashes.add(digest)
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            try:
                for rec in parse_setupapi_log(data, path):
                    if rec.get("record_type") != "usb_usage_event":
                        continue
                    did = str(rec.get("device_id") or "")
                    if not did or not re.search(r"USB|VID_|USBSTOR|WPDBUSENUM", did, re.I):
                        continue
                    class_id = _setupapi_device_key(did)
                    key = f"setupapi|{class_id}"
                    if key in seen:
                        continue
                    seen.add(key)
                    devices.append({
                        "record_type": "usb_device",
                        "bus": "SetupAPI",
                        "device_name": class_id,
                        "class_id": class_id,
                        "serial": rec.get("serial"),
                        "source": rec.get("source") or path,
                    })
            except Exception:
                continue

    if not devices:
        return 0, []

    return len(devices), devices


def _usb_devices_from_parse_results(db, job_id: str, seen: set[str], devices: list[dict[str, Any]]) -> None:
    """Supplement registry USB counts with parsed usb_device records (SetupAPI / SYSTEM)."""
    rows = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:j AND (
             ja.file_path ILIKE '%/SYSTEM'
             OR lower(ja.file_name) = 'system'
             OR ja.file_path ILIKE '%setupapi.dev%'
             OR apr.normalized::text ILIKE '%usb_device%'
             OR apr.normalized::text ILIKE '%USBSTOR%'
           )
           LIMIT 500""",
        {"j": job_id},
    )
    import json as _json

    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = _json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict) or rec.get("record_type") != "usb_device":
                continue
            key = _usb_record_key(rec)
            if key in seen:
                continue
            seen.add(key)
            devices.append(rec)


def count_rdp_connection_records(db, job_id: str) -> tuple[int, list[dict[str, Any]]]:
    """RDP — Terminal Server Client Servers + MRU per user profile (parsed records)."""
    from app.parsers.registry import parse_registry_hive
    from app.services.artifact_live_counts import _read_job_files

    conns: list[dict[str, Any]] = []
    seen: set[str] = set()

    ntuser_rows = fetchall(
        db,
        """SELECT file_path, size_bytes, sha256 FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 4096 AND (
             lower(file_name) = 'ntuser.dat'
             OR file_path ILIKE '%/NTUSER.DAT'
           )
           ORDER BY size_bytes DESC""",
        {"j": job_id},
    )
    if ntuser_rows:
        contents = _read_job_files(db, job_id, ntuser_rows)
        seen_hive_hashes: set[str] = set()
        for row in ntuser_rows:
            digest = str(row.get("sha256") or "").strip().lower()
            if digest and digest in seen_hive_hashes:
                continue
            if digest:
                seen_hive_hashes.add(digest)
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            try:
                for rec in parse_registry_hive(data, path):
                    if rec.get("record_type") != "rdp_connection":
                        continue
                    host = (rec.get("host") or "").strip()
                    if not host or "\\AddIns\\" in host or host.lower().startswith("software\\"):
                        continue
                    user = (rec.get("user") or rec.get("username_hint") or path or "").strip()
                    source = str(rec.get("source") or "")
                    key = f"{path.lower()}|{source.lower()}|{user.lower()}|{host.lower()}"
                    if key in seen:
                        continue
                    seen.add(key)
                    conns.append({
                        "host": host,
                        "user": rec.get("user"),
                        "username_hint": rec.get("username_hint"),
                        "source": source or path,
                    })
            except Exception:
                continue

    if conns:
        return len(conns), conns

    return 0, []


def count_feature_usage_records(db, job_id: str) -> int:
    """Feature Usage — sum of FeatureUsage registry values across all NTUSER profiles."""
    from app.parsers.registry import parse_registry_hive
    from app.services.artifact_live_counts import _read_job_files

    total = 0
    ntuser_rows = fetchall(
        db,
        """SELECT file_path, size_bytes, sha256 FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 4096 AND (
             lower(file_name) = 'ntuser.dat'
             OR file_path ILIKE '%/NTUSER.DAT'
           )
           ORDER BY size_bytes DESC""",
        {"j": job_id},
    )
    if ntuser_rows:
        contents = _read_job_files(db, job_id, ntuser_rows)
        seen_hive_hashes: set[str] = set()
        for row in ntuser_rows:
            digest = str(row.get("sha256") or "").strip().lower()
            if digest and digest in seen_hive_hashes:
                continue
            if digest:
                seen_hive_hashes.add(digest)
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            try:
                for rec in parse_registry_hive(data, path):
                    if rec.get("record_type") != "feature_usage":
                        continue
                    if rec.get("metric") == "app_launch_switched":
                        continue
                    key_path = str(rec.get("key_path") or "")
                    subkey = key_path.rsplit("\\", 1)[-1] if key_path else ""
                    if subkey and subkey not in _FEATURE_USAGE_SUBKEYS and "\\FeatureUsage\\" in key_path:
                        continue
                    total += int(rec.get("entry_count") or 0)
            except Exception:
                continue

    if total > 0:
        return total

    from app.services.artifact_live_counts import scan_registry_inventory

    live = scan_registry_inventory(db, job_id)
    return int(live.get("feature_usage") or 0)


def count_url_visit_occurrences(db, job_id: str, category: str) -> int:
    """Communication URL categories — visit occurrences per AXIOM reconciliation rules."""
    from app.services.browser_url_inventory import compute_communication_url_totals

    totals = compute_communication_url_totals(db, job_id)
    key = (category or "").strip().lower()
    return int(totals.get(key) or 0)


def count_parsed_records_for_artifact(db, job_id: str, *, encyclopedia_ids: list[str]) -> int:
    """Sum parsed artifact records for files classified under encyclopedia IDs."""
    if not encyclopedia_ids:
        return 0
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
           WHERE ja.job_id=:j AND ja.encyclopedia_artifact_id = ANY(:ids)""",
        {"j": job_id, "ids": encyclopedia_ids},
    )
    parsed = int(row["c"]) if row else 0
    if parsed > 0:
        return parsed
    row = fetchone(
        db,
        """SELECT count(*) AS c FROM job_artifacts
           WHERE job_id=:j AND encyclopedia_artifact_id = ANY(:ids)""",
        {"j": job_id, "ids": encyclopedia_ids},
    )
    return int(row["c"]) if row else 0


def _norm_axiom_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower()).lstrip("$")


_DOCUMENT_EXTENSIONS: dict[str, list[str]] = {
    "csv documents": [".csv"],
    "microsoft powerpoint documents": [".ppt", ".pptx"],
    "microsoft excel documents": [".xls", ".xlsx", ".xlsm"],
    "pdf documents": [".pdf"],
    "rtf documents": [".rtf"],
    # Keep system/application logs out of Text Documents; Logfile Analysis owns .log.
    "text documents": [".txt"],
    "microsoft word documents": [".doc", ".docx", ".docm"],
    "openoffice documents": [".odt", ".ods", ".odp"],
    "onenote documents": [".one"],
    "publisher documents": [".pub"],
}
# Public alias — browse/export and the axiom_aligned_counts shim import this name.
DOCUMENT_EXTENSIONS = _DOCUMENT_EXTENSIONS


def document_extensions_for(artifact_name: str) -> list[str]:
    """Extension list for a catalog document artifact, or empty if not a document type."""
    name = _norm_axiom_name(artifact_name)
    return list(
        _DOCUMENT_EXTENSIONS.get(name)
        or _DOCUMENT_EXTENSIONS.get(name.replace("microsoft ", ""))
        or []
    )


def _document_ext_key(extensions: list[str]) -> str:
    return ",".join(sorted(_normalized_extensions(extensions)))


def build_document_disk_inventory(db, job_id: str, *, force: bool = False) -> dict[str, Any]:
    """Full-disk document extension census (Axiom allocates all matching files)."""
    from app.services.disk_build_log import write_disk_log
    from app.services.disk_ext_census import ensure_disk_extension_censuses

    def _progress(message: str, meta: dict | None = None) -> None:
        write_disk_log(
            db,
            job_id,
            message,
            stage="artifact_inventory",
            metadata=meta or {},
        )
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    censuses = ensure_disk_extension_censuses(
        db,
        job_id,
        force=force,
        on_progress=_progress,
    )
    return censuses.get("document_disk_inventory") or {
        "by_ext_key": {},
        "enumerated_files": 0,
        "source": "full_disk_enumeration",
    }


def count_document_occurrences_axiom(db, job_id: str, extensions: list[str]) -> int:
    """Allocated document file occurrences only.

    Recovered/carved documents are a different count domain and must not be added
    to the primary file-occurrence total. They remain available in the carve inventory.
    """
    job_count = count_document_file_occurrences(db, job_id, extensions)
    try:
        inv = build_document_disk_inventory(db, job_id)
        disk_count = int((inv.get("by_ext_key") or {}).get(_document_ext_key(extensions), 0))
    except Exception:
        disk_count = 0
    return max(job_count, disk_count)

def count_logfile_analysis_occurrences(db, job_id: str) -> int:
    """Logfile Analysis primary value = deterministic file occurrences.

    Parsed EVTX/log events are a different count domain. The previous implementation
    synthesized 1..12 events from file size and forced a 3x/4x multiplier, producing
    non-reproducible totals. Keep those event counts in query metadata instead.
    """
    from app.services.catalog_section_queries import LOGFILE_ANALYSIS_WHERE

    row = fetchone(
        db,
        f"""SELECT count(*) AS c FROM job_artifacts
              WHERE job_id=:j AND ({LOGFILE_ANALYSIS_WHERE})""",
        {"j": job_id},
    )
    return int(row["c"]) if row else 0


def count_jump_list_occurrences(db, job_id: str) -> int:
    from app.services.artifact_live_counts import count_jump_list_destinations

    info = count_jump_list_destinations(db, job_id)
    entry_total = int(info.get("count") or 0)
    if entry_total > 0:
        return entry_total
    row = fetchone(
        db,
        """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND (
             file_path ILIKE '%.automaticdestinations-ms'
             OR encyclopedia_artifact_id = 'WFS-SHL-0002'
           )""",
        {"j": job_id},
    )
    return int(row["c"]) if row else 0


def count_lnk_occurrences(db, job_id: str) -> int:
    """LNK Files primary value = standalone shortcut file occurrences only.

    Embedded LNK structures inside Jump Lists are container members, not standalone
    file occurrences, and therefore must not be added to this count.
    """
    row = fetchone(
        db,
        """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND (
             lower(coalesce(extension,''))='.lnk'
             OR file_path ILIKE '%.lnk'
             OR encyclopedia_artifact_id = 'WFS-SHL-0001'
           )""",
        {"j": job_id},
    )
    fs_count = int(row["c"]) if row else 0
    try:
        import json as _json
        from app.services.disk_ext_census import ensure_disk_extension_censuses
        r = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
        ds = r.get("disk_source") if r else {}
        if isinstance(ds, str):
            try:
                ds = _json.loads(ds)
            except Exception:
                ds = {}
        disk_lnk = ds.get("lnk_disk_count") if isinstance(ds, dict) else None
        if not isinstance(disk_lnk, int):
            disk_lnk = int(ensure_disk_extension_censuses(db, job_id).get("lnk_disk_count") or 0)
        return max(fs_count, int(disk_lnk or 0))
    except Exception:
        return fs_count


def count_media_occurrences_axiom(db, job_id: str, kind: str) -> int:
    from app.services.media_inventory import media_counts_for_answer

    inv = media_counts_for_answer(db, job_id)
    base = int(inv.get(kind) or 0)
    try:
        from app.services.signature_carve_inventory import carved_axiom_count

        if kind == "photoshop":
            return max(base, carved_axiom_count(db, job_id, "photoshop files"))
        if kind == "picture":
            # AXIOM Picture ≈ allocated images + thumbcache entries + carved/unalloc images.
            carved = carved_axiom_count(db, job_id, "picture")
            return base + max(carved, 0)
        if kind == "video":
            # AXIOM Video ≈ allocated containers + carved BMFF/AVI/MKV fragments.
            carved = carved_axiom_count(db, job_id, "video")
            return base + max(carved, 0)
    except Exception:
        pass
    return base


def _mobile_platform_job(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT type, disk_source FROM jobs WHERE id=:jid""",
        {"jid": job_id},
    )
    if not row:
        return False
    if str(row.get("type") or "") in {"mobile_extraction", "android_mobile", "ios_mobile", "ios_backup", "android_backup"}:
        return True
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            import json as _json

            ds = _json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        return False
    platform = str(ds.get("axiom_platform") or ds.get("evidence_platform") or ds.get("mobile_os") or "").lower()
    return platform in {"android", "ios"} or str(ds.get("source_type") or "").lower() == "mobile"


def count_axiom_catalog_artifact(
    db,
    job_id: str,
    *,
    artifact_name: str,
    category: str,
    artifact_id: str = "",
) -> int:
    """Single AXIOM-aligned count for one catalog artifact (no section-inventory merge)."""
    from app.services.catalog_ingest import _norm_artifact_name

    name = _norm_axiom_name(_norm_artifact_name(artifact_name))
    cat = _norm_axiom_name(category)
    if not name:
        return 0

    # Mobile jobs: dedicated forensic inventory (never fall through to disk collectors).
    if _mobile_platform_job(db, job_id):
        try:
            from app.services.mobile_forensic.inventory import count_mobile_axiom_artifact

            mobile = count_mobile_axiom_artifact(
                db, job_id, artifact_name=artifact_name, category=category,
            )
            return int(mobile.get("count") or 0)
        except Exception as exc:
            log.warning("mobile forensic count failed job=%s artifact=%s: %s", job_id, artifact_name, exc)
            try:
                db.rollback()
            except Exception:
                pass
            return 0

    if name == "usb devices":
        return count_usb_device_records(db, job_id)[0]
    if "recycle bin" in name or name in {
        "deleted files found in recycle bin",
        "deleted files",
        "recycle bin",
    }:
        from app.services.deleted_evidence import count_deleted_job_artifacts

        deleted = count_deleted_job_artifacts(db, job_id)
        if "recycle" in name or "deleted files found" in name:
            return int(deleted.get("recycle_bin") or deleted.get("deleted_files") or 0)
        return int(deleted.get("deleted_files") or 0)
    if "whatsapp" in name and "deleted" in name:
        from app.services.deleted_evidence import count_deleted_job_artifacts

        return int(count_deleted_job_artifacts(db, job_id).get("deleted_whatsapp") or 0)
    if "deleted" in name and any(
        x in name for x in ("telegram", "signal", "instagram", "facebook", "social", "messenger")
    ):
        from app.services.deleted_evidence import count_deleted_job_artifacts

        return int(count_deleted_job_artifacts(db, job_id).get("deleted_social") or 0)
    if name in {"remote desktop protocol", "remote desktop protocol (rdp)"}:
        return count_rdp_connection_records(db, job_id)[0]
    if name in {"your phone device", "your phone devices", "your phone contacts"}:
        from app.services.forensic_inventory import collect_phone_usage

        phone = collect_phone_usage(db, job_id)
        return int(phone.get("unique_device_count") or len(phone.get("devices") or []) or 0)
    if name == "feature usage":
        return count_feature_usage_records(db, job_id)
    if name == "installed microsoft programs":
        from app.services.forensic_inventory import collect_installed_programs

        return int(collect_installed_programs(db, job_id).get("microsoft_count") or 0)
    if name in {"installed programs (non-microsoft)", "installed programs"}:
        from app.services.forensic_inventory import collect_installed_programs

        return int(collect_installed_programs(db, job_id).get("non_microsoft_count") or 0)
    if name == "windows defender logs":
        from app.services.forensic_inventory import collect_defender_logs

        return int(collect_defender_logs(db, job_id).get("count") or 0)
    if name == "web chat urls":
        return count_url_visit_occurrences(db, job_id, "web chat urls")
    if name == "social media urls":
        return count_url_visit_occurrences(db, job_id, "social media urls")
    if name in {"malware/phishing urls", "malware / phishing urls"}:
        return count_url_visit_occurrences(db, job_id, "malware/phishing urls")
    if name == "pornography urls":
        return count_url_visit_occurrences(db, job_id, "pornography urls")
    if name in {"dating site urls", "dating urls"}:
        return count_url_visit_occurrences(db, job_id, "dating site urls")

    doc_exts = _DOCUMENT_EXTENSIONS.get(name)
    if doc_exts or cat == "documents":
        doc_exts = doc_exts or _DOCUMENT_EXTENSIONS.get(name.replace("microsoft ", ""), [])
        if doc_exts:
            return count_document_occurrences_axiom(db, job_id, doc_exts)

    if name in {"picture", "pictures"}:
        return count_media_occurrences_axiom(db, job_id, "picture")
    if name == "audio":
        return count_media_occurrences_axiom(db, job_id, "audio")
    if name in {"video", "videos"}:
        return count_media_occurrences_axiom(db, job_id, "video")
    if name == "photoshop files":
        return count_media_occurrences_axiom(db, job_id, "photoshop")

    if name in {"logfile analysis", "$logfile analysis"}:
        return count_logfile_analysis_occurrences(db, job_id)
    if name in {"jump list", "jump lists"}:
        return count_jump_list_occurrences(db, job_id)
    if name == "lnk files":
        return count_lnk_occurrences(db, job_id)

    # Dedicated collectors are path/SQL cheap — never route them through the
    # token path-index fallback (that matched "files"/"windows" into 30k–57k).
    if name in {"web related files", "web-related files"}:
        from app.services.catalog_section_queries import WEB_RELATED_WHERE

        row = fetchone(
            db,
            f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND ({WEB_RELATED_WHERE})",
            {"j": job_id},
        )
        return int(row["c"]) if row else 0

    if "email" in cat or "calendar" in cat:
        from app.services.email_inventory import EMAIL_COLLECTORS, collect_email_artifact

        data = collect_email_artifact(db, job_id, artifact_name)
        count = int(data.get("count") or 0)
        key = _norm_axiom_name(artifact_name)
        if key in EMAIL_COLLECTORS or any(k in key or key in k for k in EMAIL_COLLECTORS):
            return count
        if count > 0:
            return count
        # Unknown email-catalog titles: still avoid token fallback on large jobs.
        if _is_large_artifact_job(db, job_id):
            return 0
        return count_catalog_artifact_fallback(
            db,
            job_id,
            artifact_name=artifact_name,
            category=category,
            artifact_id=artifact_id,
        )
    if "encrypt" in cat or "credential" in cat:
        from app.services.encryption_inventory import compute_report_encryption_counts

        enc_counts = compute_report_encryption_counts(db, job_id, scan_encrypted=False)
        return int(enc_counts.get(name, 0))

    return count_catalog_artifact_fallback(
        db,
        job_id,
        artifact_name=artifact_name,
        category=category,
        artifact_id=artifact_id,
    )


def count_axiom_catalog_artifact_result(
    db,
    job_id: str,
    *,
    artifact_name: str,
    category: str,
    artifact_id: str = "",
):
    """Single AXIOM-aligned count with provenance metadata."""
    from app.services.catalog_count_result import CountResult, count_result_from_int
    from app.services.catalog_count_spec import metadata_for_artifact, query_snapshot_for_key
    from app.services.mobile_forensic.detection import is_mobile_job
    from app.services.mobile_forensic.inventory import count_mobile_axiom_artifact

    meta = metadata_for_artifact(artifact_name=artifact_name, category=category)
    query_key = str(meta.get("query_key") or "")
    count_domain = str(meta.get("count_domain") or "artifact_record")
    unique_count: int | None = None

    # Mobile jobs: dedicated path (no disk/EWF collectors).
    if is_mobile_job(db, job_id):
        mobile = count_mobile_axiom_artifact(
            db, job_id, artifact_name=artifact_name, category=category,
        )
        snap = dict(mobile.get("query_snapshot") or {})
        snap["query_key"] = query_key or "MOBILE_FORENSIC"
        if artifact_id:
            snap["artifact_id"] = artifact_id
        warnings: list[str] = []
        answer = str(mobile.get("answer") or "")
        if "—" in answer:
            # Keep limitation / source note in warnings so answer_text surfaces it.
            tail = answer.split("—", 1)[1].strip()
            if tail:
                warnings.append(tail[:240])
        return CountResult(
            occurrence_count=int(mobile.get("count") or 0),
            unique_content_count=int(mobile.get("count") or 0) or None,
            count_domain=str(mobile.get("domain") or count_domain),
            query_id=query_key or "MOBILE_FORENSIC",
            query_snapshot=snap,
            confidence=str(mobile.get("confidence") or "LOW"),
            warnings=warnings,
        )

    name = _norm_axiom_name(artifact_name)
    if name == "usb devices":
        cnt, devices = count_usb_device_records(db, job_id)
        unique_count = len(devices)
        snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
        snap["collector"] = "count_usb_device_records"
        return CountResult(
            occurrence_count=cnt,
            unique_content_count=unique_count,
            count_domain=count_domain,
            query_id=query_key,
            query_snapshot=snap,
        )
    if name in {"remote desktop protocol", "remote desktop protocol (rdp)"}:
        cnt, records = count_rdp_connection_records(db, job_id)
        unique_count = len(records)
        snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
        snap["collector"] = "count_rdp_connection_records"
        return CountResult(
            occurrence_count=cnt,
            unique_content_count=unique_count,
            count_domain=count_domain,
            query_id=query_key,
            query_snapshot=snap,
        )

    if name in {"eml(x) files", "eml files"}:
        from app.services.email_inventory import count_eml_files

        data = count_eml_files(db, job_id)
        snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
        snap["collector"] = "count_eml_files"
        snap["browseable_allocated_files"] = int(data.get("filtered_files") or 0)
        snap["mime_validated_messages"] = int(data.get("mime_validated_messages") or 0)
        snap["extensionless_messages"] = int(data.get("extensionless_messages") or 0)
        snap["carved_eml"] = int(data.get("carved_eml") or 0)
        snap["parse_failures"] = int(data.get("parse_failures") or 0)
        if artifact_id:
            snap["artifact_id"] = artifact_id
        warnings = []
        if int(data.get("parse_failures") or 0) > 0:
            warnings.append(
                f"{int(data.get('parse_failures') or 0)} candidate email file(s) could not be MIME-parsed; "
                "they are not included as confirmed EML(X) evidence."
            )
        return CountResult(
            occurrence_count=int(data.get("count") or 0),
            unique_content_count=int(data.get("filtered_files") or 0) or None,
            count_domain="browseable_eml_occurrences",
            query_id=query_key,
            query_snapshot=snap,
            confidence="HIGH" if not warnings else "MEDIUM",
            warnings=warnings,
        )

    if name in {"email attachments", "email attachment"}:
        from app.services.email_inventory import count_email_attachments

        data = count_email_attachments(db, job_id)
        snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
        snap["collector"] = "count_email_attachments"
        snap["indexed_files"] = int(data.get("indexed_files") or data.get("folder_files") or 0)
        snap["mime_attachment_occurrences"] = int(data.get("mime_attachment_occurrences") or 0)
        snap["path_occurrences"] = int(data.get("path_occurrences") or 0)
        if artifact_id:
            snap["artifact_id"] = artifact_id
        return CountResult(
            occurrence_count=int(data.get("count") or 0),
            unique_content_count=int(data.get("indexed_files") or 0) or None,
            count_domain=count_domain,
            query_id=query_key,
            query_snapshot=snap,
        )

    if name in {"mbox emails"}:
        from app.services.email_inventory import count_mbox_emails

        data = count_mbox_emails(db, job_id)
        snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
        snap["collector"] = "count_mbox_emails"
        snap["indexed_files"] = int(data.get("count") or 0)
        if artifact_id:
            snap["artifact_id"] = artifact_id
        return CountResult(
            occurrence_count=int(data.get("count") or 0),
            unique_content_count=int(data.get("count") or 0) or None,
            count_domain="file_occurrence",
            query_id=query_key,
            query_snapshot=snap,
        )

    if _mobile_platform_job(db, job_id):
        try:
            from app.services.mobile_artifact_inventory import count_mobile_family_for_axiom_name

            mobile_count, sample_paths, sample_ids = count_mobile_family_for_axiom_name(
                db, job_id, artifact_name
            )
            if mobile_count > 0 or any(
                tok in name
                for tok in (
                    "whatsapp",
                    "sms",
                    "call log",
                    "telegram",
                    "signal",
                    "instagram",
                    "facebook",
                    "linkedin",
                    "sim card",
                    "device information",
                    "installed application",
                    "account",
                )
            ):
                snap = query_snapshot_for_key(query_key, artifact_name=artifact_name)
                snap["collector"] = "mobile_artifact_inventory"
                snap["sample_paths"] = sample_paths
                snap["evidence_paths"] = sample_paths
                snap["sample_artifact_ids"] = sample_ids
                if artifact_id:
                    snap["artifact_id"] = artifact_id
                return count_result_from_int(
                    mobile_count,
                    artifact_name=artifact_name,
                    count_domain="file_occurrence",
                    query_id=query_key,
                    query_snapshot=snap,
                    unique_count=mobile_count or None,
                    confidence="HIGH" if mobile_count else "LOW",
                )
        except Exception as exc:
            # SQL errors abort the Postgres transaction — must rollback before more queries.
            log.warning("mobile family count failed job=%s artifact=%s: %s", job_id, artifact_name, exc)
            try:
                db.rollback()
            except Exception:
                pass

    count = count_axiom_catalog_artifact(
        db,
        job_id,
        artifact_name=artifact_name,
        category=category,
        artifact_id=artifact_id,
    )
    exts = _DOCUMENT_EXTENSIONS.get(name)
    snap = query_snapshot_for_key(
        query_key,
        artifact_name=artifact_name,
        extensions=list(exts) if exts else None,
    )
    snap["collector"] = "count_axiom_catalog_artifact"
    if exts:
        snap["indexed_files"] = count_document_file_occurrences(db, job_id, exts)
    if artifact_id:
        snap["artifact_id"] = artifact_id
    fallback_unverified = query_key == "PATH_FALLBACK_UNVERIFIED"
    if fallback_unverified:
        snap["warning"] = (
            "No artifact-specific parser/query contract is implemented for this catalog row; "
            "the value is a source-path hit and is not AXIOM-parity evidence."
        )
    return count_result_from_int(
        count,
        artifact_name=artifact_name,
        count_domain=count_domain,
        query_id=query_key,
        query_snapshot=snap,
        unique_count=unique_count,
        confidence="LOW" if fallback_unverified else "HIGH",
    )


def compute_all_aligned_count_results(
    db,
    job_id: str,
    platform: str,
    *,
    progress_cb: Any | None = None,
    schema_name: str | None = None,
    rows: list[dict[str, Any]] | None = None,
    workers: int | None = None,
    skip_warm: bool = False,
) -> dict[str, Any]:
    """Canonical AXIOM-aligned CountResult map — parallel CPU threads with per-thread DB sessions."""
    import concurrent.futures
    import itertools
    import threading

    from sqlalchemy import text

    from app.config import get_settings
    from app.services.catalog_count_result import CountResult, count_result_from_int

    settings = get_settings()
    worker_n = max(int(workers if workers is not None else getattr(settings, "axiom_inventory_workers", 8) or 8), 1)
    # Live performance plan + CPU thermal pace (shared across workers).
    try:
        from app.services.perf_broadcast import live_inventory_workers

        worker_n = min(worker_n, live_inventory_workers(worker_n))
    except Exception:
        pass
    try:
        from app.services.gpu_thermal import recommended_parallel_workers

        worker_n = recommended_parallel_workers(worker_n, min_workers=1)
    except Exception:
        pass
    try:
        from app.services.host_capacity import cpu_thermal_pace

        pace = float(cpu_thermal_pace())
        if pace <= 0.30:
            worker_n = 1
        elif pace <= 0.55:
            worker_n = min(worker_n, 2)
    except Exception:
        pass
    # Large jobs OOM with many threads + heavy collectors — keep concurrency modest.
    try:
        art_n = int(
            db.execute(
                text("SELECT COUNT(*) FROM job_artifacts WHERE job_id=:j"),
                {"j": job_id},
            ).scalar()
            or 0
        )
    except Exception:
        art_n = 0
    if art_n >= 100_000:
        worker_n = min(worker_n, 2)
    else:
        worker_n = min(worker_n, 4)

    if rows is not None:
        ax_rows = [
            {
                "artifact_id": str(r.get("artifact_id") or ""),
                "artifact_name": str(r.get("artifact_name") or ""),
                "category": str(r.get("category") or ""),
            }
            for r in rows
            if r.get("artifact_id")
        ]
    else:
        ax_rows = [
            dict(r)
            for r in db.execute(
                text(
                    "SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts WHERE platform = :platform"
                ),
                {"platform": platform},
            ).mappings().all()
        ]

    total = len(ax_rows)
    if total <= 0:
        return {}

    schema = schema_name or (db.info.get("firm_schema") if hasattr(db, "info") else None)
    results: dict[str, CountResult] = {}
    done_n = 0
    lock = threading.Lock()

    if not skip_warm:
        # Warm expensive collectors once so parallel workers hit caches (URL/encryption/USB/paths).
        try:
            from app.services.disk_ext_census import ensure_disk_extension_censuses

            ensure_disk_extension_censuses(db, job_id)
        except Exception:
            pass
        try:
            from app.services.inventory_path_cache import ensure_fallback_path_counts

            if progress_cb:
                progress_cb("Building streaming path index", 0, total)
            # Only warm with the full catalog row set — never a batch subset.
            ensure_fallback_path_counts(
                db,
                job_id,
                ax_rows,
                progress_cb=progress_cb,
            )
        except Exception:
            pass
        # Skip URL/encryption full-job warm on large disks (OOM / multi-hour scans).
        # Always use the fast encryption path — deep ZIP/PDF header scans hang inventory.
        # Carve is warmed once by axiom_artifact_runner (single-flight). Avoid
        # starting it here during skip_warm=False paths that race parallel workers.
        if art_n < 80_000:
            try:
                from app.services.browser_url_inventory import compute_communication_url_totals

                compute_communication_url_totals(db, job_id)
            except Exception:
                pass
            try:
                from app.services.encryption_inventory import compute_report_encryption_counts

                compute_report_encryption_counts(db, job_id, scan_encrypted=False)
            except Exception:
                pass
        else:
            # Large jobs: still warm URL totals (History-only SQL; carve URLs merge in).
            try:
                from app.services.browser_url_inventory import compute_communication_url_totals

                compute_communication_url_totals(db, job_id)
            except Exception:
                pass

    def _count_one(row: dict[str, Any]) -> tuple[str, CountResult]:
        aid = str(row["artifact_id"])
        name = str(row.get("artifact_name") or aid)
        category = str(row.get("category") or "")
        try:
            if schema:
                from app.db.session import firm_session_readonly

                with firm_session_readonly(schema) as thread_db:
                    result = count_axiom_catalog_artifact_result(
                        thread_db,
                        job_id,
                        artifact_name=name,
                        category=category,
                        artifact_id=aid,
                    )
            else:
                result = count_axiom_catalog_artifact_result(
                    db,
                    job_id,
                    artifact_name=name,
                    category=category,
                    artifact_id=aid,
                )
            return aid, result
        except Exception:
            return aid, count_result_from_int(0, artifact_name=name, query_id="ERROR", confidence="LOW")

    # Single-threaded fallback when schema unknown (can't open thread-local firm sessions).
    if worker_n <= 1 or not schema:
        for idx, row in enumerate(ax_rows, start=1):
            aid, result = _count_one(row)
            results[aid] = result
            if progress_cb and (idx == 1 or idx == total or idx % 5 == 0):
                progress_cb(f"Counting {row.get('artifact_name') or aid}", idx, total)
        return results

    # Bounded in-flight window — avoids submitting hundreds of futures / DB checkouts at once.
    in_flight_cap = max(worker_n * 2, worker_n)
    row_iter = iter(ax_rows)
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_n) as pool:
        futures: dict[concurrent.futures.Future, dict[str, Any]] = {}
        for row in itertools.islice(row_iter, in_flight_cap):
            futures[pool.submit(_count_one, row)] = row

        while futures:
            done, _ = concurrent.futures.wait(
                futures,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                row = futures.pop(fut)
                try:
                    aid, result = fut.result()
                except Exception:
                    aid = str(row["artifact_id"])
                    result = count_result_from_int(
                        0,
                        artifact_name=str(row.get("artifact_name") or aid),
                        query_id="ERROR",
                        confidence="LOW",
                    )
                with lock:
                    results[aid] = result
                    done_n += 1
                    n = done_n
                if progress_cb and (n == 1 or n == total or n % 5 == 0):
                    progress_cb(f"Counting {row.get('artifact_name') or aid}", n, total)
                try:
                    nxt = next(row_iter)
                except StopIteration:
                    continue
                futures[pool.submit(_count_one, nxt)] = nxt

    return results


def compute_all_aligned_counts(db, job_id: str, platform: str) -> dict[str, int]:
    """Canonical AXIOM-aligned counts for every catalog artifact on this platform."""
    return {
        aid: result.primary_count
        for aid, result in compute_all_aligned_count_results(db, job_id, platform).items()
    }


def count_catalog_artifact_fallback(
    db,
    job_id: str,
    *,
    artifact_name: str,
    category: str,
    artifact_id: str = "",
) -> int:
    """Fallback count for catalog entries without a section collector (files or parsed records)."""
    from app.services.catalog_ingest import _norm_artifact_name
    from app.services.inventory_path_cache import get_fallback_path_count

    name = _norm_artifact_name(artifact_name)
    cat = _norm_artifact_name(category)
    if not name:
        return 0

    # Prefer streaming path index (when warm).
    if artifact_id:
        pre = get_fallback_path_count(job_id, artifact_id)
        if pre is not None:
            return int(pre)
        # Index should have been warmed by inventory. Do NOT fall through to
        # handbook OR-token SQL (ILIKE '%windows%'/'%files%' matches most of the disk).
        return 0

    # No artifact_id (ad-hoc calls only): targeted handbook SQL, never encyclopedia.
    from app.services.handbook_query_sql import sql_handbook_evidence_fallback

    hb_where = sql_handbook_evidence_fallback(name, category=cat)
    if hb_where and hb_where != "FALSE":
        row = fetchone(
            db,
            f"""SELECT count(*) AS c FROM job_artifacts ja
                WHERE ja.job_id=:j AND ({hb_where})
                AND ja.file_path NOT ILIKE '%/Windows/WinSxS/%'
                AND ja.file_path NOT ILIKE '%/Installer/%'""",
            {"j": job_id},
        )
        return int(row["c"]) if row else 0
    return 0
