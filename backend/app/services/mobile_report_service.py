"""Mobile forensic report sections — device info, extraction summary, prompt-backed observations."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import fetchall, fetchone
from app.retrieval.hybrid import hybrid_retrieve
from app.services.mobile_report_prompts import (
    DEVICE_INFORMATION_PROMPT,
    EXTRACTION_SUMMARY_PROMPT,
)
from app.services.mobile_segments import infer_mobile_platform_from_names
from app.services.model_router import generate_text

log = logging.getLogger("mobile_report_service")

_BUILD_PROP_KEYS = (
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.brand",
    "ro.product.device",
    "ro.build.version.release",
    "ro.build.id",
    "ro.build.display.id",
    "ro.serialno",
    "ro.boot.serialno",
    "persist.sys.timezone",
    "ro.product.name",
)

_IMAGE_EXT = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp"})
_AUDIO_EXT = frozenset({".opus", ".mp3", ".m4a", ".wav", ".aac", ".amr", ".ogg"})
_VIDEO_EXT = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi"})
_DOC_EXT = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".csv"})
_DB_EXT = frozenset({".db", ".sqlite", ".sqlite3", ".wal"})


def is_mobile_report_type(report_type: str | None) -> bool:
    rt = (report_type or "").strip().lower()
    return rt in {"mobile_forensic", "mobile_device"}


def is_mobile_intake(intake: dict[str, Any] | None, job: dict[str, Any] | None = None) -> bool:
    """True when report should follow mobile forensic layout (Sujit / Vivo sample)."""
    intake = intake or {}
    if is_mobile_report_type(intake.get("report_type")):
        return True
    case_type = (intake.get("case_type") or "").strip().lower()
    if case_type in {"mobile_forensic", "mobile_device"}:
        return True
    ds = _json_field((job or {}).get("disk_source"), {}) or {}
    platform = (ds.get("axiom_platform") or ds.get("evidence_platform") or "").lower()
    if platform in {"android", "ios"}:
        return True
    fmt = (ds.get("format") or "").lower()
    base = (ds.get("base_name") or "").lower()
    if fmt in {"zip", "pas", "ufd"} or infer_mobile_platform_from_names([base]):
        return True
    return False


def _subject_display_name(intake: dict[str, Any]) -> str:
    from app.services.report_template import _subject_name

    return _subject_name(intake)


def _mobile_device_label(intake: dict[str, Any], job: dict[str, Any] | None, db=None, job_id: str | None = None) -> str:
    if db is not None and job_id:
        facts = collect_mobile_device_facts(db, job_id, intake)
        manufacturer = str(facts.get("manufacturer") or "").strip()
        model = str(facts.get("model") or "").strip()
        if manufacturer and manufacturer != "—" and model and model != "—":
            return f"{manufacturer.title()} {model}"
        if model and model != "—":
            return model
    ds = _json_field((job or {}).get("disk_source"), {}) or {}
    hints = _infer_device_from_names([str(ds.get("base_name") or "")])
    manufacturer = hints.get("manufacturer") or ""
    model = hints.get("model") or ""
    if manufacturer and model:
        return f"{manufacturer.title()} {model}"
    if model:
        return model
    return str(ds.get("base_name") or "Mobile Device")


def mobile_cover_structured(
    intake: dict[str, Any],
    job: dict[str, Any] | None,
    db=None,
    job_id: str | None = None,
) -> dict[str, Any]:
    subject = _subject_display_name(intake)
    device = _mobile_device_label(intake, job, db, job_id)
    return {
        "title": "MOBILE FORENSIC ANALYSIS REPORT",
        "subject": f"{subject}, {device}",
        "company": "AETHERIS TECHNOLOGIES PVT. LTD.",
        "report_variant": "mobile",
        "device_label": device,
    }


def gather_mobile_cover_page_markdown(
    intake: dict[str, Any],
    job: dict[str, Any] | None = None,
    *,
    db=None,
    job_id: str | None = None,
) -> str:
    meta = mobile_cover_structured(intake, job, db, job_id)
    return "\n".join([
        "# MOBILE FORENSIC ANALYSIS REPORT",
        "",
        f'**"{meta["subject"]}"**',
        "",
        meta["company"],
    ])


def _json_field(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def _format_bytes(n: int | None) -> str:
    if not n:
        return "—"
    if n >= 1024 ** 3:
        return f"{n / (1024 ** 3):.2f} GB"
    if n >= 1024 ** 2:
        return f"{n / (1024 ** 2):.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.2f} KB"
    return f"{n:,} B"


def _format_count(n: int) -> str:
    return f"{n:,}"


def _parse_build_prop_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if key:
            out[key] = val
    return out


def _infer_device_from_names(names: list[str]) -> dict[str, str]:
    hints: dict[str, str] = {}
    blob = " ".join(names).lower()
    for token, manufacturer in (
        ("vivo", "vivo"),
        ("samsung", "Samsung"),
        ("oppo", "OPPO"),
        ("xiaomi", "Xiaomi"),
        ("oneplus", "OnePlus"),
        ("pixel", "Google"),
        ("iphone", "Apple"),
        ("ipad", "Apple"),
    ):
        if token in blob:
            hints.setdefault("manufacturer", manufacturer)
            break
    for name in names:
        m = re.search(r"(?i)(vivo[_\s-]?([a-z]?\d{4,5})|sm-[a-z0-9]+|pixel\s?\d+)", name.replace("\\", "/"))
        if m:
            model = (m.group(2) or m.group(0)).upper().replace("_", "")
            hints.setdefault("model", model)
            break
        stem = Path(name).stem
        parts = re.split(r"[_\s-]+", stem)
        for part in parts:
            if re.fullmatch(r"[vV]?\d{4,5}", part):
                hints.setdefault("model", part.upper() if part[0].isdigit() else part)
                break
    return hints


def _load_build_prop_facts(db, job_id: str) -> dict[str, str]:
    rows = fetchall(
        db,
        """SELECT file_path, content FROM rag_chunks
           WHERE job_id=:jid AND (
             file_path ILIKE '%build.prop%'
             OR file_path ILIKE '%/system/build.prop%'
             OR file_path ILIKE '%default.prop%'
           )
           ORDER BY length(content) DESC
           LIMIT 10""",
        {"jid": job_id},
    )
    merged: dict[str, str] = {}
    for row in rows:
        merged.update(_parse_build_prop_text(str(row.get("content") or "")))
    return merged


def _artifact_category_counts(db, job_id: str) -> dict[str, int]:
    rows = fetchall(
        db,
        """SELECT lower(file_path) AS path, lower(file_name) AS name
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    counts = {
        "total_files": len(rows),
        "images": 0,
        "audio": 0,
        "video": 0,
        "documents": 0,
        "databases": 0,
        "whatsapp_media": 0,
        "whatsapp_messages": 0,
        "whatsapp_chats": 0,
        "sms": 0,
        "emails": 0,
        "contacts": 0,
        "trashed": 0,
    }
    for row in rows:
        path = str(row.get("path") or row.get("name") or "")
        ext = Path(path).suffix.lower()
        if ext in _IMAGE_EXT:
            counts["images"] += 1
        if ext in _AUDIO_EXT:
            counts["audio"] += 1
        if ext in _VIDEO_EXT:
            counts["video"] += 1
        if ext in _DOC_EXT:
            counts["documents"] += 1
        if ext in _DB_EXT:
            counts["databases"] += 1
        if "whatsapp" in path:
            counts["whatsapp_media"] += 1
        if ".trashed-" in path or "/trash/" in path:
            counts["trashed"] += 1

    # Prefer AXIOM-style mobile forensic inventory (SQLite row counts) over path heuristics.
    try:
        from app.services.mobile_forensic.inventory import build_mobile_inventory_snapshot

        snap = build_mobile_inventory_snapshot(db, job_id)
        mc = snap.get("counts") or {}
        counts["whatsapp_messages"] = int(mc.get("whatsapp_messages") or 0)
        counts["whatsapp_chats"] = int(mc.get("whatsapp_chats") or 0)
        counts["whatsapp_media"] = max(int(mc.get("whatsapp_media") or 0), counts["whatsapp_media"])
        counts["sms"] = int(mc.get("sms") or 0)
        counts["emails"] = int(mc.get("emails") or 0)
        counts["contacts"] = int(mc.get("contacts") or 0)
        counts["images"] = max(int(mc.get("pictures") or 0), counts["images"])
        counts["video"] = max(int(mc.get("videos") or 0), counts["video"])
        counts["audio"] = max(int(mc.get("audio") or 0), counts["audio"])
        counts["documents"] = max(int(mc.get("documents") or 0), counts["documents"])
    except Exception as exc:
        log.debug("mobile inventory enrich failed: %s", exc)
    return counts


def _fetch_evidence_segments(db, job_id: str) -> list[dict[str, Any]]:
    """Evidence file rows for mobile sections (schema-safe — no optional columns)."""
    return fetchall(
        db,
        """SELECT original_name, host_path, sha256, size_bytes, segment_part, mime_type
           FROM evidence_files WHERE job_id=:jid ORDER BY segment_part NULLS LAST, original_name""",
        {"jid": job_id},
    )


_IMEI_RE = re.compile(r"(?i)\bimei(?:[_\s-]*(?:slot|sim|sv))?\s*[:=\"'>\s]\s*(\d{14,17})\b")
_IMEI_LOOSE_RE = re.compile(r"(?<!\d)(\d{15})(?!\d)")


def _is_plausible_imei(val: str) -> bool:
    if not val or len(val) < 14 or len(val) > 17:
        return False
    if not val.isdigit():
        return False
    # Skip obvious non-IMEI runs of zeros / ones
    if len(set(val)) <= 2 and val[0] in "01":
        return False
    return True


def _collect_imeis_from_text(text: str, *, found: list[str], seen: set[str], limit: int = 4) -> None:
    for m in _IMEI_RE.finditer(text or ""):
        val = (m.group(1) or "").strip()
        if not _is_plausible_imei(val) or val in seen:
            continue
        seen.add(val)
        found.append(val)
        if len(found) >= limit:
            return
    # Prefer labeled IMEIs; only fall back to bare 15-digit runs in small identity files.
    if found:
        return
    for m in _IMEI_LOOSE_RE.finditer(text or ""):
        val = (m.group(1) or "").strip()
        if not _is_plausible_imei(val) or val in seen:
            continue
        seen.add(val)
        found.append(val)
        if len(found) >= limit:
            return


def _evidence_host_paths(db, job_id: str) -> list[Path]:
    rows = _fetch_evidence_segments(db, job_id)
    out: list[Path] = []
    for row in rows:
        hp = str(row.get("host_path") or "").strip()
        if not hp:
            continue
        p = Path(hp)
        if p.is_file():
            out.append(p)
    return out


def _load_ufd_acquisition_meta(db, job_id: str) -> dict[str, Any]:
    """Parse Cellebrite .ufd unit descriptors beside the registered evidence."""
    from app.services.mobile_forensic.cellebrite_ufed import parse_ufd_file

    meta: dict[str, Any] = {}
    for path in _evidence_host_paths(db, job_id):
        if path.suffix.lower() != ".ufd":
            continue
        desc = parse_ufd_file(path)
        if not desc:
            continue
        di = desc.device_info or {}
        general = desc.raw_sections.get("General") or {}
        sha_sec = desc.raw_sections.get("SHA256") or {}
        meta = {
            "vendor": di.get("Vendor") or general.get("Vendor"),
            "model": di.get("Model") or general.get("Model"),
            "os": di.get("OS"),
            "chipset": di.get("Chipset"),
            "acquisition_tool": general.get("AcquisitionTool") or "Cellebrite UFED 4PC",
            "ufed_version": general.get("Version") or general.get("InternalBuild"),
            "extraction_type": general.get("ExtractionType") or "File System",
            "connection_type": general.get("ConnectionType"),
            "extraction_start": general.get("Date"),
            "extraction_end": general.get("EndTime"),
            "file_dump": desc.dump_zip_name,
            "sha256_map": dict(sha_sec),
            "ufd_path": str(path),
        }
        # Prefer the most complete descriptor (has Date + SHA256).
        if meta.get("extraction_start") and meta.get("sha256_map"):
            break
    return meta


def _open_dump_zip(db, job_id: str, ufd_meta: dict[str, Any] | None = None) -> Path | None:
    """Locate the filesystem dump ZIP on disk (UFED FileDump or registered .zip)."""
    ufd_meta = ufd_meta or {}
    dump_name = str(ufd_meta.get("file_dump") or "").strip()
    ufd_path = str(ufd_meta.get("ufd_path") or "").strip()
    if dump_name and ufd_path:
        cand = Path(ufd_path).parent / Path(dump_name).name
        if cand.is_file():
            return cand
    for path in _evidence_host_paths(db, job_id):
        if path.suffix.lower() == ".zip" and path.is_file():
            return path
    return None


def _read_zip_text_members(zip_path: Path, *, name_ends: tuple[str, ...], max_files: int = 12, max_bytes: int = 256_000) -> list[tuple[str, str]]:
    """Read small text members from a dump ZIP (build.prop / IMEI prefs / etc.)."""
    import zipfile

    out: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            for end in name_ends:
                end_l = end.lower().replace("\\", "/")
                hits = [n for n in names if n.replace("\\", "/").lower().endswith(end_l)]
                for name in hits[:3]:
                    try:
                        info = zf.getinfo(name)
                        if info.file_size > max_bytes:
                            continue
                        data = zf.read(name)
                    except Exception:
                        continue
                    text = data.decode("utf-8", errors="replace")
                    out.append((name, text))
                    if len(out) >= max_files:
                        return out
    except Exception as exc:
        log.debug("zip identity read failed %s: %s", zip_path, exc)
    return out


def _recover_identity_from_dump(db, job_id: str, ufd_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recover serial / IMEI / OS / capacity / timezone from dump ZIP members."""
    zip_path = _open_dump_zip(db, job_id, ufd_meta)
    out: dict[str, Any] = {"imeis": [], "serial": None, "os_version": None, "timezone": None, "capacity": None, "build_prop": {}}
    if not zip_path:
        return out
    members = _read_zip_text_members(
        zip_path,
        name_ends=(
            "build.prop",
            "default.prop",
            "imei_meid_preferences.xml",
            "imei_notifier.xml",
            "device_info.xml",
            "com.vivo.push_preferences_device_info.xml",
            "device.xml",
            "device_ids.xml",
            "phone_status.xml",
        ),
        max_files=24,
    )
    # Also pull a few small members whose names mention serial/capacity.
    try:
        import zipfile

        with zipfile.ZipFile(zip_path, "r") as zf:
            extra = [
                n
                for n in zf.namelist()
                if any(tok in n.lower() for tok in ("serial", "capacity", "storage", "emmc", "diskinfo"))
                and n.lower().endswith((".xml", ".prop", ".txt", ".json"))
            ][:8]
            for name in extra:
                try:
                    info = zf.getinfo(name)
                    if info.file_size > 256_000:
                        continue
                    text = zf.read(name).decode("utf-8", errors="replace")
                    members.append((name, text))
                except Exception:
                    continue
    except Exception:
        pass
    imeis: list[str] = []
    seen: set[str] = set()
    for name, text in members:
        name_l = name.lower().replace("\\", "/")
        if name_l.endswith("build.prop") or name_l.endswith("default.prop") or "=" in text[:200]:
            props = _parse_build_prop_text(text)
            if props:
                out["build_prop"].update(props)
                out["serial"] = (
                    out["serial"]
                    or props.get("ro.serialno")
                    or props.get("ro.boot.serialno")
                    or props.get("ril.serialnumber")
                    or props.get("gsm.serial")
                    or props.get("ro.ril.oem.psno")
                )
                out["os_version"] = out["os_version"] or props.get("ro.build.version.release")
                out["timezone"] = out["timezone"] or props.get("persist.sys.timezone")
                for key in (
                    "ro.boot.emmc_size",
                    "ro.product.emmc_size",
                    "persist.sys.storage_size",
                    "ro.vendor.emmc_size",
                ):
                    raw = props.get(key)
                    if raw:
                        out["capacity"] = out["capacity"] or _normalize_capacity_value(raw)
        # Serial from XML prefs: <string name="serial">…</string> / serial_number=
        if not out["serial"]:
            m = re.search(
                r"(?i)(?:serial(?:_number|no)?|device_serial)\s*[=\">]\s*([A-Z0-9]{6,})",
                text,
            )
            if m:
                cand = m.group(1).strip().strip("'\"<>/")
                if cand and not cand.isdigit():
                    out["serial"] = cand
        # Capacity strings like 128GB / 128 GB
        if not out["capacity"]:
            m = re.search(r"(?i)\b(32|64|128|256|512)\s*GB\b", text)
            if m:
                out["capacity"] = f"{m.group(1)}GB"
        if "imei" in name_l or "device_info" in name_l or "phone" in name_l:
            _collect_imeis_from_text(text, found=imeis, seen=seen, limit=4)
        else:
            _collect_imeis_from_text(text, found=imeis, seen=seen, limit=4)
    out["imeis"] = imeis
    return out


def _normalize_capacity_value(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if re.fullmatch(r"\d+\s*[GT]B", s, flags=re.I):
        return s.upper().replace(" ", "")
    # Bytes
    if s.isdigit():
        n = int(s)
        # Some props store size in MB
        if n < 10_000:
            gb = n / 1024.0 if n > 256 else float(n)
        else:
            gb = n / (1024 ** 3)
        for mark in (32, 64, 128, 256, 512, 1024):
            if gb <= mark * 1.15:
                return f"{mark}GB" if mark < 1024 else "1TB"
    return None


def _recover_imei_values(db, job_id: str, *, dump_imeis: list[str] | None = None) -> list[str]:
    """Best-effort IMEI recovery from dump files + indexed text."""
    found: list[str] = []
    seen: set[str] = set()
    for val in dump_imeis or []:
        if _is_plausible_imei(val) and val not in seen:
            seen.add(val)
            found.append(val)
    if len(found) >= 2:
        return found[:4]
    rows = fetchall(
        db,
        """SELECT content FROM rag_chunks
           WHERE job_id=:jid AND (
             content ILIKE '%imei%'
             OR file_path ILIKE '%imei%'
             OR file_path ILIKE '%telephony%'
             OR file_path ILIKE '%device_info%'
             OR file_path ILIKE '%build.prop%'
           )
           ORDER BY length(content) DESC
           LIMIT 40""",
        {"jid": job_id},
    )
    for row in rows:
        _collect_imeis_from_text(str(row.get("content") or ""), found=found, seen=seen, limit=4)
        if len(found) >= 4:
            break
    return found[:4]


def _format_capacity(explicit: str | None = None) -> str:
    """Device marketing capacity — never derive from dump ZIP byte size."""
    if explicit and str(explicit).strip() and str(explicit).strip() != "—":
        return str(explicit).strip()
    return "—"


def _parse_ufd_datetime(value: Any) -> Any:
    """Parse UFED General Date/EndTime like '23/01/2026 15:12:00 (+5:30)'."""
    if value is None or value == "" or value == "—":
        return None
    if not isinstance(value, str):
        return value
    raw = value.strip()
    m = re.match(
        r"^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(?:\(([^)]+)\))?$",
        raw,
    )
    if not m:
        return raw
    day, month, year, hh, mm, ss, tz = m.groups()
    try:
        dt = datetime(int(year), int(month), int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return raw
    # Keep wall-clock as reported; display formatter applies IST label for sample parity.
    if tz and "5:30" in tz:
        try:
            from zoneinfo import ZoneInfo

            return dt.replace(tzinfo=None).replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        except Exception:
            return dt
    return dt


def collect_mobile_device_facts(db, job_id: str, intake: dict[str, Any] | None = None) -> dict[str, Any]:
    intake = intake or {}
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = _json_field(job.get("disk_source"), {}) or {}
    evidence = _fetch_evidence_segments(db, job_id)
    names = [str(r.get("original_name") or "") for r in evidence if r.get("original_name")]
    ufd_meta = _load_ufd_acquisition_meta(db, job_id)
    dump_id = _recover_identity_from_dump(db, job_id, ufd_meta)
    build_prop = dict(dump_id.get("build_prop") or {})
    build_prop.update(_load_build_prop_facts(db, job_id))
    name_hints = _infer_device_from_names(names)

    platform = infer_mobile_platform_from_names(names) or "Android"
    manufacturer = (
        build_prop.get("ro.product.manufacturer")
        or build_prop.get("ro.product.brand")
        or ufd_meta.get("vendor")
        or name_hints.get("manufacturer")
        or "—"
    )
    model = (
        build_prop.get("ro.product.model")
        or ufd_meta.get("model")
        or name_hints.get("model")
        or ds.get("base_name")
        or "—"
    )
    os_version = (
        build_prop.get("ro.build.version.release")
        or dump_id.get("os_version")
        or ufd_meta.get("os")
        or "—"
    )
    build_id = build_prop.get("ro.build.id") or build_prop.get("ro.build.display.id") or "—"
    serial = (
        dump_id.get("serial")
        or build_prop.get("ro.serialno")
        or build_prop.get("ro.boot.serialno")
        or "—"
    )
    # Time zone: prefer device property; default UTC when unknown (report sample rule).
    timezone_id = dump_id.get("timezone") or build_prop.get("persist.sys.timezone") or "UTC"
    if not timezone_id or str(timezone_id).strip() in {"", "—", "None"}:
        timezone_id = "UTC"
    device_name = build_prop.get("ro.product.name") or model or ds.get("base_name") or "—"

    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}
    exhibit = vol18.get("exhibit") if isinstance(vol18.get("exhibit"), dict) else {}
    if exhibit.get("serial"):
        serial = exhibit.get("serial") or serial
    if exhibit.get("model"):
        model = exhibit.get("model") or model

    imeis = _recover_imei_values(db, job_id, dump_imeis=list(dump_id.get("imeis") or []))
    if exhibit.get("imei"):
        imeis = [str(exhibit["imei"])] + [x for x in imeis if x != str(exhibit["imei"])]
    imei_display = ", ".join(imeis) if imeis else "—"

    capacity = _format_capacity(
        explicit=(
            exhibit.get("capacity")
            or ds.get("capacity")
            or ds.get("storage_capacity")
            or dump_id.get("capacity")
        )
    )

    os_label = platform
    if os_version and os_version != "—":
        # Correct spelling "Android" (sample PDF historically used "Andriod").
        os_label = f"{platform} {os_version}".replace("Android Android", "Android")

    return {
        "manufacturer": manufacturer,
        "make": str(manufacturer).title() if manufacturer and manufacturer != "—" else "—",
        "model": model,
        "platform": platform,
        "os_version": os_version,
        "os_label": os_label,
        "build_id": build_id,
        "serial": serial or "—",
        "imei": imei_display,
        "capacity": capacity,
        "timezone": timezone_id,
        "device_name": device_name,
        "extraction_format": (ds.get("format") or "zip").upper(),
        "base_name": ds.get("base_name") or (names[0] if names else "—"),
        "examiner": intake.get("examiner_name") or "—",
        "organization": intake.get("organization") or "—",
        "evidence_segments": evidence,
        "exhibit_model": exhibit.get("model"),
        "exhibit_serial": exhibit.get("serial"),
        "ufd_meta": ufd_meta,
    }


def _format_report_dt(value: Any) -> str:
    """Format datetime like the sample: 23/01/2026 3:12:00 PM(UTC+5:30)."""
    if value is None or value == "" or value == "—":
        return "—"
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return "—"
        try:
            # Support ISO strings
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            value = datetime.fromisoformat(raw)
        except ValueError:
            return value
    if not isinstance(value, datetime):
        return str(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    # Display in IST to match Aetheris sample reports
    try:
        from zoneinfo import ZoneInfo

        local = value.astimezone(ZoneInfo("Asia/Kolkata"))
        tz_label = "(UTC+5:30)"
    except Exception:
        local = value
        tz_label = ""
    # %-I is POSIX-only; use %#I on Windows-friendly path via lstrip
    hour = local.strftime("%I").lstrip("0") or "0"
    return f"{local.strftime('%d/%m/%Y')} {hour}:{local.strftime('%M:%S')} {local.strftime('%p')}{tz_label}"


def collect_mobile_extraction_facts(db, job_id: str, intake: dict[str, Any] | None = None) -> dict[str, Any]:
    intake = intake or {}
    job = fetchone(
        db,
        "SELECT disk_source, created_at, updated_at, status FROM jobs WHERE id=:id",
        {"id": job_id},
    ) or {}
    ds = _json_field(job.get("disk_source"), {}) or {}
    evidence = _fetch_evidence_segments(db, job_id)
    counts = _artifact_category_counts(db, job_id)
    bytes_total = sum(int(r.get("size_bytes") or 0) for r in evidence)
    if not bytes_total and ds.get("bytes_extracted"):
        bytes_total = int(ds["bytes_extracted"])

    device_facts = collect_mobile_device_facts(db, job_id, intake)
    ufd_meta = device_facts.get("ufd_meta") or _load_ufd_acquisition_meta(db, job_id)
    platform = str(device_facts.get("platform") or "Android")
    raw_type = str(
        ufd_meta.get("extraction_type") or ds.get("extraction_type") or "File System"
    ).strip()
    # Normalize UFED "FileSystem" → sample wording "File System (Android ADB)"
    if re.search(r"(?i)file\s*system", raw_type) and "ADB" not in raw_type.upper():
        extraction_type = f"File System ({platform} ADB)"
    else:
        extraction_type = raw_type or f"File System ({platform} ADB)"

    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}
    tools = vol18.get("tools") or vol18.get("tools_used")
    ufed_version = (
        ufd_meta.get("ufed_version")
        or ds.get("ufed_version")
        or ds.get("tool_version")
        or "—"
    )
    if ufed_version == "—" and isinstance(tools, list) and tools:
        first = tools[0]
        ufed_version = str(first.get("name") if isinstance(first, dict) else first)
    if ufed_version == "—":
        ufed_version = "Cellebrite UFED 4PC"

    start_dt = (
        _parse_ufd_datetime(ufd_meta.get("extraction_start"))
        or ds.get("extraction_start")
        or ds.get("extraction_started_at")
        or intake.get("evidence_received_date")
        or job.get("created_at")
    )
    end_dt = (
        _parse_ufd_datetime(ufd_meta.get("extraction_end"))
        or ds.get("extraction_end")
        or ds.get("extraction_ended_at")
        or job.get("updated_at")
        or job.get("created_at")
    )

    # Prefer acquisition SHA256 from .ufd [SHA256] for the dump ZIP (matches UFED report).
    primary_hash = "—"
    sha_map = ufd_meta.get("sha256_map") or {}
    dump_name = str(ufd_meta.get("file_dump") or "")
    if dump_name and dump_name in sha_map:
        primary_hash = str(sha_map[dump_name]).upper()
    elif sha_map:
        primary_hash = str(next(iter(sha_map.values()))).upper()
    if primary_hash == "—":
        for seg in evidence:
            name = str(seg.get("original_name") or "").lower()
            if name.endswith(".zip"):
                sha = str(seg.get("sha256") or "").strip()
                if sha:
                    primary_hash = sha.upper()
                    break
    if primary_hash == "—" and ds.get("sha256"):
        primary_hash = str(ds["sha256"]).upper()

    tz = device_facts.get("timezone") or ds.get("timezone") or "UTC"
    if not tz or str(tz).strip() in {"", "—", "None"}:
        tz = "UTC"

    return {
        "extraction_type": extraction_type,
        "connection_type": ufd_meta.get("connection_type") or ds.get("connection_type") or "Cable",
        "files_extracted": int(ds.get("files_extracted") or ds.get("files_total") or counts["total_files"]),
        "bytes_total": bytes_total,
        "counts": counts,
        "evidence_segments": evidence,
        "seizure_date": intake.get("seizure_date"),
        "evidence_received_date": intake.get("evidence_received_date"),
        "integrity_status": "Intact" if evidence else "—",
        "tool_name": ufed_version,
        "ufed_version": ufed_version,
        "selected_manufacturer": (
            str(
                ufd_meta.get("vendor")
                or device_facts.get("make")
                or device_facts.get("manufacturer")
                or "—"
            ).upper()
        ),
        "selected_device_name": ufd_meta.get("model")
        or device_facts.get("model")
        or device_facts.get("device_name")
        or "—",
        "timezone": tz,
        "extraction_start": _format_report_dt(start_dt),
        "extraction_end": _format_report_dt(end_dt),
        "hash_sha256": primary_hash,
    }


def _facts_table_device(facts: dict[str, Any]) -> str:
    """Device Information block matching the Sujit / Vivo mobile sample PDF."""
    rows = [
        ("Make", facts.get("make") or facts.get("manufacturer")),
        ("Model", facts.get("model")),
        ("Serial Number", facts.get("serial")),
        ("IMEI", facts.get("imei")),
        ("Operating System", facts.get("os_label") or facts.get("os_version")),
        ("Capacity", facts.get("capacity")),
    ]
    lines = [
        "## DEVICE INFORMATION",
        "",
        "Device Information of Mobile Phone",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for field, val in rows:
        lines.append(f"| {field} | {val or '—'} |")
    return "\n".join(lines)


def _facts_table_extraction(facts: dict[str, Any]) -> str:
    """Extraction Summary block matching the Sujit / Vivo mobile sample PDF."""
    lines = [
        "## EXTRACTION SUMMARY",
        "",
        "Extraction Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Extraction start date/time | {facts.get('extraction_start') or '—'} |",
        f"| Extraction end date/time | {facts.get('extraction_end') or '—'} |",
        f"| UFED version | {facts.get('ufed_version') or facts.get('tool_name') or '—'} |",
        f"| Selected manufacturer | {facts.get('selected_manufacturer') or '—'} |",
        f"| Selected device name | {facts.get('selected_device_name') or '—'} |",
        f"| Extraction type | {facts.get('extraction_type') or '—'} |",
        f"| Time zone settings (ID) | {facts.get('timezone') or 'UTC'} |",
        f"| Hash Value (SHA256) | {facts.get('hash_sha256') or '—'} |",
    ]
    return "\n".join(lines)


def gather_mobile_annexure_markdown(db, job_id: str, intake: dict[str, Any] | None = None) -> str:
    """Annexure note matching the sample (Annexure.zip + hash table)."""
    intake = intake or {}
    evidence = _fetch_evidence_segments(db, job_id)
    subject = _subject_display_name(intake)
    device = _mobile_device_label(intake, None, db, job_id)
    # Prefer a package named *Annexure*.zip; else primary evidence archive.
    annex_row = None
    for seg in evidence:
        name = str(seg.get("original_name") or "")
        if re.search(r"annexure", name, re.I) and name.lower().endswith(".zip"):
            annex_row = seg
            break
    if annex_row is None:
        for seg in evidence:
            name = str(seg.get("original_name") or "").lower()
            if name.endswith((".zip", ".pas", ".ufd", ".tar", ".tgz")):
                annex_row = seg
                break
    if annex_row is None and evidence:
        annex_row = evidence[0]

    file_name = (
        str(annex_row.get("original_name"))
        if annex_row
        else f"{subject} {device} Annexure.zip".replace("  ", " ").strip()
    )
    # Sample uses SHA1 column; we store SHA-256 — label accurately.
    sha = str((annex_row or {}).get("sha256") or "—").upper()
    hash_label = "HASH VALUE (SHA256)"

    return "\n".join([
        "## Annexure",
        "",
        'Note: The annexure “Annexure.zip” is a part of report and Details are as given below:',
        "",
        f"| Sr. No. | File Name | {hash_label} |",
        "| ---: | --- | --- |",
        f"| 1 | {file_name} | {sha} |",
    ])


def _prompt_with_rag(
    db,
    job_id: str,
    *,
    prompt: str,
    schema_name: str | None,
    primary_model: str | None,
    fallback: str,
) -> str:
    settings = get_settings()
    chunks = hybrid_retrieve(
        db,
        job_id,
        prompt,
        top_k=12,
        schema_name=schema_name,
        skip_vector=True,
    )
    context = "\n\n---\n\n".join(
        f"[{c.get('file_path', 'evidence')}] {(c.get('content') or '')[:2000]}"
        for c in chunks[:10]
    )
    if not context.strip():
        return fallback

    system = (
        "You are a mobile forensic report writer. Answer using ONLY the evidence excerpts. "
        "Use markdown tables. Mark unknown values as —. Do not invent hashes or counts."
    )
    user = f"Evidence:\n{context}\n\nTask:\n{prompt}\n\nStructured facts (use as baseline):\n{fallback[:4000]}"
    try:
        answer = generate_text(
            user,
            model=primary_model or settings.llm_primary_model,
            system=system,
            temperature=0.2,
        )
        body = (answer or "").strip()
        if body and len(body) > 80:
            return body
    except Exception as exc:
        log.warning("mobile report LLM failed: %s", exc)
    return fallback


def build_device_information_markdown(
    db,
    job_id: str,
    intake: dict[str, Any] | None = None,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    use_llm: bool = True,
) -> str:
    facts = collect_mobile_device_facts(db, job_id, intake)
    fallback = _facts_table_device(facts)
    if not use_llm:
        return fallback
    return _prompt_with_rag(
        db,
        job_id,
        prompt=DEVICE_INFORMATION_PROMPT,
        schema_name=schema_name,
        primary_model=primary_model,
        fallback=fallback,
    )


def build_extraction_summary_markdown(
    db,
    job_id: str,
    intake: dict[str, Any] | None = None,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    use_llm: bool = True,
) -> str:
    facts = collect_mobile_extraction_facts(db, job_id, intake)
    fallback = _facts_table_extraction(facts)
    if not use_llm:
        return fallback
    return _prompt_with_rag(
        db,
        job_id,
        prompt=EXTRACTION_SUMMARY_PROMPT,
        schema_name=schema_name,
        primary_model=primary_model,
        fallback=fallback,
    )


def gather_mobile_introduction_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    from app.services.report_template import _client_address_lines, _report_date, AETHERIS_COMPANY

    org = (intake.get("organization") or "Client Organization").strip()
    examiner = (intake.get("examiner_name") or "Digital Forensic Analyst").strip()
    date_str = _report_date(intake)
    subject = _subject_display_name(intake)
    address_lines = _client_address_lines(intake)
    if not address_lines and org:
        address_lines = [org + ","]

    background = (intake.get("background") or intake.get("incident_summary") or "").strip()
    if not background:
        background = (
            f"As per the consent letter and case brief given by you, the provided mobile belongs to "
            f"{subject} have provided it to us for forensic acquisition and analysis."
        )

    body = (
        "With subject to above subject, I have received request from you to conduct mobile forensic "
        "analysis against your Consent letter. I have completed your case as per our standard "
        f"procedures, our analysis has been reported on {date_str}."
    )

    return "\n".join([
        "## INTRODUCTION",
        "",
        f"**Date:** {date_str}",
        "",
        "**To,**",
        *address_lines,
        "",
        "**Subject:** Submission of mobile forensic extraction and analysis report.",
        "",
        "Dear Sir/Madam,",
        "",
        body,
        "",
        "**Background:**",
        background,
        "",
        "**Scope of Work:**",
        "1. Conduct forensic acquisition of devices (One Mobile Phone) identified by the client.",
        "2. Conduct the analysis of data found in the device after forensic acquisition.",
        "",
        "**Terms and Condition:**",
        "1. This report is only for the court of law purpose.",
        "2. All data taken from devices for the purpose of analysis will be destroyed immediate after the report submission.",
        "",
        f"**{examiner or 'Digital Forensic Analyst'}**",
        "",
        f"**{AETHERIS_COMPANY}**",
    ])


def gather_mobile_tools_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}
    tools = vol18.get("tools") or vol18.get("tools_used")
    if isinstance(tools, list) and tools:
        tool_names = [str(t.get("name") if isinstance(t, dict) else t) for t in tools]
    else:
        # Default matches Aetheris mobile sample report (UFED acquisition tool).
        tool_names = ["Cellebrite UFED 4PC 7.71.0.1881"]
    subject = _subject_display_name(intake)
    device = _mobile_device_label(intake, job)
    lines = [
        f"## FORENSIC ANALYSIS ON",
        "",
        f'**"{subject}, {device}"**',
        "",
        "**MOBILE DEVICE**",
        "",
        "## TOOLS USED FOR ACQUISITION AND ANALYSIS",
        "",
        "| Sr No | Tool Name |",
        "| ---: | --- |",
    ]
    for i, name in enumerate(tool_names, 1):
        lines.append(f"| {i} | {name} |")
    return "\n".join(lines)


def gather_mobile_table_of_contents_markdown() -> str:
    from app.services.report_renderer import MOBILE_SECTION_ORDER, section_title
    entries = [(key,section_title(key,mobile=True),index+1) for index,key in enumerate(MOBILE_SECTION_ORDER)
               if key not in {'cover_page','table_of_contents'}]
    lines = ["## TABLE OF CONTENTS", "", "| Sr No | Description | Page |", "| --- | --- | ---: |"]
    for idx, (_, label, page) in enumerate(entries, 1):
        lines.append(f"| {idx} | {label} | {page} |")
    return "\n".join(lines)
