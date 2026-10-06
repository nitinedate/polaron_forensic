"""Job inventory stats + USB/browser/email evidence summaries for Q&A."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("forensic_inventory")

from app.services.critical_forensic_paths import FORENSIC_PARSE_PATH_SQL as _PRIORITY_PATH_SQL


def collect_job_inventory(db, job_id: str) -> dict[str, Any]:
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    total = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:j", {"j": job_id})
    by_status = fetchall(
        db,
        """SELECT coalesce(parse_status,'unknown') AS st, count(*) c
           FROM job_artifacts WHERE job_id=:j GROUP BY 1 ORDER BY c DESC""",
        {"j": job_id},
    )
    chunks = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:j", {"j": job_id})
    cats = fetchall(
        db,
        """SELECT coalesce(encyclopedia_artifact_id,'(unmatched)') AS cat, count(*) c
           FROM job_artifacts WHERE job_id=:j
           GROUP BY 1 ORDER BY c DESC LIMIT 25""",
        {"j": job_id},
    )
    # Always include high-value forensic categories even if outside the top-N by volume.
    forensic = fetchall(
        db,
        """SELECT encyclopedia_artifact_id AS cat, count(*) c
           FROM job_artifacts WHERE job_id=:j
             AND encyclopedia_artifact_id ~ '^(BRW-|EML-|CHAT-|WRG-HIVE-|WRG-EVT-|WRG-USB-|WRX-|WFS-SHL-|WFS-RB-)'
           GROUP BY 1 ORDER BY c DESC LIMIT 30""",
        {"j": job_id},
    )
    interesting = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND {_PRIORITY_PATH_SQL}""",
        {"j": job_id},
    )
    merged: dict[str, int] = {}
    for r in list(cats) + list(forensic):
        merged[r["cat"]] = int(r["c"])
    top_categories = []
    for cid, count in merged.items():
        top_categories.append({
            "id": cid,
            "name": labels.get(cid, cid if cid != "(unmatched)" else "Unmatched"),
            "count": count,
        })
    top_categories.sort(key=lambda x: -x["count"])
    return {
        "artifacts_total": int(total["c"]) if total else 0,
        "chunks_total": int(chunks["c"]) if chunks else 0,
        "by_parse_status": {r["st"]: int(r["c"]) for r in by_status},
        "top_categories": top_categories,
        "priority_forensic_files": int(interesting["c"]) if interesting else 0,
    }


def _iter_normalized_records(db, job_id: str, *, where_sql: str, params: dict | None = None, limit: int = 40):
    """Yield (file_path, record_dict) from artifact_parse_results."""
    p = {"jid": job_id, **(params or {})}
    rows = fetchall(
        db,
        f"""SELECT ja.file_path, apr.normalized
            FROM job_artifacts ja
            JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
            WHERE ja.job_id=:jid AND ({where_sql})
            ORDER BY apr.created_at DESC LIMIT {int(limit)}""",
        p,
    )
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if isinstance(rec, dict):
                yield row.get("file_path"), rec


def collect_usb_devices(db, job_id: str) -> list[dict[str, Any]]:
    """Axiom-style USB Devices: Enum\\USB+USBSTOR registry instances (+ SetupAPI IDs)."""
    from app.services.axiom_aligned_counts import count_usb_device_records

    _count, devices = count_usb_device_records(db, job_id)
    if devices:
        return devices

    from app.parsers.registry import parse_registry_hive
    from app.services.artifact_live_counts import _read_job_files

    devices: list[dict[str, Any]] = []
    seen: set[str] = set()

    hive_rows = fetchall(
        db,
        """SELECT file_path, size_bytes FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 4096
             AND (file_path ILIKE '%/SYSTEM' OR lower(file_name) = 'system')
           ORDER BY size_bytes DESC LIMIT 12""",
        {"j": job_id},
    )
    if hive_rows:
        contents = _read_job_files(db, job_id, hive_rows)
        for row in hive_rows:
            path = row.get("file_path") or ""
            data = contents.get(path.replace("\\", "/"))
            if not data:
                continue
            try:
                records = parse_registry_hive(data, path)
            except Exception:
                continue
            for rec in records:
                if rec.get("record_type") != "usb_device":
                    continue
                name = rec.get("device_name") or rec.get("class_id")
                if not name:
                    continue
                key = (
                    f"{rec.get('source')}|{rec.get('bus')}|{rec.get('class_id')}|"
                    f"{rec.get('serial')}|{name}"
                ).lower()
                if key in seen:
                    continue
                seen.add(key)
                devices.append({
                    "device_name": name,
                    "vendor": rec.get("vendor"),
                    "product": rec.get("product"),
                    "serial": rec.get("serial"),
                    "bus": rec.get("bus") or "USBSTOR",
                    "class_id": rec.get("class_id"),
                    "last_write": rec.get("last_write"),
                    "source": rec.get("source") or path,
                })

    if not devices:
        for path, rec in _iter_normalized_records(
            db,
            job_id,
            where_sql=(
                "ja.file_path ILIKE '%/SYSTEM' OR ja.file_path ILIKE '%setupapi.dev%' "
                "OR apr.normalized::text ILIKE '%usb_device%' OR apr.normalized::text ILIKE '%USBSTOR%'"
            ),
            limit=500,
        ):
            if rec.get("record_type") != "usb_device":
                continue
            name = rec.get("device_name") or rec.get("class_id")
            if not name:
                continue
            key = (
                f"{rec.get('source')}|{rec.get('bus')}|{rec.get('class_id')}|"
                f"{rec.get('serial')}|{name}"
            ).lower()
            if key in seen:
                continue
            seen.add(key)
            devices.append({
                "device_name": name,
                "vendor": rec.get("vendor"),
                "product": rec.get("product"),
                "serial": rec.get("serial"),
                "bus": rec.get("bus") or "USBSTOR",
                "class_id": rec.get("class_id"),
                "last_write": rec.get("last_write"),
                "source": rec.get("source") or path,
            })

    # Augment with unique SetupAPI USB device IDs not already covered (Axiom often merges these).
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql="apr.normalized::text ILIKE '%usb_usage_event%' OR ja.file_path ILIKE '%setupapi.dev%'",
        limit=40,
    ):
        if rec.get("record_type") != "usb_usage_event":
            continue
        did = str(rec.get("device_id") or "")
        if not did or not re.search(r"USB|VID_|USBSTOR|WPDBUSENUM", did, re.I):
            continue
        # Normalize to VID/PID or USBSTOR product key
        m = re.search(
            r"(USBSTOR\\[^\\]+\\[^\\]+|USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\\]*)",
            did,
            re.I,
        )
        class_id = m.group(1) if m else did[:120]
        key = f"setupapi|{class_id}".lower()
        if any(class_id.lower() in (d.get("class_id") or "").lower() or class_id.lower() in (d.get("device_name") or "").lower() for d in devices):
            continue
        if key in seen:
            continue
        seen.add(key)
        devices.append({
            "device_name": class_id,
            "vendor": None,
            "product": None,
            "serial": rec.get("serial"),
            "bus": "SetupAPI",
            "class_id": class_id,
            "last_write": rec.get("event_time"),
            "source": rec.get("source") or path,
        })

    devices.sort(key=lambda d: (0 if d.get("bus") == "USBSTOR" else 1, str(d.get("device_name") or "")))
    return devices


def collect_usb_usage_events(db, job_id: str, *, limit: int = 100) -> dict[str, Any]:
    """Collect USB connect/usage events (frequency), distinct from unique device inventory."""
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    devices = collect_usb_devices(db, job_id)
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql=(
            "apr.normalized::text ILIKE '%usb_usage_event%' "
            "OR ja.file_path ILIKE '%setupapi.dev%' OR ja.file_path ILIKE '%/SYSTEM'"
        ),
        limit=40,
    ):
        if rec.get("record_type") != "usb_usage_event":
            continue
        key = f"{rec.get('event_time')}|{rec.get('device_id')}|{rec.get('serial')}"
        if key in seen:
            continue
        seen.add(key)
        events.append({
            "event_time": rec.get("event_time"),
            "device_id": rec.get("device_id") or rec.get("device_name"),
            "serial": rec.get("serial"),
            "event_kind": rec.get("event_kind"),
            "source": rec.get("source") or path,
            "text": rec.get("text"),
        })
        if len(events) >= limit:
            break

    events.sort(key=lambda ev: str(ev.get("event_time") or ""))
    return {
        "usage_event_count": len(events),
        "unique_device_count": len(devices),
        "events": events,
        "devices": devices,
    }


# Common phone / MTP USB vendor IDs (lowercase hex).
_PHONE_USB_VIDS = frozenset({
    "05ac",  # Apple
    "18d1",  # Google
    "04e8",  # Samsung
    "22b8",  # Motorola
    "0bb4",  # HTC
    "12d1",  # Huawei
    "2717",  # Xiaomi
    "2a45",  # Xiaomi
    "0e8d",  # MediaTek (phones)
    "2a70",  # OnePlus
    "1bbb",  # T-Mobile / Alcatel phones
    "19d2",  # ZTE
    "29a9",  # Vivo
    "22d9",  # Oppo
    "0a9d",  # often phone MTP (PID_FF40 pattern on this image)
    "2b4c",  # Zebra / some handhelds
})

_PHONE_HINT = re.compile(
    r"WPDBUSENUM|\\MTP|Android|iPhone|iPad|Samsung|Xiaomi|Huawei|OnePlus|Pixel|"
    r"Mobile|WPD|Portable.?Device|VID_05AC|VID_18D1|VID_04E8|VID_2717|VID_0A9D|"
    r"PID_FF40|PID_4EE[12]|Apple.?Mobile",
    re.I,
)

# Exclude obvious non-phones even if under USB.
_PHONE_EXCLUDE = re.compile(
    r"USBSTOR|SanDisk|Cruzer|USBPRINT|LaserJet|Printer|VID_03F0|VID_0403|VID_04B4|"
    r"FT232|FTDI|Hub|Keyboard|Mouse|Root.?Hub",
    re.I,
)


def _is_phone_device_id(device_id: str | None) -> bool:
    if not device_id:
        return False
    text = str(device_id)
    if _PHONE_EXCLUDE.search(text) and not _PHONE_HINT.search(text):
        return False
    if _PHONE_HINT.search(text):
        return True
    m = re.search(r"VID_([0-9A-Fa-f]{4})", text, re.I)
    if m and m.group(1).lower() in _PHONE_USB_VIDS:
        return True
    return False


def collect_phone_usage(db, job_id: str, *, limit: int = 100) -> dict[str, Any]:
    """Phone / portable-device usage from SetupAPI USB + WPDBUSENUM events."""
    usb = collect_usb_usage_events(db, job_id, limit=max(limit * 3, 200))
    phone_events = [e for e in (usb.get("events") or []) if _is_phone_device_id(e.get("device_id"))]
    phone_events = phone_events[:limit]

    # Unique phones by serial / VID+PID instance when possible.
    unique: dict[str, dict] = {}
    for ev in phone_events:
        did = str(ev.get("device_id") or "")
        serial = ev.get("serial")
        m = re.search(r"(VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\\]*)(?:\\([^\s]+))?", did, re.I)
        if m:
            key = (m.group(2) or m.group(1)).lower()
            label = m.group(0)
        elif "WPDBUSENUM" in did.upper():
            # Portable volume — group by GUID
            gm = re.search(r"WPDBUSENUM\\\{([^}]+)\}", did, re.I)
            key = f"wpd:{(gm.group(1) if gm else did).lower()}"
            label = f"Windows Portable Device {{{gm.group(1)}}}" if gm else did
        else:
            key = did.lower()
            label = did
        if serial:
            key = str(serial).lower()
        entry = unique.get(key) or {
            "device_name": label,
            "first_seen": ev.get("event_time"),
            "last_seen": ev.get("event_time"),
            "event_count": 0,
            "serial": serial,
        }
        entry["event_count"] = int(entry["event_count"]) + 1
        if ev.get("event_time"):
            if not entry.get("first_seen") or str(ev["event_time"]) < str(entry["first_seen"]):
                entry["first_seen"] = ev["event_time"]
            if not entry.get("last_seen") or str(ev["event_time"]) > str(entry["last_seen"]):
                entry["last_seen"] = ev["event_time"]
        unique[key] = entry

    devices = sorted(unique.values(), key=lambda d: str(d.get("last_seen") or ""), reverse=True)

    # Prefer explicit Your Phone / CrossDevice registry phone_device records when present.
    # Exclude USBSTOR portable volumes mistakenly tagged as phone.
    reg_phones: list[dict[str, Any]] = []
    seen_reg: set[str] = set()
    your_phone_only: list[dict[str, Any]] = []
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql="apr.normalized::text ILIKE '%phone_device%'",
        limit=40,
    ):
        if rec.get("record_type") != "phone_device":
            continue
        name = rec.get("device_name") or ""
        src = (rec.get("source") or path or "").lower()
        if not name or "usbstor" in name.lower():
            continue
        key = "|".join([
            str(rec.get("source") or path or "").lower(),
            str(rec.get("serial") or "").lower(),
            name.lower(),
        ])
        if key in seen_reg:
            continue
        seen_reg.add(key)
        entry = {
            "device_name": name,
            "first_seen": rec.get("last_write"),
            "last_seen": rec.get("last_write"),
            "event_count": 1,
            "serial": rec.get("serial"),
            "source": rec.get("source") or path,
        }
        reg_phones.append(entry)
        if "yourphone" in src or "crossdevice" in src or "taskflow" in src:
            your_phone_only.append(entry)

    # Axiom "Your Phone Device" prefers YourPhone/CrossDevice keys; else phone VID/MTP.
    if your_phone_only:
        devices = your_phone_only
    else:
        # Prefer unique phone VID/PID from SetupAPI over raw WPD volume GUIDs.
        phone_vid_devices = [
            d for d in devices
            if re.search(r"VID_[0-9A-Fa-f]{4}", str(d.get("device_name") or ""), re.I)
        ]
        if phone_vid_devices:
            devices = phone_vid_devices
        elif reg_phones:
            collapsed: dict[str, dict] = {}
            for d in reg_phones:
                name = str(d.get("device_name") or "")
                gm = re.search(r"\{([0-9a-f-]{36})\}", name, re.I)
                key = gm.group(1).lower() if gm else name.lower()
                collapsed[key] = d
            devices = list(collapsed.values())

    return {
        "usage_event_count": len(phone_events),
        "unique_device_count": len(devices),
        "events": phone_events,
        "devices": devices,
        "note": (
            "Your Phone / portable devices from registry (YourPhone/CrossDevice/WPDBUSENUM) "
            "plus SetupAPI USB/MTP connect events."
        ),
    }


def collect_rdp_connections(db, job_id: str) -> dict[str, Any]:
    """Axiom RDP artifacts — Terminal Server Client hosts per user profile."""
    from app.services.axiom_aligned_counts import count_rdp_connection_records

    count, conns = count_rdp_connection_records(db, job_id)
    if count > 0:
        return {
            "count": count,
            "connections": conns,
            "samples": [c.get("host") for c in conns[:12] if c.get("host")],
        }

    conns = []
    seen_keys: set[str] = set()
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql=(
            "apr.normalized::text ILIKE '%rdp_connection%' "
            "OR ja.file_path ILIKE '%NTUSER.DAT'"
        ),
        limit=500,
    ):
        if rec.get("record_type") != "rdp_connection":
            continue
        host = (rec.get("host") or "").strip()
        if not host or "\\AddIns\\" in host or host.lower().startswith("software\\"):
            continue
        user = (rec.get("user") or rec.get("username_hint") or path or "").strip()
        key = f"{user.lower()}|{host.lower()}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        conns.append({
            "host": host,
            "user": rec.get("user"),
            "username_hint": rec.get("username_hint"),
            "source": rec.get("source") or path,
        })
    # Fallback: Terminal Services session event logs
    if not conns:
        rows = fetchall(
            db,
            """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
                 file_path ILIKE '%TerminalServices%RemoteConnectionManager%.evtx'
                 OR file_path ILIKE '%TerminalServices-LocalSessionManager%.evtx'
                 OR file_path ILIKE '%RemoteDesktopServices%.evtx'
               ) LIMIT 20""",
            {"j": job_id},
        )
        for r in rows:
            conns.append({"host": r["file_path"], "user": None, "source": "evtx"})
    return {
        "count": len(conns),
        "connections": conns,
        "samples": [c.get("host") for c in conns[:12]],
    }


def collect_installed_programs(db, job_id: str) -> dict[str, Any]:
    """Uninstall registry programs — Microsoft vs Non-Microsoft."""
    from app.services.artifact_live_counts import scan_registry_inventory

    live = scan_registry_inventory(db, job_id)
    if int(live.get("microsoft_count") or 0) + int(live.get("non_microsoft_count") or 0) > 0:
        return {
            "total": int(live.get("microsoft_count") or 0) + int(live.get("non_microsoft_count") or 0),
            "microsoft_count": int(live.get("microsoft_count") or 0),
            "non_microsoft_count": int(live.get("non_microsoft_count") or 0),
            "microsoft": [],
            "non_microsoft": [],
            "samples_ms": live.get("samples_ms") or [],
            "samples_non_ms": live.get("samples_non_ms") or [],
        }

    programs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql=(
            "apr.normalized::text ILIKE '%installed_program%' "
            "OR ja.file_path ILIKE '%/SOFTWARE'"
        ),
        limit=20,
    ):
        if rec.get("record_type") != "installed_program":
            continue
        name = rec.get("display_name") or ""
        key = "|".join([
            str(rec.get("source") or path or "").lower(),
            str(rec.get("uninstall_key") or "").lower(),
            name.lower(),
        ])
        if not name or key in seen:
            continue
        seen.add(key)
        programs.append({
            "display_name": name,
            "publisher": rec.get("publisher"),
            "version": rec.get("version"),
            "is_microsoft": bool(rec.get("is_microsoft")),
            "source": rec.get("source") or path,
        })
    ms = [p for p in programs if p.get("is_microsoft")]
    non = [p for p in programs if not p.get("is_microsoft")]
    return {
        "total": len(programs),
        "microsoft_count": len(ms),
        "non_microsoft_count": len(non),
        "microsoft": ms,
        "non_microsoft": non,
        "samples_ms": [p["display_name"] for p in ms[:15]],
        "samples_non_ms": [p["display_name"] for p in non[:20]],
    }


def collect_feature_usage_artifacts(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_feature_usage_records

    reg_count = count_feature_usage_records(db, job_id)
    if reg_count > 0:
        return {
            "count": reg_count,
            "registry_entries": reg_count,
            "prefetch_count": 0,
            "jumplist_count": 0,
            "samples": [],
        }

    from app.services.artifact_live_counts import scan_registry_inventory

    live = scan_registry_inventory(db, job_id)
    reg_count = int(live.get("feature_usage") or 0)
    if reg_count > 0:
        return {
            "count": reg_count,
            "registry_entries": reg_count,
            "prefetch_count": 0,
            "jumplist_count": 0,
            "samples": live.get("samples_ms") or [],
        }

    # Legacy parse-result path (small sample)
    reg_count = 0
    reg_samples: list[str] = []
    for path, rec in _iter_normalized_records(
        db,
        job_id,
        where_sql="apr.normalized::text ILIKE '%feature_usage%'",
        limit=20,
    ):
        if rec.get("record_type") != "feature_usage":
            continue
        reg_count += int(rec.get("entry_count") or 0)
        reg_samples.append(rec.get("key_path") or path)

    if reg_count > 0:
        return {
            "count": reg_count,
            "registry_entries": reg_count,
            "prefetch_count": 0,
            "jumplist_count": 0,
            "samples": reg_samples[:6],
        }

    return {
        "count": 0,
        "registry_entries": 0,
        "prefetch_count": 0,
        "jumplist_count": 0,
        "samples": [],
    }


def collect_defender_logs(db, job_id: str) -> dict[str, Any]:
    """Windows Defender *logs* only — not definition/cache binaries."""
    rows = fetchall(
        db,
        """SELECT file_path, size_bytes, sha256 FROM job_artifacts WHERE job_id=:j AND (
             file_name ILIKE 'MPLog-%'
             OR file_path ILIKE '%Windows Defender%Support%MPLog%'
             OR file_path ILIKE '%Windows Defender%Operational%.evtx'
             OR file_path ILIKE '%Windows Defender%WHC%.evtx'
             OR (
               file_path ILIKE '%Windows Defender%'
               AND lower(coalesce(extension,'')) IN ('.log')
             )
           )
           ORDER BY size_bytes DESC NULLS LAST LIMIT 40""",
        {"j": job_id},
    )
    unique_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in rows:
        digest = str(r.get("sha256") or "").strip().lower()
        key = f"sha256:{digest}" if digest else str(r.get("file_path") or "").replace("\\", "/").lower()
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(dict(r))
    return {
        "count": len(unique_rows),
        "samples": [r["file_path"] for r in unique_rows[:12]],
        "items": unique_rows,
    }


def collect_encyclopedia_category_rollup(db, job_id: str) -> list[dict[str, Any]]:
    """Group job files by encyclopedia category for Axiom/encyclopedia coverage."""
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia
    from app.services.encyclopedia_ingest import get_artifact_catalog

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    # Map artifact_id → category via catalog when available
    id_to_cat: dict[str, str] = {}
    try:
        catalog = get_artifact_catalog(db)
        for sec in catalog.get("sections") or []:
            cat = sec.get("category") or sec.get("name") or "Other"
            for sub in sec.get("subcategories") or []:
                for art in sub.get("artifacts") or []:
                    aid = art.get("artifact_id") or art.get("id")
                    if aid:
                        id_to_cat[aid] = cat
            # some catalogs flatten differently
            for art in sec.get("artifacts") or []:
                aid = art.get("artifact_id") or art.get("id")
                if aid:
                    id_to_cat[aid] = cat
    except Exception:
        pass

    rows = fetchall(
        db,
        """SELECT coalesce(encyclopedia_artifact_id,'unmatched') AS cid, count(*) c
           FROM job_artifacts WHERE job_id=:j GROUP BY 1 ORDER BY c DESC""",
        {"j": job_id},
    )
    by_cat: dict[str, int] = {}
    samples_by_cat: dict[str, list[str]] = {}
    for r in rows:
        cid = r["cid"]
        cat = id_to_cat.get(cid) or _encyclopedia_category_fallback(cid)
        by_cat[cat] = by_cat.get(cat, 0) + int(r["c"])
        if cat not in samples_by_cat:
            samples_by_cat[cat] = [labels.get(cid, cid)]
        elif len(samples_by_cat[cat]) < 8:
            samples_by_cat[cat].append(labels.get(cid, cid))

    out = []
    for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
        out.append({
            "key": re.sub(r"[^a-z0-9]+", "_", cat.lower()).strip("_"),
            "title": cat,
            "count": count,
            "samples": samples_by_cat.get(cat) or [],
            "description": f"Files classified under encyclopedia category '{cat}'.",
        })
    return out


def _encyclopedia_category_fallback(artifact_id: str) -> str:
    aid = artifact_id or ""
    if aid.startswith("BRW-"):
        return "Browser"
    if aid.startswith("EML-"):
        return "Email"
    if aid.startswith("CHAT-"):
        return "Chat"
    if aid.startswith("DOC-"):
        return "Documents"
    if aid.startswith("WRG-USB") or aid == "WRG-USB-0001":
        return "USB / Devices"
    if aid.startswith("WRG-EVT") or aid.startswith("WRG-HIVE") or aid.startswith("WRG-"):
        return "Registry"
    if aid.startswith("WRX-PRE") or aid.startswith("WFS-SHL"):
        return "Execution"
    if aid.startswith("WFS-"):
        return "File System"
    if aid.startswith("USR-"):
        return "User Profile"
    if aid.startswith("SYS-"):
        return "System"
    if aid.startswith("FS-"):
        return "File System"
    if aid == "unmatched":
        return "Unmatched"
    return "Other"


# Natural-language → encyclopedia category (for "X artifacts with counts" questions).
_CATEGORY_QUERY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Note: "operating system artifacts" is handled by Axiom section Operating System
    # (Logfile / Jump List / LNK) — not this encyclopedia System rollup.
    (
        "System",
        re.compile(
            r"\b(system\s+category|windows\s+system\s+files?|sys-\w+\s+artifacts?)\b",
            re.I,
        ),
    ),
    ("Registry", re.compile(r"\b(registry\s+artifacts?|registry\s+hives?|hive\s+artifacts?)\b", re.I)),
    ("Browser", re.compile(r"\b(browser\s+artifacts?|web\s+browser\s+artifacts?)\b", re.I)),
    ("Email", re.compile(r"\b(email\s+artifacts?|mail\s+artifacts?)\b", re.I)),
    ("Documents", re.compile(r"\b(document\s+artifacts?|documents?\s+category)\b", re.I)),
    ("Execution", re.compile(r"\b(execution\s+artifacts?|prefetch\s+artifacts?)\b", re.I)),
    ("File System", re.compile(r"\b(file\s+system\s+artifacts?|ntfs\s+artifacts?)\b", re.I)),
    ("User Profile", re.compile(r"\b(user\s+profile\s+artifacts?|profile\s+artifacts?)\b", re.I)),
    ("USB / Devices", re.compile(r"\b(usb\s+artifacts?|device\s+artifacts?)\b", re.I)),
    ("Chat", re.compile(r"\b(chat\s+artifacts?|messaging\s+artifacts?)\b", re.I)),
]


def detect_encyclopedia_category_query(query: str) -> str | None:
    """Return encyclopedia category when the question asks for that category's artifacts/counts."""
    q = query or ""
    # Must look like an artifact-inventory ask, not "what OS is installed"
    if not re.search(
        r"\b(artifacts?|counts?|how\s+many|list|show|provide|inventory|catalog|available)\b",
        q,
        re.I,
    ):
        return None
    for cat, pat in _CATEGORY_QUERY_PATTERNS:
        if pat.search(q):
            return cat
    return None


def collect_encyclopedia_category_breakdown(
    db,
    job_id: str,
    category: str,
    *,
    limit: int = 40,
) -> dict[str, Any]:
    """Per-encyclopedia-artifact-id counts for one category (e.g. Operating System / System)."""
    from app.services.encyclopedia_match import encyclopedia_label_map, ensure_extended_encyclopedia

    ensure_extended_encyclopedia(db)
    labels = encyclopedia_label_map(db)
    cat_norm = (category or "").strip().lower()

    rows = fetchall(
        db,
        """SELECT coalesce(encyclopedia_artifact_id,'unmatched') AS cid, count(*) c
           FROM job_artifacts WHERE job_id=:j
           GROUP BY 1 ORDER BY c DESC""",
        {"j": job_id},
    )
    items: list[dict[str, Any]] = []
    total = 0
    want = (category or "").strip().lower()
    # Map common aliases onto encyclopedia category names
    if want in {"operating system", "os", "windows", "windows system"}:
        want = "system"

    for r in rows:
        cid = r["cid"]
        cat = _encyclopedia_category_fallback(cid)
        if cat.lower() != want:
            continue
        count = int(r["c"])
        total += count
        items.append({
            "artifact_id": cid,
            "label": labels.get(cid, cid),
            "count": count,
            "category": cat,
        })
        if len(items) >= limit:
            break

    # Related classic OS forensic types when asking for Operating System artifacts
    related: list[dict[str, Any]] = []
    if want == "system":
        for rel_cat in ("Registry", "Execution"):
            rel_total = 0
            rel_items = []
            for r in rows:
                cid = r["cid"]
                if _encyclopedia_category_fallback(cid) != rel_cat:
                    continue
                c = int(r["c"])
                rel_total += c
                if len(rel_items) < 12:
                    rel_items.append({
                        "artifact_id": cid,
                        "label": labels.get(cid, cid),
                        "count": c,
                        "category": rel_cat,
                    })
            if rel_total:
                related.append({
                    "category": rel_cat,
                    "count": rel_total,
                    "items": rel_items,
                })

    title = "Operating System (System)" if want == "system" else category
    return {
        "category": title,
        "category_key": "System" if want == "system" else category,
        "count": total,
        "items": items,
        "related": related,
        "description": (
            f"Encyclopedia / artifact inventory for category '{title}' "
            "with per-artifact-type counts from this disk image."
        ),
    }


def collect_documents_by_type(
    db,
    job_id: str,
    *,
    extensions: list[str],
    label: str,
    limit: int = 40,
) -> dict[str, Any]:
    """Count and list artifacts by file extension(s)."""
    exts = []
    for e in extensions:
        e = (e or "").strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = f".{e}"
        exts.append(e)
    if not exts:
        return {"label": label, "count": 0, "extensions": [], "items": []}

    rows = fetchall(
        db,
        """SELECT file_path, extension, size_bytes, parse_status
           FROM job_artifacts
           WHERE job_id=:jid AND lower(coalesce(extension,'')) = ANY(:exts)
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT :lim""",
        {"jid": job_id, "exts": exts, "lim": limit},
    )
    total = fetchone(
        db,
        """SELECT count(*) AS c FROM job_artifacts
           WHERE job_id=:jid AND (
             lower(coalesce(extension, '')) = ANY(:exts)
             OR lower(regexp_replace(coalesce(file_name, ''), '^.*(\\.[a-z0-9]+)$', '\\1')) = ANY(:exts)
             OR lower(regexp_replace(coalesce(file_path, ''), '^.*(\\.[a-z0-9]+)$', '\\1')) = ANY(:exts)
           )""",
        {"jid": job_id, "exts": exts},
    )
    items = [dict(r) for r in rows]
    return {
        "label": label,
        "count": int(total["c"]) if total else 0,
        "extensions": exts,
        "items": items,
    }


def detect_document_query(query: str) -> tuple[str, list[str]] | None:
    """Return (label, extensions) if the question asks for a document/file type count/list."""
    q = (query or "").lower()
    if not re.search(r"\b(how\s+many|count|number\s+of|list|show|available|find|are\s+there)\b", q):
        return None

    catalog: list[tuple[str, list[str], re.Pattern[str]]] = [
        ("CSV documents", [".csv"], re.compile(r"\bcsv\b", re.I)),
        ("PDF documents", [".pdf"], re.compile(r"\bpdfs?\b", re.I)),
        ("Word documents", [".doc", ".docx"], re.compile(r"\b(word|docx?|ms\s*word)\b", re.I)),
        ("Excel spreadsheets", [".xls", ".xlsx"], re.compile(r"\b(excel|xlsx?|spreadsheets?)\b", re.I)),
        ("PowerPoint files", [".ppt", ".pptx"], re.compile(r"\b(powerpoint|pptx?)\b", re.I)),
        ("Text documents", [".txt"], re.compile(r"\b(text\s+files?|txt\s+documents?|\.txt\b)\b", re.I)),
        ("Log files", [".log"], re.compile(r"\b(log\s+files?|\.log\b)\b", re.I)),
        ("JSON files", [".json"], re.compile(r"\bjson\b", re.I)),
        ("XML files", [".xml"], re.compile(r"\bxml\b", re.I)),
        ("HTML files", [".html", ".htm"], re.compile(r"\bhtml?\b", re.I)),
        (
            "Image files",
            [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"],
            re.compile(r"\b(images?|photos?|pictures?|jpe?g|png|gif)\b", re.I),
        ),
        ("Video files", [".mp4", ".avi", ".mkv", ".mov", ".wmv"], re.compile(r"\b(videos?|mp4|mkv|avi)\b", re.I)),
        ("Audio files", [".mp3", ".wav", ".m4a", ".flac"], re.compile(r"\b(audio|mp3|wav)\b", re.I)),
        ("ZIP / archives", [".zip", ".rar", ".7z", ".cab"], re.compile(r"\b(zip|rar|7z|archives?)\b", re.I)),
        ("SQLite databases", [".sqlite", ".sqlite3", ".db"], re.compile(r"\b(sqlite|\.db\b)\b", re.I)),
    ]
    for label, exts, pat in catalog:
        if pat.search(q):
            return label, exts
    return None


def collect_browser_urls(db, job_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    from app.services.browser_url_inventory import collect_job_browser_url_records

    records = collect_job_browser_url_records(db, job_id)
    urls: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in records:
        u = rec.get("url")
        if not u or u in seen:
            continue
        seen.add(u)
        urls.append({
            "url": u,
            "title": rec.get("title"),
            "last_visit": rec.get("last_visit"),
            "source": rec.get("source"),
            "visit_count": rec.get("visit_count"),
        })
        if len(urls) >= limit:
            return urls
    if urls:
        return urls

    rows = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid AND (
             apr.normalized::text ILIKE '%browser_url%'
             OR ja.file_path ILIKE '%/History'
             OR ja.file_path ILIKE '%places.sqlite'
           )
           ORDER BY apr.created_at DESC LIMIT 500""",
        {"jid": job_id},
    )
    urls: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict) or rec.get("record_type") != "browser_url":
                continue
            u = rec.get("url")
            if not u or u in seen:
                continue
            seen.add(u)
            urls.append({
                "url": u,
                "title": rec.get("title"),
                "last_visit": rec.get("last_visit"),
                "source": rec.get("source") or row.get("file_path"),
            })
            if len(urls) >= limit:
                return urls
    return urls


def collect_email_artifacts(db, job_id: str) -> dict[str, Any]:
    # Prefer mailboxes / message files — not Outlook.exe, MSI caches, etc.
    rows = fetchall(
        db,
        """SELECT file_path, parse_status, size_bytes
           FROM job_artifacts
           WHERE job_id=:jid AND (
             file_path ILIKE '%.eml'
             OR file_path ILIKE '%.pst'
             OR file_path ILIKE '%.ost'
             OR file_path ILIKE '%.msg'
             OR file_path ILIKE '%/Outlook Files/%'
             OR file_path ILIKE '%/Mail/%'
           )
           AND file_path NOT ILIKE '%.exe'
           AND file_path NOT ILIKE '%.msi'
           AND file_path NOT ILIKE '%.dll'
           AND file_path NOT ILIKE '%Program Files%'
           AND file_path NOT ILIKE '%MSOCache%'
           ORDER BY
             CASE
               WHEN file_path ILIKE '%.pst' THEN 0
               WHEN file_path ILIKE '%.ost' THEN 1
               WHEN file_path ILIKE '%.eml' THEN 2
               ELSE 3
             END,
             size_bytes DESC NULLS LAST
           LIMIT 100""",
        {"jid": job_id},
    )
    items = [dict(r) for r in rows]
    return {
        "count": len(items),
        "pst_count": sum(1 for r in items if str(r.get("file_path", "")).lower().endswith(".pst")),
        "ost_count": sum(1 for r in items if str(r.get("file_path", "")).lower().endswith(".ost")),
        "eml_count": sum(1 for r in items if str(r.get("file_path", "")).lower().endswith(".eml")),
        "items": items[:40],
        "note": (
            "PST/OST paths are listed; full message bodies need a mailbox parser "
            "(not yet applied to every file)."
        ),
    }


def collect_whatsapp_artifacts(db, job_id: str) -> dict[str, Any]:
    files = fetchall(
        db,
        """SELECT file_path, parse_status FROM job_artifacts
           WHERE job_id=:jid AND (
             file_path ILIKE '%WhatsApp%'
             OR file_path ILIKE '%msgstore%'
           ) LIMIT 50""",
        {"jid": job_id},
    )
    msgs = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid AND apr.normalized::text ILIKE '%whatsapp%'
           LIMIT 20""",
        {"jid": job_id},
    )
    message_count = 0
    deleted_count = 0
    samples: list[str] = []
    deleted_samples: list[str] = []
    for row in msgs:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict):
                continue
            if rec.get("record_type") == "whatsapp_summary":
                message_count += int(rec.get("message_count") or 0)
                deleted_count += int(rec.get("deleted_message_count") or 0)
            elif rec.get("record_type") == "whatsapp_message_deleted":
                deleted_count += 1
                body = str(rec.get("text_body") or "")[:200]
                if body:
                    day = ""
                    if rec.get("deleted_at"):
                        day = f" (deleted {str(rec['deleted_at'])[:10]})"
                    deleted_samples.append(f"{body}{day}")
            elif rec.get("record_type") == "whatsapp_message" and rec.get("text_body"):
                samples.append(str(rec["text_body"])[:200])
    return {
        "file_count": len(files),
        "files": [r["file_path"] for r in files],
        "message_count": message_count,
        "deleted_message_count": deleted_count,
        "samples": samples[:10],
        "deleted_samples": deleted_samples[:10],
    }


def _distinct_external_storage_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return likely physical external storage devices, de-duplicated by stable identity.

    AXIOM-style USB inventories contain multiple rows for hubs, interfaces, volumes
    and the same physical device.  Section-C observations must not treat those raw
    rows as a count of external hard disks.
    """
    storage_re = re.compile(
        r"(?:USBSTOR|mass\s*storage|portable|external|hard\s*disk|\bHDD\b|\bSSD\b|"
        r"expansion|uasp|scsi\s+disk|disk&ven_|storage\\volume)",
        re.I,
    )
    exclude_re = re.compile(
        r"(?:root hub|bluetooth|camera|input device|keyboard|mouse|audio|printer|webcam)",
        re.I,
    )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dev in devices or []:
        blob = " ".join(
            str(dev.get(k) or "")
            for k in ("bus", "device_name", "vendor", "product", "class_id")
        )
        if exclude_re.search(blob):
            continue
        if not storage_re.search(blob):
            continue
        # Avoid a known internal-NVMe pattern unless the record is explicitly USBSTOR.
        if re.search(r"\bNVMe\b", blob, re.I) and "usbstor" not in str(dev.get("bus") or "").lower():
            continue
        serial = re.sub(r"[^a-z0-9]", "", str(dev.get("serial") or "").lower())
        vendor = re.sub(r"[^a-z0-9]", "", str(dev.get("vendor") or "").lower())
        product = re.sub(r"[^a-z0-9]", "", str(dev.get("product") or dev.get("device_name") or "").lower())
        class_id = re.sub(r"[^a-z0-9]", "", str(dev.get("class_id") or "").lower())
        key = serial or (f"{vendor}|{product}" if vendor or product else class_id)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(dev)
    return out


def ensure_usb_fact_chunks(db, job_id: str) -> int:
    devices = collect_usb_devices(db, job_id)
    if not devices:
        return 0
    external_storage = _distinct_external_storage_devices(devices)
    lines = [
        "USB / connected devices recovered from this disk image.",
        f"Raw de-duplicated USB device-record count: {len(devices)}",
        f"Distinct likely external storage device count: {len(external_storage)}",
        "The external-storage count excludes obvious hubs, cameras, Bluetooth/input devices and non-USB internal NVMe rows.",
        "A connection record alone does not prove that files were copied.",
    ]
    if external_storage:
        lines.append("Distinct external storage devices:")
        for d in external_storage[:20]:
            lines.append(
                f"- {d.get('product') or d.get('device_name') or 'External storage'}"
                + (f" vendor={d['vendor']}" if d.get("vendor") else "")
                + (f" serial={d['serial']}" if d.get("serial") else "")
                + (f" last_seen={d['last_write']}" if d.get("last_write") else "")
            )
    lines.append("All USB inventory rows (for examiner traceability):")
    for d in devices[:40]:
        lines.append(
            f"- {d.get('device_name')}"
            + (f" serial={d['serial']}" if d.get("serial") else "")
            + (f" [{d.get('source')}]" if d.get("source") else "")
        )
    content = "\n".join(lines)
    path = "__forensic__/usb_devices"
    existing = fetchone(
        db,
        """SELECT id FROM rag_chunks WHERE job_id=:jid AND file_path=:path LIMIT 1""",
        {"jid": job_id, "path": path},
    )
    meta = json.dumps(
        {
            "kind": "usb_devices",
            "devices": devices[:50],
            "distinct_external_storage": external_storage[:30],
            "distinct_external_storage_count": len(external_storage),
        },
        default=str,
    )
    if existing:
        execute(
            db,
            """UPDATE rag_chunks SET content=:c, metadata=CAST(:m AS jsonb) WHERE id=:id""",
            {"c": content[:8000], "m": meta, "id": existing["id"]},
        )
    else:
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
               artifact_id, chunk_type, metadata)
               VALUES (:jid, :path, 0, :c, NULL, NULL, 'WRG-USB-0001', 'evidence', CAST(:m AS jsonb))""",
            {"jid": job_id, "path": path, "c": content[:8000], "m": meta},
        )
    return 1


def prioritize_pending_forensic_parse(db, job_id: str, *, limit: int = 80) -> dict[str, Any]:
    """Mark high-value pending/no_parser artifacts for re-parse and parse them."""
    from app.services.artifact_parse import parse_job_artifacts_for_paths
    from app.services.disk_manifest import build_index_map
    from app.services.dual_rag_index import append_job_evidence_rag

    # Reset History no_parser → pending now that sqlite routing exists
    execute(
        db,
        f"""UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
            WHERE job_id=:jid AND parse_status IN ('pending','no_parser')
              AND {_PRIORITY_PATH_SQL}""",
        {"jid": job_id},
    )
    # Force SYSTEM reparse for USBSTOR
    execute(
        db,
        """UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
           WHERE job_id=:jid AND file_path ILIKE 'Windows/System32/config/SYSTEM'""",
        {"jid": job_id},
    )
    execute(
        db,
        """DELETE FROM artifact_parse_results
           WHERE job_artifact_id IN (
             SELECT id FROM job_artifacts WHERE job_id=:jid
               AND file_path ILIKE 'Windows/System32/config/SYSTEM'
           )""",
        {"jid": job_id},
    )
    db.flush()

    rows = fetchall(
        db,
        f"""SELECT file_path FROM job_artifacts
            WHERE job_id=:jid AND parse_status='pending' AND {_PRIORITY_PATH_SQL}
            ORDER BY
              CASE
                WHEN file_path ILIKE '%/SYSTEM' THEN 0
                WHEN file_path ILIKE '%/History' THEN 1
                WHEN file_path ILIKE '%.pst' THEN 2
                WHEN file_path ILIKE '%WhatsApp%' THEN 3
                ELSE 4
              END,
              size_bytes DESC NULLS LAST
            LIMIT :lim""",
        {"jid": job_id, "lim": limit},
    )
    paths = [r["file_path"] for r in rows]
    if not paths:
        return {"parsed": 0, "paths": []}

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception:
            manifest = {}
    index_map = build_index_map(manifest or {})
    pr = parse_job_artifacts_for_paths(
        db, job_id, paths=paths, index_map=index_map, update_status=False,
    )
    try:
        from app.config import get_settings as _rag_settings

        if getattr(_rag_settings(), "rag_embedding_enabled", False):
            append_job_evidence_rag(db, job_id, file_paths=paths, index_map=index_map)
    except Exception as exc:
        log.warning("RAG append after priority parse failed: %s", exc)
    try:
        ensure_usb_fact_chunks(db, job_id)
    except Exception as exc:
        log.warning("USB fact chunk failed: %s", exc)
    return {"parse": pr, "paths": paths}
