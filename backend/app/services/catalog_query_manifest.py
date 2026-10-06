"""AXIOM artifact query manifest and reconciliation.

Answers, per job and per AXIOM catalog artifact:

* which count domain / record unit the number is in (DOCX §1.1),
* which collector or SQL fragment produced it (reproducible in psql),
* which evidence sources on the disk image feed that collector,
* what the application counted, what AXIOM reported, and the delta,
* the examiner-facing reason when a delta is expected.

This is the piece that was missing for matching numbers against a Magnet AXIOM
report: ``job_axiom_artifact_results`` stored a count and a partial
``query_snapshot`` but nothing exposed the whole chain in one place, and the
only AXIOM reference counts lived in a hard-coded dict for a single case.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger(__name__)

MANIFEST_VERSION = "4.8"

# ---------------------------------------------------------------------------
# Runnable SQL fragments (job_artifacts WHERE clauses) keyed by query_key.
# Every fragment here is safe to paste into
#   SELECT count(*) FROM job_artifacts WHERE job_id='<job>' AND ( <fragment> );
# ---------------------------------------------------------------------------


def _runnable_fragments() -> dict[str, str]:
    from app.services.catalog_section_queries import (
        EMAIL_ATTACHMENT_WHERE,
        EMLX_FILE_WHERE,
        JUMP_LIST_WHERE,
        LNK_FILE_WHERE,
        LOGFILE_ANALYSIS_WHERE,
        MBOX_EMAIL_WHERE,
        OUTLOOK_EMAIL_WHERE,
        OUTLOOK_MSG_WHERE,
        WEB_RELATED_WHERE,
        WINDOWS_MAIL_WHERE,
    )

    frags: dict[str, str] = {
        "EMAIL_ATTACHMENT_WHERE": EMAIL_ATTACHMENT_WHERE,
        "EMLX_FILE_WHERE": EMLX_FILE_WHERE,
        "JUMP_LIST_WHERE": JUMP_LIST_WHERE,
        "LNK_FILE_WHERE": LNK_FILE_WHERE,
        "LOGFILE_ANALYSIS_WHERE": LOGFILE_ANALYSIS_WHERE,
        "MBOX_EMAIL_WHERE": MBOX_EMAIL_WHERE,
        "OUTLOOK_EMAIL_WHERE": OUTLOOK_EMAIL_WHERE,
        "OUTLOOK_MSG_WHERE": OUTLOOK_MSG_WHERE,
        "WEB_RELATED_WHERE": WEB_RELATED_WHERE,
        "WINDOWS_MAIL_WHERE": WINDOWS_MAIL_WHERE,
    }
    try:
        from app.services.encryption_inventory import (  # type: ignore[attr-defined]
            _ANTIFORENSICS_SQL,
            _CREDENTIALS_SQL,
            _ENCRYPTED_PATH_SQL,
        )

        frags["ENCRYPTED_FILES_PATH"] = _ENCRYPTED_PATH_SQL
        frags["WINDOWS_CREDENTIALS_STORE_FILES"] = _CREDENTIALS_SQL
        frags["ANTIFORENSICS_TOOLS"] = _ANTIFORENSICS_SQL
    except Exception:  # pragma: no cover - optional
        pass
    return {k: " ".join(v.split()) for k, v in frags.items()}


# ---------------------------------------------------------------------------
# Evidence sources per collector (what on the disk feeds the number). Used for
# the PROCEDURE section and for examiner review when matching AXIOM.
# ---------------------------------------------------------------------------

COLLECTOR_SOURCES: dict[str, dict[str, Any]] = {
    "USB_REGISTRY_SETUPAPI": {
        "collector": "axiom_aligned_counts.count_usb_device_records",
        "record_unit": "unique USB device instance (VID/PID/serial)",
        "sources": [
            r"SYSTEM\ControlSet00x\Enum\USBSTOR",
            r"SYSTEM\ControlSet00x\Enum\USB",
            r"SOFTWARE\Microsoft\Windows Portable Devices\Devices",
            r"NTUSER.DAT\...\Explorer\MountPoints2",
            r"Windows\INF\setupapi.dev.log (first-install timestamps)",
        ],
        "axiom_note": "AXIOM 'USB Devices' merges USBSTOR + USB + WPD + setupapi; the app keys on VID/PID/serial and dedups across hives, so extra AXIOM rows are usually composite/hub devices without a serial.",
    },
    "RDP_REGISTRY": {
        "collector": "axiom_aligned_counts.count_rdp_connection_records",
        "record_unit": "remote host connection record",
        "sources": [
            r"NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers",
            r"NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default (MRU0..n)",
            r"Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-*.evtx (1024/1102/21/24/25)",
        ],
    },
    "YOUR_PHONE_REGISTRY": {
        "collector": "forensic_inventory.collect_phone_usage",
        "record_unit": "linked phone device",
        "sources": [
            r"Users\<user>\AppData\Local\Packages\Microsoft.YourPhone_*\LocalCache\Indexed\<device>\System\Database\*.db",
            r"NTUSER.DAT\Software\Microsoft\YourPhone",
        ],
    },
    "FEATURE_USAGE_REGISTRY": {
        "collector": "axiom_aligned_counts.count_feature_usage_records",
        "record_unit": "registry value (AppSwitched/AppLaunch/ShowJumpView/AppBadgeUpdated/TrayButtonClicked)",
        "sources": [r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\*"],
    },
    "INSTALLED_PROGRAMS_REGISTRY": {
        "collector": "forensic_inventory.collect_installed_programs",
        "record_unit": "Uninstall registry entry",
        "sources": [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ],
        "axiom_note": "AXIOM splits Microsoft vs Non-Microsoft by Publisher; the app applies the same split on the Publisher value and falls back to DisplayName prefix.",
    },
    "WINDOWS_DEFENDER_LOG_FILES": {
        "collector": "forensic_inventory.collect_defender_logs",
        "record_unit": "Defender log file",
        "sources": [
            r"ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log",
            r"ProgramData\Microsoft\Windows Defender\Support\MPDetection-*.log",
            r"Windows\Temp\MpCmdRun.log",
        ],
    },
    "URL_VISIT_WEB_CHAT": {
        "collector": "browser_url_inventory.compute_communication_url_totals",
        "record_unit": "URL visit (History.visits / moz_historyvisits) classified by domain list",
        "sources": [
            r"Users\<user>\AppData\Local\Google\Chrome\User Data\<profile>\History (urls, visits)",
            r"Users\<user>\AppData\Local\Microsoft\Edge\User Data\<profile>\History",
            r"Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite (moz_places, moz_historyvisits)",
        ],
        "axiom_note": "AXIOM classifies by its own domain lists and also pulls URLs from cache/cookie/session files; the app classifies history-DB visits only. Deleted/WAL-only visits are included when the -wal file is registered.",
    },
    "MEDIA_FULL_DISK": {
        "collector": "media_inventory.media_counts_for_answer (+ signature_carve_inventory)",
        "record_unit": "allocated file by extension + thumbcache/CMMM entries + carved headers",
        "sources": [
            "Full-volume extension census (disk_ext_census) over allocated files",
            r"Users\<user>\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db (CMMM entries)",
            "Signature carve of $Recycle.Bin, pagefile.sys, hiberfil.sys and sampled unallocated clusters",
        ],
        "axiom_note": "AXIOM Picture/Video also carves the full unallocated space and embedded images inside documents/archives; the app carves a bounded unalloc budget.",
    },
    "DOCUMENT_FULL_DISK": {
        "collector": "axiom_aligned_counts.count_document_occurrences_axiom",
        "record_unit": "allocated file by extension (+ carved headers for PDF/Office)",
        "sources": [
            "Full-volume extension census (disk_ext_census) over allocated files",
            "Signature carve of $Recycle.Bin / pagefile / unalloc for %PDF-, D0CF11E0 (OLE), PK (OOXML), {\\rtf",
        ],
        "axiom_note": "AXIOM counts allocated + deleted + carved documents, and documents inside archives/mailboxes. Residual gaps are unalloc recovery depth.",
    },
}

_URL_KEYS = ("URL_VISIT_SOCIAL", "URL_VISIT_MALWARE", "URL_VISIT_PORNOGRAPHY", "URL_VISIT_DATING")
for _k in _URL_KEYS:
    COLLECTOR_SOURCES[_k] = dict(COLLECTOR_SOURCES["URL_VISIT_WEB_CHAT"])

_SQL_COLLECTORS: dict[str, dict[str, Any]] = {
    "EMAIL_ATTACHMENT_WHERE": {"collector": "email_inventory.count_email_attachments", "record_unit": "attachment part (parsed MIME/PST) or attachment file"},
    "EMLX_FILE_WHERE": {"collector": "email_inventory.count_eml_files", "record_unit": ".eml/.emlx file occurrence"},
    "WINDOWS_MAIL_WHERE": {"collector": "email_inventory.count_windows_mail", "record_unit": "parsed Windows Mail message (store files are NOT counted)"},
    "OUTLOOK_EMAIL_WHERE": {"collector": "email_inventory.count_outlook_emails", "record_unit": "PST/OST message record or .msg file"},
    "OUTLOOK_MSG_WHERE": {"collector": "email_inventory.count_outlook_emails", "record_unit": ".msg file"},
    "MBOX_EMAIL_WHERE": {"collector": "email_inventory.count_mbox_emails", "record_unit": "mbox message"},
    "JUMP_LIST_WHERE": {"collector": "axiom_aligned_counts.count_jump_list_occurrences", "record_unit": "DestList entry (falls back to .automaticDestinations-ms file)"},
    "LNK_FILE_WHERE": {"collector": "axiom_aligned_counts.count_lnk_occurrences", "record_unit": "standalone .lnk file"},
    "LOGFILE_ANALYSIS_WHERE": {"collector": "axiom_aligned_counts.count_logfile_analysis_occurrences", "record_unit": "log file occurrence (.log/.evtx/.etl/…)"},
    "WEB_RELATED_WHERE": {"collector": "axiom_aligned_counts (WEB_RELATED_WHERE)", "record_unit": "web-related file occurrence"},
    "ENCRYPTED_FILES_PATH": {"collector": "encryption_inventory.count_encrypted_files_by_path / scan_encrypted_files", "record_unit": "encrypted container/file (extension + optional header scan)"},
    "WINDOWS_CREDENTIALS_STORE_FILES": {"collector": "encryption_inventory.count_windows_stored_credentials", "record_unit": "parsed Credential Manager vault record (store files listed but NOT counted)"},
    "ANTIFORENSICS_TOOLS": {"collector": "encryption_inventory.count_antiforensics_tools", "record_unit": "tool binary/path occurrence"},
}

_DOMAIN_LABEL = {
    "artifact_record": "artifact record occurrences",
    "file_occurrence": "file occurrences",
    "unique_content": "unique content items",
    "recovered": "recovered (deleted/carved) items",
    "unverified_source_hit": "unverified source-path hits",
}


def _norm(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def _document_extensions_for(name: str) -> list[str]:
    try:
        from app.services.catalog_aligned_counts import _DOCUMENT_EXTENSIONS  # type: ignore[attr-defined]
    except Exception:
        return []
    n = _norm(name)
    return list(_DOCUMENT_EXTENSIONS.get(n) or _DOCUMENT_EXTENSIONS.get(n.replace("microsoft ", "")) or [])


def _runnable_sql_for(name: str, query_key: str, frags: dict[str, str]) -> str | None:
    if query_key in frags:
        return frags[query_key]
    exts = _document_extensions_for(name)
    if exts:
        quoted = ",".join("'" + e.lower() + "'" for e in exts)
        return f"lower(coalesce(extension,'')) IN ({quoted})"
    return None


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def build_query_manifest(db: Session, job_id: str, *, platform: str | None = None) -> dict[str, Any]:
    """Full artifact → query → count → AXIOM reference → delta table for one job."""
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform
    from app.services.catalog_count_spec import metadata_for_artifact

    platform = platform or resolve_job_axiom_platform(db, job_id)
    frags = _runnable_fragments()

    rows = fetchall(
        db,
        """SELECT aa.artifact_id, aa.artifact_name, aa.category, aa.observation_focus,
                  aa.primary_objective_id, aa.metadata,
                  r.status, r.answer, r.count_domain AS r_domain,
                  COALESCE(r.occurrence_count, r.artifact_count) AS app_count,
                  r.unique_count, r.query_snapshot, r.confidence, r.parser_version, r.updated_at,
                  c.axiom_export_count, c.delta_reason AS stored_reason
           FROM public.axiom_artifacts aa
           LEFT JOIN job_axiom_artifact_results r
             ON r.artifact_id = aa.artifact_id AND r.job_id = :jid
           LEFT JOIN job_count_reconciliation c
             ON c.artifact_id = aa.artifact_id AND c.job_id = :jid
           WHERE aa.platform = :p
           ORDER BY aa.sort_order, aa.artifact_name""",
        {"jid": job_id, "p": platform},
    )

    try:
        from app.services.catalog_report_reconciliation import GAP_REASONS
    except Exception:
        GAP_REASONS = {}

    items: list[dict[str, Any]] = []
    matched = 0
    with_reference = 0
    for row in rows:
        name = str(row.get("artifact_name") or "")
        category = str(row.get("category") or "")
        meta = metadata_for_artifact(artifact_name=name, category=category)
        snap = row.get("query_snapshot")
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except Exception:
                snap = {}
        snap = snap if isinstance(snap, dict) else {}
        query_key = str(snap.get("query_key") or meta.get("query_key") or "")
        domain = str(row.get("r_domain") or meta.get("count_domain") or "artifact_record")
        collector_meta = COLLECTOR_SOURCES.get(query_key) or _SQL_COLLECTORS.get(query_key) or {}
        if not collector_meta and _document_extensions_for(name):
            collector_meta = COLLECTOR_SOURCES["DOCUMENT_FULL_DISK"]
            query_key = query_key or "DOCUMENT_FULL_DISK"
        runnable = _runnable_sql_for(name, query_key, frags)

        app_count = row.get("app_count")
        app_count = int(app_count) if app_count is not None else None
        ref = row.get("axiom_export_count")
        ref = int(ref) if ref is not None else None
        delta = (app_count or 0) - ref if (ref is not None and app_count is not None) else None
        if ref is not None:
            with_reference += 1
            if delta == 0:
                matched += 1

        reason = str(row.get("stored_reason") or "")
        if reason in ("", "pending_axiom_export") and ref is not None and delta:
            reason = GAP_REASONS.get(name) or collector_meta.get("axiom_note") or _generic_reason(domain, delta)

        items.append(
            {
                "artifact_id": row.get("artifact_id"),
                "artifact_name": name,
                "category": category,
                "objective_id": row.get("primary_objective_id"),
                "count_domain": domain,
                "count_domain_label": _DOMAIN_LABEL.get(domain, domain),
                "record_unit": str(collector_meta.get("record_unit") or meta.get("record_unit") or ""),
                "parser_family": str(meta.get("parser_family") or ""),
                "query_key": query_key,
                "collector": str(snap.get("collector") or collector_meta.get("collector") or ""),
                "sources": list(collector_meta.get("sources") or []),
                "sql_where": runnable,
                "psql": (
                    f"SELECT count(*) FROM job_artifacts WHERE job_id='{job_id}' AND ({runnable});"
                    if runnable
                    else None
                ),
                "status": row.get("status") or "not_run",
                "app_count": app_count,
                "unique_count": row.get("unique_count"),
                "confidence": row.get("confidence"),
                "answer": (row.get("answer") or "")[:400],
                "axiom_count": ref,
                "delta": delta,
                "delta_reason": reason or None,
                "query_snapshot": snap,
                "observation_focus": row.get("observation_focus"),
                "updated_at": str(row.get("updated_at") or ""),
            }
        )

    return {
        "job_id": job_id,
        "platform": platform,
        "manifest_version": MANIFEST_VERSION,
        "artifact_total": len(items),
        "with_axiom_reference": with_reference,
        "matched": matched,
        "gaps": with_reference - matched,
        "items": items,
    }


def _generic_reason(domain: str, delta: int) -> str:
    if domain == "file_occurrence":
        return (
            "App counts allocated files (+bounded carve). AXIOM adds deleted/carved items from full unallocated space "
            "and files nested in archives/mailboxes." if delta < 0 else
            "App extension/path rule is wider than AXIOM's signature-based classification; review samples via explain."
        )
    if domain == "artifact_record":
        return (
            "AXIOM parses additional sources (cache/session/WAL/volume shadow copies) for this record type." if delta < 0 else
            "App counts occurrences (every record); AXIOM may dedupe on content or drop records without timestamps."
        )
    if domain == "unverified_source_hit":
        return "No dedicated parser: app number is a source-path hit, not a parsed record. Treat as indicative only."
    return "Count domains differ; compare record_unit before treating as a gap."


def manifest_to_csv(manifest: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "artifact_id", "artifact_name", "category", "count_domain", "record_unit", "query_key",
            "collector", "app_count", "axiom_count", "delta", "delta_reason", "sources", "sql_where",
        ]
    )
    for it in manifest.get("items") or []:
        w.writerow(
            [
                it.get("artifact_id"), it.get("artifact_name"), it.get("category"), it.get("count_domain"),
                it.get("record_unit"), it.get("query_key"), it.get("collector"),
                "" if it.get("app_count") is None else it.get("app_count"),
                "" if it.get("axiom_count") is None else it.get("axiom_count"),
                "" if it.get("delta") is None else it.get("delta"),
                it.get("delta_reason") or "", " | ".join(it.get("sources") or []), it.get("sql_where") or "",
            ]
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Explain: run the artifact's SQL and show what is being counted.
# ---------------------------------------------------------------------------


def explain_artifact(db: Session, job_id: str, artifact_id: str, *, limit: int = 50) -> dict[str, Any]:
    """Sample rows + aggregate for one artifact so the examiner can see what the number is made of."""
    manifest = build_query_manifest(db, job_id)
    item = next((i for i in manifest["items"] if str(i.get("artifact_id")) == str(artifact_id)), None)
    if not item:
        return {"job_id": job_id, "artifact_id": artifact_id, "error": "artifact not in catalog for this platform"}
    out: dict[str, Any] = {k: item.get(k) for k in (
        "artifact_id", "artifact_name", "category", "count_domain", "record_unit", "query_key",
        "collector", "sources", "sql_where", "app_count", "axiom_count", "delta", "delta_reason",
    )}
    where = item.get("sql_where")
    if not where:
        out["note"] = "This artifact is produced by a parser/collector, not a job_artifacts SQL rule. See 'sources' and the collector name."
        out["samples"] = _samples_from_snapshot(item.get("query_snapshot") or {})
        return out
    lim = max(1, min(int(limit or 50), 500))
    try:
        agg = fetchone(
            db,
            f"""SELECT count(*) AS c,
                       min(coalesce(metadata->>'mtime', metadata->>'modified_at')) AS first_seen,
                       max(coalesce(metadata->>'mtime', metadata->>'modified_at')) AS last_seen,
                       coalesce(sum(size_bytes),0) AS bytes,
                       count(*) FILTER (WHERE coalesce(metadata->>'is_deleted','') IN ('true','1')) AS deleted_n
                FROM job_artifacts WHERE job_id=:j AND ({where})""",
            {"j": job_id},
        ) or {}
        rows = fetchall(
            db,
            f"""SELECT file_path, size_bytes, parse_status, ocr_status, encyclopedia_artifact_id,
                       metadata->>'is_deleted' AS is_deleted, metadata->>'recovery_state' AS recovery_state
                FROM job_artifacts WHERE job_id=:j AND ({where})
                ORDER BY size_bytes DESC NULLS LAST LIMIT {lim}""",
            {"j": job_id},
        )
        top_dirs = fetchall(
            db,
            f"""SELECT regexp_replace(file_path, '/[^/]*$', '') AS dir, count(*) AS c
                FROM job_artifacts WHERE job_id=:j AND ({where})
                GROUP BY 1 ORDER BY c DESC LIMIT 15""",
            {"j": job_id},
        )
    except Exception as exc:  # column set differs per deployment; degrade gracefully
        try:
            db.rollback()
        except Exception:
            pass
        log.warning("explain_artifact failed for %s/%s: %s", job_id, artifact_id, exc)
        agg = fetchone(db, f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND ({where})", {"j": job_id}) or {}
        rows = fetchall(
            db, f"SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND ({where}) LIMIT {lim}", {"j": job_id}
        )
        top_dirs = []
    out["sql_count_now"] = int(agg.get("c") or 0)
    out["first_seen"] = str(agg.get("first_seen") or "") or None
    out["last_seen"] = str(agg.get("last_seen") or "") or None
    out["total_bytes"] = int(agg.get("bytes") or 0)
    out["deleted_count"] = int(agg.get("deleted_n") or 0)
    out["top_directories"] = [{"dir": r.get("dir"), "count": int(r.get("c") or 0)} for r in top_dirs]
    out["samples"] = [dict(r) for r in rows]
    if out["app_count"] is not None and out["sql_count_now"] != out["app_count"]:
        out["note"] = (
            "Stored app_count differs from the plain job_artifacts SQL: the collector adds parsed records, "
            "disk-census or carved items on top of registered files (see record_unit)."
        )
    return out


def _samples_from_snapshot(snap: dict[str, Any]) -> list[Any]:
    for key in ("samples", "sample_paths", "devices", "records"):
        val = snap.get(key)
        if isinstance(val, list) and val:
            return val[:50]
    return []


# ---------------------------------------------------------------------------
# AXIOM reference-count import (Case Summary → Artifact categories export, or
# a hand-typed list from the AXIOM PDF report Section B).
# ---------------------------------------------------------------------------

_ALIASES: dict[str, str] = {
    "pictures": "picture",
    "videos": "video",
    "jump lists": "jump list",
    "lnk": "lnk files",
    "shortcut files": "lnk files",
    "rdp": "remote desktop protocol (rdp)",
    "remote desktop protocol": "remote desktop protocol (rdp)",
    "$logfile analysis": "logfile analysis",
    "eml files": "eml(x) files",
    "emlx files": "eml(x) files",
    "eml/emlx files": "eml(x) files",
    "word documents": "microsoft word documents",
    "excel documents": "microsoft excel documents",
    "powerpoint documents": "microsoft powerpoint documents",
    "malware / phishing urls": "malware/phishing urls",
    "installed programs - microsoft": "installed microsoft programs",
    "installed programs - non-microsoft": "installed programs (non-microsoft)",
}


def _canon(name: str) -> str:
    n = _norm(name)
    n = re.sub(r"\s*\(\d[\d,]*\)\s*$", "", n)  # strip trailing "(1,234)"
    n = n.replace("–", "-").replace("—", "-")
    return _ALIASES.get(n, n)


def parse_reference_counts(payload: Any) -> list[tuple[str, int]]:
    """Accept JSON list [{artifact,count}], {name: count}, or CSV/TSV text (name,count)."""
    pairs: list[tuple[str, int]] = []
    if isinstance(payload, dict) and "items" in payload:
        payload = payload["items"]
    if isinstance(payload, dict):
        for k, v in payload.items():
            try:
                pairs.append((str(k), int(str(v).replace(",", ""))))
            except Exception:
                continue
        return pairs
    if isinstance(payload, list):
        for it in payload:
            if isinstance(it, dict):
                name = it.get("artifact") or it.get("artifact_name") or it.get("name") or it.get("Artifact")
                cnt = it.get("count") if "count" in it else it.get("Count", it.get("hits", it.get("Hits")))
                if name is None or cnt is None:
                    continue
                try:
                    pairs.append((str(name), int(str(cnt).replace(",", ""))))
                except Exception:
                    continue
            elif isinstance(it, (list, tuple)) and len(it) >= 2:
                try:
                    pairs.append((str(it[0]), int(str(it[1]).replace(",", ""))))
                except Exception:
                    continue
        return pairs
    text = str(payload or "")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("artifact", "name", "category")):
            continue
        # split on tab, two+ spaces, or a comma that precedes the trailing number —
        # but never on the thousands separator inside "12,463".
        parts = [p.strip() for p in re.split(r"\t|(?<!\d),(?=\s*\d[\d,]*\s*$)|\s{2,}", line) if p.strip()]
        if len(parts) < 2:
            m = re.match(r"^(.*?)[\s:]+(\d[\d,]*)$", line)
            if not m:
                continue
            parts = [m.group(1), m.group(2)]
        try:
            pairs.append((parts[0], int(parts[-1].replace(",", ""))))
        except Exception:
            continue
    return pairs


def import_reference_counts(
    db: Session,
    job_id: str,
    payload: Any,
    *,
    source: str = "axiom_export",
) -> dict[str, Any]:
    """Store AXIOM reference counts and compute per-artifact deltas."""
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    platform = resolve_job_axiom_platform(db, job_id)
    catalog = fetchall(
        db,
        "SELECT artifact_id, artifact_name FROM public.axiom_artifacts WHERE platform=:p",
        {"p": platform},
    )
    by_name: dict[str, str] = {}
    for row in catalog:
        by_name[_canon(str(row.get("artifact_name") or ""))] = str(row.get("artifact_id"))

    app_counts: dict[str, int] = {}
    for row in fetchall(
        db,
        """SELECT artifact_id, COALESCE(occurrence_count, artifact_count, 0) AS c
           FROM job_axiom_artifact_results WHERE job_id=:jid""",
        {"jid": job_id},
    ):
        app_counts[str(row.get("artifact_id"))] = int(row.get("c") or 0)

    pairs = parse_reference_counts(payload)
    applied: list[dict[str, Any]] = []
    unmatched: list[str] = []
    for name, cnt in pairs:
        aid = by_name.get(_canon(name))
        if not aid:
            # loose match: canonical name contained either way
            cn = _canon(name)
            cands = [k for k in by_name if cn and (cn in k or k in cn)]
            aid = by_name[cands[0]] if len(cands) == 1 else None
        if not aid:
            unmatched.append(name)
            continue
        py = app_counts.get(aid)
        delta = (py - cnt) if py is not None else None
        reason = "match" if delta == 0 else ("pending_inventory" if py is None else "gap")
        execute(
            db,
            """INSERT INTO job_count_reconciliation
               (job_id, artifact_id, axiom_export_count, python_inventory_count, delta,
                delta_reason, query_snapshot, updated_at)
               VALUES (:jid, :aid, :ax, :py, :delta, :reason, CAST(:qs AS jsonb), NOW())
               ON CONFLICT (job_id, artifact_id) DO UPDATE SET
                 axiom_export_count = EXCLUDED.axiom_export_count,
                 python_inventory_count = EXCLUDED.python_inventory_count,
                 delta = EXCLUDED.delta,
                 delta_reason = EXCLUDED.delta_reason,
                 query_snapshot = COALESCE(job_count_reconciliation.query_snapshot, EXCLUDED.query_snapshot),
                 updated_at = NOW()""",
            {
                "jid": job_id,
                "aid": aid,
                "ax": int(cnt),
                "py": py,
                "delta": delta,
                "reason": reason,
                "qs": json.dumps({"source": source, "axiom_label": name}),
            },
        )
        applied.append({"artifact_id": aid, "axiom_label": name, "axiom_count": int(cnt), "app_count": py, "delta": delta})
    db.flush()
    return {
        "job_id": job_id,
        "platform": platform,
        "imported": len(applied),
        "unmatched": unmatched,
        "items": applied,
    }


def seed_reference_counts_from_builtin(db: Session, job_id: str) -> dict[str, Any]:
    """Load the built-in Ex-5 reference (axiom_report_reconciliation.PDF_REFERENCE_COUNTS)."""
    from app.services.catalog_report_reconciliation import PDF_REFERENCE_COUNTS

    return import_reference_counts(db, job_id, dict(PDF_REFERENCE_COUNTS), source="builtin_ex5_pdf")


# ---------------------------------------------------------------------------
# Helpers consumed by observation / procedure builders
# ---------------------------------------------------------------------------


def provenance_for_artifacts(db: Session, job_id: str, artifact_ids: list[str]) -> dict[str, dict[str, Any]]:
    """query_key / collector / sources / record_unit / temporal range per artifact id."""
    if not artifact_ids:
        return {}
    manifest = build_query_manifest(db, job_id)
    wanted = {str(a) for a in artifact_ids}
    out: dict[str, dict[str, Any]] = {}
    for it in manifest["items"]:
        aid = str(it.get("artifact_id"))
        if aid not in wanted:
            continue
        prov: dict[str, Any] = {
            "query_key": it.get("query_key"),
            "collector": it.get("collector"),
            "sources": it.get("sources") or [],
            "record_unit": it.get("record_unit"),
            "count_domain": it.get("count_domain"),
            "count_domain_label": it.get("count_domain_label"),
            "axiom_count": it.get("axiom_count"),
            "delta": it.get("delta"),
            "delta_reason": it.get("delta_reason"),
        }
        where = it.get("sql_where")
        if where and (it.get("app_count") or 0) > 0:
            try:
                agg = fetchone(
                    db,
                    f"""SELECT min(coalesce(metadata->>'mtime', metadata->>'modified_at')) AS first_seen,
                               max(coalesce(metadata->>'mtime', metadata->>'modified_at')) AS last_seen,
                               count(*) FILTER (WHERE coalesce(metadata->>'is_deleted','') IN ('true','1')) AS deleted_n
                        FROM job_artifacts WHERE job_id=:j AND ({where})""",
                    {"j": job_id},
                ) or {}
                prov["first_seen"] = str(agg.get("first_seen") or "") or None
                prov["last_seen"] = str(agg.get("last_seen") or "") or None
                prov["deleted_count"] = int(agg.get("deleted_n") or 0)
                dirs = fetchall(
                    db,
                    f"""SELECT regexp_replace(file_path, '/[^/]*$', '') AS dir, count(*) AS c
                        FROM job_artifacts WHERE job_id=:j AND ({where})
                        GROUP BY 1 ORDER BY c DESC LIMIT 3""",
                    {"j": job_id},
                )
                prov["top_directories"] = [
                    {"dir": d.get("dir"), "count": int(d.get("c") or 0)} for d in dirs
                ]
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
        out[aid] = prov
    return out
