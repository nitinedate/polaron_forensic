"""Structured evidence gathering for forensic report sections."""

from __future__ import annotations

import json
import re
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.artifact_export import artifact_scope_payload
from app.services.report_objectives_service import resolve_intake_objectives
from app.services.report_template import (
    _device_label,
    _evidence_details_with_db,
    gather_cover_page_markdown,
    gather_forensic_imaging_markdown,
    gather_introduction_markdown,
    gather_scope_of_work_markdown,
    gather_table_of_contents_markdown,
    gather_tools_used_markdown,
)

_URL_ARTIFACT_NAMES = (
    "Social Media URLs",
    "Web Chat URLs",
    "Malware/Phishing URLs",
    "Pornography URLs",
    "Dating Site URLs",
)


def _rows_from_parse(db, job_id: str, *, record_type: str | None = None, path_hint: str | None = None) -> list[dict]:
    sql = """
        SELECT apr.normalized, ja.file_path, ja.file_name
        FROM artifact_parse_results apr
        JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
        WHERE ja.job_id=:jid
    """
    params: dict[str, Any] = {"jid": job_id}
    if record_type:
        sql += " AND apr.normalized::text ILIKE :rt"
        params["rt"] = f"%{record_type}%"
    if path_hint:
        sql += " AND ja.file_path ILIKE :ph"
        params["ph"] = f"%{path_hint}%"
    sql += " LIMIT 500"
    return fetchall(db, sql, params)


def _format_count(n: int) -> str:
    return f"{n:,}"


def collect_windows_users_structured(db, job_id: str) -> list[dict[str, str]]:
    """Return Windows user-account evidence used by both Section A and Section C.

    Keeping one structured collector prevents the Report Agent from saying that account
    details are unavailable while the User Profile table on the preceding page already
    displays them.
    """
    users: dict[str, dict[str, str]] = {}

    for row in _rows_from_parse(db, job_id, record_type="sam_user"):
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                norm = None
        if not isinstance(norm, dict):
            continue
        name = (norm.get("username") or norm.get("account_name") or norm.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        users.setdefault(key, {
            "username": name,
            "type": "Local User",
            "profile_path": "—",
            "last_logon": "—",
            "password_change": "—",
        })
        if norm.get("last_logon"):
            users[key]["last_logon"] = str(norm["last_logon"])[:32]
        if norm.get("password_last_set"):
            users[key]["password_change"] = str(norm["password_last_set"])[:32]
        if norm.get("sid"):
            users[key]["sid"] = str(norm.get("sid"))[:96]
        if norm.get("rid"):
            users[key]["rid"] = str(norm.get("rid"))[:32]

    for row in _rows_from_parse(db, job_id, record_type="profile_list"):
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                norm = None
        if not isinstance(norm, dict):
            continue
        profile_path = str(norm.get("profile_path") or "").strip()
        name = (profile_path or str(norm.get("username") or norm.get("sid") or "")).split("\\")[-1].strip()
        if not name:
            continue
        key = name.lower()
        users.setdefault(key, {
            "username": name,
            "type": "Local User",
            "profile_path": "—",
            "last_logon": "—",
            "password_change": "—",
        })
        if profile_path:
            users[key]["profile_path"] = profile_path[:220]
        if norm.get("sid"):
            users[key]["sid"] = str(norm.get("sid"))[:96]

    if not users:
        for row in _rows_from_parse(db, job_id, path_hint="SAM"):
            text = json.dumps(row.get("normalized") or "")
            for match in re.finditer(r'"username"\s*:\s*"([^"]+)"', text):
                name = match.group(1)
                users.setdefault(name.lower(), {
                    "username": name,
                    "type": "Local User",
                    "profile_path": "—",
                    "last_logon": "—",
                    "password_change": "—",
                })

    return sorted(users.values(), key=lambda x: str(x.get("username") or "").lower())


def gather_windows_users_markdown(db, job_id: str) -> str:
    """Windows user accounts table from the same facts consumed by Section C."""
    users = collect_windows_users_structured(db, job_id)
    if not users:
        return (
            "**Insufficient evidence** — no parsed SAM / ProfileList / Security.evtx user records were indexed. "
            "Re-run parse on registry hives and Security event logs."
        )

    intro = """## A. OPERATING SYSTEM

### 2. USER PROFILE

The User Profile contains key information about individuals who have used the computer. It includes the name of the user, the type of account they used, where their personal data is stored, when they last accessed the device, and when their password was last changed.

**Status:** All user profile information was examined to determine the users present on the system, the nature of their accounts, and their most recent activity.

| Sr No | Username | Type of User | Profile Path | Last Local Login Date/Time | Last Password Change Date/Time |
| ---: | --- | --- | --- | --- | --- |"""
    lines = [intro]
    for i, u in enumerate(users, 1):
        lines.append(
            f"| {i} | {u.get('username') or '—'} | {u.get('type') or 'Local User'} | "
            f"{u.get('profile_path') or '—'} | {u.get('last_logon') or '—'} | {u.get('password_change') or '—'} |"
        )
    return "\n".join(lines)


def gather_os_hardware_markdown(db, job_id: str) -> str:
    """Operating system and hardware details table."""
    fields = {
        "Operating System": "—",
        "Version Number": "—",
        "Build Number": "—",
        "Computer Name": "—",
        "Install Date": "—",
        "Product Key": "—",
        "Product ID": "—",
        "Last Shutdown": "—",
        "System Root": "—",
    }

    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    ds = job.get("disk_source") if job else {}
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except json.JSONDecodeError:
            ds = {}
    detected = (ds or {}).get("detected_os") if isinstance(ds, dict) else {}
    if isinstance(detected, dict):
        if detected.get("family"):
            fields["Operating System"] = str(detected["family"]).title()
        if detected.get("version"):
            fields["Version Number"] = str(detected["version"])
        if detected.get("build"):
            fields["Build Number"] = str(detected["build"])

    for row in _rows_from_parse(db, job_id, path_hint="SOFTWARE"):
        blob = json.dumps(row.get("normalized") or "")
        for key, label in (
            ("ProductName", "Operating System"),
            ("CurrentVersion", "Version Number"),
            ("CurrentBuild", "Build Number"),
            ("ComputerName", "Computer Name"),
            ("InstallDate", "Install Date"),
            ("ProductId", "Product ID"),
            ("DigitalProductId", "Product Key"),
        ):
            m = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"', blob)
            if m and fields.get(label) == "—":
                fields[label] = m.group(1)[:80]

    for row in _rows_from_parse(db, job_id, path_hint="SYSTEM"):
        blob = json.dumps(row.get("normalized") or "")
        m = re.search(r'"LastShutdownTime"\s*:\s*"([^"]+)"', blob)
        if m:
            fields["Last Shutdown"] = m.group(1)[:32]

    fields["System Root"] = "C:\\Windows"

    intro = """## A. OPERATING SYSTEM

### 1. OPERATING SYSTEM INFORMATION

This refers to details about the installed OS (Windows, macOS, Linux, etc.), including version, system settings, user accounts, boot logs, and configurations.

| Sr No | Artifacts Details | Value |
| ---: | --- | --- |"""
    mapping = [
        (1, "Operating System", fields["Operating System"]),
        (2, "Version Number", fields["Version Number"]),
        (3, "Installed/Updated Date/Time", fields["Install Date"]),
        (4, "Product Key", fields["Product Key"]),
        (5, "Computer Name", fields["Computer Name"]),
        (6, "Operating System Version", fields["Operating System"]),
        (7, "Build Number", fields["Build Number"]),
        (8, "Product ID", fields["Product ID"]),
        (9, "Last Shutdown Date/Time", fields["Last Shutdown"]),
        (10, "System Root", fields["System Root"]),
    ]
    lines = [intro]
    for sr, label, value in mapping:
        lines.append(f"| {sr} | {label} | {value} |")
    return "\n".join(lines)


def gather_artifact_summary_markdown(db, job_id: str, *, schema_name: str | None = None) -> str:
    from app.services.artifact_report_service import gather_artifact_summary

    md, _ = gather_artifact_summary(db, job_id, schema_name=schema_name)
    try:
        from app.services.browser_url_inventory import gather_browsing_summary_markdown

        browse_md = gather_browsing_summary_markdown(db, job_id, sample_limit=10)
        if browse_md.strip():
            md = (md or "").rstrip() + "\n\n" + browse_md
    except Exception:
        pass
    return md


def gather_browsing_summary_markdown(db, job_id: str, *, sample_limit: int = 10) -> str:
    """Report helper — short visited-URL / content-type summary."""
    from app.services.browser_url_inventory import gather_browsing_summary_markdown as _md

    return _md(db, job_id, sample_limit=sample_limit)


def _artifact_counts_by_name(db, job_id: str) -> dict[str, int]:
    rows = fetchall(
        db,
        """SELECT aa.artifact_name, r.artifact_count
           FROM job_axiom_artifact_results r
           JOIN public.axiom_artifacts aa ON aa.artifact_id = r.artifact_id
           WHERE r.job_id=:jid AND r.status='done'""",
        {"jid": job_id},
    )
    out: dict[str, int] = {}
    for row in rows:
        name = (row.get("artifact_name") or "").strip()
        if name:
            out[name] = max(out.get(name, 0), int(row.get("artifact_count") or 0))
    return out


_URL_ARTIFACT_NAMES = (
    "Social Media URLs",
    "Web Chat URLs",
    "Malware/Phishing URLs",
)

_ANNEXURE_LABEL_HINTS: dict[str, str] = {
    "social media urls": "url_category:social media urls",
    "web chat urls": "url_category:web chat urls",
    "malware/phishing urls": "url_category:malware/phishing urls",
    "malware / phishing urls": "url_category:malware/phishing urls",
    "pornography urls": "url_category:pornography urls",
    "dating site urls": "url_category:dating site urls",
    "facebook urls": "url_category:facebook",
    "browser history": "url_category:browser history",
    "browsing history": "url_category:browser history",
    "visited urls": "url_category:browser history",
    "usb devices": "usb_devices",
    "remote desktop protocol": "rdp_connections",
    "remote desktop protocol (rdp)": "rdp_connections",
    "recycle bin": "recycle_bin",
    "deleted files": "recycle_bin",
}


def _enabled_artifact_labels(scope: dict[str, Any]) -> dict[str, str]:
    """Map enabled artifact keys to normalized labels."""
    enabled = set(scope.get("enabled_keys") or [])
    out: dict[str, str] = {}
    for section in scope.get("sections") or []:
        if section.get("enabled") is False:
            continue
        for sub in section.get("subcategories") or []:
            key = sub.get("key") or ""
            if key in enabled:
                out[key] = (sub.get("label") or key).strip()
    if out:
        return out
    for group in scope.get("groups") or []:
        for art in group.get("artifacts") or []:
            key = str(art.get("key") or art.get("artifact_id") or "")
            if key in enabled:
                out[key] = (art.get("label") or art.get("artifact_name") or key).strip()
    return out


def _label_matches_annexure(label: str) -> str | None:
    low = label.strip().lower()
    if low in _ANNEXURE_LABEL_HINTS:
        return _ANNEXURE_LABEL_HINTS[low]
    for key, hint in _ANNEXURE_LABEL_HINTS.items():
        if key in low:
            return hint
    return None


def _url_rows_for_category(
    records: list[dict[str, Any]],
    *,
    category: str,
    limit: int,
) -> list[list[str]]:
    from app.services.browser_url_inventory import content_type_short_label, infer_url_content_type
    from app.services.url_category_counts import classify_url_category, url_matches_domains
    from app.services.url_category_counts import _FACEBOOK_SUFFIXES

    rows: list[list[str]] = []
    for rec in records:
        url = str(rec.get("url") or "").strip()
        if not url:
            continue
        if category == "facebook":
            if not url_matches_domains(url, _FACEBOOK_SUFFIXES):
                continue
        else:
            if classify_url_category(url) != category:
                continue
        host = url.split("/")[2] if "://" in url else url[:60]
        ct = content_type_short_label(rec.get("content_type") or infer_url_content_type(url))
        visits = max(int(rec.get("visit_count") or 0), 1)
        rows.append([str(len(rows) + 1), host, url[:200], ct, str(visits)])
        if len(rows) >= limit:
            break
    return rows


def _annexure_kinds_for_report_keys(
    db,
    job_id: str,
    report_keys: set[str],
    *,
    scope: dict[str, Any] | None = None,
) -> set[str]:
    """Derive annexure table kinds from report-template artifact selections."""
    from app.services.report_template_service import (
        list_template_artifacts,
        normalize_report_type_id,
        _intake_report_type,
    )

    annexure_kinds: set[str] = set()
    if report_keys:
        rt = normalize_report_type_id(_intake_report_type(db, job_id))
        for art in list_template_artifacts(db, rt):
            aid = str(art.get("artifact_id") or "")
            if aid not in report_keys:
                continue
            hint = _label_matches_annexure(str(art.get("artifact_name") or ""))
            if hint:
                annexure_kinds.add(hint)

    if scope is None:
        scope = artifact_scope_payload(db, job_id, read_only=True)
    enabled_labels = _enabled_artifact_labels(scope)
    if report_keys:
        enabled_labels = {k: v for k, v in enabled_labels.items() if k in report_keys}
    for label in enabled_labels.values():
        hint = _label_matches_annexure(label)
        if hint:
            annexure_kinds.add(hint)

    if "url_category:social media urls" in annexure_kinds:
        annexure_kinds.add("url_category:facebook")
    return annexure_kinds


def _objective_annexure_kinds(db, job_id: str) -> set[str]:
    """Evidence tables implied by selected examination objectives.

    AXIOM-style reports show the evidence needed to support the selected Objective /
    Procedure / Observation even when the user did not separately tick the matching
    artifact preview. This keeps Section D consistent with Section C.
    """
    try:
        from app.services.report_template_service import resolve_report_objectives

        objectives = resolve_report_objectives(db, job_id, None)
    except Exception:
        objectives = []
    titles = {str(o.get("title") or "").strip().lower() for o in objectives}
    kinds: set[str] = set()
    # V12: the five supplied examiner reports teach which Annexure evidence should
    # accompany each objective.  This is traceability guidance only; rows still come
    # exclusively from the current case.
    try:
        from app.services.report_reference_kb import reference_annexure_kinds

        for objective in objectives:
            kinds.update(reference_annexure_kinds(str(objective.get("title") or ""), str(objective.get("objective") or "")))
    except Exception:
        pass
    if any("cloud storage" in t for t in titles):
        kinds.add("url_category:cloud services")
    if any("whatsapp web" in t or "chat / communication" in t for t in titles):
        kinds.add("url_category:web chat urls")
    if any("malware" in t or "phishing" in t or "pornography" in t for t in titles):
        kinds.update({"url_category:malware/phishing urls", "url_category:pornography urls"})
    if any("usb" in t or "external hard disk" in t or "external device" in t for t in titles):
        kinds.add("usb_devices")
    if any("remote desktop" in t or "network connections" in t for t in titles):
        kinds.add("rdp_connections")
    if any("recycle" in t and "deleted" in t for t in titles):
        kinds.add("recycle_bin")
    return kinds


def gather_annexure_structured(db, job_id: str, *, url_sample_limit: int = 15) -> dict[str, Any]:
    """Annexure preview tables for selected artifacts only, with real sample rows when available."""
    from app.services.report_template_service import resolve_report_artifact_keys

    scope = artifact_scope_payload(db, job_id, read_only=True)
    report_keys = resolve_report_artifact_keys(db, job_id)
    annexure_kinds = _annexure_kinds_for_report_keys(db, job_id, report_keys, scope=scope) if report_keys else set()
    annexure_kinds.update(_objective_annexure_kinds(db, job_id))
    if not annexure_kinds:
        return {"tables": [], "url_sample_limit": url_sample_limit}

    tables: list[dict[str, Any]] = []
    url_records: list[dict[str, Any]] | None = None

    def _url_records() -> list[dict[str, Any]]:
        nonlocal url_records
        if url_records is None:
            from app.services.browser_url_inventory import collect_job_browser_url_records

            url_records = collect_job_browser_url_records(db, job_id)
        return url_records

    # Always lead with a short browsing overview when any browser URLs exist (or URL annexure selected).
    url_kinds_selected = any(k.startswith("url_category:") for k in annexure_kinds)
    try:
        from app.services.browser_url_inventory import gather_browsing_summary

        browse = gather_browsing_summary(db, job_id, sample_limit=url_sample_limit)
        if int(browse.get("total_urls") or 0) > 0 or url_kinds_selected:
            by_cat = browse.get("by_category") or {}
            by_ct = browse.get("by_content_type") or {}
            overview_rows = [
                ["Web Chat URLs", str(int(by_cat.get("web chat urls") or 0))],
                ["Social Media URLs", str(int(by_cat.get("social media urls") or 0))],
                ["Malware/Phishing URLs", str(int(by_cat.get("malware/phishing urls") or 0))],
                ["Pornography URLs", str(int(by_cat.get("pornography urls") or 0))],
                ["Dating Site URLs", str(int(by_cat.get("dating site urls") or 0))],
                ["Other URLs", str(int(by_cat.get("other") or 0))],
                ["Distinct URLs (total)", str(int(browse.get("total_urls") or 0))],
            ]
            for label, n in list(by_ct.items())[:6]:
                overview_rows.append([f"Content type — {label}", str(n)])
            sample_rows = []
            for i, s in enumerate(browse.get("samples") or [], 1):
                sample_rows.append([
                    str(i),
                    str(s.get("url") or "")[:200],
                    str(s.get("content_type_label") or "Web page"),
                    str(s.get("browser") or "—"),
                    str(int(s.get("visit_count") or 1)),
                ])
            tables.append({
                "title": "Browsing Activity (summary)",
                "total_count": int(browse.get("total_urls") or 0),
                "shown_count": len(overview_rows),
                "note": (
                    f"Visited URLs recovered from browser history — "
                    f"{int(browse.get('total_urls') or 0):,} distinct URL(s), "
                    f"{int(browse.get('total_visits') or 0):,} visit count total."
                ),
                "columns": ["Metric", "Count"],
                "rows": overview_rows,
            })
            if sample_rows:
                tables.append({
                    "title": "Browsing Activity (top visited URLs)",
                    "total_count": int(browse.get("total_urls") or 0),
                    "shown_count": len(sample_rows),
                    "note": f"Preview — {len(sample_rows)} most-visited URL(s) with content type.",
                    "columns": ["Sr. No", "URL", "Content Type", "Browser", "Visits"],
                    "rows": sample_rows,
                })
    except Exception:
        pass

    url_titles = {
        "url_category:social media urls": "Social Media URLs",
        "url_category:web chat urls": "Web Chat URLs",
        "url_category:malware/phishing urls": "Malware/Phishing URLs",
        "url_category:pornography urls": "Pornography URLs",
        "url_category:facebook": "Facebook URLs",
    }
    for kind, title in url_titles.items():
        if kind not in annexure_kinds:
            continue
        category = kind.split(":", 1)[1]
        rows = _url_rows_for_category(_url_records(), category=category, limit=url_sample_limit)
        if not rows:
            tables.append({
                "title": title,
                "total_count": 0,
                "shown_count": 0,
                "note": "No matching URLs were recovered from browser history on the examined device.",
                "columns": ["Sr. No", "Domain", "URL", "Content Type", "Visits"],
                "rows": [],
            })
            continue
        tables.append({
            "title": title,
            "total_count": len(rows),
            "shown_count": len(rows),
            "note": f"Preview — {len(rows)} sample URL(s) from browser history on the examined device.",
            "columns": ["Sr. No", "Domain", "URL", "Content Type", "Visits"],
            "rows": rows,
        })

    if "url_category:torrent" in annexure_kinds:
        from app.services.report_objective_case_facts import _browser_records_with_persisted_fallback, _is_torrent_url

        torrent_records, _ = _browser_records_with_persisted_fallback(db, job_id)
        seen_torrent: set[str] = set()
        torrent_rows: list[list[str]] = []
        total_torrent = 0
        for rec in torrent_records:
            url = str(rec.get("url") or "").strip()
            key = url.lower()
            if not url or key in seen_torrent or not _is_torrent_url(url):
                continue
            seen_torrent.add(key)
            total_torrent += 1
            if len(torrent_rows) < url_sample_limit:
                torrent_rows.append([
                    str(len(torrent_rows) + 1),
                    url[:240],
                    str(rec.get("browser") or "—"),
                    str(max(int(rec.get("visit_count") or 0), 1)),
                ])
        tables.append({
            "title": "Torrent URLs",
            "total_count": total_torrent,
            "shown_count": len(torrent_rows),
            "note": (
                f"Preview — {len(torrent_rows)} of {total_torrent:,} controlled torrent/magnet URL(s)."
                if total_torrent
                else "No controlled torrent/magnet URLs were recovered from the available browser evidence."
            ),
            "columns": ["Sr. No", "URL", "Browser", "Visits"],
            "rows": torrent_rows,
        })

    if "url_category:cloud services" in annexure_kinds:
        # Use the exact same resilient URL evidence pool as the Section C cloud
        # detector. This prevents Annexure and Observation from disagreeing when raw
        # History is unavailable but recovered/WAL or persisted snapshot evidence exists.
        from app.services.report_objective_case_facts import (
            _browser_records_with_persisted_fallback,
            _cloud_provider,
        )

        cloud_records, _cloud_source_notes = _browser_records_with_persisted_fallback(db, job_id)
        seen_urls: set[str] = set()
        cloud_rows: list[list[str]] = []
        total_cloud = 0
        for rec in cloud_records:
            url = str(rec.get("url") or "").strip()
            provider = _cloud_provider(url)
            key = url.lower().rstrip("/")
            if not provider or not url or key in seen_urls:
                continue
            seen_urls.add(key)
            total_cloud += 1
            if len(cloud_rows) < url_sample_limit:
                cloud_rows.append([
                    str(len(cloud_rows) + 1),
                    provider,
                    url[:240],
                    str(rec.get("browser") or "—"),
                    str(max(int(rec.get("visit_count") or 0), 1)),
                ])
        tables.append({
            "title": "Cloud Service URLs",
            "total_count": total_cloud,
            "shown_count": len(cloud_rows),
            "note": (
                f"Preview — {len(cloud_rows)} of {total_cloud:,} distinct cloud-service URL(s) recovered from browser evidence."
                if total_cloud
                else "No matching cloud-service URLs were recovered from the available browser evidence."
            ),
            "columns": ["Sr. No", "Site Name", "URL", "Browser", "Visits"],
            "rows": cloud_rows,
        })

    if "usb_devices" in annexure_kinds:
        from app.services.axiom_aligned_counts import count_usb_device_records

        total, devices = count_usb_device_records(db, job_id)
        shown = min(total, url_sample_limit) if total > 0 else 0
        rows = []
        for i, dev in enumerate(devices[:shown], 1):
            rows.append([
                str(i),
                str(dev.get("device_name") or dev.get("class_id") or "—")[:80],
                str(dev.get("serial") or "—")[:40],
                str(dev.get("source") or "—")[:120],
            ])
        tables.append({
            "title": "USB Connections",
            "total_count": total,
            "shown_count": shown,
            "note": (
                f"Showing {shown} of {total:,} USB device record(s)."
                if total > 0
                else "No USB connection records were recovered from the examined device."
            ),
            "columns": ["Sr. No", "Device", "Serial", "Source"],
            "rows": rows,
        })

    if "recycle_bin" in annexure_kinds:
        from app.services.report_objective_case_facts import _live_recycle_bin_records

        recycle_items = _live_recycle_bin_records(db, job_id)
        recycle_rows: list[list[str]] = []
        for item in recycle_items[:url_sample_limit]:
            original_path = str(item.get("original_path") or "")
            original_name = str(item.get("original_name") or "")
            if not original_name and original_path:
                original_name = original_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            recycle_rows.append([
                str(len(recycle_rows) + 1),
                original_name[:140] or "—",
                str(item.get("deleted_at") or "—")[:40],
                "Recovered Recycle Bin metadata" if item.get("descriptor_path") else "Recovered Recycle Bin payload",
            ])
        tables.append({
            "title": "Recycle Bin Deleted Items",
            "total_count": len(recycle_items),
            "shown_count": len(recycle_rows),
            "note": (
                f"Preview — {len(recycle_rows)} of {len(recycle_items):,} distinct Recycle Bin item(s)."
                if recycle_items
                else "No distinct Windows Recycle Bin items were recovered from the available evidence."
            ),
            "columns": ["Sr. No", "Original File", "Deletion Time", "Evidence"],
            "rows": recycle_rows,
        })

    if "rdp_connections" in annexure_kinds:
        from app.services.axiom_aligned_counts import count_rdp_connection_records

        total, conns = count_rdp_connection_records(db, job_id)
        shown = min(total, url_sample_limit) if total > 0 else 0
        rows = []
        for i, conn in enumerate(conns[:shown], 1):
            rows.append([
                str(i),
                str(conn.get("host") or "—")[:120],
                str(conn.get("user") or conn.get("username_hint") or "—")[:80],
            ])
        tables.append({
            "title": "Remote Desktop Protocol",
            "total_count": total,
            "shown_count": shown,
            "note": (
                f"Showing {shown} of {total:,} RDP connection record(s)."
                if total > 0
                else "No remote desktop connection records were recovered from the examined device."
            ),
            "columns": ["Sr. No", "Host / Server", "User Profile"],
            "rows": rows,
        })

    return {"tables": tables, "url_sample_limit": url_sample_limit}


def annexure_markdown(structured: dict[str, Any]) -> str:
    parts: list[str] = ["## D. Annexure", ""]
    for table in structured.get("tables") or []:
        parts.append(f"### {table.get('title')}")
        if table.get("note"):
            parts.append(f"*{table['note']}*")
        parts.append("")
        cols = table.get("columns") or []
        if cols:
            parts.append("| " + " | ".join(str(c) for c in cols) + " |")
            parts.append("| " + " | ".join("---" for _ in cols) + " |")
            for row in table.get("rows") or []:
                parts.append("| " + " | ".join(str(c) for c in row) + " |")
        parts.append("")
    if len(parts) <= 2:
        parts.append("_No annexure categories were selected on the Artifacts page._")
    return "\n".join(parts)


# Default Android mobile objective/procedure — matches Aetheris sample report (Sujit / Vivo).
_MOBILE_ANDROID_OBJECTIVE = (
    "The examination aims to collect digital evidence of money transaction or illegal "
    "payments from the Android devices. It involves checking messages, calls, documents, "
    "media, and financial records, identifying links with suppliers or third parties, "
    "recovering deleted data if possible, and creating a simple timeline of supply and "
    "payment activities during the supply of cattle feed / mixtures."
)

_MOBILE_ANDROID_PROCEDURE = [
    "Checked system integrity and Android version for any signs of rooting or unauthorized modifications.",
    "Reviewed installed applications for suspicious or unrecognized apps.",
    "Verified app permissions, background activities, and any unnecessary system permissions granted to apps.",
    "Scanned device storage and network activities using an Android security application.",
    "Examined browser history, downloads, and configuration profiles for any abnormalities.",
]


def gather_mobile_findings_markdown(intake: dict[str, Any]) -> str:
    """Single OBJECTIVE / PROCEDURE / FINDINGS block for mobile reports (no catalog objectives)."""
    # Prefer case brief when provided; otherwise use the standard Android mobile objective.
    objective = (intake.get("background") or intake.get("incident_summary") or "").strip()
    if not objective:
        objective = _MOBILE_ANDROID_OBJECTIVE
    lines = [
        "## OBJECTIVE, OBSERVATION with FINDINGS",
        "",
        "### 1. Objective",
        "",
        objective,
        "",
        "### 2. Procedure",
        "",
    ]
    for item in _MOBILE_ANDROID_PROCEDURE:
        lines.append(f"- {item}")
    lines.extend([
        "",
        "### 3. Observations",
        "",
        "_(Findings will be generated from the indexed mobile extraction evidence and artifacts during report generation.)_",
        "",
    ])
    return "\n".join(lines)


def gather_objectives_observation_context(db, job_id: str, intake: dict[str, Any]) -> str:
    """Objective / procedure block from intake — observations filled via LLM + RAG during generation."""
    from app.services.mobile_report_service import is_mobile_intake
    from app.services.report_template_service import resolve_report_objectives

    # Mobile reports never use multi-objective catalog blocks (Contacts / WhatsApp / …).
    if is_mobile_intake(intake):
        return gather_mobile_findings_markdown(intake)

    objectives = resolve_report_objectives(db, job_id, intake)
    if not objectives:
        return "**No examination objectives selected in Case intake.**"

    parts = ["## C. OBJECTIVE, PROCEDURE & OBSERVATION", ""]
    for idx, obj in enumerate(objectives, 1):
        parts.append(f"**{idx}. {obj.get('title')}**")
        parts.append("")
        parts.append("**Objective:**")
        parts.append(str(obj.get("objective") or obj.get("statement") or "—"))
        parts.append("")
        proc = obj.get("procedure_text") or obj.get("procedure") or "—"
        parts.append("**Procedure:**")
        parts.append(str(proc))
        parts.append("")
        parts.append("**Observation:**")
        parts.append("_(Pending — generated from intake procedure and RAG evidence.)_")
        parts.append("")
    return "\n".join(parts)


def gather_analysis_summary_markdown(db, job_id: str, intake: dict[str, Any]) -> str:
    from app.services.report_objective_evidence import format_procedure_for_report
    from app.services.report_template_service import resolve_report_objectives

    objectives = resolve_report_objectives(db, job_id, intake)
    parts = ["## E. ANALYSIS SUMMARY", ""]
    if not objectives:
        parts.append("_No objectives configured in intake._")
        return "\n".join(parts)

    obs_rows = fetchall(
        db,
        """SELECT objective_id, observation_md, status FROM job_objective_observations
           WHERE job_id=:jid""",
        {"jid": job_id},
    )
    obs_by_id = {str(r["objective_id"]): r for r in obs_rows}

    parts.append("| Sr. No. | Objective | Procedure | Observation |")
    parts.append("| ---: | --- | --- | --- |")
    for i, obj in enumerate(objectives, 1):
        obj_id = str(obj.get("id") or obj.get("objective_id") or "")
        title = str(obj.get("title") or obj_id).replace("|", "/")
        proc = format_procedure_for_report(
            str(obj.get("procedure_text") or obj.get("procedure") or "—"),
            title=str(obj.get("title") or ""),
        ).replace("|", "/").replace("\n", " ").strip() or "—"
        obs = obs_by_id.get(obj_id) or {}
        observation = (obs.get("observation_md") or "").strip().replace("|", "/").replace("\n", " ")
        if not observation:
            observation = (
                f"See Section C for the finding on {title}."
            )
        parts.append(f"| {i} | {title} | {proc} | {observation} |")
    parts.append("")
    return "\n".join(parts)


def gather_appendix_markdown(db, job_id: str) -> str:
    return "\n".join([
        "## F. APPENDIX",
        "",
        "• **Exhibit Details:** The details of the original exhibit.",
        "• **Target Drive Details:** The acquisition of the original exhibit onto another hard disk for analysis.",
        "• **Capacity:** The size or storage capacity of the hard disk.",
        "• **Media:** Audio, video, and picture files considered as media files.",
        "• **Shortcut files (LNK):** Shortcuts to programs, documents, or other files, used to see what was opened.",
        "• **Recent items list:** Quick lists of recent applications or files that a person launched.",
        "",
    ])


def gather_structured_section(
    section_key: str,
    db,
    job_id: str,
    intake: dict[str, Any],
    *,
    schema_name: str | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Return template/evidence markdown for a report section."""
    from app.services.mobile_report_service import (
        gather_mobile_cover_page_markdown,
        gather_mobile_introduction_markdown,
        gather_mobile_table_of_contents_markdown,
        gather_mobile_tools_markdown,
        is_mobile_intake,
        mobile_cover_structured,
    )

    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    mobile = is_mobile_intake(intake, job)

    if section_key == "cover_page":
        if mobile:
            md = gather_mobile_cover_page_markdown(intake, job, db=db, job_id=job_id)
            return md, mobile_cover_structured(intake, job, db, job_id)
        return gather_cover_page_markdown(intake, job), None
    if section_key == "table_of_contents":
        if mobile:
            return gather_mobile_table_of_contents_markdown(), None
        return gather_table_of_contents_markdown(intake, job), None
    if section_key == "introduction":
        if mobile:
            return gather_mobile_introduction_markdown(intake, job), None
        return gather_introduction_markdown(intake, job), None
    if section_key == "scope_of_work":
        return gather_scope_of_work_markdown(intake, job), None
    if section_key == "tools_used":
        if mobile:
            return gather_mobile_tools_markdown(intake, job), None
        return gather_tools_used_markdown(intake, job), None
    if section_key == "forensic_imaging":
        return gather_forensic_imaging_markdown(intake, job), None
    if section_key == "evidence_details":
        return _evidence_details_with_db(db, intake, job_id), None
    if section_key == "user_profile_information":
        if mobile:
            lines=['## A. DEVICE USER PROFILES','','An acquired account or user record alone does not identify the person operating the device.','']
            exists=fetchone(db,"SELECT to_regclass('mobile_normalized_artifacts') AS t")
            profiles=fetchall(db,"""SELECT artifact_id,artifact_type,data,forensic FROM mobile_normalized_artifacts
                WHERE job_id=:jid AND artifact_type IN ('device_account','device_user') ORDER BY artifact_id""",{'jid':job_id}) if exists and exists['t'] else []
            if profiles:
                lines+=['| Type | User/account | Provider / user ID | Source | Record |','| --- | --- | --- | --- | --- |']
                for profile in profiles:
                    data=profile['data'] or {};forensic=profile['forensic'] or {}
                    values=[profile['artifact_type'],data.get('name'),data.get('account_type') or data.get('user_id'),forensic.get('source_path'),profile['artifact_id']]
                    lines.append('| '+' | '.join(str(value or 'Unavailable').replace('|','\\|').replace('\n',' ') for value in values)+' |')
            else:
                lines.append('No readable user/account records were captured in this acquisition. Device Information and B. Artifacts show the available device and source provenance.')
            return '\n'.join(lines), None
        return gather_windows_users_markdown(db, job_id), None
    if section_key == "os_information":
        return gather_os_hardware_markdown(db, job_id), None
    if section_key == "device_information":
        from app.services.mobile_report_service import build_device_information_markdown

        return build_device_information_markdown(
            db, job_id, intake, schema_name=schema_name, use_llm=False,
        ), None
    if section_key == "extraction_summary":
        from app.services.mobile_report_service import build_extraction_summary_markdown

        md = build_extraction_summary_markdown(
            db, job_id, intake, schema_name=schema_name, use_llm=False,
        )
        try:
            from app.services.browser_url_inventory import gather_browsing_summary_markdown

            browse_md = gather_browsing_summary_markdown(db, job_id, sample_limit=8)
            if browse_md.strip() and "No visited URLs" not in browse_md:
                md = (md or "").rstrip() + "\n\n" + browse_md
        except Exception:
            pass
        return md, None
    if section_key == "artifact_summary":
        from app.services.artifact_report_service import gather_artifact_summary

        md, structured = gather_artifact_summary(db, job_id, schema_name=schema_name)
        try:
            from app.services.browser_url_inventory import gather_browsing_summary_markdown

            browse_md = gather_browsing_summary_markdown(db, job_id, sample_limit=10)
            if browse_md.strip():
                md = (md or "").rstrip() + "\n\n" + browse_md
                if isinstance(structured, dict):
                    structured = {**structured, "browsing_summary_included": True}
        except Exception:
            pass
        return md, structured
    if section_key == 'suspicious_activity':
        from app.services.suspicious_activity import suspicious_report_section
        return suspicious_report_section(db, job_id)
    if section_key == "objectives_procedure_observation":
        return gather_objectives_observation_context(db, job_id, intake), None
    if section_key == "annexure":
        if mobile:
            from app.services.mobile_report_service import gather_mobile_annexure_markdown

            md = gather_mobile_annexure_markdown(db, job_id, intake)
            try:
                from app.services.browser_url_inventory import gather_browsing_summary_markdown

                browse_md = gather_browsing_summary_markdown(db, job_id, sample_limit=12)
                if browse_md.strip() and "No visited URLs" not in browse_md:
                    md = (md or "").rstrip() + "\n\n" + browse_md
            except Exception:
                pass
            return md, {"report_variant": "mobile", "section": "annexure"}
        structured = gather_annexure_structured(db, job_id, url_sample_limit=15)
        return annexure_markdown(structured), structured
    if section_key == "final_analysis_summary":
        return gather_analysis_summary_markdown(db, job_id, intake), None
    if section_key == "appendix":
        return gather_appendix_markdown(db, job_id), None
    return "", None
