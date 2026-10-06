"""Aetheris forensic report templates — match sample PDF structure (Seger / Histotechlab)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.report_renderer import SECTION_ORDER, section_title

AETHERIS_COMPANY = "POLARON TECHNOLOGIES PVT. LTD."

_DEFAULT_TOOLS = [
    "Magnet AXIOM Examiner v7.2.0.36145",
    "AccessData® FTK® Imager 4.7.1.2",
]

_TOC_ENTRIES: list[tuple[str, str]] = [
    ("introduction", "INTRODUCTION"),
    ("os_information", "A. OPERATING SYSTEM"),
    ("user_profile_information", "A. OPERATING SYSTEM — User Profile"),
    ("artifact_summary", "B. ARTIFACTS"),
    ("objectives_procedure_observation", "C. OBJECTIVE, PROCEDURE & OBSERVATION"),
    ("annexure", "D. ANNEXURE"),
    ("final_analysis_summary", "E. ANALYSIS SUMMARY"),
    ("appendix", "F. APPENDIX"),
]


def _json_field(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def _subject_name(intake: dict[str, Any]) -> str:
    incident = (intake.get("incident_summary") or "") + " " + (intake.get("background") or "")
    m = re.search(r"\b(Mr\.?\s+[A-Za-z]+|Mrs\.?\s+[A-Za-z]+)\b", incident)
    if m:
        return m.group(1).replace("Mr.", "Mr.").strip()
    subjects = _json_field(intake.get("subjects"), []) or []
    if subjects and isinstance(subjects[0], dict):
        name = (subjects[0].get("name") or "").strip()
        if name:
            return name
    org = (intake.get("organization") or "").strip()
    if org:
        return org
    return "Subject"


def _device_label(intake: dict[str, Any], job: dict[str, Any] | None) -> str:
    ds = _json_field((job or {}).get("disk_source"), {}) or {}
    base = (ds.get("base_name") or "").strip()
    if base:
        return base
    subjects = _json_field(intake.get("subjects"), []) or []
    if subjects and isinstance(subjects[0], dict):
        role = (subjects[0].get("role") or "").strip()
        if role:
            return role
    return "Laptop"


def _report_date(intake: dict[str, Any]) -> str:
    raw = intake.get("evidence_received_date")
    if raw:
        if hasattr(raw, "strftime"):
            return raw.strftime("%d/%m/%Y")
        return str(raw)[:10]
    return datetime.now(timezone.utc).strftime("%d/%m/%Y")


def _format_count(n: int) -> str:
    return f"{n:,}"


def _disk_source(job: dict[str, Any] | None) -> dict[str, Any]:
    if not job:
        return {}
    return _json_field(job.get("disk_source"), {}) or {}


def gather_cover_page_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    subject = _subject_name(intake)
    return "\n".join([
        "# CYBER FORENSIC ANALYSIS REPORT",
        "",
        f'**"{subject}"**',
        "",
        AETHERIS_COMPANY,
    ])


def gather_table_of_contents_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    lines = ["## TABLE OF CONTENTS", ""]
    lines.append("| Sr No | Description | Page |")
    lines.append("| --- | --- | ---: |")
    page = 4
    for idx, (key, label) in enumerate(_TOC_ENTRIES, 1):
        lines.append(f"| {idx} | {label} | {page} |")
        page += 2 if key in ("artifact_summary", "objectives_procedure_observation", "annexure") else 1
    lines.extend(["", "*(Page numbers are indicative for export layout.)*"])
    return "\n".join(lines)


def _client_address_lines(intake: dict[str, Any]) -> list[str]:
    """Recipient name and postal address only — never case narrative or background text."""
    org = (intake.get("organization") or "").strip()
    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}
    raw_address = (vol18.get("client_address") or intake.get("address") or "").strip()

    lines: list[str] = []
    if org:
        lines.append(org + ("," if not org.endswith(",") else ""))

    if not raw_address:
        return lines

    narrative_re = re.compile(
        r"\b(forensic|examination|requested|device identified|evidence ex-|transferred outside|"
        r"submitted forensic|analysis has been|conduct cyber forensic)\b",
        re.I,
    )
    for part in re.split(r"\n+", raw_address):
        line = part.strip()
        if not line:
            continue
        if org and line.lower().rstrip(",.") == org.lower():
            continue
        if len(line) > 120 or narrative_re.search(line):
            continue
        lines.append(line + ("" if line.endswith(",") or line.endswith(".") else ","))
    return lines


def gather_introduction_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    org = (intake.get("organization") or "Client Organization").strip()
    date_str = _report_date(intake)
    case_type = (intake.get("case_type") or "forensic examination").strip()
    examiner = (intake.get("examiner_name") or "Digital Forensic Analyst").strip()
    device = _device_label(intake, job)

    address_lines = _client_address_lines(intake)
    if not address_lines and org:
        address_lines = [org + ","]

    scope = _json_field(intake.get("scan_scope_json"), {}) or {}
    scope_items = scope.get("events") or scope.get("items") or []
    if isinstance(scope_items, list) and scope_items:
        scope_text = "\n".join(f"{i + 1}. {item}" for i, item in enumerate(scope_items))
    else:
        scope_text = (
            "1. Computer forensic extraction of the system and identification of data transfer "
            "from outside the organization, if any."
        )

    body = (
        f"With reference to the above subject, I have received a request from you to conduct cyber forensic "
        f"audit relating to {case_type}. I have completed your case as per our standard procedures; "
        f"our analysis has been reported on {date_str}."
    )

    return "\n".join([
        "## INTRODUCTION",
        "",
        f"**Date:** {date_str}",
        "",
        "**To,**",
        *address_lines,
        "",
        "**Subject:** Computer Forensic Extraction Report",
        "",
        "Dear Sir,",
        "",
        body,
        "",
        "**Scope of Work:**",
        f"Conduct forensic extraction of devices ({device}) identified by the client for the following events:",
        scope_text,
        "",
        "**Terms and Condition:**",
        "1. The report has indicated the status of recovered data.",
        "2. All data taken from devices for the purpose of analysis will be destroyed immediately after the report submission.",
        "",
        f"**{examiner}**",
        "",
        f"**{AETHERIS_COMPANY}**",
    ])


def gather_scope_of_work_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    """Standalone scope section (also summarized in Introduction per sample PDF)."""
    device = _device_label(intake, job)
    objectives = _json_field(intake.get("objective_ids"), []) or []
    custom = _json_field(intake.get("custom_objectives"), []) or []
    lines = [
        "## Scope of Work",
        "",
        f"Forensic examination of **{device}** covering:",
        "",
    ]
    if objectives or custom:
        idx = 1
        for obj in custom:
            title = obj.get("title") if isinstance(obj, dict) else str(obj)
            lines.append(f"{idx}. {title}")
            idx += 1
        if objectives and not custom:
            lines.append(f"{idx}. {len(objectives)} examination objective(s) selected in case intake (see Section C).")
    else:
        lines.append(
            "1. Computer forensic extraction and analysis of the seized device per client request."
        )
    return "\n".join(lines)


def gather_tools_used_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}
    tools = vol18.get("tools") or vol18.get("tools_used")
    if isinstance(tools, list) and tools:
        tool_names = [str(t.get("name") if isinstance(t, dict) else t) for t in tools]
    else:
        tool_names = _DEFAULT_TOOLS

    lines = [
        "## TOOLS USED FOR ACQUISITION AND EXTRACTION",
        "",
        "| Sr No | Tool Name |",
        "| ---: | --- |",
    ]
    for i, name in enumerate(tool_names, 1):
        lines.append(f"| {i} | {name} |")
    return "\n".join(lines)


def gather_forensic_imaging_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    ds = _disk_source(job)
    org = (intake.get("organization") or "Client").strip()
    device = _device_label(intake, job)
    vol18 = _json_field(intake.get("vol18_form_json"), {}) or {}

    custodian = vol18.get("custodian_name") or org
    evidence_tag = vol18.get("evidence_tag") or device
    acq_start = vol18.get("acquisition_started") or "—"
    acq_finish = vol18.get("acquisition_finished") or "—"

    # Do not mislabel a registered evidence-file SHA-256 as the forensic image SHA-1.
    # ``segment_hashes`` are populated from evidence_files.sha256 by virtual_disk.py.
    # A whole-image SHA-1 is shown only when acquisition/intake metadata explicitly
    # supplies one.  This distinction is material in forensic reports.
    hashes = [str(h).strip() for h in (ds.get("segment_hashes") or []) if str(h).strip()]
    explicit_sha1 = str(vol18.get("image_hash_sha1") or ds.get("image_hash_sha1") or "").strip()
    if explicit_sha1:
        hash_header = "Image Hash SHA1"
        image_hash = explicit_sha1
    elif hashes:
        hash_header = "Evidence File SHA-256"
        image_hash = hashes[0]
    else:
        hash_header = "Image Hash"
        image_hash = "—"

    lines = [
        "## FORENSIC IMAGING",
        "",
        "Details of laptop acquisition are given below:",
        "",
        f"| Sr No | Custodian Name | Evidence Tag | Acquisition Started | Acquisition Finished | {hash_header} |",
        "| ---: | --- | --- | --- | --- | --- |",
        f"| 1 | {custodian} | {evidence_tag} | {acq_start} | {acq_finish} | {image_hash} |",
        "",
        f"Forensic imaging has been performed of the device provided by **{org}**. "
        "Details of the respective storage are given below:",
        "",
        "| Custodian Name | Type | Drive Model | Drive Serial No. | Capacity | Location |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    exhibit = vol18.get("exhibit") or {}
    if isinstance(exhibit, dict) and exhibit:
        lines.append(
            f"| {exhibit.get('custodian', custodian)} | {exhibit.get('type', 'Laptop')} | "
            f"{exhibit.get('model', '—')} | {exhibit.get('serial', '—')} | "
            f"{exhibit.get('capacity', '—')} | {exhibit.get('location', org)} |"
        )
    else:
        # bytes_extracted is the amount materialized by the parser, not the physical
        # storage capacity.  Reporting it as drive capacity can make a partial or
        # filtered extraction look like a different source disk.
        lines.append(f"| {custodian} | Laptop | — | — | — | {org} |")

    subject = _subject_name(intake)
    lines.extend([
        "",
        f"## FORENSIC ANALYSIS ON",
        f'**"{subject}"**',
        f"({device})",
    ])
    return "\n".join(lines)


def gather_evidence_details_markdown(intake: dict[str, Any], job: dict[str, Any] | None = None) -> str:
    ds = _disk_source(job)
    base = (ds.get("base_name") or "Evidence image").strip()
    fmt = (ds.get("format") or "E01").upper()
    files_total = int(ds.get("files_extracted") or ds.get("files_total") or 0)
    bytes_ext = int(ds.get("bytes_extracted") or 0)
    size_human = f"{bytes_ext / (1024 ** 3):.2f} GB" if bytes_ext else "—"
    coc = (intake.get("chain_of_custody_ref") or "—").strip()

    lines = [
        "## Evidence Details",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Evidence image | {base}.{fmt.lower()} |",
        f"| Image format | {fmt} |",
        f"| Files extracted | {_format_count(files_total)} |",
        f"| Data volume | {size_human} |",
        f"| Chain of custody reference | {coc} |",
        f"| Case type | {intake.get('case_type') or '—'} |",
    ]
    return "\n".join(lines)


def _evidence_details_with_db(db, intake: dict[str, Any], job_id: str) -> str:
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    md = gather_evidence_details_markdown(intake, job)
    ev = fetchall(
        db,
        """SELECT original_name, sha256, size_bytes FROM evidence_files
           WHERE job_id=:jid ORDER BY segment_part NULLS LAST, original_name LIMIT 10""",
        {"jid": job_id},
    )
    if ev:
        md += "\n\n### E01 Segments\n\n| Segment | SHA-256 (prefix) | Size |\n| --- | --- | ---: |\n"
        for row in ev:
            sha = (row.get("sha256") or "—")[:16]
            size = row.get("size_bytes") or 0
            size_s = f"{int(size) / (1024 ** 3):.2f} GB" if size else "—"
            md += f"| {row.get('original_name')} | {sha}… | {size_s} |\n"
    return md
