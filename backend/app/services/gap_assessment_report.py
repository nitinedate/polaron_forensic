"""Gap Assessment Report — Aetheris template (Lilavati-style) per case."""

from __future__ import annotations

import html
import io
import json
import re
from datetime import date, datetime, timezone
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.gap_report_llm import enrich_gap_findings
from app.services.gap_report_template import build_styled_gap_report_html
from app.services.scan_assessment_evidence import load_case_scan_assessment, merge_scan_assessments
from app.services.vuln_report_export import _risk_label, load_service_coverage

_RISK_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

_gap_site_column_ready = False


def ensure_gap_site_column(db) -> None:
    """Idempotent: older firm schemas may lack cases.gap_site_json."""
    global _gap_site_column_ready
    if _gap_site_column_ready:
        return
    from app.db.sql_helpers import execute

    try:
        execute(
            db,
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS gap_site_json JSONB DEFAULT '{}'::jsonb",
        )
        db.commit()
        _gap_site_column_ready = True
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        # Fall through — caller will surface the original DB error if still missing.
        raise


def _group_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Keep service instances distinct. The same NVT/CVE on tcp/443 and
    # tcp/8443 is not the same affected service and must not be collapsed.
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    for r in rows:
        name = (r.get("synopsis") or r.get("cve") or "Finding").strip()
        host = (r.get("host") or "").strip()
        sev = (r.get("severity") or "medium").lower()
        risk = _risk_label(sev, r.get("cvss"))
        try:
            port_key = int(r.get("port")) if r.get("port") is not None else -1
        except (TypeError, ValueError):
            port_key = -1
        protocol = str(r.get("protocol") or "").strip().lower()
        identity = str(r.get("plugin_id") or r.get("cve") or name).strip().casefold()
        key = (identity, port_key, protocol)
        if key not in groups:
            groups[key] = {
                "name": name,
                "risk": risk,
                "risk_rank": _RISK_RANK.get(risk, 5),
                "hosts": set(),
                "port": None if port_key < 0 else port_key,
                "protocol": protocol or None,
                "service": r.get("service"),
                "plugin_id": r.get("plugin_id"),
                "cve": r.get("cve"),
                "cvss": r.get("cvss"),
                "description": (r.get("description") or "").strip(),
                "observation": (r.get("description") or r.get("synopsis") or "").strip(),
                "remediation": (r.get("remediation") or "").strip(),
                "nvt_impact": "",
            }
        g = groups[key]
        rank = _RISK_RANK.get(risk, 5)
        if rank < g["risk_rank"]:
            g["risk_rank"] = rank
            g["risk"] = risk
        if host:
            g["hosts"].add(host)
        if not g["description"] and r.get("description"):
            g["description"] = str(r["description"]).strip()
        if not g["remediation"] and r.get("remediation"):
            g["remediation"] = str(r["remediation"]).strip()
        rf = r.get("risk_factors_json")
        if isinstance(rf, str):
            try:
                rf = json.loads(rf)
            except json.JSONDecodeError:
                rf = {}
        if isinstance(rf, dict) and rf.get("nvt_impact") and not g.get("nvt_impact"):
            g["nvt_impact"] = str(rf.get("nvt_impact") or "").strip()
        if r.get("nvt_impact") and not g.get("nvt_impact"):
            g["nvt_impact"] = str(r.get("nvt_impact") or "").strip()
    out = list(groups.values())
    for g in out:
        g["hosts"] = sorted(g["hosts"])
    out.sort(key=lambda x: (x["risk_rank"], x["name"].lower()))
    return out


DEFAULT_KEY_CONTACTS = [
    {"name": "Mr. Nitin Jambhale", "title": "Operations Manager", "email": "nitin@aetheris.in"},
]

_LEGACY_CONTACT_EMAILS = frozenset({"makarand@aetheris.in", "nivedita@aetheris.in"})


def _resolved_key_contacts(contacts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not contacts:
        return DEFAULT_KEY_CONTACTS
    emails = {
        str(c.get("email", "")).strip().lower()
        for c in contacts
        if isinstance(c, dict) and str(c.get("email", "")).strip()
    }
    if emails & _LEGACY_CONTACT_EMAILS:
        return DEFAULT_KEY_CONTACTS
    return contacts

DEFAULT_GAP_INTRO = """This report presents the results of the Vulnerability Assessment conducted by AETHERIS TECHNOLOGIES PVT LTD. on IP's as per project scope.

The purpose of this assessment was to…

• Test the IPs to identify technical vulnerabilities and discover whether a malicious user may leverage these flaws to compromise the security.
• Provide recommendations for risk mitigation that may arise on successful exploitation of these vulnerabilities.

The subsequent sections of this document provide statistics of the vulnerabilities identified; severity of VA done for IP. The detailed technical findings section constitutes identified vulnerabilities with recommendations to mitigate security risks associated with IP. The assessment was done as per VA methodology.

During the time of assessment, the testing team has considered the latest vulnerabilities and security threats that were disclosed. Our opinion provided in this report is valid for the period during which the assessment was carried out and is based on the information provided for the assessment. Projection of any conclusions based on our findings for future periods is subject to the risk that the validity of such conclusions may be altered because of changes made to the network or application or system. Furthermore, the findings in this report reflect the conditions found during the assessment, and do not necessarily reflect current conditions."""


def _esc(text: str | None) -> str:
    return html.escape(str(text or ""))


def _parse_json_field(val: Any) -> dict[str, Any]:
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val.strip():
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def load_case_row(db, case_id: str) -> dict[str, Any] | None:
    row = fetchone(db, "SELECT * FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    return dict(row) if row else None


_MISSING_SITE_VALUES = {"", "-", "—", "n/a", "na", "not specified", "unknown"}


def _site_value_missing(value: Any) -> bool:
    """Return True when an intake value is only a blank/placeholder value."""
    return str(value or "").strip().lower() in _MISSING_SITE_VALUES


def _derive_case_endpoint_count(db, case_id: str) -> int | None:
    """Derive the number of in-scope endpoints from real vulnerability data.

    Prefer active assets because they represent hosts actually materialized by scan
    ingestion, including completed scans with zero findings.  If scan ingestion has
    not created assets yet, fall back to distinct host-like scan targets.  CIDR and
    network ranges are deliberately not counted as one endpoint.
    """
    asset_row = fetchone(
        db,
        """SELECT COUNT(DISTINCT LOWER(BTRIM(
                     COALESCE(NULLIF(BTRIM(primary_ip), ''), NULLIF(BTRIM(hostname), ''))
                   ))) AS endpoint_count
           FROM vuln_assets
           WHERE case_id = CAST(:cid AS uuid)
             AND COALESCE(lifecycle_state, 'active') <> 'retired'
             AND COALESCE(NULLIF(BTRIM(primary_ip), ''), NULLIF(BTRIM(hostname), '')) IS NOT NULL""",
        {"cid": case_id},
    )
    try:
        asset_count = int((asset_row or {}).get("endpoint_count") or 0)
    except (TypeError, ValueError):
        asset_count = 0
    if asset_count > 0:
        return asset_count

    target_row = fetchone(
        db,
        """SELECT COUNT(DISTINCT LOWER(BTRIM(t.target))) AS endpoint_count
           FROM vuln_scan_targets t
           JOIN vuln_scan_jobs j ON j.id = t.scan_job_id
           WHERE j.case_id = CAST(:cid AS uuid)
             AND COALESCE(t.excluded, FALSE) = FALSE
             AND BTRIM(COALESCE(t.target, '')) <> ''
             AND LOWER(BTRIM(COALESCE(t.target_type, 'host')))
                 IN ('host', 'hostname', 'ip', 'ipv4', 'ipv6', 'endpoint')""",
        {"cid": case_id},
    )
    try:
        target_count = int((target_row or {}).get("endpoint_count") or 0)
    except (TypeError, ValueError):
        target_count = 0
    return target_count if target_count > 0 else None


def _apply_derived_site_facts(db, case_id: str, site: dict[str, Any]) -> dict[str, Any]:
    """Fill report facts from scan data without overwriting examiner-entered intake."""
    if _site_value_missing(site.get("num_endpoints")):
        endpoint_count = _derive_case_endpoint_count(db, case_id)
        if endpoint_count is not None:
            site["num_endpoints"] = str(endpoint_count)
    return site


def load_gap_site(db, case_id: str) -> dict[str, Any]:
    ensure_gap_site_column(db)
    row = load_case_row(db, case_id)
    if not row:
        return {}
    raw = _parse_json_field(row.get("gap_site_json"))
    site = dict(raw)
    if not site.get("client_name") and row.get("title"):
        site.setdefault("client_name", row["title"])
    site["key_contacts"] = _resolved_key_contacts(site.get("key_contacts"))
    # Strip legacy default author; leave blank for examiner to fill.
    if str(site.get("author") or "").strip() == "Manav Mahapatra":
        site["author"] = ""
    site.setdefault("author", "")
    site.setdefault("document_version", "1.0")
    site.setdefault("company_name", "Aetheris Technologies Pvt Ltd")
    site["has_saved_intake"] = bool(raw)
    return site


def save_gap_site(db, case_id: str, site: dict[str, Any]) -> dict[str, Any]:
    ensure_gap_site_column(db)
    payload = {k: v for k, v in site.items() if k != "has_saved_intake"}
    execute_payload = json.dumps(payload)
    from app.db.sql_helpers import execute

    execute(
        db,
        """UPDATE cases SET gap_site_json = CAST(:js AS jsonb), updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"js": execute_payload, "id": case_id},
    )
    db.commit()
    return load_gap_site(db, case_id)


def _load_open_finding_rows(db, case_id: str) -> list[dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT f.id, f.plugin_id, f.plugin_family, f.cve, f.severity, f.cvss,
                  f.port, f.protocol, f.service, f.synopsis, f.description, f.remediation,
                  f.risk_factors_json,
                  COALESCE(a.primary_ip, a.hostname, '') AS host
           FROM vuln_findings f
           LEFT JOIN vuln_assets a ON a.id = f.asset_id
           WHERE f.case_id = CAST(:cid AS uuid) AND f.status = 'open'
           ORDER BY f.enterprise_risk_score DESC NULLS LAST, f.severity, f.synopsis, f.port""",
        {"cid": case_id},
    )
    return [dict(r) for r in rows]


def _finding_inventory_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    informational: list[dict[str, Any]] = []
    for r in rows:
        risk = _risk_label(str(r.get("severity") or "info").lower(), r.get("cvss"))
        counts[risk if risk in counts else "Info"] += 1
        if risk == "Info":
            informational.append(
                {
                    "id": str(r.get("id") or ""),
                    "name": (r.get("synopsis") or r.get("cve") or "Informational observation").strip(),
                    "host": str(r.get("host") or "").strip(),
                    "port": r.get("port"),
                    "protocol": str(r.get("protocol") or "").strip(),
                    "service": str(r.get("service") or "").strip(),
                    "plugin_id": str(r.get("plugin_id") or "").strip(),
                    "plugin_family": str(r.get("plugin_family") or "").strip(),
                    "cvss": r.get("cvss"),
                }
            )
    grouped = _group_findings(rows)
    actionable = [f for f in grouped if f.get("risk") != "Info"]
    informational.sort(
        key=lambda x: (
            x.get("host") or "",
            int(x.get("port")) if isinstance(x.get("port"), int) else -1,
            (x.get("name") or "").lower(),
        )
    )
    return {
        "findings": actionable,
        "informational_findings": informational,
        "finding_summary": {
            **counts,
            "total": len(rows),
            "actionable": sum(counts[k] for k in ("Critical", "High", "Medium", "Low")),
            "informational": counts["Info"],
        },
    }


def load_gap_finding_inventory(db, case_id: str) -> dict[str, Any]:
    return _finding_inventory_from_rows(_load_open_finding_rows(db, case_id))


def load_grouped_findings(db, case_id: str) -> list[dict[str, Any]]:
    return load_gap_finding_inventory(db, case_id)["findings"]


def _bullets_from_text(text: str) -> list[str]:
    if not text:
        return []
    parts = re.split(r"[\n\r]+|(?<=[.!?])\s+(?=[A-Z])", text.strip())
    items = [p.strip(" •\t-") for p in parts if p.strip()]
    return items[:12]


def _mitigation_bullets(remediation: str) -> list[str]:
    if not remediation:
        return ["Review and remediate per vendor guidance and organizational change control."]
    lines = [ln.strip(" •\t-") for ln in remediation.replace("\r", "").split("\n") if ln.strip()]
    if len(lines) > 1:
        return lines[:10]
    return _bullets_from_text(remediation) or [remediation]


def _is_scanner_stub(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t or len(t) < 20:
        return True
    stub_markers = (
        "stub",
        "nuclei",
        "trivy",
        "wazuh",
        "zap stub",
        "template match",
        "passive scan finding",
        "endpoint visibility finding",
        "nmap discovered open tcp/",
    )
    if any(m in t for m in stub_markers):
        return True
    if t.startswith("the system is affected by") and len(t) < 120:
        return True
    return False


def _impact_text(name: str, description: str, risk: str) -> str:
    if description and len(description) > 40 and not _is_scanner_stub(description):
        return description
    return (
        f"The presence of {name} ({risk} severity) increases the likelihood of unauthorized access, "
        f"data exposure, or service disruption if exploited by a malicious actor."
    )


def _page_text(text: str, *, max_len: int = 420) -> str:
    text = (text or "").strip()
    if len(text) <= max_len:
        return text
    cut = text[: max_len - 1].rsplit(" ", 1)[0] or text[: max_len - 1]
    return cut.rstrip(".,;:") + "…"


def _finding_observation(f: dict[str, Any]) -> str:
    for key in ("client_observation", "observation", "description"):
        val = (f.get(key) or "").strip()
        if len(val) >= 50 and not _is_scanner_stub(val):
            return _page_text(val, max_len=520)
    name = f.get("name") or "This finding"
    risk = f.get("risk") or "Medium"
    return _page_text(
        f"During the assessment, {name} was identified on the in-scope systems. "
        f"This issue is rated {risk} severity and should be remediated to reduce the "
        f"risk of unauthorized access, data exposure, or service disruption.",
        max_len=520,
    )


def _finding_impact(f: dict[str, Any]) -> str:
    if f.get("client_impact"):
        return _page_text(str(f["client_impact"]).strip(), max_len=520)
    nvt_impact = str(f.get("nvt_impact") or "").strip()
    if len(nvt_impact) >= 40 and not _is_scanner_stub(nvt_impact):
        return _page_text(nvt_impact, max_len=520)
    name = f.get("name") or "Finding"
    risk = f.get("risk") or "Medium"
    return _page_text(
        f"The presence of {name} ({risk} severity) increases the risk of unauthorized access, "
        f"data exposure, or service disruption if exploited by a malicious actor.",
        max_len=520,
    )


def _finding_description(f: dict[str, Any]) -> str:
    for key in ("client_description", "description", "observation"):
        val = (f.get(key) or "").strip()
        if len(val) >= 50 and not _is_scanner_stub(val):
            return _page_text(val, max_len=520)
    return _finding_observation(f)


def _finding_mitigation(f: dict[str, Any]) -> list[str]:
    client = f.get("client_mitigation")
    if isinstance(client, list) and client:
        return [_page_text(str(x).strip(), max_len=280) for x in client if str(x).strip()][:5]
    return [_page_text(x, max_len=280) for x in _mitigation_bullets(f.get("remediation") or "")][:5]


def _finding_recommendation(f: dict[str, Any]) -> str:
    from app.services.gap_report_llm import (
        _build_recommendation_text,
        _display_finding_name,
        _recommendation_is_detailed,
        _is_scanner_stub,
    )

    rem = str(f.get("remediation") or "").strip()
    if len(rem) >= 60 and not _is_scanner_stub(rem):
        return _page_text(rem, max_len=520)
    rec = (f.get("client_recommendation") or "").strip()
    mit = _finding_mitigation(f)
    name = _display_finding_name(f.get("name") or "Finding")
    risk = f.get("risk") or "Medium"
    if rec and _recommendation_is_detailed(rec):
        return _page_text(rec, max_len=520)
    return _page_text(_build_recommendation_text(name, risk, mit), max_len=520)


def _finding_mitigation_paragraph(f: dict[str, Any]) -> str:
    from app.services.gap_report_llm import (
        _build_mitigation_text,
        _display_finding_name,
        _mitigation_is_detailed,
        _is_scanner_stub,
    )

    rem = str(f.get("remediation") or "").strip()
    if len(rem) >= 60 and not _is_scanner_stub(rem):
        return _page_text(rem, max_len=520)

    para = str(f.get("client_mitigation_paragraph") or "").strip()
    if _mitigation_is_detailed(para):
        return _page_text(para, max_len=520)

    client = f.get("client_mitigation")
    bullets: list[str] = []
    if isinstance(client, list) and client:
        bullets = [str(x).strip() for x in client if str(x).strip()]
    elif para:
        return _page_text(para, max_len=520)
    else:
        bullets = _mitigation_bullets(rem)

    name = _display_finding_name(f.get("name") or "Finding")
    risk = f.get("risk") or "Medium"
    return _page_text(_build_mitigation_text(name, risk, bullets), max_len=520)


def build_gap_report_context(
    db,
    case_id: str,
    *,
    site_override: dict[str, Any] | None = None,
    use_llm: bool | None = None,
) -> dict[str, Any]:
    case_row = load_case_row(db, case_id)
    if not case_row:
        raise ValueError("Case not found")
    site = load_gap_site(db, case_id)
    stored_site = dict(site)
    if site_override:
        site = {**site, **{k: v for k, v in site_override.items() if v is not None and k != "has_saved_intake"}}
    _apply_derived_site_facts(db, case_id, site)
    inventory = load_gap_finding_inventory(db, case_id)
    findings = inventory["findings"]
    client = site.get("client_name") or case_row.get("title") or "Client"
    if findings:
        cache_key = _findings_cache_key(findings)
        cached = site.get("_enriched_findings_cache")
        if isinstance(cached, dict) and cached.get("key") == cache_key and cached.get("items"):
            findings = cached["items"]
        else:
            from app.config import get_settings

            llm_on = use_llm if use_llm is not None else bool(get_settings().gap_report_llm_enabled)
            findings = enrich_gap_findings(findings, client=client, enabled=llm_on)
            if llm_on:
                cache_value = {"key": cache_key, "items": findings}
                site["_enriched_findings_cache"] = cache_value
                stored_site["_enriched_findings_cache"] = cache_value
                try:
                    # Persist only saved intake + enrichment cache.  Auto-derived
                    # report facts (for example num_endpoints) must remain dynamic.
                    save_gap_site(db, case_id, stored_site)
                except Exception:
                    pass
    assessment = load_case_scan_assessment(db, case_id)
    return {
        "case_id": case_id,
        "case": case_row,
        "site": site,
        "client": client,
        "report_date": date.today().strftime("%d-%m-%Y"),
        "findings": findings,
        "informational_findings": inventory["informational_findings"],
        "finding_summary": inventory["finding_summary"],
        "assessment": assessment,
        "service_coverage_jobs": load_service_coverage(db, case_id=case_id),
        "intro": site.get("introduction") or DEFAULT_GAP_INTRO,
    }


def _findings_cache_key(findings: list[dict[str, Any]]) -> str:
    parts = [
        f"{f.get('name')}|{f.get('risk')}|{f.get('port')}|{f.get('protocol')}|{','.join(f.get('hosts') or [])}"
        for f in findings
    ]
    return str(hash(("gap-enrich-v4-port-aware", tuple(parts))))


def build_gap_report_html(ctx: dict[str, Any], *, include_cover: bool = True) -> str:
    ctx = {
        **ctx,
        "_impact_text": _finding_impact,
        "_mitigation_text": _finding_mitigation_paragraph,
        "_finding_observation": _finding_observation,
        "_finding_description": _finding_description,
    }
    if not ctx["site"].get("key_contacts"):
        ctx = {**ctx, "site": {**ctx["site"], "key_contacts": DEFAULT_KEY_CONTACTS}}
    return build_styled_gap_report_html(ctx, include_cover=include_cover)


def render_gap_pdf(
    html_content: str,
    *,
    client: str | None = None,
    company: str | None = None,
    report_date: str | None = None,
) -> bytes | None:
    try:
        from xhtml2pdf import pisa

        buf = io.BytesIO()
        status = pisa.CreatePDF(html_content, dest=buf, encoding="utf-8")
        if status.err:
            return None
        if buf.tell() <= 100:
            return None
        body_pdf = buf.getvalue()
    except Exception:
        return None

    from app.services.gap_report_template import apply_confidential_watermark, stamp_gap_page_numbers

    if not client:
        stamped = apply_confidential_watermark(body_pdf, skip_first_page=False)
        return stamp_gap_page_numbers(stamped)

    try:
        import fitz

        from app.services.gap_report_template import render_gap_cover_pdf

        cover_pdf = render_gap_cover_pdf(
            client,
            company or "Aetheris Technologies Pvt Ltd",
            report_date or "",
        )
        if not cover_pdf:
            stamped = apply_confidential_watermark(body_pdf, skip_first_page=False)
            return stamp_gap_page_numbers(stamped)

        cover_doc = fitz.open(stream=cover_pdf, filetype="pdf")
        body_doc = fitz.open(stream=body_pdf, filetype="pdf")
        if body_doc.page_count > 0:
            cover_doc.insert_pdf(body_doc)
        merged = cover_doc.tobytes()
        cover_doc.close()
        body_doc.close()
        stamped = apply_confidential_watermark(merged, skip_first_page=True)
        return stamp_gap_page_numbers(stamped)
    except Exception:
        stamped = apply_confidential_watermark(body_pdf, skip_first_page=False)
        return stamp_gap_page_numbers(stamped)


def render_gap_docx(ctx: dict[str, Any]) -> bytes:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc = Document()
    client = ctx["client"]
    site = ctx["site"]
    findings = ctx["findings"]

    cover = doc.add_paragraph()
    cover.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = cover.add_run("GAP ANALYSIS REPORT\n")
    run.bold = True
    cover.add_run(f"\n{client}\n\n")
    cover.add_run(site.get("company_name", "Aetheris Technologies Pvt Ltd"))
    doc.add_page_break()

    doc.add_heading("1. Introduction", level=1)
    doc.add_paragraph(ctx["intro"])

    doc.add_heading("2. Site Overview / Site Infrastructure", level=1)
    for label, key in (
        ("CLIENT", "client_name"),
        ("BRANCH LOCATION's", "branch_locations"),
        ("CONTACT PERSON", "contact_person"),
    ):
        doc.add_paragraph(f"{label}: {site.get(key, client if key == 'client_name' else '—')}")

    doc.add_heading("4. Summary of Vulnerability Assessment", level=1)
    assessment = ctx.get("assessment") or {}
    if assessment.get("verified"):
        doc.add_paragraph(assessment.get("message") or "Assessment evidence verified.")
        if not findings:
            doc.add_paragraph("Scan completed successfully; no actionable vulnerabilities were identified.")
    else:
        doc.add_paragraph(
            assessment.get("message")
            or "Assessment status is unverified; no clean conclusion can be made."
        )
    summary = ctx.get("finding_summary") or {}
    if summary:
        doc.add_paragraph(
            "Finding counts - Critical: {Critical}, High: {High}, Medium: {Medium}, "
            "Low: {Low}, Informational: {Info}, Total: {total}.".format(
                Critical=summary.get("Critical", 0), High=summary.get("High", 0),
                Medium=summary.get("Medium", 0), Low=summary.get("Low", 0),
                Info=summary.get("Info", 0), total=summary.get("total", 0)
            )
        )
    table = doc.add_table(rows=1, cols=3)
    table.rows[0].cells[0].text = "Sr No."
    table.rows[0].cells[1].text = "Risk"
    table.rows[0].cells[2].text = "Name"
    for i, f in enumerate(findings, 1):
        row = table.add_row().cells
        row[0].text = str(i)
        row[1].text = f["risk"]
        row[2].text = f["name"]

    doc.add_heading("5. Vulnerability Observation", level=1)
    if not findings:
        if assessment.get("verified"):
            doc.add_paragraph("Scan completed successfully; no actionable vulnerabilities were identified.")
        else:
            doc.add_paragraph(
                assessment.get("message")
                or "Assessment status is unverified; no clean conclusion can be made."
            )
    for f in findings[:10]:
        doc.add_heading(f"➢ {f['name']}", level=2)
        doc.add_paragraph(f"Risk: {f['risk']}")
        doc.add_paragraph(f"IP address: {', '.join(f['hosts']) if f['hosts'] else '—'}")
        doc.add_paragraph(f"Description: {_finding_description(f)}")
        doc.add_paragraph(f"Impact: {_finding_impact(f)}")
        doc.add_paragraph(f"Mitigation: {_finding_mitigation_paragraph(f)}")

    doc.add_heading("6. Key Contacts", level=1)
    for c in site.get("key_contacts") or DEFAULT_KEY_CONTACTS:
        title = c.get("title", "")
        name_line = f"{c.get('name')}  - {title}" if title else c.get("name", "")
        doc.add_paragraph(f"• {name_line}\n{c.get('email')}", style="List Number")

    if ctx.get("service_coverage_jobs"):
        doc.add_page_break()
        doc.add_heading("7. Service Coverage and Limitations", level=1)
        doc.add_paragraph("A native engine assessment does not prove every service rule passed. Missing credentials, fingerprint evidence and network-scoped collectors remain coverage gaps. The companion Service coverage CSV contains all 52 families and IP forwarding per host.")
        for job in ctx["service_coverage_jobs"]:
            doc.add_heading(f"Job {job['job_id']} ({job.get('status') or 'unknown'})", level=2)
            for host, evidence in job["service_coverage"].items():
                counts = evidence.get("counts") or {}
                doc.add_paragraph(f"{host}: {counts.get('finding', 0)} families with findings; {counts.get('observation', 0)} observed; {counts.get('not-tested', 0)} not tested; {counts.get('unsupported', 0)} unsupported.")
                doc.add_paragraph(evidence.get("limitation") or job["limitation"])
            for task, policy in job["policy_snapshots"].items():
                doc.add_paragraph(f"Task {task}: {policy.get('snapshot_status', 'unknown')}; ports {policy.get('port_range') or 'not captured'}; configuration SHA-256 {policy.get('configuration_sha256') or 'not captured'}")

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def export_gap_report(
    db,
    case_id: str,
    *,
    fmt: str = "pdf",
    site_override: dict[str, Any] | None = None,
    use_llm: bool | None = None,
) -> tuple[bytes, str, str]:
    from app.config import get_settings

    settings = get_settings()
    if use_llm is None:
        use_llm = bool(settings.gap_report_llm_enabled)
    ctx = build_gap_report_context(db, case_id, site_override=site_override, use_llm=use_llm)
    client_slug = re.sub(r"[^\w\-]+", "-", ctx["client"])[:40].strip("-") or "client"
    if fmt == "docx":
        data = render_gap_docx(ctx)
        return data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", f"gap-assessment-{client_slug}.docx"
    html_doc = build_gap_report_html(ctx, include_cover=False)
    pdf = render_gap_pdf(
        html_doc,
        client=ctx["client"],
        company=ctx["site"].get("company_name"),
        report_date=ctx.get("report_date"),
    )
    if pdf:
        return pdf, "application/pdf", f"gap-assessment-{client_slug}.pdf"
    return build_gap_report_html(ctx, include_cover=True).encode("utf-8"), "text/html", f"gap-assessment-{client_slug}.html"


_SITE_COMPARE_KEYS = (
    "client_name",
    "branch_locations",
    "contact_person",
    "date_of_visit",
    "author",
    "document_version",
    "geographic_locations",
    "num_offices",
    "num_endpoints",
    "data_centers",
    "critical_servers",
    "critical_devices",
    "web_apps",
    "mobile_apps",
    "nac",
    "antivirus",
    "backup_storage",
    "company_name",
    "introduction",
)


def _norm_merge_text(val: Any) -> str:
    text = re.sub(r"\s+", " ", str(val or "").strip().lower())
    return text


def _finding_content_key(f: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    """Identity for merge; hosts excluded, affected service retained."""
    return (
        _norm_merge_text(f.get("name")),
        _norm_merge_text(f.get("risk")),
        _norm_merge_text(f.get("description") or f.get("observation")),
        _norm_merge_text(f.get("remediation")),
        _norm_merge_text(f.get("port")),
        _norm_merge_text(f.get("protocol")),
    )


def _hosts_list(f: dict[str, Any]) -> list[str]:
    hosts = f.get("hosts") or []
    if isinstance(hosts, str):
        parts = [p.strip() for p in hosts.split(",") if p.strip()]
        return parts
    return [str(h).strip() for h in hosts if str(h).strip()]


def merge_gap_findings(findings_lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """
    Merge findings from multiple gap reports.

    Same content (name/risk/description/remediation) → one finding with IPs appended
    (comma-separated). Different content → kept as separate findings.
    """
    merged: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str, str, str, str]] = []
    for findings in findings_lists:
        for f in findings:
            if not isinstance(f, dict):
                continue
            key = _finding_content_key(f)
            hosts = _hosts_list(f)
            if key not in merged:
                item = dict(f)
                item["hosts"] = list(hosts)
                merged[key] = item
                order.append(key)
                continue
            existing = merged[key]
            seen = {h.lower(): h for h in _hosts_list(existing)}
            for h in hosts:
                if h.lower() not in seen:
                    seen[h.lower()] = h
            existing["hosts"] = list(seen.values())
            # Prefer higher severity if labels somehow diverge after normalize.
            rank = _RISK_RANK.get(str(f.get("risk") or ""), 5)
            if rank < _RISK_RANK.get(str(existing.get("risk") or ""), 5):
                existing["risk"] = f.get("risk")
                existing["risk_rank"] = rank
    out = [merged[k] for k in order]
    for g in out:
        g["hosts"] = sorted(g["hosts"], key=lambda x: x.lower())
        g["risk_rank"] = _RISK_RANK.get(str(g.get("risk") or ""), 5)
    out.sort(key=lambda x: (x.get("risk_rank", 5), str(x.get("name") or "").lower()))
    return out


def _nested_dict_equal(a: Any, b: Any) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a) | set(b)
        return all(_nested_dict_equal(a.get(k), b.get(k)) for k in keys if k != "has_saved_intake")
    return _norm_merge_text(a) == _norm_merge_text(b)


def sites_are_equivalent(sites: list[dict[str, Any]]) -> bool:
    if len(sites) <= 1:
        return True
    base = sites[0]
    for other in sites[1:]:
        for key in _SITE_COMPARE_KEYS:
            if _norm_merge_text(base.get(key)) != _norm_merge_text(other.get(key)):
                return False
        for key in ("operating_systems", "firewall", "internet"):
            if not _nested_dict_equal(base.get(key) or {}, other.get(key) or {}):
                return False
    return True


def merge_gap_sites(sites: list[dict[str, Any]]) -> dict[str, Any]:
    """Use first site when equivalent; otherwise keep primary and note divergence."""
    if not sites:
        return {}
    primary = dict(sites[0])
    if sites_are_equivalent(sites):
        return primary
    # Different site overview — keep primary fields; do not invent a blended narrative.
    primary["_merged_site_diverged"] = True
    return primary


def build_merged_gap_report_context(
    db,
    case_ids: list[str],
    *,
    use_llm: bool | None = None,
) -> dict[str, Any]:
    ids = [str(c).strip() for c in case_ids if str(c).strip()]
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for cid in ids:
        if cid in seen:
            continue
        seen.add(cid)
        ordered.append(cid)
    if len(ordered) < 2:
        raise ValueError("Select at least two cases to merge gap assessment reports")

    sites: list[dict[str, Any]] = []
    findings_lists: list[list[dict[str, Any]]] = []
    informational_lists: list[list[dict[str, Any]]] = []
    summary_items: list[dict[str, Any]] = []
    assessment_states: list[dict[str, Any]] = []
    service_coverage_jobs: list[dict[str, Any]] = []
    primary_case: dict[str, Any] | None = None
    for cid in ordered:
        case_row = load_case_row(db, cid)
        if not case_row:
            raise ValueError(f"Case not found: {cid}")
        if primary_case is None:
            primary_case = case_row
        case_site = load_gap_site(db, cid)
        _apply_derived_site_facts(db, cid, case_site)
        sites.append(case_site)
        assessment_states.append(load_case_scan_assessment(db, cid))
        service_coverage_jobs.extend(load_service_coverage(db, case_id=cid))
        # Merge on raw scanner text before LLM rewrite so identical findings share IPs.
        inventory = load_gap_finding_inventory(db, cid)
        findings_lists.append(inventory["findings"])
        informational_lists.append(inventory["informational_findings"])
        summary_items.append(inventory["finding_summary"])

    site = merge_gap_sites(sites)
    findings = merge_gap_findings(findings_lists)
    informational_findings = [item for items in informational_lists for item in items]
    finding_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "total": 0, "actionable": 0, "informational": 0}
    for item in summary_items:
        for key in finding_summary:
            try:
                finding_summary[key] += int(item.get(key) or 0)
            except (TypeError, ValueError):
                pass
    client = (
        site.get("client_name")
        or (primary_case or {}).get("title")
        or "Client"
    )
    if findings:
        from app.config import get_settings

        llm_on = use_llm if use_llm is not None else bool(get_settings().gap_report_llm_enabled)
        findings = enrich_gap_findings(findings, client=client, enabled=llm_on)

    return {
        "case_id": ordered[0],
        "case_ids": ordered,
        "case": primary_case,
        "site": site,
        "client": client,
        "report_date": date.today().strftime("%d-%m-%Y"),
        "findings": findings,
        "informational_findings": informational_findings,
        "finding_summary": finding_summary,
        "assessment": merge_scan_assessments(assessment_states),
        "service_coverage_jobs": service_coverage_jobs,
        "intro": site.get("introduction") or DEFAULT_GAP_INTRO,
        "merged": True,
    }


def export_merged_gap_report(
    db,
    case_ids: list[str],
    *,
    fmt: str = "pdf",
    use_llm: bool | None = None,
) -> tuple[bytes, str, str]:
    from app.config import get_settings

    settings = get_settings()
    if use_llm is None:
        use_llm = bool(settings.gap_report_llm_enabled)
    ctx = build_merged_gap_report_context(db, case_ids, use_llm=use_llm)
    client_slug = re.sub(r"[^\w\-]+", "-", ctx["client"])[:40].strip("-") or "client"
    suffix = "merged"
    if fmt == "docx":
        data = render_gap_docx(ctx)
        return (
            data,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            f"gap-assessment-{client_slug}-{suffix}.docx",
        )
    html_doc = build_gap_report_html(ctx, include_cover=False)
    pdf = render_gap_pdf(
        html_doc,
        client=ctx["client"],
        company=ctx["site"].get("company_name"),
        report_date=ctx.get("report_date"),
    )
    if pdf:
        return pdf, "application/pdf", f"gap-assessment-{client_slug}-{suffix}.pdf"
    return (
        build_gap_report_html(ctx, include_cover=True).encode("utf-8"),
        "text/html",
        f"gap-assessment-{client_slug}-{suffix}.html",
    )
