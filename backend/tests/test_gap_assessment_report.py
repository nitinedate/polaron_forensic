"""Unit tests for gap assessment report grouping and template."""

from app.services.gap_assessment_report import (
    _group_findings,
    build_gap_report_html,
    merge_gap_findings,
    sites_are_equivalent,
)


def test_merge_gap_findings_appends_ips_when_same_else_keeps_separate():
    a = [
        {
            "name": "Open SSH",
            "risk": "High",
            "description": "SSH exposed",
            "remediation": "Restrict SSH",
            "hosts": ["192.168.1.1"],
        }
    ]
    b = [
        {
            "name": "Open SSH",
            "risk": "High",
            "description": "SSH exposed",
            "remediation": "Restrict SSH",
            "hosts": ["10.0.0.5"],
        },
        {
            "name": "Weak TLS",
            "risk": "Medium",
            "description": "TLS 1.0 enabled",
            "remediation": "Disable TLS 1.0",
            "hosts": ["10.0.0.5"],
        },
    ]
    merged = merge_gap_findings([a, b])
    by_name = {f["name"]: f for f in merged}
    assert set(by_name) == {"Open SSH", "Weak TLS"}
    assert by_name["Open SSH"]["hosts"] == ["10.0.0.5", "192.168.1.1"]
    assert by_name["Weak TLS"]["hosts"] == ["10.0.0.5"]


def test_sites_are_equivalent_ignores_whitespace():
    assert sites_are_equivalent(
        [
            {"client_name": "Acme", "author": "", "branch_locations": "Pune"},
            {"client_name": "Acme", "author": "", "branch_locations": " Pune "},
        ]
    )
    assert not sites_are_equivalent(
        [
            {"client_name": "Acme", "author": ""},
            {"client_name": "Other", "author": ""},
        ]
    )


def test_group_findings_merges_hosts_and_keeps_highest_severity():
    rows = [
        {
            "synopsis": "SNMP Agent Default Community Name (public)",
            "severity": "high",
            "cvss": 7.5,
            "description": "SNMP uses public community.",
            "remediation": "Change community string.",
            "host": "172.16.1.1",
        },
        {
            "synopsis": "SNMP Agent Default Community Name (public)",
            "severity": "medium",
            "cvss": 5.0,
            "description": "",
            "remediation": "",
            "host": "172.16.1.2",
        },
    ]
    groups = _group_findings(rows)
    assert len(groups) == 1
    assert groups[0]["risk"] == "High"
    assert groups[0]["hosts"] == ["172.16.1.1", "172.16.1.2"]


def test_load_grouped_findings_includes_low_risk():
    from app.services.gap_assessment_report import _group_findings

    rows = [
        {"synopsis": "Low issue", "severity": "low", "cvss": 2.0, "host": "10.0.0.1"},
        {"synopsis": "High issue", "severity": "high", "cvss": 8.0, "host": "10.0.0.2"},
    ]
    grouped = _group_findings(rows)
    filtered = [f for f in grouped if f.get("risk") != "Info"]
    assert len(filtered) == 2
    risks = {f["risk"] for f in filtered}
    assert "Low" in risks
    assert "High" in risks


def test_styled_gap_html_uses_branded_template():
    html_doc = build_gap_report_html(
        {
            "client": "Demo Client",
            "report_date": "01-01-2026",
            "intro": "Intro text",
            "site": {
                "author": "Author",
                "document_version": "1.0",
                "company_name": "Aetheris Technologies Pvt Ltd",
                "key_contacts": [],
            },
            "findings": [],
        }
    )
    assert "cover-analysis-title" in html_doc
    assert "GAP ANALYSIS REPORT" in html_doc
    assert "section-bar" in html_doc
    assert "2. SITE OVERVIEW</div>" in html_doc
    assert "3. SITE INFRASTRUCTURE</div>" in html_doc
    assert "site-overview-label" in html_doc
    assert "1. INTRODUCTION" in html_doc
    assert "doc-page-bar" in html_doc
    assert "GENERAL SITE REPORT" in html_doc
    assert "report-page-doc-control" in html_doc
    assert "doc-control-spacer" in html_doc
    assert "disclaimer-box" in html_doc
    assert "THIS REPORT IS CONFIDENTIAL" in html_doc
    # Two separate full-width tables (xhtml2pdf-safe); 7 blank lines before banner.
    assert "doc-control-footer" not in html_doc
    meta_idx = html_doc.index("GENERAL SITE REPORT")
    rev_idx = html_doc.index("REVISION HISTORY", meta_idx)
    disc_idx = html_doc.index("class='disclaimer-box'", rev_idx)
    assert rev_idx < disc_idx
    assert html_doc[rev_idx:disc_idx].count("<br/>") == 7
    assert "toc-shell" in html_doc
    assert "toc-footer-cell" in html_doc
    assert "6. KEY CONTACTS" in html_doc
    assert "8. RECOMMENDATION" not in html_doc
    assert "5. OBSERVATION" not in html_doc
    assert html_doc.count("6. KEY CONTACTS</div>") == 1
    assert "data:image/" in html_doc
    assert "finding-kv-table" in html_doc or "No open findings" in html_doc


def test_stamp_gap_page_numbers():
    from app.services.gap_report_template import render_gap_cover_pdf, stamp_gap_page_numbers

    pdf = render_gap_cover_pdf("Demo Client")
    assert pdf is not None
    stamped = stamp_gap_page_numbers(pdf)
    import fitz

    doc = fitz.open(stream=stamped, filetype="pdf")
    text = doc[0].get_text()
    assert "1" in text
    doc.close()


def test_gap_observation_one_table_per_page():
    html_doc = build_gap_report_html(
        {
            "client": "Demo Client",
            "report_date": "01-01-2026",
            "intro": "Intro text",
            "site": {
                "author": "Author",
                "document_version": "1.0",
                "company_name": "Aetheris Technologies Pvt Ltd",
                "key_contacts": [],
            },
            "findings": [
                {"name": "Finding A", "risk": "High", "hosts": ["10.0.0.1"], "description": "desc a"},
                {"name": "Finding B", "risk": "Medium", "hosts": ["10.0.0.2"], "description": "desc b"},
            ],
        },
        include_cover=False,
    )
    assert html_doc.count("5. VULNERABILITY OBSERVATION</div>") == 1
    assert html_doc.count('class="report-page report-page-flow">') == 0
    assert "border='1'" in html_doc
    assert html_doc.count("finding-detail'>") == 2
    assert html_doc.count("class='finding-kv-table'") == 2
    assert html_doc.count("finding-kv-key'>Risk</td>") == 2
    assert html_doc.count('class="finding-kv-value finding-kv-risk"') == 2
    assert "finding-detail-keep" not in html_doc
    assert "<span class='finding-kv-risk'" not in html_doc
    assert "Recommendation" not in html_doc


def test_gap_html_has_no_inline_page_footer():
    html_doc = build_gap_report_html(
        {
            "client": "Demo Client",
            "report_date": "01-01-2026",
            "intro": "Intro text",
            "site": {
                "author": "Author",
                "document_version": "1.0",
                "company_name": "AETHERIS TECHNOLOGIES PVT LTD",
                "key_contacts": [],
            },
            "findings": [],
        },
        include_cover=False,
    )
    assert "<div class=\"page-footer\">" not in html_doc


def test_confidential_watermark_png():
    from app.services.gap_report_template import _build_confidential_watermark_png

    png = _build_confidential_watermark_png()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(png) > 1000


def test_finding_description_rejects_scanner_stub_text():
    from app.services.gap_assessment_report import _finding_description, _finding_observation

    finding = {
        "name": "X-Content-Type-Options Header Missing",
        "risk": "Medium",
        "description": "The system is affected by X-Content-Type-Options Header Missing. web application passive scan finding",
    }
    obs = _finding_observation(finding)
    desc = _finding_description(finding)
    assert "passive scan finding" not in obs.lower()
    assert "passive scan finding" not in desc.lower()
    assert len(obs) >= 50


def test_summary_table_uses_full_risk_cell():
    html_doc = build_gap_report_html(
        {
            "client": "Demo Client",
            "report_date": "01-01-2026",
            "intro": "Intro text",
            "site": {"author": "Author", "document_version": "1.0", "key_contacts": []},
            "findings": [
                {"name": "Low finding", "risk": "Low", "hosts": ["10.0.0.3"], "description": "desc"},
                {"name": "High finding", "risk": "High", "hosts": ["10.0.0.4"], "description": "desc"},
            ],
        },
        include_cover=False,
    )
    assert "risk-cell" in html_doc
    assert "#ff0000" in html_doc
    assert "#92d050" in html_doc
    assert "LOW" in html_doc


def test_finding_recommendation_uses_detailed_fallback():
    from app.services.gap_assessment_report import _finding_recommendation

    finding = {
        "name": "X-Content-Type-Options Header Missing",
        "risk": "Medium",
        "remediation": "Set X-Content-Type-Options: nosniff.",
        "client_recommendation": "Set nosniff.",
    }
    rec = _finding_recommendation(finding)
    assert len(rec) >= 80
    assert "nosniff" in rec.lower()
    from app.services.gap_report_llm import _fallback_enrich

    finding = {
        "name": "SSL/TLS weak protocol (stub)",
        "risk": "Critical",
        "description": "Nuclei stub: rapid CVE/misconfiguration template match",
        "remediation": "Disable weak TLS; enforce TLS 1.2+.",
    }
    out = _fallback_enrich(finding)
    assert "nuclei" not in out["client_observation"].lower()
    assert "stub" not in out["client_description"].lower()
    assert len(out["client_impact"]) >= 50


def test_toc_leader_dots_fill_to_page_number():
    from app.services.gap_report_template import _compute_toc_page_map, _toc_leader_line, _toc_page

    intro = _toc_leader_line(1, "INTRODUCTION", "4")
    contacts = _toc_leader_line(6, "KEY CONTACTS", "16")
    assert intro.startswith("1. INTRODUCTION")
    assert intro.endswith("4")
    assert intro.count(".") >= 100
    assert contacts.startswith("6. KEY CONTACTS")
    assert contacts.endswith("16")
    assert contacts.count(".") >= 80

    html = _toc_page(3, _compute_toc_page_map(findings_count=4))
    assert "toc-col-sr" in html
    assert "toc-col-title" in html
    assert "toc-col-page" in html
    from app.services.gap_report_template import GAP_REPORT_CSS

    assert "toc-shell td" in GAP_REPORT_CSS
    assert "Times New Roman" in GAP_REPORT_CSS
    assert "Courier New', Courier, monospace" not in GAP_REPORT_CSS.split(".toc-shell td")[1].split(".toc-col-sr")[0]
    assert "width:89%" in html
    assert "width:5%" in html
    assert "1." in html
    assert "INTRODUCTION" in html
    assert "CONTACTS" in html
    assert "colspan='3'" in html
    # Image-2 style (nested leader / solid underlines) must not return.
    assert "toc-title-leader" not in html
    assert "toc-title-inner" not in html


def test_resolved_key_contacts_replaces_legacy_founders():
    from app.services.gap_assessment_report import DEFAULT_KEY_CONTACTS, _resolved_key_contacts

    legacy = [
        {"name": "Dr. Makarand Wagh", "title": "Founder", "email": "makarand@aetheris.in"},
        {"name": "Ms. Nivedita Marathe", "title": "Founder", "email": "nivedita@aetheris.in"},
    ]
    resolved = _resolved_key_contacts(legacy)
    assert resolved == DEFAULT_KEY_CONTACTS
    assert resolved[0]["email"] == "nitin@aetheris.in"


def test_key_contacts_render_multiline_entry():
    from app.services.gap_report_template import _contacts_html

    html = _contacts_html(
        [{"name": "Mr. Nitin Jambhale", "title": "Operations Manager", "email": "nitin@aetheris.in"}]
    )
    assert "Mr. Nitin Jambhale" in html
    assert "Operations Manager" in html
    assert "contacts-entry" in html
    assert "\u00a0\u00a0Operations Manager" in html
    assert "nitin@aetheris.in" in html
    assert "-&nbsp;Operations Manager" not in html
    assert "Makarand" not in html


def test_site_overview_and_infrastructure_sections_are_split():
    from app.services.gap_assessment_report import build_gap_report_html

    html_doc = build_gap_report_html(
        {
            "client": "Demo Client",
            "report_date": "01-01-2026",
            "intro": "Intro text",
            "site": {
                "author": "Author",
                "document_version": "1.0",
                "branch_locations": "Vashi",
                "contact_person": "Nitin",
                "num_endpoints": "1",
                "key_contacts": [],
            },
            "findings": [],
        },
        include_cover=False,
    )
    overview_pos = html_doc.index("2. SITE OVERVIEW</div>")
    client_pos = html_doc.index("site-overview-label'>CLIENT:</span>")
    infra_bar_pos = html_doc.index("3. SITE INFRASTRUCTURE</div>")
    endpoints_pos = html_doc.index("<strong>ENDPOINTS:</strong>")
    assert overview_pos < client_pos < infra_bar_pos < endpoints_pos
    from app.services.gap_report_template import _intro_paragraphs

    html = _intro_paragraphs("Line one part A\nLine one part B\n\nSecond paragraph.")
    assert html.count("<p class='body-text'>") == 2
    assert "Line one part A Line one part B" in html
    assert "Second paragraph." in html



def test_build_gap_report_context_autofills_num_endpoints_from_scan_data(monkeypatch):
    import app.services.gap_assessment_report as gap

    case_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(gap, "load_case_row", lambda db, cid: {"id": cid, "title": "Demo Client"})
    monkeypatch.setattr(
        gap,
        "load_gap_site",
        lambda db, cid: {
            "client_name": "Demo Client",
            "num_endpoints": "",
            "key_contacts": [],
            "has_saved_intake": True,
        },
    )
    monkeypatch.setattr(gap, "_derive_case_endpoint_count", lambda db, cid: 3)
    monkeypatch.setattr(gap, "load_grouped_findings", lambda db, cid: [])
    monkeypatch.setattr(
        gap,
        "load_gap_finding_inventory",
        lambda db, cid: {"findings": [], "informational_findings": [], "finding_summary": {}},
    )
    monkeypatch.setattr(gap, "load_case_scan_assessment", lambda db, cid: {})
    monkeypatch.setattr(gap, "load_service_coverage", lambda db, **kwargs: [])

    ctx = gap.build_gap_report_context(object(), case_id, use_llm=False)

    assert ctx["site"]["num_endpoints"] == "3"


def test_apply_derived_site_facts_preserves_manual_num_endpoints(monkeypatch):
    import app.services.gap_assessment_report as gap

    def should_not_run(db, case_id):
        raise AssertionError("automatic endpoint derivation should not override manual intake")

    monkeypatch.setattr(gap, "_derive_case_endpoint_count", should_not_run)
    site = {"num_endpoints": "600+"}

    gap._apply_derived_site_facts(object(), "00000000-0000-0000-0000-000000000001", site)

    assert site["num_endpoints"] == "600+"

def test_derive_case_endpoint_count_prefers_materialized_assets(monkeypatch):
    import app.services.gap_assessment_report as gap

    calls = []

    def fake_fetchone(db, sql, params):
        calls.append(sql)
        if "FROM vuln_assets" in sql:
            return {"endpoint_count": 4}
        raise AssertionError("scan-target fallback should not run when assets exist")

    monkeypatch.setattr(gap, "fetchone", fake_fetchone)

    assert gap._derive_case_endpoint_count(object(), "00000000-0000-0000-0000-000000000001") == 4
    assert len(calls) == 1


def test_derive_case_endpoint_count_falls_back_to_distinct_host_targets(monkeypatch):
    import app.services.gap_assessment_report as gap

    def fake_fetchone(db, sql, params):
        if "FROM vuln_assets" in sql:
            return {"endpoint_count": 0}
        if "FROM vuln_scan_targets" in sql:
            assert "'cidr'" not in sql
            assert "'network'" not in sql
            return {"endpoint_count": 2}
        raise AssertionError(sql)

    monkeypatch.setattr(gap, "fetchone", fake_fetchone)

    assert gap._derive_case_endpoint_count(object(), "00000000-0000-0000-0000-000000000001") == 2


def test_apply_derived_site_facts_replaces_not_specified_placeholder(monkeypatch):
    import app.services.gap_assessment_report as gap

    monkeypatch.setattr(gap, "_derive_case_endpoint_count", lambda db, case_id: 1)
    site = {"num_endpoints": "Not specified"}

    gap._apply_derived_site_facts(object(), "00000000-0000-0000-0000-000000000001", site)

    assert site["num_endpoints"] == "1"


def _gap_ctx_with_info_oids() -> dict:
    return {
        "client": "Demo Client",
        "report_date": "01-01-2026",
        "intro": "Intro text",
        "site": {
            "author": "Author",
            "document_version": "1.0",
            "company_name": "Aetheris Technologies Pvt Ltd",
            "key_contacts": [],
        },
        "findings": [
            {
                "name": "DCE/RPC and MSRPC Services Enumeration Reporting",
                "risk": "Medium",
                "hosts": ["10.10.80.16"],
                "port": 135,
                "protocol": "tcp",
                "description": "DCE/RPC services enumerated.",
                "remediation": "Restrict RPC exposure.",
            }
        ],
        "informational_findings": [
            {
                "host": "192.168.29.85",
                "port": None,
                "protocol": "CPE-T",
                "name": "CPE Inventory",
                "plugin_id": "1.3.6.1.4.1.25623.1.0.810002",
            },
            {
                "host": "192.168.29.85",
                "port": 5432,
                "protocol": "tcp",
                "name": "PostgreSQL Detection (TCP)",
                "plugin_id": "1.3.6.1.4.1.25623.1.0.108449",
            },
        ],
    }


def test_oid_lines_break_at_dots():
    from app.services.gap_report_template import _OID_LINE_CHARS, _oid_lines

    lines = _oid_lines("1.3.6.1.4.1.25623.1.0.810002")
    assert all(len(line) <= _OID_LINE_CHARS + 1 for line in lines)
    assert "".join(lines).replace(".", "") == "1.3.6.1.4.1.25623.1.0.810002".replace(".", "")
    assert "<br/>".join(lines) != "1.3.6.1.4.1.25623.1.0.810002"


def test_gap_report_omits_affected_service_and_appendices():
    html_doc = build_gap_report_html(_gap_ctx_with_info_oids(), include_cover=False)
    assert "Affected service" not in html_doc
    assert "135/tcp" not in html_doc
    assert "APPENDIX A" not in html_doc
    assert "APPENDIX B" not in html_doc
    assert "INFORMATIONAL OBSERVATIONS" not in html_doc
    assert "SCANNER WARNINGS" not in html_doc
    assert "KEY CONTACTS" in html_doc
