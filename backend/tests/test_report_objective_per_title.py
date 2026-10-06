"""Tests for per-title report objectives and evidence prompts."""

from __future__ import annotations

from app.services.report_objective_evidence import build_objective_evidence_prompt
from app.services.report_template_service import (
    _REPORT_TITLE_AXIOM_OBJECTIVE_ID,
    _report_objective_catalog_entry,
    dedupe_objective_rows,
)


def test_report_objective_catalog_entry_unique_procedures():
    registry = _report_objective_catalog_entry("Registry Analysis")
    scheduled = _report_objective_catalog_entry("Scheduled Tasks & Startup Items")
    assert registry is not None
    assert scheduled is not None
    assert registry["objective_id"] != scheduled["objective_id"]
    assert registry["axiom_objective_id"] == scheduled["axiom_objective_id"] == "O018"
    assert "Examination approach:" in registry["procedure_text"]
    assert "Examination approach:" in scheduled["procedure_text"]
    # Same AXIOM id still yields title-scoped procedure text.
    assert 'report section "Registry Analysis"' in registry["procedure_text"]
    assert 'report section "Scheduled Tasks & Startup Items"' in scheduled["procedure_text"]
    assert registry["procedure_text"] != scheduled["procedure_text"]
    assert len(registry["procedure_text"]) >= 180


def test_document_procedures_include_ocr_company_scan():
    file_access = _report_objective_catalog_entry("File Access and Handling")
    rrp = _report_objective_catalog_entry("Storage of RRP-Related Documents on Personal Laptop")
    assert file_access is not None and rrp is not None
    for entry in (file_access, rrp):
        proc = entry["procedure_text"]
        assert "Examination approach:" in proc
        assert "OCR" in proc
        assert "company name" in proc.lower()
        assert "email" in proc.lower()


def test_dedupe_objective_rows_prefers_per_title_rpt():
    rows = dedupe_objective_rows([
        {
            "objective_id": "RPT-O906",
            "title": "Registry Analysis",
            "objective": "Recover configuration and user activity evidence from registry hives.",
            "procedure_text": (
                "1. Confirm legal/organizational authority.\n"
                "2. Review registry hives for Run keys, USB keys, userassist.\n"
                "3. Verify raw key paths.\n"
                "4. Corroborate across sources.\n"
                "5. Normalize times.\n"
                "6. Write observation."
            ) + (" detail" * 40),
        },
        {
            "objective_id": "O018",
            "title": "Registry Analysis",
            "objective": "Generic AXIOM registry objective.",
            "procedure_text": "1. Confirm legal/organizational authority..." * 20,
        },
    ])
    assert len(rows) == 1
    assert rows[0]["objective_id"] == "RPT-O906"
    assert "Run keys" in rows[0]["procedure_text"]


def test_dedupe_objective_rows_keeps_distinct_titles_sharing_axiom():
    registry = {
        "objective_id": "RPT-O906",
        "title": "Registry Analysis",
        "procedure_text": "1. Confirm authority.\n2. Examine Run keys, USB keys, userassist." + (" x" * 100),
    }
    scheduled = {
        "objective_id": "RPT-O907",
        "title": "Scheduled Tasks & Startup Items",
        "procedure_text": "1. Confirm authority.\n2. Review Task Scheduler artifacts." + (" y" * 100),
    }
    rows = dedupe_objective_rows([registry, scheduled])
    assert len(rows) == 2
    titles = {r["title"] for r in rows}
    assert titles == {"Registry Analysis", "Scheduled Tasks & Startup Items"}


def test_build_objective_evidence_prompt_includes_linked_artifacts():
    prompt = build_objective_evidence_prompt(
        header_title="Registry Analysis",
        objective_statement="Recover configuration evidence.",
        procedure_text="Examine Run keys and USB keys.",
        axiom_objective_id="O018",
        linked_artifacts=[
            {
                "artifact_id": "A001",
                "category": "Operating System",
                "name": "Registry Hives",
                "observation_focus": "User and system registry settings",
            }
        ],
    )
    assert "LINKED ARTIFACTS" in prompt
    assert "Registry Hives" in prompt
    assert "Run keys" in prompt


def test_axiom_map_still_links_artifacts_for_shared_workbook_id():
    assert _REPORT_TITLE_AXIOM_OBJECTIVE_ID["Registry Analysis"] == "O018"
    assert _REPORT_TITLE_AXIOM_OBJECTIVE_ID["Scheduled Tasks & Startup Items"] == "O018"


def test_axiom_id_prefers_mobile_template_title_for_o043():
    from app.services.report_template_service import _axiom_id_to_report_title

    title = _axiom_id_to_report_title("O043", "mobile_forensic")
    assert title == "Chat / Communication Apps"


def test_resolve_objective_to_template_row_matches_legacy_axiom_id():
    from app.services.report_template_service import resolve_objective_to_template_row

    template_row = {
        "objective_id": "RPT-O913",
        "title": "Chat / Communication Apps",
        "objective": "Review chat apps.",
        "procedure_text": "Extract WhatsApp and SMS.",
        "axiom_objective_id": "O043",
        "source": "report_template",
    }
    by_id = {"RPT-O913": template_row}
    by_title = {"chat / communication apps": template_row}
    by_axiom = {"O043": [template_row]}

    resolved = resolve_objective_to_template_row(
        None,
        "O043",
        "mobile_forensic",
        by_id=by_id,
        by_title=by_title,
        by_axiom=by_axiom,
    )
    assert resolved is not None
    assert resolved["objective_id"] == "RPT-O913"
    assert resolved["title"] == "Chat / Communication Apps"


def test_resolve_objective_to_template_row_matches_snapshot_title():
    from app.services.report_template_service import resolve_objective_to_template_row

    template_row = {
        "objective_id": "RPT-O914",
        "title": "File Access and Handling",
        "objective": "Review file activity.",
        "procedure_text": "Inspect downloads and shared files.",
        "axiom_objective_id": "O022",
        "source": "report_template",
    }
    by_id = {"RPT-O914": template_row}
    by_title = {"file access and handling": template_row}
    by_axiom = {"O022": [template_row]}

    resolved = resolve_objective_to_template_row(
        None,
        {"id": "O022", "title": "File Access and Handling"},
        "mobile_forensic",
        by_id=by_id,
        by_title=by_title,
        by_axiom=by_axiom,
    )
    assert resolved is not None
    assert resolved["objective_id"] == "RPT-O914"
    assert resolved["title"] == "File Access and Handling"


def test_snapshot_catalog_id_title_does_not_replace_question_name():
    from app.services.report_template_service import resolve_objective_to_template_row

    template_row = {
        "objective_id": "RPT-O920",
        "title": "Access to Cloud Storage Services",
        "objective": "Determine use of cloud storage.",
        "procedure_text": "Review browser history for cloud sites.",
        "axiom_objective_id": "O059",
        "source": "report_template",
    }
    resolved = resolve_objective_to_template_row(
        None,
        {"id": "RPT-O920", "title": "RPT-O920", "objective": "", "procedure_text": ""},
        "data_exfiltration",
        by_id={"RPT-O920": template_row},
        by_title={"access to cloud storage services": template_row},
        by_axiom={"O059": [template_row]},
    )
    assert resolved is not None
    assert resolved["title"] == "Access to Cloud Storage Services"
    assert "cloud" in (resolved.get("objective") or "").lower()
    assert resolved["procedure_text"]
