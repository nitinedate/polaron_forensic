"""Tests for report template catalog and job selection."""

from __future__ import annotations

from app.services.report_template import _client_address_lines, gather_introduction_markdown
from app.services.report_template_service import (
    _REPORT_TITLE_AXIOM_OBJECTIVE_ID,
    apply_report_template_artifact_defaults,
    canonical_objective_id,
    dedupe_objective_rows,
    normalize_report_type_id,
)


def test_report_title_axiom_objective_map():
    assert _REPORT_TITLE_AXIOM_OBJECTIVE_ID["User Accounts & Login Activity"] == "O016"
    assert _REPORT_TITLE_AXIOM_OBJECTIVE_ID["File Access and Handling"] == "O022"
    assert _REPORT_TITLE_AXIOM_OBJECTIVE_ID["Malware, Phishing and Pornography URLs"] == "O077"


def test_dedupe_objective_rows_prefers_axiom_detail():
    rows = dedupe_objective_rows([
        {
            "objective_id": "RPT-O902",
            "title": "File Access and Handling",
            "objective": "Identify abnormal file open, modify, copy, delete, or compression activity.",
            "procedure_text": "Examine file access logs, timestamps, rename/delete patterns, and bulk transfers.",
        },
        {
            "objective_id": "O022",
            "title": "File Access and Handling",
            "objective": "Reconstruct the lifecycle of relevant files and folders.",
            "procedure_text": "1. Confirm legal/organizational authority..." * 20,
        },
    ])
    assert len(rows) == 1
    assert rows[0]["objective_id"] == "RPT-O902"


def test_dedupe_objective_rows_merges_same_title_different_ids():
    short = {
        "objective_id": "RPT-O901",
        "title": "User Accounts & Login Activity",
        "objective": "Determine who used the system, login times, and unauthorized access attempts.",
        "procedure_text": "Review user accounts, login/logout events, and unusual access patterns.",
    }
    long = {
        "objective_id": "O016",
        "title": "User Accounts & Login Activity",
        "objective": "Determine successful and failed authentication, interactive and remote sessions.",
        "procedure_text": "1. Confirm legal/organizational authority..." * 20,
    }
    rows = dedupe_objective_rows([short, long])
    assert len(rows) == 1
    assert rows[0]["objective_id"] == "RPT-O901"


def test_normalize_report_type_aliases():
    assert normalize_report_type_id("data_leakage") == "data_exfiltration"
    assert normalize_report_type_id("general") == "general_computer_forensic"


def test_apply_report_template_artifact_defaults():
    scope = {
        "enabled_keys": ["a1", "a2", "a3"],
        "sections": [
            {
                "title": "Communication",
                "subcategories": [
                    {"key": "a1", "label": "Social", "count": 1},
                    {"key": "a2", "label": "Chat", "count": 2},
                ],
            },
            {
                "title": "Other",
                "subcategories": [{"key": "a3", "label": "USB", "count": 0}],
            },
        ],
        "groups": [],
    }
    result = apply_report_template_artifact_defaults(scope, {"a1", "a3"})
    assert set(result["recommended_artifact_ids"]) == {"a1", "a3"}
    assert len(result["sections"]) == 2
    comm = result["sections"][0]["subcategories"]
    assert comm[0]["key"] == "a1" and comm[0]["in_template"] is True
    assert comm[1]["key"] == "a2" and comm[1]["in_template"] is False
    assert result["sections"][1]["subcategories"][0]["in_template"] is True
    assert result["report_template_filtered"] is False


def test_report_artifact_mapping_structure():
    """Mapping response shape (no DB required)."""
    sample = {
        "platform": "Windows",
        "report_types": [
            {
                "report_type_id": "data_exfiltration",
                "report_name": "Data Exfiltration Report",
                "groups": [
                    {
                        "category": "Communication",
                        "artifacts": [
                            {"artifact_id": "AX-1", "artifact_name": "Social Media URLs", "axiom_matched": True},
                        ],
                    },
                ],
            },
        ],
    }
    assert sample["report_types"][0]["groups"][0]["category"] == "Communication"


def test_client_address_lines_excludes_background_narrative():
    intake = {
        "organization": "Lilavati Hospital and Research Centre",
        "background": (
            "Lilavati Hospital and Research Centre requested a forensic examination of the device "
            "identified as 'Histotechlab1' to determine whether data had been transferred outside "
            "the organization."
        ),
        "address": "Bandra West, Mumbai",
    }
    lines = _client_address_lines(intake)
    assert lines == ["Lilavati Hospital and Research Centre,", "Bandra West, Mumbai,"]
    intro = gather_introduction_markdown(intake)
    assert "requested a forensic examination" not in intro.split("**Subject:**")[0]


def test_template_payload_preserves_axiom_observation_requirements():
    from app.services.report_template_service import _objective_payload_from_template_row

    row = {
        "objective_id": "RPT-O900",
        "title": "File Access and Handling",
        "objective": "Identify supported file actions.",
        "procedure_text": "Review file-action evidence.",
        "axiom_objective_id": "O022",
        "required_observation_fields": "file name; action; timestamp",
        "expected_output_fields": "user; path; corroboration",
        "minimum_corroboration": 2,
        "limitations": "Do not infer copy from access alone.",
    }
    payload = _objective_payload_from_template_row(row)
    assert payload["axiom_objective_id"] == "O022"
    assert payload["required_observation_fields"] == "file name; action; timestamp"
    assert payload["expected_output_fields"] == "user; path; corroboration"
    assert payload["minimum_corroboration"] == 2
    assert "infer copy" in payload["limitations"]


def test_template_payload_preserves_attached_axiom_reasoning_text():
    from app.services.report_template_service import _objective_payload_from_template_row

    row = {
        "objective_id": "RPT-O901",
        "title": "User Accounts & Login Activity",
        "objective": "Identify supported account activity.",
        "procedure_text": "Review account and sign-in records.",
        "axiom_objective_id": "O016",
        "axiom_statement": "Determine successful and failed authentication.",
        "axiom_procedure_text": "1. Review account records.\n2. Correlate sign-in events.",
    }
    payload = _objective_payload_from_template_row(row)
    assert payload["axiom_statement"].startswith("Determine successful")
    assert "Correlate sign-in" in payload["axiom_procedure_text"]
