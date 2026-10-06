"""Tests for mobile forensic report fact collection."""

from __future__ import annotations

from app.services.mobile_report_prompts import (
    DEVICE_INFORMATION_PROMPT,
    EXTRACTION_SUMMARY_PROMPT,
)
from app.services.mobile_report_service import (
    _facts_table_device,
    _facts_table_extraction,
    _infer_device_from_names,
    _parse_build_prop_text,
    gather_mobile_cover_page_markdown,
    gather_mobile_table_of_contents_markdown,
    is_mobile_intake,
    is_mobile_report_type,
    mobile_cover_structured,
)
from app.services.report_renderer import MOBILE_SECTION_ORDER, section_order_for_report_type


def test_is_mobile_report_type():
    assert is_mobile_report_type("mobile_forensic")
    assert is_mobile_report_type("mobile_device")
    assert not is_mobile_report_type("policy_violation")


def test_mobile_section_order():
    order = section_order_for_report_type("mobile_forensic")
    assert order == MOBILE_SECTION_ORDER
    assert len(order) == 14
    assert "device_information" in order
    assert "extraction_summary" in order
    assert "tools_used" in order
    assert "annexure" in order
    assert "objectives_procedure_observation" in order
    # Disk-only sections must not appear on mobile reports
    assert "os_information" not in order
    assert "forensic_imaging" not in order
    assert "artifact_summary" in order
    assert "suspicious_activity" in order
    assert "appendix" in order
    assert "final_analysis_summary" in order


def test_parse_build_prop():
    text = "ro.product.manufacturer=vivo\nro.product.model=V2403\n# comment\n"
    props = _parse_build_prop_text(text)
    assert props["ro.product.manufacturer"] == "vivo"
    assert props["ro.product.model"] == "V2403"


def test_infer_device_from_vivo_zip_name():
    hints = _infer_device_from_names(["vivo_V2403.pas", "vivo_V2403.zip"])
    assert hints.get("manufacturer") == "vivo"
    assert hints.get("model") == "V2403"


def test_mobile_prompts_non_empty():
    assert "Make" in DEVICE_INFORMATION_PROMPT
    assert "IMEI" in DEVICE_INFORMATION_PROMPT
    assert "SHA256" in EXTRACTION_SUMMARY_PROMPT
    assert "UFED version" in EXTRACTION_SUMMARY_PROMPT


def test_mobile_cover_page_markdown():
    intake = {"organization": "Tokarshi Bhawanji & Co", "subjects": [{"name": "Mr. Sujit"}]}
    job = {"disk_source": {"base_name": "vivo_V2403.zip", "format": "zip"}}
    md = gather_mobile_cover_page_markdown(intake, job)
    assert "MOBILE FORENSIC ANALYSIS REPORT" in md
    assert "CYBER FORENSIC" not in md
    assert "Mr. Sujit" in md
    assert "V2403" in md


def test_is_mobile_intake_from_case_type():
    assert is_mobile_intake({"case_type": "mobile_forensic", "report_type": "general"})
    assert is_mobile_intake({"case_type": "mobile_device", "report_type": "mobile_forensic"})
    assert not is_mobile_intake({"case_type": "general_computer_forensic"})


def test_mobile_device_table_matches_sample_fields():
    md = _facts_table_device({
        "make": "Vivo",
        "model": "V2403",
        "serial": "10B9L0H80001GV",
        "imei": "865110075900036, 865110075900028",
        "os_label": "Android 15",
        "capacity": "128GB",
    })
    assert "DEVICE INFORMATION" in md
    assert "| Make | Vivo |" in md
    assert "| Model | V2403 |" in md
    assert "| IMEI |" in md
    assert "| Capacity | 128GB |" in md


def test_mobile_extraction_table_matches_sample_fields():
    md = _facts_table_extraction({
        "extraction_start": "23/01/2026 3:12:00 PM(UTC+5:30)",
        "extraction_end": "23/01/2026 4:33:20 PM(UTC+5:30)",
        "ufed_version": "Cellebrite UFED 4PC 7.71.0.1858",
        "selected_manufacturer": "VIVO",
        "selected_device_name": "V2403",
        "extraction_type": "File System (Android ADB)",
        "timezone": "UTC",
        "hash_sha256": "7E34B26B",
    })
    assert "EXTRACTION SUMMARY" in md
    assert "Extraction start date/time" in md
    assert "UFED version" in md
    assert "Hash Value (SHA256)" in md
    assert "| Time zone settings (ID) | UTC |" in md
    assert "File System (Android ADB)" in md


def test_mobile_toc_matches_sample():
    md = gather_mobile_table_of_contents_markdown()
    assert "INTRODUCTION" in md
    assert "TOOLS USED FOR ACQUISITION AND EXTRACTION" in md
    assert "DEVICE INFORMATION" in md
    assert "EXTRACTION SUMMARY" in md
    assert "C. OBJECTIVE, PROCEDURE & OBSERVATION" in md
    assert "ARTIFACTS" in md
    assert "SUSPICIOUS ACTIVITY" in md
    assert "APPENDIX" in md


def test_mobile_findings_template_is_single_block():
    from app.services.report_evidence import gather_mobile_findings_markdown, gather_objectives_observation_context

    md = gather_mobile_findings_markdown({})
    assert "### 1. Objective" in md
    assert "### 2. Procedure" in md
    assert "### 3. Observations" in md
    assert "money transaction" in md.lower()
    assert "Contacts & Address Book" not in md
    # Mobile intake always returns the single findings template (ignores catalog objectives).
    md2 = gather_objectives_observation_context(object(), "job", {"report_type": "mobile_forensic"})
    assert "### 1. Objective" in md2
    assert "C. OBJECTIVE" not in md2


def test_mobile_observation_grounding_rejects_invented_payee():
    from app.services.report_evidence import gather_mobile_findings_markdown
    from app.services.report_generator import (
        _fallback_mobile_observations,
        _looks_like_dump_analysis,
        _observation_bullets_grounded,
        _splice_mobile_observations,
    )

    evidence = "path: img/gpay_upi_receipt.jpg text: Google Pay UPI payment successful"
    assert _observation_bullets_grounded(
        "- Found **Google Pay UPI** screenshots in .jpg format.",
        evidence,
    )
    assert not _observation_bullets_grounded(
        "- Cheque in favour of Tokarshi Bhawanji Co.",
        evidence,
    )
    assert _looks_like_dump_analysis(
        "- Key Observations:\n- YouTube API Requests and IndexedDB logs were decoded."
    )
    assert not _looks_like_dump_analysis(
        "- The device is not rooted.\n- We found images in **.jpg** format of UPI transactions."
    )
    fb = _fallback_mobile_observations(
        {"pictures": 10, "whatsapp_messages": 5, "audio": 3},
        payment_hits=[{"file_path": "DCIM/gpay_upi.jpg", "content": "Google Pay UPI"}],
    )
    assert "Tokarshi" not in fb
    assert "not rooted" in fb.lower() or "rooting" in fb.lower()
    assert "jpg" in fb.lower() or "image" in fb.lower()
    assert "indexeddb" not in fb.lower()
    assert "youtube" not in fb.lower()
    tmpl = gather_mobile_findings_markdown({})
    out = _splice_mobile_observations(tmpl, "- Grounded bullet one.\n- Grounded bullet two.")
    assert "### 1. Objective" in out
    assert "### 2. Procedure" in out
    assert "Grounded bullet one." in out
    assert "Findings will be generated" not in out


def test_parse_ufd_datetime_and_capacity():
    from app.services.mobile_report_service import _format_capacity, _parse_ufd_datetime

    assert _format_capacity(explicit="128GB") == "128GB"
    assert _format_capacity(explicit=None) == "—"
    dt = _parse_ufd_datetime("23/01/2026 15:12:00 (+5:30)")
    assert dt is not None
    assert getattr(dt, "year", None) == 2026 or isinstance(dt, str)
