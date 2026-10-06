"""Unit tests for unified logs IST conversion and source classification."""

from datetime import datetime, timezone

from app.services.unified_logs import (
    classify_job_source,
    format_timestamp_ist,
    normalize_level,
    normalize_origin,
    origin_label,
    source_label,
    with_ist_offset,
)


def test_with_ist_offset_appends_kolkata_offset():
    assert with_ist_offset("2026-08-27T10:15") == "2026-08-27T10:15:00+05:30"
    assert with_ist_offset("2026-08-27T10:15:00+05:30") == "2026-08-27T10:15:00+05:30"
    assert with_ist_offset("2026-08-27T04:45:00Z") == "2026-08-27T04:45:00Z"
    assert with_ist_offset("") is None
    assert with_ist_offset(None) is None


def test_format_timestamp_ist_converts_utc():
    ts = datetime(2026, 8, 27, 4, 45, 0, tzinfo=timezone.utc)
    text = format_timestamp_ist(ts)
    assert text.endswith("IST")
    assert "10:15:00 AM" in text
    assert text.startswith("27-08-2026")


def test_format_timestamp_ist_from_iso_string():
    text = format_timestamp_ist("2026-08-27T04:45:00Z")
    assert "10:15:00 AM" in text
    assert text.endswith("IST")


def test_classify_job_source():
    assert classify_job_source("mobile_extraction") == "mobile"
    assert classify_job_source("ios_backup") == "mobile"
    assert classify_job_source("host_disk") == "disk"
    assert classify_job_source("host_disk", {"source_type": "mobile"}) == "mobile"
    assert classify_job_source("host_disk", {"mobile_os": "android"}) == "mobile"
    assert classify_job_source("forensic") == "disk"


def test_normalize_level_and_labels():
    assert normalize_level("WARN") == "warning"
    assert normalize_level("failed") == "error"
    assert normalize_level("info") == "info"
    assert source_label("disk") == "Disk extract"
    assert source_label("mobile") == "Mobile extract"
    assert source_label("vuln") == "Vuln"


def test_normalize_origin_and_labels():
    assert normalize_origin(None) is None
    assert normalize_origin("all") is None
    assert normalize_origin("inhouse") == "inhouse"
    assert normalize_origin("in-house") == "inhouse"
    assert normalize_origin("internal") == "inhouse"
    assert normalize_origin("external") == "external"
    assert normalize_origin("laptop") == "external"
    assert normalize_origin("edge") == "external"
    assert origin_label("external") == "External"
    assert origin_label("inhouse") == "In-house"
    assert origin_label(None) == "In-house"
