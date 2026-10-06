from __future__ import annotations

import struct


def test_root_level_recycle_bin_is_critical_and_full_read():
    from app.services.critical_forensic_paths import is_critical_forensic_path, is_forensic_full_read_path

    path = r"$Recycle.Bin\S-1-5-21-123\$IABC123"
    assert is_critical_forensic_path(path)
    assert is_forensic_full_read_path(path)


def test_recycle_partial_materialization_is_inconclusive(monkeypatch):
    from app.services import report_objective_case_facts as mod
    from app.services import deleted_evidence

    monkeypatch.setattr(
        mod,
        "_live_recycle_bin_records",
        lambda *_a, **_k: [
            {
                "descriptor_path": "$Recycle.Bin/SID/$I1",
                "original_name": "one.xlsx",
                "original_path": r"C:\\Users\\LENOVO\\Desktop\\one.xlsx",
                "deleted_at": "2025-02-21T17:52:00Z",
            }
        ],
    )
    monkeypatch.setattr(mod, "_manifest_recycle_descriptor_paths", lambda *_a, **_k: {f"$i{i}" for i in range(10)})
    monkeypatch.setattr(deleted_evidence, "count_deleted_job_artifacts", lambda *_a, **_k: {"recycle_bin": 1, "samples": []})

    fact = mod._deleted_fact(None, "job", "Deleted Files Found in Recycle Bin")
    assert fact["status"] == "INCONCLUSIVE"
    assert "10" in fact["observation"]
    assert "only 1" in fact["observation"]
    assert fact["allowed_counts"] == []


def test_recycle_ten_valid_descriptors_report_ten(monkeypatch):
    from app.services import report_objective_case_facts as mod
    from app.services import deleted_evidence

    items = []
    for i in range(10):
        items.append(
            {
                "descriptor_path": f"$Recycle.Bin/SID/$I{i}",
                "payload_path": f"$Recycle.Bin/SID/$R{i}",
                "original_name": f"deleted-{i}.xlsx",
                "original_path": rf"C:\\Users\\LENOVO\\Desktop\\deleted-{i}.xlsx",
                "deleted_at": "2025-02-21T17:52:00Z",
            }
        )
    monkeypatch.setattr(mod, "_live_recycle_bin_records", lambda *_a, **_k: items)
    monkeypatch.setattr(mod, "_manifest_recycle_descriptor_paths", lambda *_a, **_k: {f"$i{i}" for i in range(10)})
    monkeypatch.setattr(deleted_evidence, "count_deleted_job_artifacts", lambda *_a, **_k: {"recycle_bin": 10, "samples": []})

    fact = mod._deleted_fact(None, "job", "Deleted Files Found in Recycle Bin")
    assert fact["status"] == "CONFIRMED"
    assert fact["allowed_counts"][0]["count"] == 10
    assert "10 distinct Recycle Bin" in fact["observation"]


def test_utf16_notepad_credential_note_is_detected(monkeypatch):
    from app.services import report_objective_case_facts as mod
    import sys
    import types

    path = r"C:\Users\LENOVO\Desktop\official email login.txt"
    note = "Email ID: Project@rrpelectronics.com\r\nPassword: REDACTED-TEST".encode("utf-16-le")

    def fake_fetchall(_db, sql, _params=None):
        if "FROM artifact_parse_results" in sql:
            return []
        if "FROM rag_chunks" in sql:
            return []
        if "FROM job_artifacts" in sql:
            return [{"file_path": path, "file_name": "official email login.txt", "size_bytes": len(note), "extension": ".txt"}]
        return []

    monkeypatch.setattr(mod, "fetchall", fake_fetchall)
    fake_live = types.ModuleType("app.services.artifact_live_counts")
    fake_live._read_job_files = lambda *_a, **_k: {path.replace('\\', '/'): note}
    monkeypatch.setitem(sys.modules, "app.services.artifact_live_counts", fake_live)

    fact = mod._credential_note_fact(None, "job", "Storage of Email Login Details in Notepad")
    assert fact["status"] == "CONFIRMED"
    assert fact["allowed_counts"][0]["count"] == 1
    assert "official email login.txt" in fact["key_entities"]["note_files"]
    assert "REDACTED-TEST" not in repr(fact)


def test_company_document_live_body_fallback_detects_rrp(monkeypatch):
    from app.services import report_objective_case_facts as mod
    import sys
    import types

    path = "Users/LENOVO/Documents/Project Plan.txt"
    data = b"Confidential planning document for RRP Electronics and project delivery."

    def fake_fetchall(_db, sql, _params=None):
        if "SELECT id, file_name, file_path, extension" in sql and "AND (" in sql:
            return []  # no filename/path match
        if "FROM rag_chunks" in sql:
            return []
        if "SELECT count(*) AS c" in sql:
            return [{"c": 1}]
        if "SELECT id, file_path, file_name, extension, size_bytes" in sql:
            return [{"id": "1", "file_path": path, "file_name": "Project Plan.txt", "extension": ".txt", "size_bytes": len(data)}]
        return []

    monkeypatch.setattr(mod, "fetchall", fake_fetchall)
    fake_live = types.ModuleType("app.services.artifact_live_counts")
    fake_live._read_job_files = lambda *_a, **_k: {path: data}
    monkeypatch.setitem(sys.modules, "app.services.artifact_live_counts", fake_live)
    fake_preview = types.ModuleType("app.services.artifact_preview")
    fake_preview._extract_document_preview_text = lambda *_a, **_k: None
    monkeypatch.setitem(sys.modules, "app.services.artifact_preview", fake_preview)

    fact = mod._company_document_fact(None, "job", "Storage of RRP-Related Documents on Personal Laptop", {"organization": "RRP Electronics"})
    assert fact["status"] == "CONFIRMED"
    assert "Project Plan.txt" in fact["key_entities"]["documents"]


def _encrypted_local_header() -> bytes:
    header = bytearray(30)
    header[:4] = b"PK\x03\x04"
    struct.pack_into("<H", header, 6, 0x1)
    return bytes(header)


def test_encryption_scan_reads_complete_archive_not_four_mb_prefix(monkeypatch):
    from app.services import encryption_inventory as enc
    import sys
    import types

    # Spread 418 encrypted local headers across > 4 MB. The old 4 MB prefix read would
    # undercount this archive; the V11 archive read cap must request the complete object.
    member = _encrypted_local_header() + (b"x" * 13000)
    data = member * 418
    path = "Users/LENOVO/Documents/MFGSTAT.zip"
    zip_row = {"file_path": path, "size_bytes": len(data)}

    def fake_fetchall(_db, sql, _params=None):
        if "lower(coalesce(extension,''))='.zip'" in sql:
            return [zip_row]
        return []

    requested = []

    def fake_read(_db, _job, _rows, *, max_bytes=None):
        requested.append(max_bytes)
        return {path: data[:max_bytes] if max_bytes is not None else data}

    monkeypatch.setattr(enc, "fetchall", fake_fetchall)
    fake_live = types.ModuleType("app.services.artifact_live_counts")
    fake_live._job_index_map = lambda *_a, **_k: {}
    fake_live._read_job_files = fake_read
    monkeypatch.setitem(sys.modules, "app.services.artifact_live_counts", fake_live)

    result = enc.scan_encrypted_files(None, "job")
    assert requested and requested[0] >= len(data)
    assert result["zip_entry_total"] == 418
    assert result["count"] == 418


def test_agent_brief_hides_generic_zero_results_when_live_fact_exists():
    from app.services.report_objectives_observation_service import _agent_safe_brief

    brief = {
        "objective": {"title": "Deleted Files Found in Recycle Bin"},
        "status": "CONFIRMED",
        "knowledge_plan": {},
        "report_results": [
            {
                "report_id": "RECYCLE_BIN",
                "report_title": "Recycle Bin",
                "objective_role": "DIRECT",
                "reported_count": 0,
                "zero_result_rule": {"finding": "No deleted files matching the criteria were found."},
            }
        ],
        "allowed_counts": [{"count": 10}],
        "case_fact": {
            "status": "CONFIRMED",
            "observation": "A total of 10 distinct Recycle Bin items were identified.",
            "simple_explanation": "This means deletion evidence was recovered.",
            "key_entities": {},
        },
    }
    safe = _agent_safe_brief(brief)
    assert safe["report_results"] == []


def test_confirmed_fact_rejects_no_items_were_found_sentence():
    from app.services.axiom_forensic_report_engine import validate_observation_against_brief

    brief = {
        "allowed_counts": [{"count": 10}],
        "case_fact": {"status": "CONFIRMED", "key_entities": {}},
    }
    ok, errors = validate_observation_against_brief(
        "A total of 10 items were identified. No deleted files were found. This means deletion evidence was recovered.",
        brief,
    )
    assert not ok
    assert any("contradicts confirmed" in e for e in errors)
