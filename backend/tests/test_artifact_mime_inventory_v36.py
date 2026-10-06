from __future__ import annotations

from app.services import artifact_mime_inventory as mimeinv


class _Db:
    def commit(self):
        return None


def test_mime_inventory_byte_sniffs_generic_files_and_persists_real_mime(monkeypatch) -> None:
    rows = [
        {
            "id": "a1",
            "job_id": "j1",
            "file_name": "f_000009",
            "file_path": "Users/x/AppData/Chrome/Cache_Data/f_000009",
            "extension": "",
            "size_bytes": 100,
            "minio_uri": None,
            "metadata": {},
            "encyclopedia_artifact_id": None,
            "created_at": None,
        }
    ]
    writes = []
    monkeypatch.setattr(mimeinv, "fetchall", lambda *_a, **_k: rows)
    monkeypatch.setattr(mimeinv, "_read_head", lambda *_a, **_k: b"%PDF-1.7\n")
    monkeypatch.setattr(mimeinv, "execute", lambda _db, _sql, params: writes.append(params))
    monkeypatch.setattr(
        mimeinv,
        "mime_inventory_progress",
        lambda *_a, **_k: {"version": mimeinv.MIME_SCAN_VERSION, "total": 1, "completed": 1, "unknown": 0, "resolved": 1, "done": True},
    )

    result = mimeinv.scan_artifact_mime_batch(_Db(), "j1", limit=10)
    assert result["byte_sniffed"] == 1
    assert len(writes) == 1
    patch = writes[0]["patch"]
    assert "application/pdf" in patch
    assert '"mime_scan_status": "resolved"' in patch


def test_mime_inventory_progress_contract_names_are_stable() -> None:
    source = open(mimeinv.__file__, "r", encoding="utf-8").read()
    assert "mime_scan_version" in source
    assert "resolved_content_type" in source
    assert "application/x-forensic-data" in source
