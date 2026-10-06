"""Report template artifact catalog matching."""

from app.services.report_catalog_sync import _find_artifact_id


class _FakeRow:
    def __init__(self, artifact_id: str, artifact_name: str, category: str):
        self._data = {
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "category": category,
        }

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]


class _FakeDb:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, *_args, **_kwargs):
        return self

    def mappings(self):
        return self

    def all(self):
        return self._rows


def test_find_artifact_id_respects_category_for_duplicate_names() -> None:
    db = _FakeDb([
        _FakeRow("AX-0574", "Malware/Phishing URLs", "Web Related"),
        _FakeRow("RPT-ART-013", "Malware/Phishing URLs", "Communication"),
    ])
    assert _find_artifact_id(db, "Windows", "Malware/Phishing URLs", "Communication") == "RPT-ART-013"
    assert _find_artifact_id(db, "Windows", "Malware/Phishing URLs", "Web Related") == "AX-0574"
    assert _find_artifact_id(db, "Windows", "Web Chat URLs", "Communication") is None


class _CountResult:
    def mappings(self):
        return self

    def first(self):
        return {"c": 12}


class _DeadlockDb:
    def __init__(self):
        self.rollbacks = 0

    def execute(self, *_args, **_kwargs):
        return _CountResult()

    def begin_nested(self):
        raise RuntimeError("deadlock detected")

    def rollback(self):
        self.rollbacks += 1

    def connection(self):
        raise RuntimeError("current transaction is aborted")


def test_ensure_platform_catalog_recovers_after_deadlock(monkeypatch) -> None:
    from app.services.axiom_catalog_ingest import ensure_platform_axiom_catalog

    monkeypatch.setattr(
        "app.services.axiom_catalog_ingest._workbook_path",
        lambda *_a, **_k: type("P", (), {"is_file": lambda self: False})(),
    )
    db = _DeadlockDb()
    result = ensure_platform_axiom_catalog(db, "Windows")
    assert result["platform"] == "Windows"
    assert result.get("source") == "none"
    assert "deadlock" in str(result.get("error") or "").lower()
    assert db.rollbacks >= 1
