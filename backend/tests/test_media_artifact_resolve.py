from app.services.artifact_evidence_browse import (
    _media_name_candidates,
    _resolve_media_artifact_id,
)


class _Db:
    pass


def test_resolve_media_skips_sqlite_and_prefers_image(monkeypatch):
    calls: list[tuple[str, dict]] = []

    def fake_fetchone(db, sql, params=None):
        calls.append((sql, params or {}))
        name = str((params or {}).get("n") or "")
        if "NOT LIKE '%.db'" in sql.replace("\n", " ") or "%.db" in sql:
            if name.lower() == "chatstorage.sqlite":
                return None
            if name.lower().endswith(".jpg"):
                return {"id": "img-1"}
        return None

    monkeypatch.setattr("app.services.artifact_evidence_browse.fetchone", fake_fetchone)
    assert _resolve_media_artifact_id(_Db(), "job", "IMG-2024-WA0001.jpg") == "img-1"
    assert _resolve_media_artifact_id(_Db(), "job", "ChatStorage.sqlite") is None
    assert any("NOT LIKE '%.sqlite%'" in sql for sql, _ in calls)


def test_resolve_media_matches_recovered_path(monkeypatch):
    def fake_fetchone(db, sql, params=None):
        pat = str((params or {}).get("pat") or "")
        if "whatsapp" in pat.lower() and "img-2024-wa0001.jpg" in pat.lower():
            return {"id": "img-path"}
        return None

    monkeypatch.setattr("app.services.artifact_evidence_browse.fetchone", fake_fetchone)
    aid = _resolve_media_artifact_id(
        _Db(),
        "job",
        "",
        media_path="Media/WhatsApp Images/IMG-2024-WA0001.jpg",
    )
    assert aid == "img-path"


def test_media_name_candidates_prefer_full_over_thumb():
    cands = _media_name_candidates("93e3e2dc-0504-4393-9593-5ec916600074.thumb")
    assert cands[0].lower().endswith((".jpg", ".jpeg", ".mp4", ".png", ".pdf", ".opus", ".m4a")) or not cands[
        0
    ].lower().endswith(".thumb")
    assert any(c.lower().endswith(".jpg") for c in cands)
    assert any(c.lower().endswith(".thumb") for c in cands)


def test_resolve_thumb_falls_back_to_jpg(monkeypatch):
    def fake_fetchone(db, sql, params=None):
        name = str((params or {}).get("n") or "").lower()
        if name.endswith(".thumb"):
            return None
        if name.endswith(".jpg"):
            return {"id": "full-jpg"}
        return None

    monkeypatch.setattr("app.services.artifact_evidence_browse.fetchone", fake_fetchone)
    aid = _resolve_media_artifact_id(
        _Db(),
        "job",
        "93e3e2dc-0504-4393-9593-5ec916600074.thumb",
    )
    assert aid == "full-jpg"
