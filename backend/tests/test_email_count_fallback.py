"""Email / fallback counting rules for report section B."""

from app.services.axiom_aligned_counts import count_axiom_catalog_artifact


def test_report_email_collectors_skip_encyclopedia_fallback(monkeypatch) -> None:
    class _Db:
        pass

    monkeypatch.setattr(
        "app.services.email_inventory.collect_email_artifact",
        lambda _db, _jid, title, **_kw: {"count": 0},
    )
    monkeypatch.setattr(
        "app.services.axiom_aligned_counts.count_catalog_artifact_fallback",
        lambda *_a, **_k: 99999,
    )
    count = count_axiom_catalog_artifact(
        _Db(),
        "job",
        artifact_name="Windows Mail",
        category="Email & Calendar",
    )
    assert count == 0


def test_eml_metadata_uses_emlx_query_key() -> None:
    from app.services.axiom_count_spec import metadata_for_artifact

    meta = metadata_for_artifact(artifact_name="EML(X) Files", category="Email & Calendar")
    assert meta["query_key"] == "EMLX_FILE_WHERE"
