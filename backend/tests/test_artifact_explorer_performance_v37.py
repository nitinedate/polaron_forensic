from __future__ import annotations

from pathlib import Path


def test_request_index_helper_is_ddl_free(monkeypatch) -> None:
    from app.services import evidence_browse_indexes as idx

    class Db:
        def execute(self, *_a, **_k):
            raise AssertionError("interactive request must not run DDL")

    # Must be a cheap no-op; indexes are applied at tenant startup/migration.
    assert idx.ensure_evidence_browse_indexes(Db()) is None


def test_carve_browse_never_builds_inventory_on_get(monkeypatch) -> None:
    from app.services import signature_carve_inventory as carve

    monkeypatch.setattr(carve, "get_cached_signature_carve_inventory", lambda *_a, **_k: None)
    monkeypatch.setattr(
        carve,
        "ensure_signature_carve_inventory",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not scan from GET")),
    )
    result = carve.list_carve_evidence(None, "job", axiom_name="EML(X) Files")
    assert result["items"] == []
    assert result["total"] == 0
    assert carve.carved_axiom_count(None, "job", "EML(X) Files") == 0


def test_fast_properties_do_not_read_evidence_bytes(monkeypatch) -> None:
    from app.services import artifact_media_properties as props

    row = {
        "id": "11111111-1111-1111-1111-111111111111",
        "job_id": "22222222-2222-2222-2222-222222222222",
        "file_name": "message.eml",
        "file_path": "Users/x/Mail/message.eml",
        "extension": ".eml",
        "size_bytes": 4096,
        "sha256": "abc",
        "metadata": {"resolved_content_type": "message/rfc822"},
    }
    monkeypatch.setattr(props, "_load_artifact_row", lambda *_a, **_k: dict(row))
    monkeypatch.setattr(props, "fetchone", lambda *_a, **_k: None)
    monkeypatch.setattr(
        props,
        "iter_artifact_content",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("fast properties must not read disk")),
    )
    result = props.get_artifact_media_properties(None, row["job_id"], row["id"], probe_media=False)
    assert result["content_type"] == "message/rfc822"


def test_eml_browse_prefers_indexable_mime_and_extension_predicates() -> None:
    from app.services.artifact_list_queries import list_where_for_artifact_name

    suffix, _params = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="EML(X) Files",
        category="Email & Calendar",
        platform="Windows",
    )
    low = suffix.lower()
    assert "resolved_content_type" in low
    assert "message/rfc822" in low
    assert "lower(coalesce(extension" in low
    # V38 keeps exact predicates first but restores file-name/path suffix parity
    # for older rows whose extension/MIME backfill has not completed yet.
    assert "file_name" in low
    assert "file_path" in low
    assert "%.eml" in low


def test_v37_migration_contains_artifact_browse_indexes() -> None:
    repo = Path(__file__).resolve().parents[2]
    sql = (repo / "migrations" / "037_search_performance_indexes.sql").read_text(encoding="utf-8").lower()
    for token in (
        "ix_job_artifacts_job_path",
        "ix_job_artifacts_job_file_name_lower",
        "ix_job_artifacts_job_ext",
        "ix_job_artifacts_job_mime_resolved",
        "ix_job_artifacts_job_mime_resolved_lower",
        "ix_job_artifacts_job_mime_lower",
        "ix_job_artifacts_job_mime_scan_version",
        "ix_job_artifacts_path_trgm",
        "analyze %i.job_artifacts",
        "ix_artifact_parse_results_parser_artifact",
    ):
        assert token in sql


def test_frontend_stops_duplicate_detail_graph_and_five_second_list_poll() -> None:
    repo = Path(__file__).resolve().parents[2]
    explorer = (repo / "frontend" / "src" / "pages" / "forensic" / "ArtifactExplorerPage.tsx").read_text(encoding="utf-8")
    graph = (repo / "frontend" / "src" / "components" / "forensic" / "ArtifactGraphPanel.tsx").read_text(encoding="utf-8")
    # Selecting a row uses the already-returned metadata instead of another GET.
    select_body = explorer.split("function selectArtifact", 1)[1].split("function saveComment", 1)[0]
    assert "forensicApi.getArtifact(" not in select_body
    # Progress polling refreshes only the small category/progress payload.
    poll = explorer.split("window.setInterval", 1)[1].split("}, 10000)", 1)[0]
    assert "loadArtifacts" not in poll
    # Graph endpoint only echoed metadata; avoid a request on every selection.
    assert "getArtifactGraph" not in graph


def test_artifact_router_does_not_seed_encyclopedia_on_get() -> None:
    repo = Path(__file__).resolve().parents[2]
    src = (repo / "backend" / "app" / "routers" / "artifacts.py").read_text(encoding="utf-8")
    assert "ensure_extended_encyclopedia" not in src


def test_startup_seeds_extended_encyclopedia_once() -> None:
    repo = Path(__file__).resolve().parents[2]
    src = (repo / "backend" / "app" / "app_factory.py").read_text(encoding="utf-8")
    assert "ensure_extended_encyclopedia" in src


def test_artifact_categories_get_is_read_only() -> None:
    repo = Path(__file__).resolve().parents[2]
    src = (repo / "backend" / "app" / "routers" / "artifacts.py").read_text(encoding="utf-8")
    body = src.split('def artifact_categories(', 1)[1].split('@router.get("/{job_id}/artifacts/resolve-path")', 1)[0]
    assert "ensure_platform_axiom_catalog" not in body
    assert "from app.services.catalog_artifact_runner import ensure_artifact_inventory" not in body
    assert "\n            ensure_artifact_inventory(" not in body
    assert "ensure_artifact_mime_inventory" not in body
    assert "mime_inventory_progress" in body
    assert "ensure_schema=False" in body
    assert "ensure_catalog=False" in body


def test_platform_migration_scripts_include_v37_indexes() -> None:
    repo = Path(__file__).resolve().parents[2]
    ps1 = (repo / "scripts" / "apply_migrations.ps1").read_text(encoding="utf-8")
    sh = (repo / "scripts" / "apply_migrations.sh").read_text(encoding="utf-8")
    assert "037_search_performance_indexes.sql" in ps1
    assert "037_search_performance_indexes.sql" in sh
