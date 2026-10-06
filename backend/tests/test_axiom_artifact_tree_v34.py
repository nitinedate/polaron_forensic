from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_windows_reference_contains_media_definitions_even_when_evidence_has_zero_hits():
    path = ROOT / "data" / "axiom" / "Magnet_AXIOM_10.2.0_All_Artifacts.csv"
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("platform") == "Windows"]
    names = {(row.get("category"), row.get("artifact_name")) for row in rows}
    assert len(rows) >= 600
    assert ("Media", "Pictures") in names
    assert ("Media", "Videos") in names
    assert ("Media", "Audio") in names
    assert ("Documents", "Microsoft Word Documents") in names
    assert ("Documents", "PDF Documents") in names


def test_explorer_tree_keeps_zero_count_axiom_definitions_visible():
    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/categories")'):
        router.index('@router.get("/{job_id}/artifacts/resolve-path")')
    ]
    assert "for row in display_rows:" in block
    assert '"count": count' in block
    assert 'stale_provider_count' in block
    assert '"query_status": "pending" if stale_provider_count' in block
    assert "if count <= 0:" not in block
    assert "if not categories and display_rows:" not in block
    assert '"pictures": ("picture",)' in block
    assert '"videos": ("video",)' in block


def test_saved_report_scope_does_not_limit_evidence_inventory_anymore():
    source = read("backend/app/services/catalog_artifact_runner.py")
    block = source[
        source.index("def inventory_scope_rows("):
        source.index("def pending_inventory_rows(")
    ]
    assert "catalog_platforms_for_job" in block
    assert "for catalog_platform in platforms" in block
    assert "_artifact_rows_for_platform(db, catalog_platform)" in block
    assert "_stored_enabled_keys" not in block
    assert "enabled_set" not in block


def test_inventory_progress_ignores_stale_legacy_results_outside_current_catalog():
    source = read("backend/app/services/catalog_artifact_runner.py")
    block = source[
        source.index("def axiom_inventory_progress("):
        source.index("def parse_pending_count(")
    ]
    assert "scope_ids" in block
    assert "done_ids" in block
    assert "len(scope_ids & done_ids)" in block
    assert "SELECT count(*) c FROM job_axiom_artifact_results" not in block


def test_tree_explains_all_definitions_and_zero_counts_are_visible():
    tree = read("frontend/src/components/forensic/ArtifactCategoryTree.tsx")
    assert "availableDefinitionCount" in tree
    assert "AXIOM artifact definitions" in tree
    assert "zero-count definitions remain visible" in tree
    assert "formatCount(node.count)" in tree


def test_reference_platform_count_matches_bundled_windows_catalog():
    from app.services.catalog_ingest import _reference_platform_count

    path = ROOT / "data" / "axiom" / "Magnet_AXIOM_10.2.0_All_Artifacts.csv"
    assert _reference_platform_count(path, "Windows") == 623


def test_catalog_ensure_repairs_partial_official_imports():
    source = read("backend/app/services/catalog_ingest.py")
    block = source[
        source.index("def ensure_platform_axiom_catalog("):
        source.index("def _upsert_mobile_catalog_pairs(")
    ]
    assert "expected_reference_count" in block
    assert "reference_incomplete" in block
    assert "official_before < expected_reference_count" in block
    assert "load_axiom_catalog_from_files(db, force=True)" in block
