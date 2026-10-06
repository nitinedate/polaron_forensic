import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_bundled_axiom_10_2_reference_is_full_and_has_exact_names():
    path = ROOT / "data" / "axiom" / "Magnet_AXIOM_10.2.0_All_Artifacts.csv"
    assert path.is_file()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) >= 3500
    windows = [row for row in rows if row.get("platform") == "Windows"]
    assert len(windows) >= 600
    lookup = {row["artifact_id"]: row for row in rows}
    assert lookup["AX-0009"]["artifact_name"] == "Feature Usage"
    assert lookup["AX-0143"]["artifact_name"] == "USB Devices"
    assert lookup["AX-0556"]["artifact_name"] == "Internet Explorer Downloads"


def test_catalog_loader_prefers_reference_csv_over_tiny_seed():
    source = read("backend/app/services/catalog_ingest.py")
    assert "Magnet_AXIOM_10.2.0_All_Artifacts.csv" in source
    assert "_upsert_csv_artifacts" in source
    assert '"official_artifact_id"' in source
    assert '"source": "magnet_axiom_10_2_csv"' in source
    assert "official_count >= 3500" in source


def test_artifact_tree_uses_axiom_names_and_persisted_counts_not_internal_ids():
    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/categories")'):
        router.index('@router.get("/{job_id}/artifacts/resolve-path")')
    ]
    assert "public.axiom_artifacts" in block
    assert "load_stored_axiom_inventory" in block
    assert '"sub_category": str(row.get("artifact_name")' in block
    assert '"catalog_key": artifact_id' in block
    assert '"count_domain": detail.get("count_domain")' in block
    assert "encyclopedia_artifact_id as cat" not in block
    assert "encyclopedia_artifact_id as cat" not in block


def test_frontend_filters_by_stable_axiom_catalog_key_and_shows_counts():
    page = read("frontend/src/pages/forensic/ArtifactExplorerPage.tsx")
    tree = read("frontend/src/components/forensic/ArtifactCategoryTree.tsx")
    api = read("frontend/src/lib/forensicApi.ts")
    assert "catalog_key: selected.catalogKey" in page
    assert "catalog_section: selected.catalogKey ? undefined" in page
    assert "node.catalog_key" in tree
    assert "formatCount(node.count)" in tree
    assert "catalog_key:" in api
    assert "axiom_inventory_done" in api


def test_optional_graph_endpoint_exists_and_never_404s_for_virtual_rows():
    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/{artifact_id}/graph")'):
        router.index('@router.get("/{job_id}/artifacts/{artifact_id}")', router.index('@router.get("/{job_id}/artifacts/{artifact_id}/graph")') + 1)
    ]
    assert '"entities": []' in block
    assert '"relationships": []' in block
    assert "raise HTTPException(status_code=404" not in block


def test_file_tree_contract_matches_react_type_and_is_lazy_loaded():
    router = read("backend/app/routers/artifacts.py")
    graph = read("frontend/src/components/forensic/ArtifactGraphPanel.tsx")
    block = router[router.index('@router.get("/{job_id}/file-tree")'):]
    assert '"summary": {' in block
    assert '"nodes": nodes' in block
    assert '"root": None' in block
    assert '"disk_artifact_id": None' in block
    assert 'tab !== "filetree"' in graph
    assert "getJobFileTree(jobId)" in graph


def test_old_jobs_automatically_backfill_missing_full_catalog_counts():
    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/categories")'):
        router.index('@router.get("/{job_id}/artifacts/resolve-path")')
    ]
    assert "ensure_artifact_inventory(db, job_id, schema_name=current.schema_name)" in block
    page = read("frontend/src/pages/forensic/ArtifactExplorerPage.tsx")
    assert "inventoryInProgress" in page
    assert "axiom_inventory_completed" in page
