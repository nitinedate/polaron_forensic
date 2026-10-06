from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_artifact_category_endpoint_returns_react_tree_contract():
    router = read("backend/app/routers/artifacts.py")
    block = router[router.index('@router.get("/{job_id}/artifacts/categories")'):router.index('@router.get("/{job_id}/artifacts/resolve-path")')]
    assert 'FROM public.axiom_artifacts' in block
    assert 'load_stored_axiom_inventory' in block
    assert '"category": str(row.get("category") or "Other")' in block
    assert '"sub_category": str(row.get("artifact_name")' in block
    assert '"catalog_key": artifact_id' in block
    assert '"total": raw_total' in block
    assert '"pending_chunk": 0' in block
    assert 'encyclopedia_artifact_id as cat' not in block


def test_frontend_normalizes_legacy_category_payloads_and_safe_counts():
    api = read("frontend/src/lib/forensicApi.ts")
    page = read("frontend/src/pages/forensic/ArtifactExplorerPage.tsx")
    tree = read("frontend/src/components/forensic/ArtifactCategoryTree.tsx")
    preview = read("frontend/src/components/forensic/ArtifactPreviewPanel.tsx")
    assert "row.category ?? row.key ?? row.label" in api
    assert "safeCount(data.total, computedTotal)" in api
    assert "tree.total.toLocaleString()" not in page
    assert "reviewSummary.flagged_total.toLocaleString()" not in page
    assert "formatCount(tree.total)" in page
    assert "safeCount(node?.count)" in tree
    assert "properties.width.toLocaleString()" not in preview


def test_unified_dashboard_uses_soft_failure_job_summary_route():
    dashboard = read("frontend/src/pages/Dashboard.tsx")
    api = read("frontend/src/lib/forensicApi.ts")
    nginx = read("frontend/nginx-gateway.conf")
    jobs = read("backend/app/routers/jobs.py")
    assert "listDashboardJobs" in dashboard
    assert 'api.get<JobList>("/api/dashboard/jobs"' in api
    assert "location = /api/dashboard/jobs" in nginx
    assert "error_page 401 403 404 502 503 504" in nginx
    assert "proxy_intercept_errors on" in nginx
    assert '"service_available":false' in nginx
    assert '@router.get("/dashboard/jobs", include_in_schema=False)' in jobs
    assert "[401, 403, 404, 502, 503, 504]" in api


def test_donut_slices_are_lightened_without_lightening_bar_charts():
    charts = read("frontend/src/components/charts/ApiCharts.tsx")
    assert '<Cell key={row.name} fill={row.fill} fillOpacity={0.62} />' in charts
    bar_block = charts[charts.index('<Bar dataKey="value"'):charts.index('</Bar>') + len('</Bar>')]
    assert "fillOpacity" not in bar_block
