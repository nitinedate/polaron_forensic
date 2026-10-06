from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_artifact_categories_carry_lightweight_job_state():
    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/categories")'):
        router.index('@router.get("/{job_id}/artifacts/resolve-path")')
    ]
    assert 'SELECT status, progress_pct FROM jobs WHERE id=:id' in block
    assert '"job_exists": True' in block
    assert '"job_status": str(job.get("status") or "")' in block
    assert '"job_progress_pct": int(job.get("progress_pct") or 0)' in block


def test_artifact_page_does_not_issue_redundant_job_detail_request():
    page = read("frontend/src/pages/forensic/ArtifactExplorerPage.tsx")
    assert "forensicApi.getJob(jobId)" not in page
    assert "setJobStatus(t.job_status ?? null)" in page
    assert "loadJobStatus" not in page


def test_category_client_preserves_job_state():
    api = read("frontend/src/lib/forensicApi.ts")
    types = read("frontend/src/lib/types/forensic.ts")
    assert 'job_exists: typeof data.job_exists === "boolean" ? data.job_exists : undefined' in api
    assert 'job_status: typeof data.job_status === "string"' in api
    assert "job_progress_pct: safeCount(data.job_progress_pct)" in api
    assert "job_status?: string | null" in types


def test_product_route_overrides_stale_job_service_pin():
    routing = read("frontend/src/lib/apiRouting.ts")
    assert 'route.startsWith("/forensic")' in routing
    assert 'return "forensic"' in routing
    job_block = routing[routing.index("const jobId = jobIdFromApiPath(path);"):routing.index("if (path.startsWith(\"/api/acquisition\"))")]
    assert "if (routeService) return routeService;" in job_block
    assert job_block.index("if (routeService) return routeService;") < job_block.index("lookupJobService(jobId)")
    assert 'alternateJobService(_service: ApiService): ApiService | null { return null; }' in routing
