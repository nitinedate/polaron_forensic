from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_acquisition_uses_catalog_job_permissions():
    acq = read("backend/app/routers/acquisition.py")
    assert 'require_firm_permission("job:read")' in acq
    assert 'require_firm_permission("job:run")' in acq
    assert "forensic.job.read" not in acq
    assert "forensic.job.create" not in acq


def test_live_run_poll_refreshes_access_token():
    api = read("frontend/src/lib/forensicApi.ts")
    sse = read("frontend/src/lib/acquisitionSse.ts")
    assert "listRuns: async (activeOnly = false)" in api
    assert "await ensureFreshAccessToken(120)" in api
    assert "await ensureFreshAccessToken(120)" in sse
