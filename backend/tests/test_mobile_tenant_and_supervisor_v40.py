from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_unified_mobile_overview_does_not_default_jobs_to_forensic():
    routing = read("frontend/src/lib/apiRouting.ts")
    assert 'route === "/mobile" || route.startsWith("/mobile/")' in routing
    assert 'if (pathIsIam(path)) return configuredMobileService() || "forensic";' in routing


def test_supervisor_skips_schemas_without_jobs_and_does_not_invent_firm_aetheris():
    supervisor = read("backend/app/services/pipeline_supervisor.py")
    tasks = read("backend/app/tasks.py")
    provisioner = read("backend/app/services/tenant_provisioner.py")
    deps = read("backend/app/deps.py")
    assert "def _jobs_table_exists(" in supervisor
    assert 'reason": "jobs_table_missing"' in supervisor
    assert 'schemas = ["firm_aetheris"]' not in tasks
    assert "def ensure_product_firm(" in provisioner
    assert "ensure_product_firm(db, ctx.slug)" in deps
    assert "schema_has_table(db, firm.schema_name, \"jobs\")" in deps
