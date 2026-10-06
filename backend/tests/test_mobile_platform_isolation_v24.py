from pathlib import Path

import yaml

from app.service_identity import (
    MOBILE_ANDROID,
    MOBILE_IOS,
    canonical_mobile_job_type,
    health_role,
    job_type_platform,
    service_allows_job_type,
)
from app.forensic_common.pipeline_routing import domain_pipeline_agents, phase3_queue

ROOT = Path(__file__).resolve().parents[2]


def test_android_ios_admission_is_hard_separated():
    assert canonical_mobile_job_type(MOBILE_ANDROID) == "android_mobile"
    assert canonical_mobile_job_type(MOBILE_IOS) == "ios_mobile"
    assert service_allows_job_type("android_mobile", service=MOBILE_ANDROID)
    assert not service_allows_job_type("ios_mobile", service=MOBILE_ANDROID)
    assert service_allows_job_type("ios_mobile", service=MOBILE_IOS)
    assert not service_allows_job_type("android_mobile", service=MOBILE_IOS)
    assert not service_allows_job_type("host_disk", service=MOBILE_ANDROID)
    assert not service_allows_job_type("host_disk", service=MOBILE_IOS)
    assert job_type_platform("android_mobile") == "android"
    assert job_type_platform("ios_mobile") == "ios"
    assert health_role(MOBILE_ANDROID) != health_role(MOBILE_IOS)


def test_android_ios_celery_queues_never_overlap():
    text = (ROOT / "backend/app/celery_factory.py").read_text()
    assert 'ANDROID_ROUTES = _mobile_routes("android")' in text
    assert 'IOS_ROUTES = _mobile_routes("ios")' in text
    assert '"app.tasks.parse_shard_task": {"queue": parse}' in text
    assert '"app.tasks.parse_bucket_task": {"queue": parse}' in text
    for q in ("android-build", "android-parse", "android-rag", "android-ocr", "android-report"):
        assert q in (ROOT / "services/mobile-android/docker-compose.yml").read_text()
        assert q not in (ROOT / "services/mobile-ios/docker-compose.yml").read_text()
    for q in ("ios-build", "ios-parse", "ios-rag", "ios-ocr", "ios-report"):
        assert q in (ROOT / "services/mobile-ios/docker-compose.yml").read_text()
        assert q not in (ROOT / "services/mobile-android/docker-compose.yml").read_text()
    assert phase3_queue(MOBILE_ANDROID) == "android-build"
    assert phase3_queue(MOBILE_IOS) == "ios-build"


def test_platform_stage_agents_are_explicit():
    agents = domain_pipeline_agents()
    assert agents["extract_agent_android"]["queue"] == "android-build"
    assert agents["parse_agent_android"]["queue"] == "android-parse"
    assert agents["inventory_agent_android"]["queue"] == "android-build"
    assert agents["extract_agent_ios"]["queue"] == "ios-build"
    assert agents["parse_agent_ios"]["queue"] == "ios-parse"
    assert agents["inventory_agent_ios"]["queue"] == "ios-build"


def test_compose_has_physical_data_and_queue_isolation():
    android_path = ROOT / "services/mobile-android/docker-compose.yml"
    ios_path = ROOT / "services/mobile-ios/docker-compose.yml"
    android = yaml.safe_load(android_path.read_text())
    ios = yaml.safe_load(ios_path.read_text())
    assert android["name"] == "aetheris-mobile-android"
    assert ios["name"] == "aetheris-mobile-ios"
    aenv = android["x-mobile-env"]
    ienv = ios["x-mobile-env"]
    assert aenv["AETHERIS_SERVICE"] == "mobile-android"
    assert ienv["AETHERIS_SERVICE"] == "mobile-ios"
    common_db = "postgresql+psycopg2://forensic:forensic@postgres:5432/forensic"
    assert aenv["DATABASE_URL"] == common_db
    assert ienv["DATABASE_URL"] == common_db
    assert aenv["REDIS_URL"] == "redis://redis:6379/1"
    assert ienv["REDIS_URL"] == "redis://redis:6379/2"
    assert "postgres" not in android["services"]
    assert "redis" not in android["services"]
    assert "minio" not in android["services"]
    assert "postgres" not in ios["services"]
    assert "mobile-android" in aenv["MINIO_BUCKET"]
    assert "mobile-ios" in ienv["MINIO_BUCKET"]
    assert android["volumes"].keys().isdisjoint(ios["volumes"].keys())
    assert "android-build" in android_path.read_text()
    assert "ios-build" in ios_path.read_text()
    assert "ios-build" not in android_path.read_text()
    assert "android-build" not in ios_path.read_text()


def test_every_mobile_application_microservice_has_gpu_visibility():
    for service in ("mobile-android", "mobile-ios"):
        data = yaml.safe_load((ROOT / f"services/{service}/docker-compose.yml").read_text())
        for name in ("api", "worker-build", "worker-rag", "worker-ocr", "worker-report", "worker-beat"):
            assert data["services"][name].get("gpus") == "all", (service, name)
        assert data["x-mobile-env"]["NVIDIA_VISIBLE_DEVICES"] == "all"
        assert data["x-mobile-env"]["NVIDIA_DRIVER_CAPABILITIES"] == "compute,utility"


def test_shared_capacity_is_leases_only_and_not_job_broker():
    for service in ("mobile-android", "mobile-ios"):
        data = yaml.safe_load((ROOT / f"services/{service}/docker-compose.yml").read_text())
        env = data["x-mobile-env"]
        assert env["RESOURCE_GOVERNOR_REDIS_URL"].endswith("/15")
        assert env["REDIS_URL"] != env["RESOURCE_GOVERNOR_REDIS_URL"]
    common = yaml.safe_load((ROOT / "services/common/docker-compose.yml").read_text())
    for name in ("postgres", "redis", "minio", "pgadmin"):
        assert name in common["services"]
    assert common["services"]["postgres"]["ports"] == ["127.0.0.1:5434:5432"]
    assert common["services"]["redis"]["ports"] == ["127.0.0.1:${REDIS_HOST_PORT:-6380}:6379"]
    assert common["services"]["minio"]["ports"] == ["127.0.0.1:9004:9000", "127.0.0.1:9005:9005"]
    assert "5052" in common["services"]["pgadmin"]["ports"][0]


def test_mobile_ui_does_not_reuse_disk_job_detail():
    app = (ROOT / "frontend/src/App.tsx").read_text()
    assert 'path="mobile/jobs/:jobId"' in app
    assert "<MobileCompactJobPage />" in app
    assert 'path="mobile/jobs/:jobId/report"' in app
    routing = (ROOT / "frontend/src/lib/apiRouting.ts").read_text()
    assert 'export function alternateJobService(_service: ApiService): ApiService | null { return null; }' in routing
    assert '"mobile-android"' in routing and '"mobile-ios"' in routing


def test_mobile_extraction_never_calls_disk_orchestration_entrypoint():
    tasks = (ROOT / "backend/app/tasks.py").read_text()
    mobile_block = tasks.split('@celery.task(bind=True, name="app.tasks.build_extracted_mobile_task")', 1)[1]
    mobile_block = mobile_block.split("\ndef phase3_finalize_sync", 1)[0]
    assert "build_extracted_mobile_sync" in mobile_block
    assert "build_extracted_disk_sync" not in mobile_block

    disk = (ROOT / "backend/app/services/disk.py").read_text()
    assert "Mobile evidence cannot run through the Disk extraction backend" in disk
    assert "def build_extracted_image(" in disk
    assert "def _build_extracted_image_locked(" in disk

    mobile = (ROOT / "backend/app/services/mobile_forensic/extraction.py").read_text()
    assert "assert_mobile_extraction_ownership" in mobile
    assert "mobile_service_platform(service)" in mobile
    assert "service_allows_job_type(job_type, service=service)" in mobile
    assert "build_extracted_image(db, job_id" in mobile
    assert "build_extracted_disk" not in mobile


def test_dedicated_mobile_ui_starts_by_default_and_never_mounts_disk_job_detail():
    for service in ("mobile-android", "mobile-ios"):
        data = yaml.safe_load((ROOT / f"services/{service}/docker-compose.yml").read_text())
        assert "frontend" in data["services"]
        assert "profiles" not in data["services"]["frontend"]
    app = (ROOT / "frontend/src/App.tsx").read_text()
    compact = app.split("isDedicatedMobileService", 1)[-1]
    assert "MobileCompactJobPage" in compact
    assert "MobileReportPage" in compact


def test_all_python_mobile_microservices_use_cuda_runtime_and_shared_capacity():
    dockerfile = (ROOT / "backend/Dockerfile").read_text()
    assert "nvidia/cuda:" in dockerfile
    assert "runtime-ubuntu" in dockerfile
    for service in ("mobile-android", "mobile-ios"):
        data = yaml.safe_load((ROOT / f"services/{service}/docker-compose.yml").read_text())
        assert int(str(data["x-mobile-env"]["MAX_CONCURRENT_DISK_BUILDS"]).split(":-")[-1].rstrip("}")) >= 3
        for name in ("api", "worker-build", "worker-rag", "worker-ocr", "worker-report", "worker-beat"):
            assert data["services"][name]["gpus"] == "all"


def test_start_all_uses_new_isolated_mobile_products_not_legacy_stack():
    script = (ROOT / "scripts/start-stack.ps1").read_text()
    all_line = next(line for line in script.splitlines() if "$targets = if ($Service -eq \"all\")" in line)
    assert '"mobile-android"' in all_line
    assert '"mobile-ios"' in all_line
    assert '"mobile-extract"' not in all_line
    assert "services/capacity/docker-compose.yml" in script


def test_platform_workers_share_the_task_decorator_celery_instance():
    """Dedicated worker entrypoints must not create a second unregistered Celery app."""
    for name, identity in (("android", "MOBILE_ANDROID"), ("ios", "MOBILE_IOS")):
        text = (ROOT / f"backend/app/celery_mobile_{name}.py").read_text()
        assert f'os.environ["AETHERIS_SERVICE"] = {identity}' in text
        assert "from app.celery_app import celery" in text
        assert "create_celery(" not in text


def test_android_ios_server_evidence_mounts_are_platform_private():
    android_text = (ROOT / "services/mobile-android/docker-compose.yml").read_text()
    ios_text = (ROOT / "services/mobile-ios/docker-compose.yml").read_text()
    assert "ANDROID_HOST_EVIDENCE_PATH" in android_text
    assert "IOS_HOST_EVIDENCE_PATH" not in android_text
    assert "IOS_HOST_EVIDENCE_PATH" in ios_text
    assert "ANDROID_HOST_EVIDENCE_PATH" not in ios_text
    android = yaml.safe_load(android_text)
    ios = yaml.safe_load(ios_text)
    assert android["x-mobile-env"]["MINIO_BUCKET"] == "mobile-android"
    assert ios["x-mobile-env"]["MINIO_BUCKET"] == "mobile-ios"


def test_mobile_hostdrive_device_proxy_filters_sibling_platforms():
    text = (ROOT / "backend/app/routers/hostdrive.py").read_text()
    assert "_platform_filter_mobile_rows" in text
    assert 'key="mobile_devices"' in text
    assert 'key="devices"' in text
    assert "mobile_service_platform()" in text
    assert "detect_mobile_platform(row) == required" in text


def test_mobile_extraction_rejects_job_evidence_platform_conflicts():
    text = (ROOT / "backend/app/services/mobile_forensic/extraction.py").read_text()
    assert "source_platforms" in text
    assert "conflicting Android/iOS evidence metadata" in text
    assert "Job type is {type_platform} but evidence metadata is {source_platform}" in text


def test_extract_admission_is_fail_closed_and_retried_on_capacity():
    disk = (ROOT / "backend/app/services/disk.py").read_text()
    tasks = (ROOT / "backend/app/tasks.py").read_text()
    assert 'cpu_heavy_slot("extract", wait_sec=180.0, fail_closed=True, job_id=job_id)' in disk
    assert 'isinstance(exc, CpuHeavySlotTimeout)' in tasks
    assert 'self.retry(exc=exc, countdown=15, max_retries=480)' in tasks
