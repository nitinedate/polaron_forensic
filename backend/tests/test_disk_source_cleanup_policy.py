from __future__ import annotations

import json


def _row(*, intake: str, status: str = "ready", progress: int = 100, phase: str = "complete", total: int = 10, extracted: int = 10):
    return {
        "disk_source": {"intake": intake, "staging_purged": False},
        "status": status,
        "progress_pct": progress,
        "pipeline_progress": {"phase": phase},
        "files_total": total,
        "files_extracted": extracted,
    }


def test_server_local_source_is_never_purged(monkeypatch):
    import app.services.pipeline_orchestrator as po

    monkeypatch.setattr(po, "fetchone", lambda *args, **kwargs: _row(intake="server_local"))
    calls = []
    monkeypatch.setattr("app.services.client_intake.purge_job_staging", lambda job_id: calls.append(job_id) or {})
    monkeypatch.setattr(po, "execute", lambda *args, **kwargs: None)

    po._purge_browser_upload_dump(object(), "job-local")
    assert calls == []


def test_client_source_is_retained_until_verified_pipeline_success(monkeypatch):
    import app.services.pipeline_orchestrator as po

    updates = []
    monkeypatch.setattr(
        po,
        "fetchone",
        lambda *args, **kwargs: _row(
            intake="browser_upload", status="processing", progress=82, phase="artifacts", total=10, extracted=10
        ),
    )
    monkeypatch.setattr(po, "execute", lambda db, sql, params: updates.append(params))
    calls = []
    monkeypatch.setattr("app.services.client_intake.purge_job_staging", lambda job_id: calls.append(job_id) or {})

    po._purge_browser_upload_dump(object(), "job-client")
    assert calls == []
    assert updates
    ds = json.loads(updates[-1]["ds"])
    assert ds["staging_purge_pending"] is True
    assert "waiting for verified success" in ds["staging_purge_reason"]


def test_client_source_is_purged_after_verified_pipeline_success(monkeypatch):
    import app.services.pipeline_orchestrator as po

    updates = []
    logs = []
    monkeypatch.setattr(po, "fetchone", lambda *args, **kwargs: _row(intake="browser_upload"))
    monkeypatch.setattr(po, "execute", lambda db, sql, params: updates.append(params))
    monkeypatch.setattr(
        "app.services.client_intake.purge_job_staging",
        lambda job_id: {
            "job_id": job_id,
            "local_path": f"/app/data/uploads/{job_id}",
            "removed_local": True,
            "objects": 0,
            "object_purge_ok": True,
            "object_purge_error": None,
            "purged": True,
        },
    )
    monkeypatch.setattr("app.services.disk_build_log.write_disk_log", lambda *args, **kwargs: logs.append((args, kwargs)))

    po._purge_browser_upload_dump(object(), "job-client")
    assert updates
    ds = json.loads(updates[-1]["ds"])
    assert ds["staging_purged"] is True
    assert ds["staging_purge_pending"] is False
    assert ds.get("staging_purged_at")
    assert logs


def test_client_disk_download_parallelism_is_exactly_five():
    from app.services.download_agent import DOWNLOAD_PARALLELISM

    assert DOWNLOAD_PARALLELISM == 5
