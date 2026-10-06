from app.services.case_delete import (
    DEFAULT_WORKSPACE_ID,
    DELETABLE_SCAN_JOB_STATUSES,
    delete_case_cascade,
)


def test_active_scan_statuses_are_deletable():
    assert {"queued", "pending", "processing", "running"}.issubset(DELETABLE_SCAN_JOB_STATUSES)


def test_delete_case_rejects_default_workspace():
    try:
        delete_case_cascade(object(), DEFAULT_WORKSPACE_ID)
    except ValueError as exc:
        assert str(exc) == "default_workspace"
    else:
        raise AssertionError("default workspace must not be deleted")
