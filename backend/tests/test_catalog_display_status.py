from app.services.axiom_catalog_ingest import catalog_display_status


def test_uncounted_catalog_items_are_done_not_pending() -> None:
    assert catalog_display_status() == "done"
    assert catalog_display_status(stored_status=None) == "done"
    assert catalog_display_status(stored_status="pending") == "done"
    assert catalog_display_status(stored_status="done") == "done"
    assert catalog_display_status(stored_status="stored") == "done"


def test_failed_catalog_status_is_preserved() -> None:
    assert catalog_display_status(stored_status="failed") == "failed"
    assert catalog_display_status(stored_status="error") == "failed"
