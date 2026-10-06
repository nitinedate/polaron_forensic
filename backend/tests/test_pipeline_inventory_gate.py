"""Pipeline phase gating — parse must finish before artifact inventory UI phase."""

from app.services.axiom_artifact_runner import INVENTORY_PHASE, inventory_pipeline_active


def test_inventory_not_active_while_parse_pending() -> None:
    assert inventory_pipeline_active(
        parse_pending=5325,
        inv_total=634,
        inv_completed=0,
        inv_done=False,
        phase="artifact_inventory",
        inventory_in_flight=False,
        inventory_started=False,
    ) is False


def test_inventory_active_after_parse_when_started() -> None:
    assert inventory_pipeline_active(
        parse_pending=0,
        inv_total=634,
        inv_completed=0,
        inv_done=False,
        phase=INVENTORY_PHASE,
        inventory_in_flight=False,
        inventory_started=True,
    ) is True


def test_inventory_active_when_counts_exist() -> None:
    assert inventory_pipeline_active(
        parse_pending=0,
        inv_total=634,
        inv_completed=12,
        inv_done=False,
        phase="rag",
        inventory_in_flight=False,
        inventory_started=False,
    ) is True
