"""Concurrent RAG + inventory pipeline_progress merges."""

from app.services.pipeline_progress import inventory_progress_active, merge_pipeline_progress


def test_rag_writer_preserves_active_inventory_fields():
    existing = {
        "phase": "artifact_inventory",
        "completed": 95,
        "total": 635,
        "label": "Artifact inventory — signature carving (15%)",
        "inventory_ui_pct": 15,
        "inventory_stage": "carve",
        "orchestration": {"overall_pct": 40, "agents": {"artifacts_agent": {"pct": 15, "state": "running"}}},
    }
    update = {
        "phase": "rag",
        "completed": 2500,
        "total": 7200,
        "label": "RAG embedding on cuda:0",
    }
    merged = merge_pipeline_progress(existing, update, writer="rag")
    assert merged["phase"] == "artifact_inventory"
    assert merged["inventory_ui_pct"] == 15
    assert merged["inventory_stage"] == "carve"
    assert merged["completed"] == 95
    assert merged["total"] == 635
    assert "signature carving" in (merged.get("label") or "")
    assert merged["rag_progress"]["completed"] == 2500
    assert merged["orchestration"]["overall_pct"] == 40


def test_inventory_active_helper():
    assert inventory_progress_active({"inventory_stage": "carve", "inventory_ui_pct": 15}) is True
    assert inventory_progress_active({"inventory_stage": "done", "inventory_ui_pct": 100}) is False
    assert inventory_progress_active({"phase": "rag", "completed": 1, "total": 10}) is False


def test_ocr_writer_preserves_orchestration():
    existing = {
        "phase": "artifact_inventory",
        "completed": 36,
        "total": 36,
        "label": "36 / 36 artifact inventory",
        "inventory_stage": "done",
        "inventory_ui_pct": 100,
        "orchestration": {
            "current_agent_id": "ocr_agent",
            "agents": {"ocr_agent": {"state": "running", "pct": 1}},
        },
    }
    update = {
        "phase": "ocr",
        "completed": 0,
        "total": 699,
        "label": "OCR starting — 699 pending",
    }
    merged = merge_pipeline_progress(existing, update, writer="ocr")
    assert merged["phase"] == "ocr"
    assert merged["completed"] == 0
    assert merged["total"] == 699
    assert merged["orchestration"]["current_agent_id"] == "ocr_agent"
    assert merged["inventory_ui_pct"] == 100
