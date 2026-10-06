from pathlib import Path


def _report_router_src() -> str:
    return (Path(__file__).resolve().parents[1] / "app" / "routers" / "report.py").read_text(encoding="utf-8")


def test_latest_report_run_prefers_running_so_recreate_is_visible():
    src = _report_router_src()
    running = src.index("WHEN 'running' THEN 0")
    completed = src.index("WHEN 'completed' THEN 1")
    assert running < completed


def test_start_report_recreate_supersedes_completed_drafts():
    src = _report_router_src()
    recreate_block = src.split("if recreate:", 1)[1].split("report_gen_task", 1)[0]
    assert "superseded" in recreate_block
    assert "completed" in recreate_block
    assert "running" in recreate_block
    assert "report_sections" in recreate_block
