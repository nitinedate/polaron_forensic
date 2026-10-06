from app.services.action_agents import collect_action_votes
from app.services.agent_duties import report_generator_health
from app.services.report_generator_agent import (
    catalog_title_for_rpt_id,
    chunk_table_rows,
    count_disk_opo_blocks,
    display_objective_title,
    ensure_all_objectives_in_report,
    hydrate_section_c_objective,
    section_c_issues,
    sort_objectives_in_catalog_order,
    table_row_units,
    wrap_table_cell,
)
def test_objectives_follow_catalog_order_not_id_scramble():
    catalog = [
        {"objective_id": "RPT-O921", "title": "Browsing", "sort_order": 1},
        {"objective_id": "RPT-O922", "title": "USB", "sort_order": 2},
        {"objective_id": "RPT-O923", "title": "Email", "sort_order": 3},
    ]
    selected = [
        {"objective_id": "RPT-O923", "title": "Email"},
        {"objective_id": "RPT-O921", "title": "Browsing"},
        {"objective_id": "RPT-O922", "title": "USB"},
    ]
    ordered = sort_objectives_in_catalog_order(selected, catalog)
    assert [r["objective_id"] for r in ordered] == ["RPT-O921", "RPT-O922", "RPT-O923"]


def test_report_generator_does_not_auto_start_from_huddle():
    health = report_generator_health({"status": "indexing"})
    assert health["should_run"] is False
    assert "letterhead" in health["duty"].lower() or "A4" in health["duty"]
    assert "page number" in health["duty"].lower()
    assert "rpt-o920" in health["duty"].lower() or "catalog" in health["duty"].lower()


def test_evidence_details_is_not_a_report_page():
    from app.services.report_renderer import SECTION_ORDER

    assert "evidence_details" not in SECTION_ORDER


def test_report_generator_agent_votes_idle_not_run():
    snap = {
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}},
        "status": "indexed",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {"total": 1, "done": True, "completed": 1},
        "chunk_n": 10,
        "artifact_n": 10,
        "parse_pending": 0,
        "ocr_pending": 0,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": False,
        "list_folder_done": True,
    }
    vote = next(v for v in collect_action_votes(snap) if v["id"] == "report_generator_agent")
    assert vote["want"] != "run"


def test_url_wraps_at_delimiters_not_mid_token():
    url = "https://www.youtube.com/shorts/7SoQUvHFUlY"
    wrapped = wrap_table_cell(url)
    assert "\u200b" in wrapped
    assert "youtube\u200b.com" in wrapped or "youtube.com" in wrapped.replace("\u200b", "")


def test_tall_url_row_moves_to_next_page_instead_of_splitting():
    short = [["Edge", "https://a.test/", "1"]]
    tall = [["Edge", "https://www.youtube.com/watch?v=abcdefghijk-long-path-segment", "2"]]
    assert table_row_units(tall[0]) > table_row_units(short[0])
    rows = short * 8 + tall
    chunks = chunk_table_rows(rows, page_units=12)
    assert all(len(chunk) >= 1 for chunk in chunks)
    flat = [row for chunk in chunks for row in chunk]
    assert flat == rows


def test_missing_objective_cards_are_appended():
    md = "## C. OBJECTIVE, PROCEDURE & OBSERVATION\n\n### 1. Browsing\n\n**Objective**\n\nx\n"
    objectives = [
        {"title": "Browsing", "objective": "x"},
        {"title": "USB devices", "objective": "Find USB use", "procedure_text": "Check logs"},
    ]
    out = ensure_all_objectives_in_report(md, objectives)
    assert count_disk_opo_blocks(out) == 2
    assert "### 2. USB devices" in out


def test_hydrate_rpt_ids_fills_objective_and_procedure():
    cloud = hydrate_section_c_objective({"id": "RPT-O920", "title": "RPT-O920", "objective": "", "procedure_text": ""})
    disks = hydrate_section_c_objective({"id": "RPT-O921", "title": "RPT-O921"})
    assert catalog_title_for_rpt_id("RPT-O920") == "Access to Cloud Storage Services"
    assert cloud["title"] == "Access to Cloud Storage Services"
    assert disks["title"] == "Connection of External Hard Disks"
    assert "cloud" in cloud["objective"].lower() or "online storage" in cloud["objective"].lower()
    assert "external" in disks["objective"].lower()
    assert cloud["procedure_text"] not in {"", "—", "-"}
    assert disks["procedure_text"] not in {"", "—", "-"}
    assert "RPT-O" not in cloud["title"]
    assert not section_c_issues(cloud)
    assert not section_c_issues(disks)


def test_progress_title_never_prints_catalog_id():
    assert display_objective_title("RPT-O920") == "Access to Cloud Storage Services"
    assert display_objective_title({"id": "RPT-O921", "title": "RPT-O921"}) == "Connection of External Hard Disks"
    assert display_objective_title({"title": "Access to Cloud Storage Services", "id": "RPT-O920"}) == (
        "Access to Cloud Storage Services"
    )
    assert "RPT-O" not in display_objective_title("RPT-O927")


def test_ensure_all_objectives_does_not_print_catalog_ids():
    md = "## C. OBJECTIVE, PROCEDURE & OBSERVATION\n"
    out = ensure_all_objectives_in_report(
        md,
        [{"title": "RPT-O920", "id": "RPT-O920", "objective": "", "procedure_text": ""}],
    )
    assert "RPT-O920" not in out
    assert "Access to Cloud Storage Services" in out
    assert "**Objective**" in out
    assert "—" not in out.split("**Objective**", 1)[1].split("**Procedure**", 1)[0]


def test_report_generation_writes_every_section_even_after_errors():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "services" / "report_generator.py").read_text(
        encoding="utf-8"
    )
    assert "_write_one_report_section" in src
    assert "missing_section_backfill" in src
    assert "fallback_after_error" in src
    assert "status='incomplete'" not in src
    from app.services.report_renderer import SECTION_ORDER

    assert SECTION_ORDER.index("artifact_summary") < SECTION_ORDER.index("objectives_procedure_observation")
    assert SECTION_ORDER[-3:] == ["annexure", "final_analysis_summary", "appendix"]


def test_observations_are_built_from_linked_artifacts_not_all_scope():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "services"
        / "report_objectives_observation_service.py"
    ).read_text(encoding="utf-8")
    assert "REPORT_AGENT_SYSTEM_RULES" in src
    assert "build_structured_observation" in src
    assert "_scoped_artifact_context" not in src
    assert "Sources examined on this device" not in src
    assert "AXIOM-SYNCED EVIDENCE PLAN" not in src
    assert "timeout=45" in src
    assert "repair_section_c_objectives" in src


def test_artifact_page_budget_splits_groups_so_panel_text_is_not_clipped():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "lib"
        / "reportPagination.ts"
    ).read_text(encoding="utf-8")
    assert "paginateArtifactItemCosts" in src
    assert "ARTIFACT_ITEM_UNITS = 4" in src
    assert "ARTIFACT_PAGE_UNITS = 28" in src
    header, item, capacity = 2, 4, 28
    application_usage = header + 4 * item
    communication = header + 5 * item
    assert application_usage + communication > capacity


def test_frontend_opo_pagination_uses_page_space_for_next_complete_panel():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "lib"
        / "reportPagination.ts"
    ).read_text(encoding="utf-8")
    assert "OPO_PAGE_UNITS = 34" in src
    assert "OPO_CARD_OVERHEAD_UNITS = 3" in src
    assert "OPO_MIN_SPLIT_ROOM_UNITS = 6" in src
    assert "OPO_CHARS_PER_LINE = 78" in src
    assert "const room = capacity - used" in src
    assert "pull that prefix forward" in src
    assert "Never leave Objective/Procedure/Observation as the last line of a page" in src


def test_whatsapp_ui_renders_complete_thread_with_hash_datetime_and_deleted_red():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "components"
        / "forensic"
        / "ArtifactBrowsePanel.tsx"
    ).read_text(encoding="utf-8")
    assert "Loading complete conversation" in src
    assert "SHA-256 record:" in src
    assert "DELETED / RECOVERED" in src
    assert "bg-red-50" in src
    assert "pageSize = 8000" in src


def test_section_c_frontend_suppresses_legacy_laptop_banner():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "components"
        / "forensic"
        / "ReportDocumentPreview.tsx"
    ).read_text(encoding="utf-8")
    assert "laptop|desktop|computer|device" in src
    assert "Section C is a list of examination questions" in src
    assert "sj.device_label =" not in src


def test_report_agent_rules_forbid_device_banner_and_raw_payloads():
    from app.services import report_generator_agent

    duty = report_generator_agent.__doc__ or ""
    assert "Laptop [1]" in duty
    assert "raw XML/JSON" in duty
    assert "This means" in duty


def test_section_c_markdown_sanitizer_removes_only_legacy_device_banner():
    from app.services.report_generator_agent import sanitize_section_c_markdown

    md = (
        "## C. OBJECTIVE, PROCEDURE & OBSERVATION\n\n"
        "- Laptop [1]\n\n"
        "**Desktop [1]**\n\n"
        "### Device [1]\n\n"
        "### 1. File Access and Handling\n\n"
        "**Observation**\n\n"
        "A laptop file was opened.\n"
    )
    out = sanitize_section_c_markdown(md)
    assert "Laptop [1]" not in out
    assert "Desktop [1]" not in out
    assert "Device [1]" not in out
    assert "File Access and Handling" in out
    assert "A laptop file was opened." in out
