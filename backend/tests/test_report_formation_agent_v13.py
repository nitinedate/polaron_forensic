from __future__ import annotations

import pytest


def test_formation_training_contains_all_supplied_report_sources():
    from app.services.report_formation_agent import introduction_layout_profile, load_formation_training

    data = load_formation_training()
    assert data["version"] == "report-formation-training-v2.4"
    assert len(data["sources"]) == 6
    assert any("Mr.Seger" in name for name in data["sources"])
    assert "report_formation_agent" in data["agent_split"]
    intro = introduction_layout_profile()
    assert any("centered" in rule.lower() and "underlined" in rule.lower() for rule in intro["layout"])
    assert any("6-8 percent" in rule.lower() for rule in intro["watermark"])


def test_snapshot_preserves_exact_saved_ui_content():
    from app.services.report_formation_agent import snapshot_report

    sections = [
        {"section_key": "introduction", "title": "Introduction", "content_md": "Line 1\n\nLine   2"},
        {"section_key": "annexure", "title": "D. Annexure", "content_md": "| A | B |\n|---|---|\n|1|x|"},
    ]
    snap = snapshot_report(sections, order=["introduction", "annexure"])
    assert snap.sections[0]["content_md"] == "Line 1\n\nLine   2"
    assert snap.sections[1]["content_md"].endswith("|1|x|")
    assert len(snap.sha256) == 64


def test_export_parity_fails_closed_on_content_rewrite():
    from app.services.report_formation_agent import assert_export_content_parity

    source = [{"section_key": "x", "title": "X", "content_md": "Exact observation."}]
    rewritten = [{"section_key": "x", "title": "X", "content_md": "Changed observation."}]
    with pytest.raises(RuntimeError, match="matches the saved UI"):
        assert_export_content_parity(source, rewritten, order=["x"])


def test_agent_registry_splits_content_and_formation_agents():
    from app.services.action_agents import list_action_agents

    rows = {row["id"]: row for row in list_action_agents()}
    assert "report_generator_agent" in rows
    assert "report_formation_agent" in rows
    assert "forensic report CONTENT" in rows["report_generator_agent"]["action"]
    assert "forbidden to rewrite" in rows["report_formation_agent"]["action"]


def _sample_opo_card(title: str, observation: str) -> list[str]:
    return [
        title,
        "Objective",
        f"To examine {title.lower()}.",
        "Procedure",
        "Installed applications and relevant system records were examined.",
        "Observation",
        observation,
    ]


def test_opo_packer_fills_page_and_never_drops_lines():
    from app.services.report_formation_agent import (
        OPO_PAGE_UNITS,
        load_formation_training,
        opo_card_units,
        opo_pages_cover_source,
        pack_opo_cards,
    )

    training = load_formation_training()
    budget = training["opo_page_training"]["physical_budget"]
    assert budget["page_units"] == OPO_PAGE_UNITS
    cards = [
        _sample_opo_card("Anti-Forensic Tools or Cleanup Attempts", "No cleanup utility was identified. This means no wiping tool was found."),
        _sample_opo_card("USB and External Device Usage", "One supported USB device record was identified. This means an external device was connected."),
        _sample_opo_card("Shadow Copies & Backup Artifacts", "Volume shadow evidence was inconclusive. This means backup copies could not be confirmed."),
    ]
    pages = pack_opo_cards(cards)
    assert pages
    assert opo_pages_cover_source(cards, pages)
    assert sum(len(page) for page in pages) >= len(cards)
    first_page_units = sum(opo_card_units(card) for card in pages[0])
    assert first_page_units <= OPO_PAGE_UNITS
    if len(cards) >= 2 and opo_card_units(cards[0]) + opo_card_units(cards[1]) <= OPO_PAGE_UNITS:
        assert len(pages[0]) >= 2


def test_annexure_packer_never_drops_or_skips_rows():
    from app.services.report_formation_agent import (
        TABLE_MAX_URL_ROWS_CONTINUED,
        TABLE_MAX_URL_ROWS_FIRST,
        TABLE_PAGE_UNITS,
        annexure_pages_cover_source,
        annexure_table_training,
        load_formation_training,
        missing_annexure_rows,
        pack_annexure_tables,
        table_row_units,
    )

    training = load_formation_training()
    budget = training["annexure_table_training"]["physical_budget"]
    assert budget["page_units"] == TABLE_PAGE_UNITS
    assert annexure_table_training()["physical_budget"]["url_chars_per_line"] == 18
    assert budget["max_url_rows_first"] == TABLE_MAX_URL_ROWS_FIRST
    columns = ["Sr. No", "Domain", "URL", "Content Type", "Visits"]
    social = [
        [str(idx), "www.facebook.com", f"https://www.facebook.com/path/item-{idx}", "Web page", "1"]
        for idx in range(1, 16)
    ]
    typical = table_row_units(social[0], columns=columns)
    assert typical >= 2
    tables = [{"title": "Social Media URLs", "columns": columns, "rows": social, "note": "Preview — 15 sample URL(s)."}]
    pages = pack_annexure_tables(tables)
    assert pages
    assert annexure_pages_cover_source(tables, pages)
    assert missing_annexure_rows(tables, pages) == []
    first_rows = pages[0][0]["rows"]
    assert 1 <= len(first_rows) <= TABLE_MAX_URL_ROWS_FIRST
    assert first_rows[0][0] == "1"
    serials = [int(row[0]) for page in pages for chunk in page for row in chunk["rows"]]
    assert serials == list(range(1, 16))
    assert all(len(chunk["rows"]) <= TABLE_MAX_URL_ROWS_CONTINUED for page in pages for chunk in page)

    chat = [
        [str(idx), "config.edge.skype.com", f"https://config.edge.skype.com/path/{idx}", "Web page", "1"]
        for idx in range(1, 7)
    ]
    mixed_tables = [
        {"title": "Social Media URLs", "columns": columns, "rows": social, "note": "Preview — 15 sample URL(s)."},
        {"title": "Web Chat URLs", "columns": columns, "rows": chat},
    ]
    mixed = pack_annexure_tables(mixed_tables)
    assert annexure_pages_cover_source(mixed_tables, mixed)
    assert missing_annexure_rows(mixed_tables, mixed) == []
    social_serials = [
        int(row[0])
        for page in mixed
        for chunk in page
        if chunk.get("title") == "Social Media URLs"
        for row in chunk["rows"]
    ]
    assert social_serials == list(range(1, 16))


def test_analysis_summary_packer_never_skips_serial_eight():
    from app.services.report_formation_agent import (
        TABLE_MAX_PROSE_ROWS,
        missing_annexure_rows,
        pack_annexure_tables,
        table_row_units,
    )

    columns = ["Sr. No.", "Objective", "Procedure", "Observation"]
    rows = [
        [
            "6",
            "Detection of Torrent Activity",
            "The relevant installed Applications, browser history, download history, and browser Cache were examined and correlated to answer this question.",
            "No supported torrent/magnet URL or installed torrent-client evidence was identified in the records examined for this objective. This means the available evidence does not show torrent-related access or a torrent client; this does not prove activity could never have occurred outside the recovered evidence.",
        ],
        [
            "7",
            "Email Artifacts (Local Clients)",
            "The relevant email Messages, communication Attachments, and contacts were examined and correlated to answer this question.",
            "The examination identified 32 distinct email messages relevant to Email Communications. This includes 16 EML(X) files and 2 email attachments. There were no recoverable artifacts related to Windows Mail or Outlook Contacts. This means the evidence contained specific email communications that matched the defined criteria for this report.",
        ],
        [
            "8",
            "Event Logs & Timeline Reconstruction",
            "The relevant windows Event Log, timeline Events, and user-account records were examined and correlated to answer this question.",
            "The examination identified 3,861 distinct log events relevant to Windows Event Logs. No normalized timeline events were identified. This means only evidence that met the controlled AXIOM rules was used to answer this question, and no recoverable activity matching the criteria for normalized timeline events was found within the defined analysis scope.",
        ],
        [
            "9",
            "File Access and Handling",
            "The relevant recent Documents, shortcut-file records, recent-file/program records, and Recycle Bin records were examined and correlated to answer this question.",
            "Recent-file evidence identified 11 distinct file references to specific user documents. These records support recent/open-reference activity, but they do not by themselves prove copying or renaming.",
        ],
    ]
    assert table_row_units(rows[1], columns=columns) > 6
    tables = [{"title": "E. ANALYSIS SUMMARY", "columns": columns, "rows": rows}]
    pages = pack_annexure_tables(tables)
    assert missing_annexure_rows(tables, pages) == []
    serials = [str(row[0]) for page in pages for chunk in page for row in chunk["rows"]]
    assert serials == ["6", "7", "8", "9"]
    assert all(len(chunk["rows"]) <= TABLE_MAX_PROSE_ROWS for page in pages for chunk in page)
    for page in pages:
        page_serials = [str(row[0]) for chunk in page for row in chunk["rows"]]
        if "7" in page_serials:
            assert "9" not in page_serials


def test_opo_packer_splits_oversized_card_without_losing_text():
    from app.services.report_formation_agent import opo_pages_cover_source, pack_opo_cards

    card = [
        "File Access and Handling",
        "Objective",
        "To examine file access and handling.",
        "Procedure",
        "Recent documents, shortcut files and recycle-bin records were examined.",
        "Observation",
        *[f"Supported finding sentence {idx} remains in the report." for idx in range(1, 28)],
    ]
    pages = pack_opo_cards([card])
    assert len(pages) >= 2
    assert opo_pages_cover_source([card], pages)
