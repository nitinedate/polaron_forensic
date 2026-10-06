from app.services.report_markdown_html import TABLE_ROWS_PER_PAGE, markdown_to_html


def test_long_table_splits_before_page_end():
    header = "| Device | Serial |\n| --- | --- |\n"
    rows = "".join(f"| USB {i} | SN-{i} |\n" for i in range(50))
    html = markdown_to_html("### USB devices\n" + header + rows)
    expected_tables = (50 + TABLE_ROWS_PER_PAGE - 1) // TABLE_ROWS_PER_PAGE
    assert html.count("<table>") == expected_tables
    assert "table-continued" in html
    assert "USB devices (continued)" in html
    assert html.count("<tr>") == 50 + expected_tables  # body rows + one header per chunk


def test_url_cells_wrap_at_slashes():
    md = (
        "### Browsing\n| URL | Visits |\n| --- | --- |\n"
        "| https://www.youtube.com/shorts/7SoQUvHFUlY | 56 |\n"
    )
    html = markdown_to_html(md)
    assert "\u200b" in html
    assert "youtube.com" in html.replace("\u200b", "")


def test_short_table_stays_on_one_page():
    md = "### Users\n| Name | Sid |\n| --- | --- |\n| Ada | S-1 |\n"
    html = markdown_to_html(md)
    assert html.count("<table>") == 1
    assert "table-continued" not in html
    assert "Users (continued)" not in html
    assert "<h3>Users</h3>" in html


def test_numbered_objective_cards_keep_together():
    md = (
        "### 5. Access to Cloud Storage Services\n\n"
        "**Objective**\n\n"
        "To check whether the laptop was used to access online storage.\n\n"
        "**Procedure**\n\n"
        "The internet browsing records were examined.\n\n"
        "**Observation**\n\n"
        "Traces of access to Google Drive were found.\n\n"
        "### 6. Connection of External Hard Disks\n\n"
        "**Objective**\n\n"
        "To find out whether external disks were connected.\n"
    )
    html = markdown_to_html(md)
    assert html.count("class='opo-card'") == 2 or html.count('class="opo-card"') == 2
    assert html.count("</div>") >= 2
    assert "Access to Cloud Storage Services" in html
    assert "RPT-O920" not in html


def test_observation_html_strips_file_paths():
    md = (
        "### 1. File Access and Handling\n\n"
        "**Observation**\n\n"
        "973 log files were analyzed from Windows/SoftwareDistribution/Download and "
        "Users/LENOVO/AppData/Local/Packages/MSTeams_8wekyb3d8bbwe/LocalCache.\n"
    )
    html = markdown_to_html(md)
    assert "AppData" not in html
    assert "SoftwareDistribution" not in html
    assert "LENOVO" not in html
    assert "no direct primary evidence" in html.lower()
    assert "This means" in html
    assert "973 log files" not in html


def test_opo_print_css_uses_full_printable_body_and_allows_long_card_continuation():
    from app.services.report_markdown_html import A4_PRINT_CSS

    assert "min-height: 217mm" in A4_PRINT_CSS
    assert ".opo-card" in A4_PRINT_CSS
    opo_css = A4_PRINT_CSS.split(".opo-card {", 1)[1].split("}", 1)[0]
    assert "page-break-inside: auto" in opo_css
    assert "break-inside: auto" in opo_css


def test_table_print_css_can_use_remaining_page_space_without_splitting_rows():
    from app.services.report_markdown_html import A4_PRINT_CSS

    table_block_css = A4_PRINT_CSS.split(".table-block {", 1)[1].split("}", 1)[0]
    table_css = A4_PRINT_CSS.split("table {", 1)[1].split("}", 1)[0]
    row_css = A4_PRINT_CSS.split("tr {", 1)[1].split("}", 1)[0]
    assert "page-break-inside: auto" in table_block_css
    assert "page-break-inside: auto" in table_css
    assert "page-break-inside: avoid" in row_css
    assert "thead { display: table-header-group; }" in A4_PRINT_CSS


def test_introduction_print_css_matches_reference_letter_layout():
    from app.services.report_markdown_html import A4_PRINT_CSS

    assert ".introduction-page > h2" in A4_PRINT_CSS
    assert "text-align: center" in A4_PRINT_CSS
    assert "text-transform: uppercase" in A4_PRINT_CSS
    assert "text-decoration: underline" in A4_PRINT_CSS
    assert "margin: 5mm 0 7mm" in A4_PRINT_CSS
