from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_all_console_themes_define_distinct_chart_palettes():
    css = read("frontend/src/index.css")
    for token in (
        '--chart-1:', '--chart-2:', '--chart-3:', '--chart-4:', '--chart-5:',
        '--chart-6:', '--chart-7:', '--chart-8:', '--chart-9:', '--chart-10:',
        '--chart-success:', '--chart-pending:', '--chart-processing:', '--chart-danger:',
        '--chart-track:', '--chart-separator:',
    ):
        assert css.count(token) == 3, token
    assert '[data-theme="harbor"]' in css
    assert '[data-theme="midnight"]' in css


def test_generic_categories_do_not_all_fall_back_to_one_status_color():
    counts = read("frontend/src/lib/chartCounts.ts")
    assert 'function semanticStatusColor' in counts
    assert 'fill: colors?.[name] || semanticStatusColor(name)' in counts
    assert 'fill: row.fill || semanticStatusColor(row.name)' in counts
    assert '|| "#f47b20"' not in counts


def test_donut_chart_uses_theme_palette_rotation_and_rounded_slices():
    charts = read("frontend/src/components/charts/ApiCharts.tsx")
    for i in range(1, 11):
        assert f'"rgb(var(--chart-{i}))"' in charts
    assert 'function paletteOffset' in charts
    assert 'paletteKey?: string' in charts
    assert 'cornerRadius={rows.length > 1 ? 5 : 0}' in charts
    assert 'stroke="rgb(var(--chart-separator))"' in charts


def test_semantic_status_and_vulnerability_donuts_are_theme_aware():
    counts = read("frontend/src/lib/chartCounts.ts")
    scan_jobs = read("frontend/src/pages/vuln/ScanJobsPage.tsx")
    assert 'rgb(var(--chart-success))' in counts
    assert 'rgb(var(--chart-danger))' in counts
    assert 'rgb(var(--chart-critical))' in scan_jobs
    assert 'rgb(var(--chart-high))' in scan_jobs
    assert 'rgb(var(--chart-medium))' in scan_jobs
    assert 'rgb(var(--chart-low))' in scan_jobs


def test_appearance_page_previews_chart_palette_for_each_theme():
    theme = read("frontend/src/lib/theme.tsx")
    page = read("frontend/src/pages/settings/AppearancePage.tsx")
    assert 'chart: string[]' in theme
    assert theme.count('chart: [') == 3
    assert 'Chart palette' in page
    assert 'item.preview.chart.map' in page
