from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (ROOT / rel).read_text(encoding='utf-8')


def test_catalog_browse_uses_virtual_evidence_before_file_sql() -> None:
    src = _src('app/routers/artifacts.py')
    marker = 'not necessarily one-to-one job_artifacts files'
    assert marker in src
    block = src[src.index(marker):]
    assert 'list_evidence_items(' in block
    assert 'catalog_key=catalog_key' in block
    assert 'return evidence_rows' in block
    assert block.index('return evidence_rows') < block.index('SELECT count(*) c FROM job_artifacts')


def test_virtual_browse_failure_falls_back_instead_of_http_500() -> None:
    src = _src('app/routers/artifacts.py')
    assert 'virtual evidence browse failed job=%s key=%s' in src
    assert 'Preserve file fallback' in src


def test_eml_browse_keeps_legacy_suffix_parity() -> None:
    src = _src('app/services/artifact_list_queries.py')
    # V38 keeps index-friendly MIME/extension predicates and compatibility for
    # legacy rows whose extension/resolved MIME have not yet been backfilled.
    assert "lower(coalesce(extension,'')) IN ('.eml', '.emlx')" in src
    assert "lower(coalesce(file_name,'')) LIKE '%.eml'" in src
    assert "lower(coalesce(file_path,'')) LIKE '%.emlx'" in src
