"""Bundled catalogs and SQL helpers used at API boot."""

from pathlib import Path

from app.catalogs.encyclopedia_seed import ENCYCLOPEDIA_RECORDS
from app.services.encyclopedia_ingest import encyclopedia_jsonl_path


REPO = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
BUNDLED_SQL = BACKEND / "app" / "db" / "sql_migrations"
MIGRATIONS = REPO / "migrations"


def test_encyclopedia_seed_is_nonempty():
    assert len(ENCYCLOPEDIA_RECORDS) >= 20
    ids = {r["artifact_id"] for r in ENCYCLOPEDIA_RECORDS}
    assert len(ids) == len(ENCYCLOPEDIA_RECORDS)
    assert any(r["operating_system"] == "Android" for r in ENCYCLOPEDIA_RECORDS)
    assert any(r["operating_system"] == "iOS" for r in ENCYCLOPEDIA_RECORDS)


def test_encyclopedia_jsonl_path_does_not_use_filesystem_root_when_missing():
    path = encyclopedia_jsonl_path()
    # Docker used to return /data/encyclopedia/artifacts.jsonl (parents[3] == /).
    assert str(path) != "/data/encyclopedia/artifacts.jsonl"


def test_bundled_036_matches_documented_login():
    sql = (BUNDLED_SQL / "036_ensure_platform_admin.sql").read_text(encoding="utf-8")
    assert "superadmin@admin.com" in sql
    assert "admin@123456789" in sql
    assert "platform" in sql
    assert "ON CONFLICT (id) DO UPDATE" in sql
    assert "$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G" in sql


def test_bundled_scanner_role_and_network_token_sql_exist():
    role = (BUNDLED_SQL / "031_firm_vuln_scanner_role.sql").read_text(encoding="utf-8")
    tokens = (BUNDLED_SQL / "034_firm_vuln_network_tokens.sql").read_text(encoding="utf-8")
    assert "apply_firm_vuln_scanner_role" in role
    assert "scanner_role" in role
    assert "apply_firm_vuln_network_tokens" in tokens
    assert "vuln_network_tokens" in tokens


def test_migrations_folder_copies_036_when_present():
    path = MIGRATIONS / "036_ensure_platform_admin.sql"
    if not path.is_file():
        return
    sql = path.read_text(encoding="utf-8")
    assert "superadmin@admin.com" in sql
    assert "'$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G'" in sql
