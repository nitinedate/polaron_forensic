"""Platform Superadmin seed SQL stays aligned with documented credentials."""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MIGRATIONS = REPO / "migrations"


def test_ensure_platform_admin_sql_creates_documented_login():
    sql = (MIGRATIONS / "036_ensure_platform_admin.sql").read_text(encoding="utf-8")
    assert "superadmin@admin.com" in sql
    assert "admin@123456789" in sql
    assert "platform" in sql
    assert "ON CONFLICT (id) DO UPDATE" in sql
    assert "$2b$12$" in sql


def test_002_and_036_use_the_same_hash_and_email():
    seed = (MIGRATIONS / "002_platform_rbac_superadmin.sql").read_text(encoding="utf-8")
    ensure = (MIGRATIONS / "036_ensure_platform_admin.sql").read_text(encoding="utf-8")
    assert "superadmin@admin.com" in seed
    assert "'$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G'" in seed
    assert "'$2b$12$6G2KYUmYNm079nYoFi5XOeB8yoXkqV7dkWtYJTIiqtkc.FK1WY3/G'" in ensure
