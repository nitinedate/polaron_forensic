"""Generate updatedDatabase/ — full SQL bundle for Aetheris (firm_aetheris).

Usage:
  python scripts/generate_updated_database.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "updatedDatabase"
MIGRATIONS = REPO / "migrations"
BACKEND = REPO / "backend"

FIRM_SLUG = "aetheris"
FIRM_NAME = "Aetheris"
FIRM_SCHEMA = "firm_aetheris"
FIRM_ID = "b0000000-0000-4000-8000-000000000001"
ADMIN_EMAIL = "admin@aetheris.in"
ADMIN_PASSWORD = "admin@123456789"
PLATFORM_ADMIN_EMAIL = "superadmin@admin.com"
PLATFORM_ADMIN_PASSWORD = "admin@123456789"
ADMIN_USER_ID = "b0000000-0000-4000-8000-000000000101"
ADMIN_ROLE_ID = "b0000000-0000-4000-8000-000000000110"
USER_ROLE_ID = "b0000000-0000-4000-8000-000000000111"
DEFAULT_CASE_ID = "00000000-0000-4000-8000-000000000001"

FUNCTION_MIGRATIONS = (
    "000_enable_pgvector.sql",
    "004_firm_rbac_seed_function.sql",
    "005_restrict_firm_user_role.sql",
    "006_firm_forensic_phase2.sql",
    "007_firm_rag_gpu.sql",
    "008_firm_job_stop_resume.sql",
    "009_phase3_forensic_rag_report.sql",
    "010_rag_chunks_nullable_job_id.sql",
    "011_export_manifest_vol18_intake.sql",
    "010_axiom_job_inventory.sql",
    "011_objective_custom.sql",
    "012_firm_vuln_module.sql",
    "013_firm_vuln_brd_complete.sql",
    "014_firm_agentic_ai.sql",
    "015_artifact_group_selection.sql",
    "016_vuln_brd_v21.sql",
    "017_vuln_asv_pentest_edr.sql",
    "018_firm_cases.sql",
    "019_vuln_orchestrator.sql",
)

PUBLIC_EXTRA = (
    ("022_case_type_catalog.sql", "04_case_type_catalog.sql"),
)

INCREMENTAL_MIGRATIONS = (
    "020_rename_installed_programs_non_microsoft.sql",
    "021_report_communication_url_artifacts.sql",
    "022_case_type_catalog.sql",
    "023_axiom_forensic_extensions.sql",
    "024_axiom_count_metadata_sync.sql",
)

APPLY_FIRM_FUNCTIONS = (
    "apply_firm_forensic_phase2",
    "apply_firm_rag_gpu",
    "apply_firm_job_control",
    "apply_firm_phase3",
    "apply_firm_phase3_fixes",
    "apply_firm_phase3_export_intake",
    "apply_firm_axiom_inventory",
    "apply_firm_axiom_custom_objectives",
    "apply_firm_vuln",
    "apply_firm_vuln_brd",
    "apply_firm_vuln_v21",
    "apply_firm_vuln_extended",
    "apply_firm_cases",
    "apply_firm_vuln_orchestrator",
    "apply_firm_agentic_ai",
    "apply_firm_artifact_group_selection",
    "apply_firm_report_template_selection",
    "apply_firm_pipeline_heal",
)


def _bcrypt(password: str) -> str:
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["bcrypt"], deprecated="auto").hash(password)
    except Exception:
        sys.path.insert(0, str(BACKEND))
        from app.services.security import hash_password

        return hash_password(password)


def _load_firm_permissions() -> list[tuple[str, str, str, str]]:
    sys.path.insert(0, str(BACKEND))
    from app.services.permissions_catalog import FIRM_PERMISSIONS

    return list(FIRM_PERMISSIONS)


def _strip_bulk_apply(sql: str) -> str:
    """Remove SELECT apply_*_all() tail calls — fresh install uses per-firm script."""
    lines = []
    for line in sql.splitlines():
        if re.match(r"^\s*SELECT\s+public\.(apply_firm_\w+_all|restrict_firm_user_roles)\(\)", line, re.I):
            continue
        if re.match(r"^\s*SELECT\s+public\.apply_firm_axiom_custom_objectives\(schema_name\)", line, re.I):
            continue
        if re.match(r"^\s*FROM\s+public\.firms", line, re.I):
            continue
        if re.match(r"^\s*WHERE\s+status\s*=\s*'active'", line, re.I):
            continue
        lines.append(line)
    return "\n".join(lines).rstrip() + "\n"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _axiom_catalog_sql() -> str:
    return """-- Public AXIOM catalog (from Alembic 002–004)

CREATE TABLE IF NOT EXISTS public.axiom_objectives (
    objective_id TEXT PRIMARY KEY,
    procedure_id TEXT,
    domain TEXT,
    title TEXT,
    statement TEXT,
    primary_artifact_families TEXT,
    required_observation_fields TEXT,
    minimum_corroboration TEXT,
    limitations TEXT,
    priority TEXT,
    prompt_question TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.axiom_procedures (
    procedure_id TEXT PRIMARY KEY,
    objective_id TEXT,
    domain TEXT,
    title TEXT,
    detailed_procedure TEXT,
    mandatory_corroboration TEXT,
    expected_output_fields TEXT,
    limitations TEXT,
    prompt_question TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.axiom_artifacts (
    artifact_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    category TEXT NOT NULL,
    application_or_profile TEXT,
    artifact_name TEXT NOT NULL,
    recovery_method TEXT,
    reference_page INTEGER,
    primary_objective_id TEXT,
    secondary_objective_ids TEXT,
    procedure_id TEXT,
    observation_focus TEXT,
    outline_path TEXT,
    prompt_question TEXT,
    critical BOOLEAN NOT NULL DEFAULT FALSE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    source_version TEXT,
    source_published TEXT,
    source_url TEXT,
    mapping_note TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_axiom_artifact_platform_cat_name UNIQUE (platform, category, artifact_name)
);

CREATE INDEX IF NOT EXISTS ix_axiom_artifacts_platform ON public.axiom_artifacts (platform);
CREATE INDEX IF NOT EXISTS ix_axiom_artifacts_platform_category ON public.axiom_artifacts (platform, category);

ALTER TABLE public.axiom_artifacts ADD COLUMN IF NOT EXISTS prompt_question TEXT;
ALTER TABLE public.axiom_artifacts ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE public.axiom_objectives ADD COLUMN IF NOT EXISTS prompt_question TEXT;
ALTER TABLE public.axiom_procedures ADD COLUMN IF NOT EXISTS prompt_question TEXT;
"""


def _firm_base_schema_sql() -> str:
    raw = (BACKEND / "app" / "db" / "firm_schema.sql").read_text(encoding="utf-8")
    sql = raw.replace("{schema}", FIRM_SCHEMA)
    header = f"""-- Base firm IAM + forensic scaffold for {FIRM_SCHEMA}
CREATE SCHEMA IF NOT EXISTS "{FIRM_SCHEMA}";

"""
    return header + sql


def _firm_rbac_seed_sql(permissions: list[tuple[str, str, str, str]]) -> str:
    perm_rows = []
    for i, (code, resource, action, desc) in enumerate(permissions, start=1):
        pid = f"b1000000-0000-4000-8000-{i:012d}"
        esc = desc.replace("'", "''")
        perm_rows.append(
            f"    ('{pid}', '{code}', '{resource}', '{action}', '{esc}')"
        )
    perm_values = ",\n".join(perm_rows)

    perm_ids = [f"b1000000-0000-4000-8000-{i:012d}" for i in range(1, len(permissions) + 1)]
    role_perm_values = ",\n".join(
        f"    ('{ADMIN_ROLE_ID}', '{pid}')" for pid in perm_ids
    )

    return f"""-- Firm RBAC catalog + admin/user roles ({FIRM_SCHEMA})
SET search_path TO "{FIRM_SCHEMA}", public;

INSERT INTO "{FIRM_SCHEMA}".permissions (id, code, resource, action, description) VALUES
{perm_values}
ON CONFLICT (code) DO NOTHING;

INSERT INTO "{FIRM_SCHEMA}".roles (id, name, description, is_system) VALUES
    ('{ADMIN_ROLE_ID}', 'admin', 'Firm administrator — full organization access', TRUE),
    ('{USER_ROLE_ID}', 'user', 'Standard firm user — profile and security settings only', TRUE)
ON CONFLICT (name) DO NOTHING;

INSERT INTO "{FIRM_SCHEMA}".role_permissions (role_id, permission_id) VALUES
{role_perm_values}
ON CONFLICT DO NOTHING;

DELETE FROM "{FIRM_SCHEMA}".role_permissions rp
USING "{FIRM_SCHEMA}".roles ro
WHERE rp.role_id = ro.id AND ro.name = 'user';
"""


def _firm_apply_sql() -> str:
    lines = [
        f"-- Apply all firm migration functions to {FIRM_SCHEMA}",
        f'SET search_path TO "{FIRM_SCHEMA}", public;',
        "",
        "SELECT public.apply_vuln_platform_v21();",
    ]
    for fn in APPLY_FIRM_FUNCTIONS:
        lines.append(f"SELECT public.{fn}('{FIRM_SCHEMA}');")
    return "\n".join(lines) + "\n"


def _firm_admin_sql(password_hash: str) -> str:
    esc_hash = password_hash.replace("'", "''")
    profile = '{"first_name": "Aetheris", "last_name": "Admin", "locale": "en", "timezone": "UTC"}'
    return f"""-- Aetheris firm admin (active, no invite required)
SET search_path TO "{FIRM_SCHEMA}", public;

INSERT INTO public.firms (id, name, slug, schema_name, status, plan, primary_host)
VALUES (
    '{FIRM_ID}',
    '{FIRM_NAME}',
    '{FIRM_SLUG}',
    '{FIRM_SCHEMA}',
    'active',
    'standard',
    NULL
)
ON CONFLICT (slug) DO UPDATE SET
    name = EXCLUDED.name,
    schema_name = EXCLUDED.schema_name,
    status = EXCLUDED.status;

INSERT INTO "{FIRM_SCHEMA}".users (
    id, email, password_hash, status, is_email_verified, mfa_enabled, profile
) VALUES (
    '{ADMIN_USER_ID}',
    '{ADMIN_EMAIL}',
    '{esc_hash}',
    'active',
    TRUE,
    FALSE,
    '{profile}'::jsonb
)
ON CONFLICT (email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    status = 'active',
    is_email_verified = TRUE,
    mfa_enabled = FALSE;

INSERT INTO "{FIRM_SCHEMA}".user_roles (user_id, role_id)
SELECT '{ADMIN_USER_ID}', r.id
FROM "{FIRM_SCHEMA}".roles r
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO "{FIRM_SCHEMA}".cases (id, title, status, timezone)
VALUES (
    '{DEFAULT_CASE_ID}',
    'Default workspace',
    'open',
    'UTC'
)
ON CONFLICT (id) DO NOTHING;
"""


def _load_optional_template(templates: dict[str, str], rel: str) -> str | None:
    return templates.get(rel)


def _investigation_area_public_sql(templates: dict[str, str]) -> str:
    template = _load_optional_template(templates, "01-public/05_investigation_area_catalog.sql")
    if template:
        return template
    src = MIGRATIONS / "023_axiom_forensic_extensions.sql"
    lines = src.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    for line in lines:
        if line.strip().startswith("-- Extend firm job_axiom"):
            break
        out.append(line)
    return "\n".join(out).rstrip() + "\n"


def _axiom_catalog_patches_sql(templates: dict[str, str]) -> str:
    template = _load_optional_template(templates, "04-seed-axiom/07_axiom_catalog_patches.sql")
    if template:
        return template
    parts = [
        (MIGRATIONS / "020_rename_installed_programs_non_microsoft.sql").read_text(encoding="utf-8"),
        (MIGRATIONS / "024_axiom_count_metadata_sync.sql").read_text(encoding="utf-8"),
    ]
    return "-- Post-seed AXIOM catalog patches\n\n" + "\n\n".join(p.rstrip() for p in parts) + "\n"


def _axiom_inventory_sp_sql(templates: dict[str, str]) -> str:
    template = _load_optional_template(templates, "02-functions/10_010_axiom_job_inventory.sql")
    if template:
        return template
    raw = (MIGRATIONS / "023_axiom_forensic_extensions.sql").read_text(encoding="utf-8")
    start = raw.index("CREATE OR REPLACE FUNCTION public.apply_firm_axiom_inventory")
    end = raw.index("SELECT public.apply_firm_axiom_inventory_all();")
    block = raw[start:end].rstrip() + "\n\n"
    block += """CREATE OR REPLACE FUNCTION public.apply_firm_axiom_inventory_all()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN SELECT schema_name FROM public.firms WHERE status = 'active' LOOP
        PERFORM public.apply_firm_axiom_inventory(rec.schema_name);
    END LOOP;
END;
$$;
"""
    return "-- AXIOM artifact inventory + structured observations (per firm).\n\n" + block + "\n"


def _incremental_bundle_readme() -> str:
    return """# Incremental migrations (020–024)

Apply on an **existing** Aetheris database that was built before the AXIOM forensic extensions.

| File | Source migration | Contents |
|------|------------------|----------|
| `sql_1.sql` | 020 | Rename AX-0011 installed programs label |
| `sql_2.sql` | 021 | Communication URL report-template artifacts |
| `sql_3.sql` | 022 | Case types + report type templates |
| `sql_4.sql` | 023 | Investigation areas, firm SP updates, artifact maps, metadata |
| `sql_5.sql` | 024 | Count-domain metadata sync |

```powershell
cd E:\\rag_new2
.\\updatedDatabase\\05-migrations\\run-incremental.ps1
```
"""


def _run_all_manifest(file_paths: list[str]) -> str:
    lines = [
        "-- Master install script (run in order against database `forensic`)",
        "\\set ON_ERROR_STOP on",
        "",
    ]
    for rel in file_paths:
        lines.append(f"\\i {rel.replace(chr(92), '/')}")
    return "\n".join(lines) + "\n"


def main() -> None:
    password_hash = _bcrypt(ADMIN_PASSWORD)
    permissions = _load_firm_permissions()

    template_paths = (
        "01-public/05_investigation_area_catalog.sql",
        "04-seed-axiom/07_axiom_catalog_patches.sql",
        "02-functions/10_010_axiom_job_inventory.sql",
    )
    templates: dict[str, str] = {}
    if OUT.exists():
        for rel in template_paths:
            path = OUT / rel
            if path.exists():
                templates[rel] = path.read_text(encoding="utf-8")

    if OUT.exists():
        import shutil

        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    manifest: list[str] = []

    # 00 extensions
    ext_src = REPO / "docker" / "postgres" / "init" / "01_extensions.sql"
    ext_dst = OUT / "00-extensions" / "01_extensions.sql"
    _write(ext_dst, ext_src.read_text(encoding="utf-8"))
    manifest.append("00-extensions/01_extensions.sql")

    # 01 public schema
    for name in ("001_public_schema.sql", "002_platform_rbac_superadmin.sql"):
        src = MIGRATIONS / name
        dst = OUT / "01-public" / name
        _write(dst, src.read_text(encoding="utf-8"))
        manifest.append(f"01-public/{name}")

    axiom_dst = OUT / "01-public" / "03_axiom_catalog.sql"
    _write(axiom_dst, _axiom_catalog_sql())
    manifest.append("01-public/03_axiom_catalog.sql")

    for src_name, dst_name in PUBLIC_EXTRA:
        src = MIGRATIONS / src_name
        if not src.exists():
            raise FileNotFoundError(src)
        _write(OUT / "01-public" / dst_name, src.read_text(encoding="utf-8"))
        manifest.append(f"01-public/{dst_name}")

    _write(OUT / "01-public" / "05_investigation_area_catalog.sql", _investigation_area_public_sql(templates))
    manifest.append("01-public/05_investigation_area_catalog.sql")

    # 04 AXIOM catalog seed (objectives, procedures, artifacts)
    scripts_dir = REPO / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from export_axiom_seed_sql import export_axiom_seed_sql

    axiom_seed_dir = OUT / "04-seed-axiom"
    seed_files = export_axiom_seed_sql(axiom_seed_dir)
    manifest.extend(seed_files)

    _write(axiom_seed_dir / "07_axiom_catalog_patches.sql", _axiom_catalog_patches_sql(templates))
    manifest.append("04-seed-axiom/07_axiom_catalog_patches.sql")

    # 02 functions / SPs
    for i, name in enumerate(FUNCTION_MIGRATIONS, start=1):
        src = MIGRATIONS / name
        if not src.exists() and name != "010_axiom_job_inventory.sql":
            raise FileNotFoundError(src)
        dst = OUT / "02-functions" / f"{i:02d}_{name}"
        if name == "010_axiom_job_inventory.sql":
            content = _axiom_inventory_sp_sql(templates)
        else:
            content = _strip_bulk_apply(src.read_text(encoding="utf-8"))
        _write(dst, content)
        manifest.append(f"02-functions/{i:02d}_{name}")

    # 03 firm aetheris
    firm_files = {
        "01_create_schema_base.sql": _firm_base_schema_sql(),
        "02_apply_firm_functions.sql": _firm_apply_sql(),
        "03_seed_rbac.sql": _firm_rbac_seed_sql(permissions),
        "04_seed_admin_and_case.sql": _firm_admin_sql(password_hash),
    }
    for name, content in firm_files.items():
        dst = OUT / "03-firm-aetheris" / name
        _write(dst, content)
        manifest.append(f"03-firm-aetheris/{name}")

    # 05 incremental migrations (existing DB upgrades)
    inc_dir = OUT / "05-migrations"
    for i, name in enumerate(INCREMENTAL_MIGRATIONS, start=1):
        src = MIGRATIONS / name
        if not src.exists():
            raise FileNotFoundError(src)
        _write(inc_dir / f"sql_{i}.sql", src.read_text(encoding="utf-8"))
    _write(inc_dir / "README.md", _incremental_bundle_readme())
    _write(
        inc_dir / "run-incremental.sql",
        "-- Incremental migration bundle (migrations 020–024)\n\n"
        + "\n".join(f"\\i sql_{i}.sql" for i in range(1, len(INCREMENTAL_MIGRATIONS) + 1))
        + "\n",
    )
    inc_ps1 = """# Apply incremental migrations 020-024 (existing database only)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Root

$files = @(
"""
    inc_ps1 += ",\n".join(f'    "05-migrations/sql_{i}.sql"' for i in range(1, len(INCREMENTAL_MIGRATIONS) + 1))
    inc_ps1 += """
)

foreach ($rel in $files) {
    $path = Join-Path $Root $rel
    Write-Host "Applying $rel ..."
    Get-Content $path -Raw | docker compose -f (Join-Path $Repo "docker-compose.yml") exec -T postgres `
        psql -U forensic -d forensic -v ON_ERROR_STOP=1
}
Write-Host "Done."
"""
    _write(inc_dir / "run-incremental.ps1", inc_ps1)

    # README + runners
    readme = f"""# updatedDatabase — Aetheris full SQL bundle

Generated by `scripts/generate_updated_database.py`.

## Login (Aetheris firm admin)

| Field | Value |
|-------|-------|
| Organization slug | `{FIRM_SLUG}` |
| Email | `{ADMIN_EMAIL}` |
| Password | `{ADMIN_PASSWORD}` |

## Platform superadmin (from 01-public/002)

| Field | Value |
|-------|-------|
| Tenant | None (platform-scoped) |
| Email | `{PLATFORM_ADMIN_EMAIL}` |
| Password | `{PLATFORM_ADMIN_PASSWORD}` |

## Apply (Docker Postgres)

```powershell
cd E:\\rag_new2
Get-Content updatedDatabase\\run-all.ps1 | docker compose exec -T postgres psql -U forensic -d forensic -v ON_ERROR_STOP=1
```

Or file-by-file:

```powershell
.\\updatedDatabase\\run-all.ps1
```

## Contents

| Folder | Purpose |
|--------|---------|
| `00-extensions` | pgcrypto, pgvector |
| `01-public` | Platform tables, superadmin seed, AXIOM catalog DDL, case types, investigation areas |
| `04-seed-axiom` | INSERT objectives, procedures, artifacts (Magnet + report template) + post-seed patches |
| `02-functions` | Stored functions / SPs (`apply_firm_*`, `seed_firm_rbac`, …) |
| `03-firm-aetheris` | Schema `{FIRM_SCHEMA}`, apply functions, RBAC, admin user, default case |
| `05-migrations` | Incremental `sql_1.sql`–`sql_5.sql` (migrations 020–024) for existing DBs |

## Incremental upgrade (existing database)

```powershell
.\\updatedDatabase\\05-migrations\\run-incremental.ps1
```

## Regenerate

```powershell
python scripts/generate_updated_database.py
```

Re-export AXIOM seed only:

```powershell
python scripts/export_axiom_seed_sql.py
```
"""
    _write(OUT / "README.md", readme)

    ps1 = """# Apply updatedDatabase SQL in order (requires docker compose postgres running)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$files = @(
"""
    ps1 += ",\n".join(f'    "{f}"' for f in manifest)
    ps1 += """
)

foreach ($rel in $files) {
    $path = Join-Path $Root $rel
    Write-Host "Applying $rel ..."
    Get-Content $path -Raw | docker compose -f (Join-Path (Split-Path -Parent $Root) "docker-compose.yml") exec -T postgres `
        psql -U forensic -d forensic -v ON_ERROR_STOP=1
}
Write-Host "Done."
"""
    _write(OUT / "run-all.ps1", ps1)

    sh = """#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
"""
    for rel in manifest:
        sh += f'echo "Applying {rel} ..."\n'
        sh += f'docker compose -f "$REPO/docker-compose.yml" exec -T postgres psql -U forensic -d forensic -v ON_ERROR_STOP=1 < "$ROOT/{rel}"\n'
    sh += 'echo "Done."\n'
    _write(OUT / "run-all.sh", sh)

    _write(OUT / "run-all.sql", _run_all_manifest(manifest))

    print(f"Wrote {len(manifest)} SQL files to {OUT}")
    print(f"Platform superadmin: {PLATFORM_ADMIN_EMAIL} / {PLATFORM_ADMIN_PASSWORD}")
    print(f"Aetheris admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")


if __name__ == "__main__":
    main()
