"""Export a modular SQL dump from the live Postgres database.

Includes:
  - CREATE EXTENSION / SCHEMA / TABLE / TYPE / SEQUENCE
  - FUNCTIONs and stored PROCEDUREs
  - INDEXes, constraints, triggers
  - INSERT data for static/master catalogs only

Excludes disk/mobile job runtime data (jobs, artifacts, RAG, reports, logs, tokens, …).

Output: database_dump/
  00_manifest.sql
  01_create_extensions_schemas.sql
  02_create_tables_types.sql
  03_functions.sql
  04_stored_procedures.sql
  05_indexes_constraints_triggers.sql
  06_insert_static_data.sql
  07_comments.sql
  99_schema_and_static_dump.sql
  run-all.ps1 / run-all.sh

Usage:
  python scripts/export_database_dump.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "database_dump"
COMPOSE = REPO / "docker-compose.yml"

# Public master / catalog tables (static seed)
PUBLIC_STATIC_TABLES = (
    "alembic_version",
    "firms",
    "platform_permissions",
    "platform_roles",
    "platform_role_permissions",
    "platform_users",
    "platform_user_roles",
    "axiom_objectives",
    "axiom_procedures",
    "axiom_artifacts",
    "encyclopedia_artifacts",
    "encyclopedia_field_rows",
    "encyclopedia_sections",
    "encyclopedia_relationships",
    "report_type_templates",
    "case_types",
    "report_type_mandatory_areas",
    "reports_artifacts",
    "reports_objective",
    "investigation_area_templates",
    "artifact_investigation_area_map",
    "cisa_kev_catalog",
)

# Firm IAM / config — never dump job runtime rows
FIRM_STATIC_TABLES = (
    "users",
    "permissions",
    "roles",
    "role_permissions",
    "user_roles",
    "cases",
    "vuln_scanners",
    "vuln_scan_policies",
    "vuln_agents",
    "vuln_credential_refs",
    "vuln_asv_providers",
    "vuln_alert_thresholds",
    "vuln_custom_checks",
    "vuln_asset_owners",
)

# Explicitly excluded from INSERTs (job / session / runtime)
FIRM_JOB_TABLES = (
    "jobs",
    "job_artifacts",
    "job_axiom_artifact_results",
    "job_artifact_groups",
    "job_count_reconciliation",
    "job_objective_observations",
    "evidence_files",
    "disk_build_logs",
    "artifact_parse_results",
    "artifact_scope",
    "selected_job_artifacts",
    "selected_job_objectives_procedure",
    "objective_procedure_scope",
    "case_intake",
    "rag_chunks",
    "rag_retrieval_log",
    "ocr_results",
    "parser_runs",
    "graph_sync_state",
    "timeline_events",
    "report_runs",
    "report_sections",
    "report_citations",
    "report_exports",
    "report_findings",
    "human_feedback",
    "agent_threads",
    "agent_messages",
    "agent_runs",
    "agent_tool_calls",
    "refresh_tokens",
    "password_reset_tokens",
    "mfa_totp",
    "mfa_recovery_codes",
    "invitations",
    "forensic_cases",
    "vuln_scan_jobs",
    "vuln_scan_targets",
    "vuln_scan_results",
    "vuln_scan_engine_runs",
    "vuln_findings",
    "vuln_assets",
    "vuln_asset_identifiers",
    "vuln_notifications",
    "vuln_audit_events",
    "vuln_exceptions",
    "vuln_remediation_tasks",
    "vuln_risk_scores",
    "vuln_dashboard_snapshots",
    "vuln_evidence_packages",
    "vuln_endpoint_inventory",
    "vuln_finding_correlations",
    "vuln_pentest_jobs",
    "vuln_pentest_findings",
    "vuln_asv_submissions",
    "vuln_asv_attestations",
    "vuln_timeline_events",
)


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True)
    if check and proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", errors="replace"))
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def _docker_exec(*args: str) -> bytes:
    return _run(
        ["docker", "compose", "-f", str(COMPOSE), "exec", "-T", "postgres", *args]
    ).stdout


def _pg_dump(*args: str) -> bytes:
    return _docker_exec(
        "pg_dump",
        "-U",
        "forensic",
        "-d",
        "forensic",
        "--no-owner",
        "--no-acl",
        *args,
    )


def _psql_t(*sql: str) -> str:
    out = _docker_exec("psql", "-U", "forensic", "-d", "forensic", "-At", "-c", " ".join(sql))
    return out.decode("utf-8", errors="replace")


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")


def _banner(title: str, *, extra: str = "") -> str:
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    lines = [
        "-- =============================================================================",
        f"-- {title}",
        "-- =============================================================================",
        "-- Source database : forensic (PostgreSQL, container rag_new2-postgres-1)",
        f"-- Generated at    : {now}",
        "-- Host port       : localhost:5434",
        "-- Generator       : scripts/export_database_dump.py",
    ]
    if extra:
        for line in extra.splitlines():
            lines.append(f"-- {line}" if line else "--")
    lines.append("-- =============================================================================")
    lines.append("")
    return "\n".join(lines)


def _detect_firm_schemas() -> list[str]:
    rows = _psql_t(
        "SELECT DISTINCT schema_name FROM public.firms "
        "WHERE schema_name IS NOT NULL AND schema_name !~ '[{}]' "
        "ORDER BY 1;"
    )
    schemas = [r.strip() for r in rows.splitlines() if r.strip()]
    # Always include firm_a if present even when firms row missing
    existing = _psql_t(
        "SELECT nspname FROM pg_namespace "
        "WHERE nspname ~ '^firm_' AND nspname !~ '[{}]' ORDER BY 1;"
    )
    for name in existing.splitlines():
        name = name.strip()
        if name and name not in schemas:
            schemas.append(name)
    if not schemas:
        schemas = ["firm_a"]
    return schemas


def _existing_tables(schema: str, names: tuple[str, ...]) -> list[str]:
    array = ",".join(f"'{n}'" for n in names)
    rows = _psql_t(
        "SELECT tablename FROM pg_tables "
        f"WHERE schemaname = '{schema}' AND tablename = ANY(ARRAY[{array}]) "
        "ORDER BY tablename;"
    )
    return [r.strip() for r in rows.splitlines() if r.strip()]


def _split_predata_tables_and_functions(pre_data: str) -> tuple[str, str]:
    """Split pg_dump --section=pre-data into tables/types vs CREATE FUNCTION blocks."""
    # Keep SET/config headers with tables file; move CREATE FUNCTION / COMMENT ON FUNCTION.
    func_blocks: list[str] = []
    other_parts: list[str] = []
    # Split on object headers produced by pg_dump
    chunks = re.split(r"(?=\n--\n-- Name: )", "\n" + pre_data)
    header = chunks[0] if chunks else ""
    for chunk in chunks[1:]:
        head = chunk[:400]
        if "Type: FUNCTION;" in head or "Type: AGGREGATE;" in head:
            func_blocks.append(chunk.lstrip("\n"))
        else:
            other_parts.append(chunk.lstrip("\n"))
    tables = header.lstrip("\n") + ("\n" if other_parts else "") + "\n".join(other_parts)
    functions = "\n".join(func_blocks)
    if functions and not functions.endswith("\n"):
        functions += "\n"
    return tables, functions


def _dump_procedures(schemas: list[str]) -> str:
    schema_list = ",".join(f"'{s}'" for s in schemas)
    sql = f"""
SELECT 'CREATE OR REPLACE PROCEDURE '
    || quote_ident(n.nspname) || '.' || quote_ident(p.proname)
    || '(' || pg_get_function_identity_arguments(p.oid) || ')' || E'\\n'
    || 'LANGUAGE ' || l.lanname || E'\\n'
    || 'AS $procedure$' || E'\\n'
    || p.prosrc || E'\\n'
    || '$procedure$;' || E'\\n\\n'
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE p.prokind = 'p'
  AND n.nspname IN ({schema_list})
ORDER BY n.nspname, p.proname;
"""
    body = _psql_t(sql)
    if not body.strip():
        return (
            "-- No user-defined stored procedures (CREATE PROCEDURE) found.\n"
            "-- Firm DDL helpers are PostgreSQL FUNCTIONs and live in 03_functions.sql.\n"
        )
    return body


def _dump_comments(schemas: list[str]) -> str:
    schema_list = ",".join(f"'{s}'" for s in schemas)
    sql = f"""
SELECT '-- ' || n.nspname || '.' || c.relname || ': ' || replace(d.description, E'\\n', ' ')
FROM pg_description d
JOIN pg_class c ON c.oid = d.objoid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE d.objsubid = 0
  AND n.nspname IN ({schema_list})
ORDER BY 1
LIMIT 500;
"""
    body = _psql_t(sql)
    return body if body.strip() else "-- (no table comments)\n"


def main() -> None:
    firm_schemas = _detect_firm_schemas()
    schemas = ["public", *firm_schemas]
    print(f"Schemas: {', '.join(schemas)}")

    if OUT.exists():
        # Keep directory but replace generated SQL files
        for old in OUT.glob("*.sql"):
            old.unlink()
        for old in ("run-all.ps1", "run-all.sh", "README.md"):
            p = OUT / old
            if p.exists():
                p.unlink()
    OUT.mkdir(parents=True, exist_ok=True)

    # --- 01 extensions + schemas ---
    ext = _banner(
        "CREATE EXTENSIONS AND SCHEMAS",
        extra="Safe to run on empty Postgres before tables.",
    )
    ext += "CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;\n"
    ext += "CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;\n\n"
    for schema in firm_schemas:
        ext += f'CREATE SCHEMA IF NOT EXISTS "{schema}";\n'
    ext += "\n"
    _write(OUT / "01_create_extensions_schemas.sql", ext)

    # --- schema-only dumps ---
    schema_args: list[str] = []
    for schema in schemas:
        schema_args.extend(["--schema", schema])

    print("Dumping pre-data (tables/types/functions)…")
    pre_data = _pg_dump("--schema-only", "--section=pre-data", *schema_args).decode(
        "utf-8", errors="replace"
    )
    tables_sql, functions_sql = _split_predata_tables_and_functions(pre_data)

    _write(
        OUT / "02_create_tables_types.sql",
        _banner(
            "CREATE TABLES / TYPES / SEQUENCES",
            extra="From pg_dump --section=pre-data (functions extracted to 03).",
        )
        + tables_sql,
    )
    _write(
        OUT / "03_functions.sql",
        _banner(
            "FUNCTIONS",
            extra="CREATE FUNCTION / AGGREGATE extracted from schema dump.",
        )
        + (functions_sql or "-- (no functions extracted)\n"),
    )

    print("Dumping procedures…")
    _write(
        OUT / "04_stored_procedures.sql",
        _banner("STORED PROCEDURES", extra="CREATE PROCEDURE objects only.")
        + _dump_procedures(schemas),
    )

    print("Dumping post-data (indexes/constraints/triggers)…")
    post_data = _pg_dump("--schema-only", "--section=post-data", *schema_args).decode(
        "utf-8", errors="replace"
    )
    _write(
        OUT / "05_indexes_constraints_triggers.sql",
        _banner(
            "INDEXES / CONSTRAINTS / TRIGGERS",
            extra="From pg_dump --section=post-data.",
        )
        + post_data,
    )

    # --- static data only ---
    print("Dumping static INSERT data…")
    data_parts: list[bytes] = [
        _banner(
            "INSERT STATIC / MASTER DATA ONLY",
            extra=(
                "Includes catalogs, platform RBAC, firm IAM/config.\n"
                "EXCLUDES disk/mobile job tables: "
                + ", ".join(FIRM_JOB_TABLES[:12])
                + ", …"
            ),
        ).encode("utf-8")
    ]

    public_tables = _existing_tables("public", PUBLIC_STATIC_TABLES)
    if public_tables:
        args = ["--data-only", "--column-inserts", "--rows-per-insert=100"]
        for t in public_tables:
            args.extend(["-t", f"public.{t}"])
        data_parts.append(b"\n-- ---------- public master catalogs ----------\n")
        data_parts.append(_pg_dump(*args))

    for firm in firm_schemas:
        firm_tables = _existing_tables(firm, FIRM_STATIC_TABLES)
        if not firm_tables:
            continue
        args = ["--data-only", "--column-inserts", "--rows-per-insert=100"]
        for t in firm_tables:
            args.extend(["-t", f"{firm}.{t}"])
        data_parts.append(f"\n-- ---------- {firm} IAM / config ----------\n".encode())
        data_parts.append(
            f'SET search_path TO "{firm}", public;\n\n'.encode("utf-8")
        )
        data_parts.append(_pg_dump(*args))

    # Sanity: never include job tables even if listed by mistake
    joined = b"".join(data_parts)
    for bad in ("COPY public.jobs ", "COPY firm_", "INSERT INTO firm_a.jobs ", "INSERT INTO public.jobs "):
        # soft check — warn only
        pass
    if b"INSERT INTO firm_a.jobs " in joined or b"INSERT INTO public.jobs " in joined:
        raise RuntimeError("Refusing to write dump: job INSERTs leaked into static data")

    _write(OUT / "06_insert_static_data.sql", joined)

    _write(
        OUT / "07_comments.sql",
        _banner("COMMENTS", extra="Table comment inventory (informational).")
        + _dump_comments(schemas),
    )

    # Combined convenience dump: schema-only full + static data
    print("Writing combined 99_schema_and_static_dump.sql…")
    full_schema = _pg_dump("--schema-only", *schema_args)
    combined = (
        _banner(
            "FULL SCHEMA + STATIC DATA DUMP",
            extra=(
                "Schema objects for public + firm schemas, plus static INSERTs only.\n"
                "Job runtime data intentionally omitted."
            ),
        ).encode("utf-8")
        + b"CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;\n"
        + b"CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;\n\n"
        + full_schema
        + b"\n-- ========== STATIC DATA ==========\n\n"
        + joined
    )
    _write(OUT / "99_schema_and_static_dump.sql", combined)

    ordered = [
        "01_create_extensions_schemas.sql",
        "02_create_tables_types.sql",
        "03_functions.sql",
        "04_stored_procedures.sql",
        "05_indexes_constraints_triggers.sql",
        "06_insert_static_data.sql",
        "07_comments.sql",
    ]
    sizes = {f: (OUT / f).stat().st_size for f in ordered}
    sizes["99_schema_and_static_dump.sql"] = (OUT / "99_schema_and_static_dump.sql").stat().st_size

    manifest = _banner(
        "DATABASE DUMP MANIFEST",
        extra="Apply order and contents of this dump set (static data only).",
    )
    manifest += "-- Apply order (fresh database):\n"
    for f in ordered:
        manifest += f"--   {f}\n"
    manifest += "--\n-- Optional single-file restore:\n--   99_schema_and_static_dump.sql\n--\n"
    manifest += "-- Quick restore example:\n"
    manifest += "--   psql -h localhost -p 5434 -U forensic -d forensic -f 01_create_extensions_schemas.sql\n"
    manifest += "--   … through 07_comments.sql\n--\n-- File inventory:\n"
    for name, size in sizes.items():
        kb = size / 1024
        manifest += f"--   {name:42} {kb:10.1f} KB\n"
    manifest += f"--\n-- Schemas: {', '.join(schemas)}\n"
    manifest += "-- Static INSERT tables (public): " + ", ".join(public_tables) + "\n"
    for firm in firm_schemas:
        ft = _existing_tables(firm, FIRM_STATIC_TABLES)
        manifest += f"-- Static INSERT tables ({firm}): " + (", ".join(ft) if ft else "(none)") + "\n"
    manifest += (
        "-- Excluded (job/runtime): jobs, job_*, evidence_files, disk_build_logs, "
        "rag_*, report_*, artifact_parse_results, agent_*, tokens, MFA, scan findings, …\n"
    )
    _write(OUT / "00_manifest.sql", manifest)

    readme = f"""# database_dump — schema + static data

Generated by `scripts/export_database_dump.py` from the live `forensic` database.

## Included
- CREATE EXTENSION / SCHEMA / TABLE / TYPE / SEQUENCE
- FUNCTIONs and stored PROCEDUREs
- Indexes, constraints, triggers
- INSERT for static catalogs + firm IAM/config

## Excluded (disk / mobile job data)
- `jobs`, `job_artifacts`, `job_axiom_artifact_results`, `evidence_files`
- `disk_build_logs`, `rag_chunks`, `report_*`, `case_intake`
- agent runtime, tokens/MFA, vuln scan findings, etc.

## Schemas
{', '.join(schemas)}

## Apply (empty Postgres)

```powershell
cd E:\\rag_new2\\database_dump
.\\run-all.ps1
```

Or restore the single file:

```powershell
Get-Content .\\99_schema_and_static_dump.sql -Raw |
  docker compose -f ..\\docker-compose.yml exec -T postgres psql -U forensic -d forensic -v ON_ERROR_STOP=1
```

## Regenerate

```powershell
python scripts\\export_database_dump.py
```
"""
    _write(OUT / "README.md", readme)

    ps1 = """# Apply database_dump bundle (requires docker compose postgres)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Root
$files = @(
"""
    ps1 += ",\n".join(f'    "{f}"' for f in ordered)
    ps1 += """
)
foreach ($rel in $files) {
    $path = Join-Path $Root $rel
    Write-Host "Applying $rel ..."
    Get-Content $path -Raw | docker compose -f (Join-Path $Repo "docker-compose.yml") exec -T postgres `
        psql -U forensic -d forensic -v ON_ERROR_STOP=1
}
Write-Host "Done."
"""
    _write(OUT / "run-all.ps1", ps1)

    sh = "#!/usr/bin/env bash\nset -euo pipefail\nROOT=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nREPO=\"$(cd \"$ROOT/..\" && pwd)\"\n"
    for rel in ordered:
        sh += f'echo "Applying {rel} ..."\n'
        sh += (
            f'docker compose -f "$REPO/docker-compose.yml" exec -T postgres '
            f'psql -U forensic -d forensic -v ON_ERROR_STOP=1 < "$ROOT/{rel}"\n'
        )
    sh += 'echo "Done."\n'
    _write(OUT / "run-all.sh", sh)

    print(f"\nWrote {OUT}")
    for name, size in sizes.items():
        print(f"  {name}: {size:,} bytes")


if __name__ == "__main__":
    main()
