# Apply platform SQL migrations in order (requires docker compose postgres).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$files = @(
    "000_enable_pgvector.sql",
    "001_public_schema.sql",
    "002_platform_rbac_superadmin.sql",
    "004_firm_rbac_seed_function.sql",
    "005_restrict_firm_user_role.sql",
    "036_ensure_platform_admin.sql",
    "037_search_performance_indexes.sql"
)

foreach ($f in $files) {
    Write-Host "Applying migrations/$f ..."
    Get-Content (Join-Path $Root "migrations\$f") -Raw |
        docker compose -f (Join-Path $Root "docker-compose.yml") exec -T postgres `
            psql -U forensic -d forensic -v ON_ERROR_STOP=1
}

Write-Host "Done. Firm schema template: migrations/003_firm_schema_template.sql (applied per firm via API)."
