#!/usr/bin/env bash
# Apply platform SQL migrations in order (requires docker compose postgres).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PSQL="docker compose -f \"$ROOT/docker-compose.yml\" exec -T postgres psql -U forensic -d forensic"

for f in 000_enable_pgvector.sql 001_public_schema.sql 002_platform_rbac_superadmin.sql 004_firm_rbac_seed_function.sql 005_restrict_firm_user_role.sql 036_ensure_platform_admin.sql 037_search_performance_indexes.sql; do
  echo "Applying migrations/$f ..."
  docker compose -f "$ROOT/docker-compose.yml" exec -T postgres \
    psql -U forensic -d forensic -v ON_ERROR_STOP=1 < "$ROOT/migrations/$f"
done

echo "Done. Firm schema template: migrations/003_firm_schema_template.sql (applied per firm via API)."
