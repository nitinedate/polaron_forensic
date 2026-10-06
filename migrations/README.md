# Database migrations (SQL)

Plain SQL migrations for the platform schema, RBAC catalog, Superadmin seed, and firm-schema helpers.

## Order

| File | Purpose |
|------|---------|
| `000_enable_pgvector.sql` | `CREATE EXTENSION vector` |
| `001_public_schema.sql` | Public tables: firms, platform users/RBAC, audit log |
| `002_platform_rbac_superadmin.sql` | Platform permissions, `superadmin` role, one Superadmin user |
| `003_firm_schema_template.sql` | Per-firm DDL template (`{schema}` placeholder) |
| `004_firm_rbac_seed_function.sql` | `seed_firm_rbac(schema)` — admin/user roles + permissions |

Firm schemas are created at runtime when the Superadmin provisions a company via **Firms** (`POST /api/tenants`). Each firm gets its own PostgreSQL schema, seeded RBAC, and an emailed **admin** invite.

## Superadmin (initial login)

| Field | Value |
|-------|-------|
| Email | `admin@platform.test` |
| Password | `ChangeMe!2026Secure` |
| Organization slug | `platform` |

Change the password after first login in production. To use a different password in SQL, regenerate the bcrypt hash:

```bash
docker compose exec api python -c "from app.services.security import hash_password; print(hash_password('YourNewPassword'))"
```

Update `002_platform_rbac_superadmin.sql` with the new hash, or set `PLATFORM_ADMIN_*` in `.env` and run `python scripts/bootstrap_platform_admin.py`.

## Apply (Docker)

**PowerShell:**

```powershell
.\scripts\apply_migrations.ps1
```

**Bash:**

```bash
./scripts/apply_migrations.sh
```

**Manual:**

```bash
docker compose exec -T postgres psql -U forensic -d forensic -f /migrations/001_public_schema.sql
docker compose exec -T postgres psql -U forensic -d forensic -f /migrations/002_platform_rbac_superadmin.sql
docker compose exec -T postgres psql -U forensic -d forensic -f /migrations/004_firm_rbac_seed_function.sql
```

## Alembic (alternative)

The API container also runs Alembic (`alembic upgrade head`) plus `scripts/bootstrap_platform_admin.py` on startup. SQL files mirror that schema for DBA review and manual installs.

## Identity flow

1. **Superadmin** (`superadmin` role) logs in with organization `platform`.
2. Provisions a **firm** — creates schema, seeds `admin` + `user` roles, emails firm **admin** invite.
3. Firm **admin** sets password via invite, invites **users** with roles.
4. RBAC enforced on every API route; frontend reads live data (no mock users).
