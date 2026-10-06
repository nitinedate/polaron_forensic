# Forensic Automation Report — Phase 1



Multi-tenant identity platform with schema-per-firm isolation, RBAC, email invitations, and optional MFA.



## Stack



- **Backend**: FastAPI, PostgreSQL 16 + pgvector, Alembic + SQL migrations

- **Frontend**: React (Vite + TypeScript + Tailwind)

- **Email (dev)**: MailHog



## How to use (UI + flowcharts)

White-background PDFs (screenshots + flowcharts): [`docs/guides/pdf/`](docs/guides/pdf/).

- [Disk & mobile forensic](docs/guides/01-disk-mobile-forensic.md) · [PDF](docs/guides/pdf/01-disk-mobile-forensic.pdf)
- [Mobile extraction](docs/guides/02-mobile-extraction.md) · [PDF](docs/guides/pdf/02-mobile-extraction.pdf)
- [Vulnerability scanning](docs/guides/03-vuln-scanning.md) · [PDF](docs/guides/pdf/03-vuln-scanning.pdf)

## Quick start



1. Copy environment file:



```bash

cp .env.example .env

```



2. Start **one** independent product (they do not share a database or API):



```bash

# Service 1 — disk + mobile forensic analysis
docker compose -f services/forensic/docker-compose.yml --project-directory . up -d --build

# Service 2 — mobile extraction (.pas / .ufd / .ufdx / .zip)
docker compose -f services/mobile-extract/docker-compose.yml --project-directory . up -d --build

# Service 3 — vulnerabilities + laptop scanner control plane
docker compose -f services/vuln/docker-compose.yml --project-directory . --profile gvm --profile vuln-scanners up -d --build

# Windows: .\scripts\start-stack.ps1 -Service forensic|mobile-extract|vuln|all

```

Architecture: [`docs/THREE_SERVICE_ARCHITECTURE.md`](docs/THREE_SERVICE_ARCHITECTURE.md).

`docker compose up` at the repo root starts **Service 1 only** (forensic). It is no longer the all-in-one stack.



3. Open the app:



- UI (all products): http://localhost:3000  (API gateway; bookmark alias :3001)
- Forensic API :8080 · Mobile extract API :8081 · Vuln API :8082
- Laptop scanner: `CENTRAL_API_URL=http://host.docker.internal:3000`

- MailHog (forensic): http://localhost:8025

- pgAdmin: http://localhost:5052 (`admin@forensic.local` / `admin` — Forensic Postgres pre-registered)

- PostgreSQL (host): `localhost:5433` (user `forensic`, password `forensic`, db `forensic`)



On first startup the API runs Alembic migrations, applies SQL helper functions, and bootstraps the **Superadmin** from `.env` (if not already seeded via SQL):



| Setting | Default |

|---------|---------|

| Organization (login) | `platform` |

| Email / username | `superadmin@admin.com` |

| Password | `admin@123456789` |



## SQL migrations



Standalone migration files live in [`migrations/`](migrations/README.md):



| File | Purpose |

|------|---------|

| `001_public_schema.sql` | Platform tables |

| `002_platform_rbac_superadmin.sql` | Permissions, `superadmin` role, Superadmin user |

| `036_ensure_platform_admin.sql` | Idempotent Superadmin create / password reset |

| `003_firm_schema_template.sql` | Per-firm DDL template |

| `004_firm_rbac_seed_function.sql` | `seed_firm_rbac(schema)` for firm admin/user roles |



Apply manually (optional — Docker startup handles schema via Alembic + bootstrap):



```powershell

.\scripts\apply_migrations.ps1

```



## Identity model



| Role | Scope | MFA |

|------|-------|-----|

| **superadmin** | Platform | Not available | Provisions firms; cannot be seen by firm users |
| **admin** | Firm (company) | Optional | Invites/manages firm users and RBAC |
| **user** | Firm (company) | Optional | Profile and security only — no user management |

### Isolation rules

- **Superadmin** lives in the platform schema only. Firm admins and users never see superadmin accounts or platform roles.
- **Firm admin** manages users, roles, and permissions inside their company schema only.
- **Firm user** has no IAM permissions — API allows `/api/users/me` and security endpoints only; Users/Roles/Permissions pages are hidden.



### End-to-end flow



1. Log in as **Superadmin** with organization slug `platform`.

2. Provision a company under **Firms** — creates an isolated DB schema, seeds `admin` + `user` roles with permissions, and emails the company **admin** invite (check MailHog).

3. Company **admin** sets password via invite link, logs in with the company slug.

4. Company **admin** invites **users** from **Users** and assigns roles.

5. Manage roles and permissions under **Access Control** — all data comes from the API (no mock users).



Verify the full API flow:



```bash

python scripts/e2e_verify.py

```




## Vulnerability scanner runtime

The scanner worker uses Docker service discovery for ZAP/Trivy and a shared Unix socket for Greenbone `gvmd`. Scanner services are profile-gated, but `.env` and `.env.example` now set `COMPOSE_PROFILES=gvm,vuln-scanners`, so the normal `docker compose up -d --build` command starts the required Greenbone, ZAP, and Trivy services. Wazuh is a separate `wazuh` profile because it only applies to enrolled endpoint agents.

Recommended local Greenbone settings:

```env
GVM_LIVE_ENABLED=true
GVM_URL=unix:///run/gvmd/gvmd.sock
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock
GVM_USERNAME=admin
GVM_PASSWORD=admin
VULN_ALLOW_STUB_FINDINGS=false
```

For an existing scanner DB record with `gmp://gvmd:9390`, the backend keeps a compatibility mapping to the Unix socket. New/edited OpenVAS scanner records should use `unix:///run/gvmd/gvmd.sock`. The first Greenbone start can take time while feed/data containers initialize; do not launch a scan until `gvmd` and `ospd-openvas` are running and the data-object/feed services are healthy.

Useful checks:

```bash
docker compose ps
docker compose logs -f gvmd ospd-openvas worker-nessus zap trivy
docker compose exec worker-nessus python /scripts/scanner_preflight.py
```

`VULN_ALLOW_STUB_FINDINGS` defaults to `false`: unavailable scanners are reported as failed/skipped instead of inserting synthetic vulnerabilities. Trivy applies only to targets whose `target_type` is an image/container type, and Wazuh applies only to endpoint/agent target types.

## Local development (without Docker frontend)



```bash

# Terminal 1 — infrastructure

docker compose up -d postgres mailhog



# Terminal 2 — API

cd backend

pip install -r requirements.txt

alembic upgrade head

python ../scripts/ensure_sql_functions.py

python ../scripts/bootstrap_platform_admin.py

uvicorn app.main:app --reload --port 8080



# Terminal 3 — frontend

cd frontend

npm install

npm run dev

```



Frontend dev server proxies `/api` to `http://127.0.0.1:8080`.



## Phase 1 scope



- Platform firm provisioning with per-firm PostgreSQL schema

- RBAC (users, roles, permissions)

- Email invite + password reset flows

- TOTP MFA for firm admin/user (not superadmin)

- Forensic case partitioned table scaffold in each firm schema



Forensic job processing and vulnerability modules are Phase 2+.


