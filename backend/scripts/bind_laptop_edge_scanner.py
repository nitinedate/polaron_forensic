"""Register or refresh a laptop/edge scanner from a laptop .env file.

Does not print tokens. Usage (inside api container):
  python /app/scripts/bind_laptop_edge_scanner.py --env /tmp/laptop.env
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.scanner_agent_auth import (
    CONNECTION_MODE_EDGE,
    EDGE_AGENT_URL,
    ensure_edge_agent_recovery_columns,
    hash_agent_token,
    token_hint,
)
from app.services.scanner_credentials import SCANNER_ROLE_PORTABLE


def _parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        out[key.strip()] = value
    return out


def _resolve_firm(db, slug: str) -> tuple[str, str]:
    slug = (slug or "").strip().lower()
    row = db.execute(
        text("SELECT slug, schema_name, status FROM public.firms WHERE slug = :s"),
        {"s": slug},
    ).mappings().first()
    if not row and slug in {"a", "aetheris"}:
        rows = db.execute(
            text("SELECT slug, schema_name, status FROM public.firms WHERE status = 'active' ORDER BY slug")
        ).mappings().all()
        if len(rows) == 1:
            row = rows[0]
    if not row:
        raise SystemExit(f"No firm for tenant slug {slug!r}")
    if row["status"] != "active":
        raise SystemExit(f"Firm {row['slug']!r} is {row['status']}")
    return str(row["slug"]), str(row["schema_name"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True, help="Path to laptop .env")
    parser.add_argument("--name", default="")
    args = parser.parse_args()
    path = Path(args.env)
    if not path.is_file():
        raise SystemExit(f"env file not found: {path}")

    env = _parse_env(path)
    token = (env.get("AGENT_TOKEN") or "").strip()
    tenant = (env.get("TENANT_SLUG") or "aetheris").strip()
    role = (env.get("SCANNER_ROLE") or SCANNER_ROLE_PORTABLE).strip() or SCANNER_ROLE_PORTABLE
    name = (args.name or env.get("SCANNER_NAME") or "Laptop").strip() or "Laptop"
    if not token:
        raise SystemExit("AGENT_TOKEN missing")

    db = SessionLocal()
    firm_slug, schema = _resolve_firm(db, tenant)
    db.execute(text(f'SET search_path TO "{schema}", public'))
    ensure_edge_agent_recovery_columns(db)
    db.execute(text(f'SET search_path TO "{schema}", public'))

    token_hash = hash_agent_token(token)
    hint = token_hint(token)

    existing = db.execute(
        text(
            """SELECT id, name FROM vuln_scanners
               WHERE lower(coalesce(connection_mode, 'gmp')) = :mode
               ORDER BY updated_at DESC NULLS LAST, created_at DESC
               LIMIT 1"""
        ),
        {"mode": CONNECTION_MODE_EDGE},
    ).mappings().first()

    if existing:
        db.execute(
            text(
                """UPDATE vuln_scanners
                   SET name = :name,
                       url = :url,
                       status = 'active',
                       connection_mode = :mode,
                       scanner_role = :role,
                       agent_token_hash = :th,
                       agent_token_hint = :hint,
                       agent_recovery_token_hash = NULL,
                       updated_at = NOW()
                   WHERE id = CAST(:id AS uuid)"""
            ),
            {
                "name": name,
                "url": EDGE_AGENT_URL,
                "mode": CONNECTION_MODE_EDGE,
                "role": role,
                "th": token_hash,
                "hint": hint,
                "id": str(existing["id"]),
            },
        )
        action = "updated"
        scanner_id = str(existing["id"])
    else:
        row = db.execute(
            text(
                """INSERT INTO vuln_scanners
                   (name, url, edition, status, connection_mode, scanner_role,
                    agent_token_hash, agent_token_hint, agent_recovery_token_hash)
                   VALUES (:name, :url, 'openvas', 'active', :mode, :role, :th, :hint, NULL)
                   RETURNING id"""
            ),
            {
                "name": name,
                "url": EDGE_AGENT_URL,
                "mode": CONNECTION_MODE_EDGE,
                "role": role,
                "th": token_hash,
                "hint": hint,
            },
        ).mappings().first()
        action = "created"
        scanner_id = str(row["id"])

    db.commit()
    print(
        f"{action} edge scanner name={name!r} id={scanner_id} firm={firm_slug} "
        f"schema={schema} hint={hint} single_token=yes"
    )


if __name__ == "__main__":
    main()
