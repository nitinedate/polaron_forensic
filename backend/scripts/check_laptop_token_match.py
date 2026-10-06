"""Compare laptop .env token hashes to firm edge scanners. Prints no secrets."""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.scanner_agent_auth import hash_agent_token


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True)
    args = parser.parse_args()
    env = _parse_env(Path(args.env))
    token = (env.get("AGENT_TOKEN") or "").strip()
    recovery = (env.get("AGENT_RECOVERY_TOKEN") or "").strip()
    db = SessionLocal()
    firms = db.execute(text("SELECT slug, schema_name FROM public.firms WHERE status = 'active'")).mappings().all()
    print(f"active_firms={','.join(r['slug'] for r in firms) or '(none)'}")
    print(f"primary_len={len(token)} recovery_len={len(recovery)}")
    for firm in firms:
        schema = firm["schema_name"]
        db.execute(text(f'SET search_path TO "{schema}", public'))
        rows = db.execute(
            text(
                """SELECT name,
                          (agent_token_hash = :th) AS primary_ok,
                          (agent_recovery_token_hash = :rh) AS recovery_ok
                   FROM vuln_scanners
                   WHERE lower(coalesce(connection_mode, 'gmp')) = 'edge_agent'"""
            ),
            {
                "th": hash_agent_token(token) if token else "",
                "rh": hash_agent_token(recovery) if recovery else "",
            },
        ).mappings().all()
        print(f"firm={firm['slug']} edge_scanners={len(rows)}")
        for row in rows:
            print(
                f"  scanner={row['name']!r} primary_match={bool(row['primary_ok'])} "
                f"recovery_match={bool(row['recovery_ok'])}"
            )


if __name__ == "__main__":
    main()
