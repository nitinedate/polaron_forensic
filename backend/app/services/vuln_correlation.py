"""Cross-scanner finding correlation."""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("vuln_correlation")


def correlation_key_for(host: str, port: int | None, name: str, cve: str | None) -> str:
    host = (host or "").strip().lower()
    name_key = (name or "").strip().lower()[:120]
    cve_key = (cve or "").strip().upper()
    port_key = str(port) if port is not None else "*"
    if cve_key:
        return f"{host}|{port_key}|cve:{cve_key}"
    return f"{host}|{port_key}|name:{name_key}"


def correlate_case_findings(db, *, case_id: str) -> dict:
    """Group findings by host/port/name/CVE; update correlation_key and summary table."""
    rows = fetchall(
        db,
        """SELECT f.id, f.synopsis, f.cve, f.port, f.scan_engine, f.risk_factors_json,
                  COALESCE(a.primary_ip, a.hostname, '') AS host
           FROM vuln_findings f
           LEFT JOIN vuln_assets a ON a.id = f.asset_id
           WHERE f.case_id = CAST(:cid AS uuid) AND f.status = 'open'""",
        {"cid": case_id},
    )
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        key = correlation_key_for(r.get("host") or "", r.get("port"), r.get("synopsis") or "", r.get("cve"))
        groups[key].append(r)

    merged = 0
    for key, items in groups.items():
        engines = sorted(
            {
                str(i.get("scan_engine")
                or (json.loads(i["risk_factors_json"]) if isinstance(i.get("risk_factors_json"), str) else i.get("risk_factors_json") or {}).get("source")
                or "unknown")
                for i in items
            }
        )
        primary_id = str(items[0]["id"])
        execute(
            db,
            """INSERT INTO vuln_finding_correlations (case_id, correlation_key, primary_finding_id, engine_count, engines_json)
               VALUES (CAST(:cid AS uuid), :key, CAST(:pid AS uuid), :ec, CAST(:eng AS jsonb))
               ON CONFLICT (case_id, correlation_key) DO UPDATE SET
                 primary_finding_id = EXCLUDED.primary_finding_id,
                 engine_count = EXCLUDED.engine_count,
                 engines_json = EXCLUDED.engines_json,
                 updated_at = NOW()""",
            {"cid": case_id, "key": key, "pid": primary_id, "ec": len(engines), "eng": json.dumps(engines)},
        )
        for item in items:
            execute(
                db,
                "UPDATE vuln_findings SET correlation_key = :key, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"key": key, "id": str(item["id"])},
            )
        if len(engines) > 1:
            merged += 1
    return {"groups": len(groups), "multi_engine": merged}
