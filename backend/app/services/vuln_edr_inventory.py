"""Endpoint inventory collection (FR-14) — NOT behavioral EDR.

Collects packages/process inventory snapshots from agents. No response actions,
quarantine, or real-time behavioral blocking.
"""

from __future__ import annotations

import json
from typing import Any

from app.db.sql_helpers import execute, fetchone


def ingest_endpoint_inventory(
    db,
    *,
    agent_id: str,
    case_id: str,
    hostname: str | None,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    packages = inventory.get("packages") or inventory.get("installed_packages") or []
    processes = inventory.get("processes") or []
    if not isinstance(packages, list):
        packages = []
    if not isinstance(processes, list):
        processes = []

    agent = fetchone(db, "SELECT asset_id FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    asset_id = str(agent["asset_id"]) if agent and agent.get("asset_id") else None

    row = fetchone(
        db,
        """INSERT INTO vuln_endpoint_inventory
           (agent_id, asset_id, case_id, hostname, inventory_json, packages_count, processes_count)
           VALUES (CAST(:aid AS uuid),
                   CASE WHEN :aset IS NULL THEN NULL ELSE CAST(:aset AS uuid) END,
                   CAST(:cid AS uuid), :host, CAST(:inv AS jsonb), :pc, :prc)
           RETURNING id, collected_at""",
        {
            "aid": agent_id,
            "aset": asset_id,
            "cid": case_id,
            "host": hostname,
            "inv": json.dumps(inventory),
            "pc": len(packages),
            "prc": len(processes),
        },
    )
    execute(
        db,
        "UPDATE vuln_agents SET last_checkin_at = NOW(), lifecycle_state = 'healthy', updated_at = NOW() WHERE id = CAST(:id AS uuid)",
        {"id": agent_id},
    )
    return {
        "id": str(row["id"]),
        "packages_count": len(packages),
        "processes_count": len(processes),
        "note": "Inventory-only collection — not EDR behavioral monitoring",
    }
