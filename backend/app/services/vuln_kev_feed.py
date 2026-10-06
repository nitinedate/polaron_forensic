"""CISA Known Exploited Vulnerabilities (KEV) feed sync and lookup (FR-7.2, FR-12.2)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.db.sql_helpers import execute, fetchone

log = logging.getLogger("vuln_kev_feed")

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Embedded fallback for offline/dev when feed is unreachable.
SAMPLE_KEV_CVES = frozenset(
    {
        "CVE-2021-44228",  # Log4Shell
        "CVE-2021-45046",
        "CVE-2023-34362",  # MOVEit
        "CVE-2024-1709",  # ConnectWise
    }
)

_local_kev_cache: set[str] = set()


def _parse_kev_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities") or []:
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve:
            continue
        out.append(
            {
                "cve_id": cve,
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
            }
        )
    return out


def sync_kev_catalog(db, *, use_sample_on_failure: bool = True) -> dict[str, Any]:
    """Fetch CISA KEV JSON and upsert into public.cisa_kev_catalog."""
    entries: list[dict[str, Any]] = []
    source = "cisa_feed"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(KEV_FEED_URL)
            resp.raise_for_status()
            entries = _parse_kev_entries(resp.json())
    except Exception as exc:
        log.warning("KEV feed fetch failed: %s", exc)
        if not use_sample_on_failure:
            return {"status": "failed", "error": str(exc), "count": 0}
        source = "sample_fallback"
        entries = [
            {"cve_id": cve, "vendor_project": None, "product": None, "vulnerability_name": "Sample KEV", "date_added": None}
            for cve in sorted(SAMPLE_KEV_CVES)
        ]

    global _local_kev_cache
    _local_kev_cache = {e["cve_id"] for e in entries}
    count = 0
    for e in entries:
        execute(
            db,
            """INSERT INTO public.cisa_kev_catalog
               (cve_id, vendor_project, product, vulnerability_name, date_added, synced_at)
               VALUES (:cve, :vp, :prod, :vn, CAST(:da AS date), NOW())
               ON CONFLICT (cve_id) DO UPDATE SET
                 vendor_project = EXCLUDED.vendor_project,
                 product = EXCLUDED.product,
                 vulnerability_name = EXCLUDED.vulnerability_name,
                 date_added = EXCLUDED.date_added,
                 synced_at = NOW()""",
            {
                "cve": e["cve_id"],
                "vp": e.get("vendor_project"),
                "prod": e.get("product"),
                "vn": e.get("vulnerability_name"),
                "da": e.get("date_added"),
            },
        )
        count += 1
    return {"status": "ok", "source": source, "count": count, "synced_at": datetime.now(timezone.utc).isoformat()}


def is_kev_cve(db, cve: str | None) -> bool:
    if not cve:
        return False
    cve_u = cve.strip().upper()
    if db is not None:
        row = fetchone(db, "SELECT 1 AS ok FROM public.cisa_kev_catalog WHERE cve_id = :c", {"c": cve_u})
        if row:
            return True
    if _local_kev_cache:
        return cve_u in _local_kev_cache
    return cve_u in SAMPLE_KEV_CVES
