# Aetheris Laptop Scanner v1.5.1 — Nessus-compatible central integration

## Purpose

This release aligns the portable/client-network laptop scanner with the central v1.5.1 Nessus severity model while keeping Greenbone/OpenVAS as the laptop-side vulnerability engine. It does not copy or redistribute Tenable's proprietary NASL feed.

## Changes

- Default TCP assessment profile is now `full` (`T:1-65535`).
- Adds high-value UDP coverage by default and supports `UDP_PROFILE=full` for `U:1-65535`.
- `GVM_OPTIMIZE_TEST=no` is now the full-assessment default.
- Preserves explicitly versioned CVSS v2/v3/v4 scores independently so the central server can apply its configured `NESSUS_SEVERITY_BASIS` instead of taking the maximum across CVSS generations.
- Preserves CWE references and separate CVSS vectors when present.
- Explicitly labels laptop findings as `scan_engine=openvas`.
- Mixed TCP/UDP port-range filtering was corrected so Aetheris control-plane TCP exclusions cannot remove the same-numbered UDP service.
- Scanner image now includes pytest and `/app/tests`, so container regression commands work directly.
- Agent version advanced to `1.5.1`.

## UDP modes

- `UDP_PROFILE=priority` (default): high-value infrastructure UDP ports.
- `UDP_PROFILE=full`: UDP 1-65535. This is substantially slower on filtered networks.
- `UDP_PROFILE=off`: TCP-only assessment.

## Rebuild and validate

```powershell
cd <laptop-scanner-folder>
docker compose down
docker compose build --no-cache scanner-agent scanner-bootstrap
docker compose up -d
docker compose exec -T scanner-agent python -m pytest -q /app/tests/test_nessus_compat_v151.py
```

Expected focused result: all v1.5.1 compatibility tests pass.
