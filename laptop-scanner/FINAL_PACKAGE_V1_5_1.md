# Aetheris Laptop Scanner v1.5.1 - Final package

This package aligns the laptop/client-network scanner with central server v1.5.1 Nessus-compatible severity handling.

## Main changes

- Full TCP scan coverage is the default: `PORT_PROFILE=full` -> `T:1-65535`.
- Priority UDP services are included by default with `UDP_PROFILE=priority`.
- `UDP_PROFILE=full` is available for exhaustive UDP `1-65535` when the longer runtime is acceptable.
- Greenbone/OpenVAS results now preserve explicit CVSS v2, v3 and v4 scores separately when provided by the NVT/report.
- CVSS vectors, CVEs, CWEs, QoD, references and raw Greenbone severity signals are preserved for central normalization/audit.
- Findings are explicitly tagged `scan_engine=openvas`; the central server remains authoritative for final Nessus-compatible severity and Risk Number.
- Full-assessment mode honors the configured socket/read retry settings instead of using the faster shallow caps.
- Mixed TCP/UDP port-range handling is protocol-safe and emits GMP-compatible `T:`/`U:` prefixes on every range.
- The scanner image includes `pytest` and `/app/tests`, fixing the previous `No module named pytest` / missing test path problem after rebuild.
- Agent version is `1.5.1`.

## Rebuild

```powershell
cd D:\laptop-scanner
docker compose down
docker compose build --no-cache scanner-agent scanner-bootstrap
docker compose up -d
```

## Focused validation

```powershell
docker compose exec -T scanner-agent python -m pytest -q /app/tests/test_nessus_compat_v151.py
```

## Full scanner test suite

```powershell
docker compose exec -T scanner-agent python -m pytest -q /app/tests
```

## Important

The laptop uses Greenbone/OpenVAS. Tenable/Nessus proprietary plugins are not copied to the laptop. When a licensed Nessus scanner is configured on the central server, central can use actual Nessus findings. Laptop-side results are normalized centrally with the same configured CVSS severity basis.
