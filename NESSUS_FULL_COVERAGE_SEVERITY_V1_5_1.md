# Nessus Full Coverage + Severity Fidelity V1.5.1

## Goal
Make the central vulnerability service consume complete findings from a configured Tenable Nessus scanner and display Tenable-compatible technical severity, while improving OpenVAS fallback coverage.

## Important licensing boundary
This package does **not** copy Tenable's proprietary NASL plugin feed. When a licensed Nessus scanner is configured, Aetheris launches the Nessus scan and imports the complete CSV finding report. When Nessus is not configured, the OpenVAS/Nmap/Nuclei/ZAP pipeline remains the open-source fallback.

## Changes

### 1. Full Nessus report ingestion
- Added `backend/app/services/nessus_report.py`.
- Completed Nessus scans are exported through the Nessus API as CSV.
- Every CSV finding row is normalized with host, port, protocol, plugin ID/family, CVEs, CVSS v2/v3/v4, VPR, EPSS, exploit maturity, description, solution, references, and plugin output.
- A failed full-report export is treated as an assessment failure instead of silently accepting summary-only data.

### 2. Nessus selected scanner is now actually used
- The orchestrator replaces the default OpenVAS vulnerability step with `nessus` when the selected scanner edition is Nessus/Tenable.
- Nessus scans are explicitly launched and polled to completion.
- Per-scanner Nessus API credentials can be stored in `api_key_ref` as JSON or `access:secret`.

### 3. Tenable-compatible severity basis
- Added `NESSUS_SEVERITY_BASIS`, default `cvss_v3`.
- Supports `cvss_v2`, `cvss_v3`, and `cvss_v4`.
- CVSS v2: Critical only at 10.0; High 7.0-9.9.
- CVSS v3/v4: Critical 9.0-10.0; High 7.0-8.9.
- Medium 4.0-6.9, Low 0.1-3.9, Info 0.0.
- The normalizer no longer incorrectly takes the maximum across different CVSS versions.
- Direct Nessus Risk/Severity is used as a fallback only for Nessus findings with no CVSS score.

### 4. Full TCP discovery
- Nmap discovery changed from top 200 ports to TCP 1-65535 (`-p-`) with bounded retries and a performance floor.
- OpenVAS reuses Nmap's discovered open TCP ports, so it does not need to run all NVTs against closed ports.
- If Nmap is unavailable and `GVM_PORT_PROFILE=full`, OpenVAS falls back to TCP 1-65535 rather than silently using the old common-port set.
- Vulnerability service default is now `GVM_PORT_PROFILE=full` with adaptive timeout/stall handling.

### 5. Nessus scan discovery settings
- Nessus-created scans request TCP ports 1-65535 and enable SYN/TCP scanners.

## Validation
Targeted regression suite:

`23 passed`

Files tested include severity, risk fidelity, Nessus CSV normalization, and scanner credential parsing.

## Runtime configuration
For a licensed Nessus scanner:

- `NESSUS_DEFAULT_URL=https://<nessus-host>:8834`
- `NESSUS_ACCESS_KEY=<access key>`
- `NESSUS_SECRET_KEY=<secret key>`
- `NESSUS_SEVERITY_BASIS=cvss_v3`

Alternatively, the scanner record `api_key_ref` may contain:

`{"access_key":"...","secret_key":"..."}`

or:

`<access-key>:<secret-key>`

## Notes
Tenable VPR is proprietary/dynamic. If Nessus provides VPR in the report, Aetheris imports and uses the real VPR value in the existing weighted risk model. Aetheris does not fabricate Tenable VPR when it is unavailable.
