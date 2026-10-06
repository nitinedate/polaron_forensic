# Vulnerability Scanner Fix Notes

Date: 2026-08-12

## Root cause

The worker log was failing before it ever reached Greenbone GMP authentication:

- `gvmd`, `zap`, and `trivy` were configured as Docker hostnames.
- Their Compose services were behind profiles, but the running stack shown in Docker Desktop did not contain those services.
- Therefore Docker DNS had no service records for those hostnames and Python raised `socket.gaierror: [Errno -2] Name or service not known`.

There were additional implementation defects that would have appeared after DNS was fixed:

- The local Greenbone Community containers use a shared `gvmd` Unix socket rather than exposing GMP on TCP `gvmd:9390` by default.
- GMP task creation did not pass `scanner_id` and target hosts were not supplied in the shape expected by `python-gvm`.
- OpenVAS was launched and read back immediately instead of polling to a terminal state.
- ZAP's spider is asynchronous, but the old adapter did not wait for spider/passive scanning to finish.
- Trivy server mode was called through a non-supported custom HTTP scan endpoint instead of the Trivy CLI in client/server mode.
- Scanner failures could fall back to synthetic/stub findings and still mark the overall scan as `completed`.
- Trivy and Wazuh were being treated as generic host scanners even though their target models are container images and enrolled endpoints respectively.

## Main changes

### Greenbone/OpenVAS

- Replaced the local endpoint with `unix:///run/gvmd/gvmd.sock`.
- Added a shared `gvm_gvmd_socket` volume to `worker-nessus`.
- Kept compatibility for an existing DB scanner URL of `gmp://gvmd:9390`; it transparently maps to the Unix socket when `GVM_SOCKET_PATH` is configured.
- Reworked GMP session handling to use `UnixSocketConnection` and the GMP context manager.
- Fixed target creation, scanner discovery/default scanner UUID, task creation, polling, report retrieval, and result parsing.
- Replaced the incomplete GVM Compose definition with the headless Greenbone Community container dependencies required by `gvmd`/`ospd-openvas`.

### ZAP

- Runs the spider through the ZAP API, polls until spider completion, waits for the passive-scan queue to drain, and then retrieves alerts.
- API-key health check now uses the configured `ZAP_API_KEY`.

### Trivy

- Uses `trivy image --server ... --format json` rather than an ad-hoc HTTP scan endpoint.
- Installs a Trivy CLI in the scanner worker, aligned with the existing Trivy server version.
- Runs only for image/container/OCI target types.
- Build fix (2026-08-12): the older `v0.58.1` GitHub release page no longer exposes the expected binary tarball, so `curl ... trivy_0.58.1_Linux-64bit.tar.gz` returned HTTP 404. The scanner Dockerfile now uses `aquasec/trivy:0.58.1` as a multi-stage build source and copies `/usr/local/bin/trivy` into the Python worker. This keeps the CLI/server versions aligned and avoids depending on the missing release asset.

### Nuclei / Nmap

- Nmap remains installed in the scanner worker.
- Nuclei v3.11.1 is installed in the scanner worker with release SHA-256 verification.
- Nuclei JSONL results are parsed as real findings.

### Wazuh

- Wazuh is no longer treated as an on-demand network scanner.
- It is applicable only to endpoint/agent target types until a target-to-Wazuh-agent mapping is implemented.
- Wazuh containers are in a separate `wazuh` Compose profile so normal host/web scans do not unnecessarily start the endpoint stack.

### Orchestration correctness

- OpenVAS is a required engine in the default pipeline.
- Required-engine failure now makes the scan job `failed`.
- Synthetic/stub findings are rejected by default (`VULN_ALLOW_STUB_FINDINGS=false`) instead of being ingested as real vulnerabilities.
- Optional engines with incompatible target types are marked `skipped` rather than failed.
- The overall job cannot report a successful scan when no real engine completed.

## Scanner record

Recommended scanner values in the UI:

- Name: `OpenVAS`
- URL: `unix:///run/gvmd/gvmd.sock`
- Edition: `Greenbone Community Edition`
- Status: `active`

The old URL `gmp://gvmd:9390` remains backward-compatible in the code, so changing the existing DB row is recommended but not required before the first retest.

## Environment

The fixed `.env.example` contains the relevant settings:

```env
COMPOSE_PROFILES=gvm,vuln-scanners
VULN_ORCHESTRATION_ENABLED=true
VULN_ALLOW_STUB_FINDINGS=false
GVM_LIVE_ENABLED=true
GVM_URL=unix:///run/gvmd/gvmd.sock
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock
GVM_USERNAME=admin
GVM_PASSWORD=admin
GVM_SCAN_POLL_INTERVAL_SEC=15
GVM_SCAN_TIMEOUT_SEC=7200
ZAP_API_URL=http://zap:8080
ZAP_API_KEY=changeme
ZAP_SCAN_TIMEOUT_SEC=300
TRIVY_SERVER_URL=http://trivy:4954
```

Do not copy `.env.example` over an existing `.env` blindly. Preserve your existing application/database/mail secrets and merge only the scanner settings you need.

## Deployment / retest

From the project root:

```powershell
docker compose down
docker compose pull
docker compose up -d --build
docker compose ps
```

The `.env` profile setting starts `gvm` and `vuln-scanners`. If you prefer explicit profiles:

```powershell
docker compose --profile gvm --profile vuln-scanners up -d --build
```

For Wazuh endpoint functionality only:

```powershell
powershell -File scripts\setup_wazuh_certs.ps1
docker compose --profile wazuh up -d
```

Check the scanner worker from inside its Docker network/namespace:

```powershell
docker compose exec worker-nessus python /scripts/scanner_preflight.py
```

Expected required result:

- `PASS Greenbone/GMP`
- `PASS ZAP` when the ZAP sidecar is running
- `PASS Trivy` when the Trivy sidecar is running
- `PASS nmap CLI`
- `PASS trivy CLI`
- `PASS nuclei CLI`

Then inspect startup/feed logs:

```powershell
docker compose logs -f gvmd ospd-openvas worker-nessus zap trivy
```

The first Greenbone start can take substantial time because feed/data containers must populate data before scan configurations and VTs are ready. Do not run the first OpenVAS test until `gvmd` and `ospd-openvas` are running and the feed/data services have initialized.

If GMP authentication fails after connectivity is healthy, reset only the Greenbone admin password (do not delete volumes just for an auth mismatch):

```powershell
docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='admin'
```

Use a stronger password in production and update `GVM_PASSWORD` accordingly.

## Expected behavior after the fix

For a normal host/IP target:

- Nmap: real scan
- OpenVAS: real scan and waited to completion
- Nuclei: real scan when the target exposes HTTP/HTTPS content
- ZAP: real spider/passive scan when the target exposes HTTP/HTTPS content
- Wazuh: skipped unless the target is an endpoint/agent target
- Trivy: skipped unless the target is an image/container target

A broken/unavailable required OpenVAS engine now produces an overall `failed` scan job and an actionable error instead of a misleading `completed` result containing synthetic findings.

## Validation performed in this review environment

- Python compilation: passed for modified scanner services/config/preflight script.
- YAML parse: passed for `docker-compose.yml`, `docker-compose.gvm.yml`, and `docker-compose.vuln-scanners.yml`.
- Scanner/vulnerability unit tests: `31 passed` for `test_vuln_module.py`, `test_vuln_orchestrator.py`, and `test_vuln_extended.py`.
- Docker runtime integration could not be executed in the review sandbox because a Docker daemon/CLI is not available there; the final live verification must be run on your Docker Desktop host with the preflight command above.

## Security note

The supplied project contains an application `.env` with live-looking credentials/secrets. They are not reproduced in these notes. Rotate any credentials that have been shared outside your trusted environment, keep `.env` out of source control, and use a secret manager or Docker secrets for production deployments.
