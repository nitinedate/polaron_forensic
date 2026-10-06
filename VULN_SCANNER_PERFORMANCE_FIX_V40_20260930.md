# Vulnerability Scanner Performance + Per-IP Progress Fix (V40)

## Scope
This patch changes only the vulnerability-scanning path and scanner packaging. Disk forensics, Android extraction, iOS extraction, OCR and RAG queues remain isolated.

## Main fixes
1. Repository `scanner-agent/` is now the canonical scanner-agent source used by the laptop packaging script.
2. Packaging refuses to build if the adaptive IP semaphore, reachability module, or target-event tests are missing.
3. Fast profile is now the default for laptop vulnerability scans.
4. Default one-IP task preferences are tuned to `max_checks=6`, `max_hosts=1`, `optimize_test=yes`, vHost expansion off, lower retries, and finite plugin timeouts.
5. Scanner-global OpenVAS capacity remains able to service multiple one-IP tasks in parallel (`GVM_GLOBAL_MAX_HOSTS=10`).
6. Common TCP ports are discovered concurrently before OpenVAS starts. For Fast scans, each IP is sent to OpenVAS with only its discovered open ports when at least one open port is known.
7. TCP connection refused now counts as proof that a host is alive. Timeout-only discovery is inconclusive and is scanned by default instead of being silently dropped.
8. One slow IP has a separate `MAX_IP_SCAN_RUNTIME_SEC` guard and cannot hold all sibling IPs indefinitely.
9. Per-IP events are delivered asynchronously to the central server and persisted in the existing PostgreSQL `orchestration_json.target_progress` map.
10. Scan Details now exposes the requested UI state labels: Waiting, In Progress, Completed, Fail, plus a per-IP percentage.
11. Terminal result ingest repairs/finalizes per-IP state so late event delivery cannot leave stale Waiting/In Progress rows.
12. Client event delivery is off the scanner critical path through a bounded background queue.

## Recommended Fast profile
- `MAX_CONCURRENT_SCAN_JOBS=1`
- `SCAN_IP_PARALLELISM=auto`
- `SCAN_IP_MAX_PARALLELISM=10`
- `GVM_GLOBAL_MAX_HOSTS=10`
- `GVM_MAX_HOSTS=1`
- `GVM_MAX_CHECKS=6`
- `PORT_PROFILE=fast`
- `GVM_OPTIMIZE_TEST=yes`
- `GVM_EXPAND_VHOSTS=no`
- `GVM_TEST_EMPTY_VHOST=no`
- `PLUGINS_TIMEOUT_SEC=900`
- `SCANNER_PLUGINS_TIMEOUT_SEC=1800`
- `GVM_TIMEOUT_RETRY=1`
- `GVM_OPEN_SOCK_MAX_ATTEMPTS=2`
- `MAX_IP_SCAN_RUNTIME_SEC=3600`
- `MAX_SCAN_RUNTIME_SEC=7200`

Run `Apply-Vuln-Performance-Profile.cmd` on an existing laptop deployment to merge these performance settings into its `.env` without changing credentials.

## Important coverage behavior
Fast discovery only restricts OpenVAS to discovered ports when it has positive open-port evidence. A host that only times out during discovery is still scanned with the normal Fast port profile. This prevents the previous false-negative behavior where closed/firewalled quick-probe ports could cause an authorized host to be skipped.

## Automated regression commands
### Linux/server checkout
```bash
./scripts/run-vuln-regression-tests.sh
```

### Windows laptop package
```powershell
.\Run-Scanner-Tests.ps1
```

or double-click `Run-Scanner-Tests.cmd`.
