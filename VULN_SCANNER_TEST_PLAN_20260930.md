# Vulnerability Scanner Test Plan

Use only IPs/systems that you are authorized to scan. For performance comparison, use the same 10 hosts, credentials, network path and scan profile for every run.

## TC-VULN-001 - Ten-IP parallel scheduling
**Purpose:** Verify that a 10-IP job is not processed serially.

**Steps**
1. Apply the Fast profile on the client laptop.
2. Start the laptop stack.
3. Create one vulnerability scan job with 10 reachable IPs.
4. Open Scan Details immediately.
5. Observe the Per-IP scan activity table for 2-3 minutes.

**Expected**
- All 10 IP rows appear immediately as `Waiting`.
- At least 5 IPs transition to `In Progress` while capacity is healthy.
- New IPs start as soon as a slot is released.
- Every row has its own progress percentage.
- Finished hosts show `Completed`; target-specific errors show `Fail`.

## TC-VULN-002 - Failed IP does not block siblings
**Purpose:** Verify semaphore release/failure isolation.

**Steps**
1. Create a 10-IP job containing 9 healthy hosts and 1 intentionally unreachable authorized test address.
2. Start the scan.
3. Watch the failed IP and the remaining rows.

**Expected**
- The unreachable IP becomes `Fail`/Host unreachable when network-unreachable evidence is conclusive.
- Its slot is released.
- Remaining IPs continue and can complete without waiting for the failed host.

## TC-VULN-003 - Closed port is not treated as dead host
**Purpose:** Prevent false unreachable decisions.

**Steps**
1. Use an authorized live host with one or more discovery ports closed/refusing TCP.
2. Start a scan containing that host.
3. Inspect `logs/ip/<job-id>/<ip>.jsonl`.

**Expected**
- TCP refusal is treated as host-alive evidence.
- The target is not skipped just because a probed service is closed.

## TC-VULN-004 - Timeout-only discovery keeps coverage
**Purpose:** Verify firewall-safe discovery.

**Steps**
1. Use an authorized host/firewall rule that silently drops the discovery probes.
2. Keep `REACHABILITY_UNKNOWN_POLICY=scan`.
3. Start a scan.

**Expected**
- Discovery reports inconclusive.
- The IP remains eligible for OpenVAS scanning instead of being silently omitted.

## TC-VULN-005 - Discovered-port optimization
**Purpose:** Verify reduced OpenVAS port workload.

**Steps**
1. Use a host with known open ports, for example 22 and 443.
2. Start a Fast scan.
3. Inspect scanner-agent logs.

**Expected**
- Log contains a message similar to `restricted to discovered open TCP ports: T:22,443`.
- The OpenVAS target uses those discovered ports instead of the entire Fast port list.

## TC-VULN-006 - Per-IP timeout
**Purpose:** Verify one slow target cannot hold the complete scan indefinitely.

**Steps**
1. In a lab only, set `MAX_IP_SCAN_RUNTIME_SEC=120`.
2. Include a deliberately slow/non-responsive authorized test host and several normal hosts.
3. Start the scan.

**Expected**
- Slow IP changes to `Fail` after the configured guard.
- Other IP scans continue.
- Partial findings already harvested from that IP are preserved when available.

Restore `MAX_IP_SCAN_RUNTIME_SEC=3600` after the test.

## TC-VULN-007 - Central live status persistence
**Purpose:** Verify the UI survives refresh/reconnect.

**Steps**
1. Start a 10-IP scan.
2. Wait until several IPs show `In Progress`.
3. Refresh the browser or reopen Scan Details.

**Expected**
- Per-IP states/progress are restored from PostgreSQL job orchestration data.
- Rows do not reset to Waiting after refresh.

## TC-VULN-008 - Agent restart/resume
**Purpose:** Verify restart safety.

**Steps**
1. Start a multi-IP scan.
2. Restart only the scanner-agent container while OpenVAS tasks exist.
3. Start the scanner-agent again.

**Expected**
- Existing task IDs are validated against this job's target set.
- Valid tasks resume.
- A task belonging to another host set/network is never attached to this job.

## TC-VULN-009 - Packaging source-of-truth
**Purpose:** Ensure release packaging cannot restore the legacy scanner.

**Steps**
1. Run `scripts\pack-laptop-scanner-zip.ps1` on Windows.
2. Extract the generated package.
3. Confirm the extracted scanner contains `agent/capacity.py`, `agent/ip_semaphore.py`, `agent/reachability.py`, and `tests/test_target_events.py`.

**Expected**
- Packaging succeeds only with the canonical performance scanner.
- `.env` credentials are not included in the ZIP.

## TC-VULN-010 - Performance benchmark
**Purpose:** Measure the 10-IP wall-clock target.

**Steps**
1. Use 10 stable, reachable LAN hosts.
2. Record scan start time and terminal time per IP.
3. Run three repetitions after feeds are fully synchronized.
4. Record CPU, RAM, scanner temperature, total findings and per-host finding counts.

**Acceptance target**
- Aim for the normal Fast-profile 10-IP run to finish around or below 60 minutes on suitable client hardware/network.
- No host should be serialized unnecessarily while healthy scan slots are available.
- Performance is accepted only if finding/coverage parity remains acceptable against the current baseline/reference scanner.

## TC-VULN-011 - Finding parity / safety gate
**Purpose:** Ensure speed changes do not create shallow scans.

**Steps**
1. Scan the same authorized hosts with the previous baseline and this Fast profile.
2. Compare CVE/plugin ID, host, port, severity and QoD.
3. Investigate missing high/critical findings before accepting the performance build.

**Expected**
- No unexplained loss of important findings.
- Any expected differences from Fast-vs-Deep port scope are documented.

## TC-VULN-012 - Forensic/mobile resource isolation
**Purpose:** Confirm vulnerability scans do not wait behind disk/mobile/RAG work.

**Steps**
1. Start an authorized disk or mobile extraction workload.
2. Start a vulnerability scan at the same time.
3. Observe queues and per-IP scan status.

**Expected**
- Vulnerability work remains on its own scanner path/queue.
- Disk, mobile, OCR or RAG tasks do not consume the laptop OpenVAS IP semaphore.
