# Aetheris Scanner Fix & Validation Report

## Scope
Reviewed and patched:
- Central project: `rag_new2_1.zip`
- Laptop scanner project: `laptop-scanner_nit.zip`

## Root causes fixed
1. **False unreachable targets**
   - TCP `ECONNREFUSED`/Windows 10061 was treated as unreachable.
   - A refused TCP connection proves the host answered; only that port is closed.
   - Fix: keep such hosts in the OpenVAS scan set.

2. **Completed edge job without durable evidence**
   - A job could remain `completed` while `vuln_scan_results` had no durable evidence row.
   - Fix: completed edge jobs with an OpenVAS task id but no durable result are automatically reopened for evidence recovery and returned to the same scanner agent.

3. **Unsafe manual edge completion**
   - Generic job PATCH could mark an edge scan `completed` without scanner evidence.
   - Fix: Central now rejects this with HTTP 409 until scanner-agent result evidence confirms `assessment_complete=true`.

4. **Incorrect clean conclusion when targets were skipped**
   - An execution with unreachable/skipped targets could be verified and still become clean-eligible.
   - Fix: skipped targets are accounted for as scope exceptions, but `clean_eligible=false` whenever any requested target was skipped.

5. **Report target counting after skip/exclusion**
   - Report verification used only non-excluded targets, which could erase original scan scope.
   - Fix: original target count is retained; coverage is assessed hosts + explicitly skipped hosts.

## Scenario coverage tested

| Scenario | Expected | Result |
|---|---|---|
| Internal literal IP, TCP port open | Keep target | PASS |
| Internal literal IP, TCP refused | Keep target; host is reachable | PASS |
| External literal IP, TCP refused | Keep target; host is reachable | PASS |
| Literal IP times out on all probes | Mark preflight-unreachable | PASS |
| Hostname target | Delegate discovery to OpenVAS | PASS |
| CIDR/network target | Delegate discovery to OpenVAS | PASS |
| OpenVAS Done, all requested IPs evidenced | Verified + clean eligible if no plugin errors | PASS |
| OpenVAS Done, one assessed + one explicitly unreachable | Verified with scope exception, not clean eligible | PASS |
| All requested hosts unreachable/skipped | Completed/accounted, not clean eligible | PASS |
| Completed job with no `vuln_scan_results` row | Reopen for durable evidence recovery | PASS |
| Edge job manually PATCHed to completed without evidence | Reject completion | IMPLEMENTED |
| Portable scanner gateway/subnet changes | Detect network change | PASS |
| Persistent edge scanner | Do not roam-abort | PASS |
| Remote VPN scanner role | GMP/remote role classification | PASS |
| Greenbone Processing/98-99% | Remains running until Done/report harvest | Existing behavior preserved |
| Zero findings but host evidence present | Verified zero-finding assessment | Existing + regression coverage |
| Plugin/scanner warnings | Findings valid, clean conclusion blocked | Existing behavior preserved |
| Durable recovery authentication | Existing implementation untouched | PRESERVED |

## Automated test results
- Laptop scanner-agent suite: **13 passed**
- Central focused scanner/evidence/role suite: **46 passed**
- Python compile check for modified runtime modules: **PASS**

## Modified production files
### Laptop
- `scanner-agent/agent/reachability.py`

### Central
- `backend/app/services/scanner_agent_jobs.py`
- `backend/app/services/scan_assessment_evidence.py`
- `backend/app/routers/vuln.py`

## Added/updated tests
### Laptop
- `scanner-agent/tests/test_reachability.py`
- `scanner-agent/tests/test_lan_fingerprint.py`
- existing scanner-agent tests retained

### Central
- `backend/tests/test_scan_assessment_evidence_edge.py`
- `backend/tests/test_edge_evidence_recovery.py`
- `backend/tests/test_edge_ingest_verdict.py` expanded
- `backend/tests/test_vuln_extended.py` aligned with configurable fast/full Greenbone port profiles

## Deployment safety
No database/Greenbone volume deletion is required. Do not run Docker prune/down-with-volumes. Existing OpenVAS task/report data is intentionally preserved.
