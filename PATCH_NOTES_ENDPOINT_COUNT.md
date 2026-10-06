# Gap Assessment Endpoint Count Fix

Date: 2026-08-18

## Problem

The Gap Analysis PDF rendered:

`ENDPOINTS: No. of Endpoints - Not specified`

when the Gap Intake form did not contain a manually entered `num_endpoints` value, even though the vulnerability case already contained scan targets/assets.

## Root cause

`backend/app/services/gap_report_template.py` only renders `site["num_endpoints"]`. The report context loader did not derive this field from vulnerability scan data.

## Fix

Updated `backend/app/services/gap_assessment_report.py` to derive the endpoint count at report-generation time when the saved intake value is blank or a placeholder such as `Not specified`.

Priority:

1. Count distinct active `vuln_assets` for the case using `primary_ip`, falling back to `hostname`.
2. If no materialized assets exist yet, count distinct non-excluded host-like rows in `vuln_scan_targets` joined to the case's `vuln_scan_jobs`.
3. CIDR/network ranges are not counted as one endpoint in the fallback path.
4. A manually entered endpoint value (for example `600+`) always wins.
5. The automatically derived value is not persisted into Gap Intake, so it remains synchronized with current scan data.

For a case with one scanned host such as `172.23.96.1`, the report will render:

`ENDPOINTS: No. of Endpoints - 1`

## Validation

Targeted backend tests passed:

- `tests/test_gap_assessment_report.py`
- `tests/test_vuln_module.py`
- `tests/test_vuln_orchestrator.py`

Result: `45 passed`.

## Non-destructive deployment

Run `Apply-Endpoint-Count-Fix.cmd` from the project root. It restarts only the existing API container and does not remove/recreate containers or delete volumes.
