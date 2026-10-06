# Merge Report — rag_new2_1 (vuln) + rag_new2_2 (disk & mobile)

**Produced:** 04 September 2026
**Method:** three-way merge using the earlier `rag_new2.zip` snapshot as the common ancestor
**Result:** one tree containing the vulnerability work from `rag_new2_1` and the disk/mobile
work from `rag_new2_2`.

---

## 1. What the two archives actually contained

The two archives were not two equal branches. Compared against the common ancestor:

| | `rag_new2_1` (A) | `rag_new2_2` (B) |
|---|---|---|
| Files differing from ancestor | 104 | 2 (plus 3 stray evidence files) |
| Genuine forward work | 6 files + 1 new file, all vulnerability/scanner | the whole tree |
| Files missing that the ancestor had | 18 | 0 |

`rag_new2_2` is essentially the ancestor tree — the disk and mobile work was already present in
the snapshot both branches came from. `rag_new2_1` was branched from an **earlier** point, so
most of its 104 differing files are *older* versions rather than newer ones. Only a small,
clearly identifiable set of vulnerability files moved forward in A.

Of A's 104 differing files:

- **29** differ only by line endings (CRLF vs LF) — no content change.
- **69** are A being behind (disk, mobile, forensic, laptop-agent, scripts).
- **6** are A being genuinely ahead — all vulnerability/scanner.

## 2. Merge decision

**Base: `rag_new2_2` (B).** Overlaid with A's six advanced files plus one new module,
and two one-line nginx additions that A's feature requires.

### Taken from `rag_new2_1` (A)

| File | What it adds |
|---|---|
| `backend/app/services/vuln_nessus_parity.py` | **New module.** Nessus CSV parity comparison. |
| `backend/app/routers/vuln_orchestrator.py` | Two endpoints: `nessus-parity/compare` and `nessus-parity/compare-file`. |
| `backend/app/services/scanner_agent_jobs.py` | Edge job ownership fencing: `_assign_job_owner`, `_owner_conflict`, `agent_instance_id` on claim and progress, `owner_mismatch` result. 1282 → 1517 lines. |
| `backend/app/routers/scanner_agent.py` | v1.2.24 transport fallback — accepts the agent instance id as a header *or* query parameter (for proxies that strip unknown headers), and returns HTTP 409 `edge_job_owned_elsewhere` on mismatch. |
| `backend/app/services/vuln_finding_ingest.py` | Richer normalisation: CVSS v3/v4 fields, multiple CVEs per finding, CWE, CVSS vector, references. |
| `backend/app/services/vuln_report_export.py` | XLSX export widened from 5 to 8 columns (adds Synopsis, Description, Solution) with severity-ordered rows. |

### Patched (one line each, added to B's file rather than replacing it)

| File | Change |
|---|---|
| `frontend/nginx.conf` | `proxy_set_header X-Aetheris-Agent-Instance $http_x_aetheris_agent_instance;` |
| `deployment/windows-ip-https/nginx.https.conf` | same header (CRLF endings preserved) |

Without these, the reverse proxy strips the header and the ownership feature silently falls
back to the query-parameter path.

### Deliberately **not** taken from A

| File | Reason |
|---|---|
| `backend/app/routers/vuln.py` | A's version is +7 lines but **functionally behind**: it removes `case_delete` and reverts the scan-job delete to queued/pending only. B's cascade delete (queued, processing *and* running) was kept. |
| `backend/Dockerfile`, `backend/requirements.txt` | A drops `docker-pip-install.sh` and its CPU-torch pinning. B's approach retained. |
| `backend/app/config.py`, `mobile_report_llm.py`, `scripts/ollama_*` | A carries the older model set. B's (`mistral-small3.2`) retained. |
| `docker-compose.drives.generated.yml` | Machine-generated drive mapping (A adds `F:`). Regenerated per host; B's kept. |
| 69 disk/mobile/forensic/agent/script files | A is behind on all of these. |

### Files restored that A had lost

A was missing 18 files present in the ancestor and in B. All are retained:

`case_delete.py`, `mobile_acquire/adapters/android_mtp.py`, `mobile_acquire/ios_usbmux.py`,
`docker-pip-install.sh`, `check_laptop_token_match.py`, `sync-agent-token.ps1`,
`ensure-examiner-kit.ps1`, `ios_usbmux_backup.py`, `ios_usbmux_list.py`,
`mtp_logical_copy.ps1`, five test modules, and two deployment placeholders.

## 3. Bug fixed during the merge

`backend/app/routers/jobs.py` **does not parse** in `rag_new2_2` — or in the original
`rag_new2.zip`. Indentation is corrupted in several blocks, for example:

```python
    total_row = fetchone(db, f"SELECT count(*) c FROM jobs {where}", params)
        rows = fetchall(          # <-- over-indented; IndentationError
```

and an `else:` branch with a de-indented body. `python -m compileall` fails on this file, so
the jobs router cannot be imported and the API would not start.

`rag_new2_1` has the same file with correct indentation. Comparing the two ignoring whitespace
shows only **three** genuine content differences — all B's mobile work. The merged file was
therefore rebuilt from A's correct structure with B's three content hunks applied:

1. `deleted_documents` entry added to the artefact category catalog
2. `deleted_documents: "trashed"` added to the browse-query filter map
3. Reworded descriptions for `pictures`, `videos`, `audio`, `documents`

**Verification:** `diff -w merged B` is empty — the merged file is content-identical to B, with
only the indentation corrected — and it parses cleanly.

## 4. Verification performed

| Check | Result |
|---|---|
| `compileall` over backend, tests, scripts, laptop agent | passes (was failing on `jobs.py` before the fix) |
| All `from app.*` imports resolve to files on disk | passes |
| Symbols `vuln.py` needs from `scanner_agent_jobs` (`RetryNotAllowed`, `retry_edge_job`, `retry_failed_edge_jobs_for_case`, `job_is_edge_agent`) | all present in A's version |
| A's five `/api/scanner-agent/*` endpoints | all five preserved |
| A's imports satisfied by B's tree | yes (`sql_helpers`, `scan_orchestrator`, `vuln_helpers`, `scanner_agent_auth`) |
| `jobs.py` content equivalence to B | identical ignoring whitespace |

## 5. Things to be aware of

1. **The ownership feature is backend-only for now.** The laptop agent in `rag_new2_2` does not
   yet send `X-Aetheris-Agent-Instance` (nor the query parameter). The parameters are optional
   and default to `None`, so nothing breaks — but the fencing only takes effect once the agent
   is updated to send its instance id.

2. **Environment files were not merged.** `.env`, `.env.example` and `laptop-scanner/.env`
   differ between the branches in site-specific ways — A points at a live host and tenant slug,
   B at local defaults. B's versions were kept unchanged. Set these per deployment; do not
   assume either archive's values are correct for your environment.

3. **Excluded from the merged tree:** three malformed evidence paths that unzipped with Windows
   path separators embedded in the filename, and two `.pre-v1.2.21-*` editor backups of
   `scanner_agent_jobs.py`. Runtime residue already present in the archives (`backups/`,
   `diagnostics/`, `recovery-snapshots/`) was carried through untouched from B.

4. **Line endings are mixed** across the repository, as they were in both archives. No bulk
   normalisation was applied — that would have produced a diff touching almost every file and
   obscured the real changes. Consider adding a `.gitattributes` if this becomes annoying.

## 6. Suggested first steps

```bash
# 1. Confirm the tree builds
python -m compileall backend/app

# 2. Apply migrations (029–032 are present and unchanged)
docker compose up -d postgres && docker compose run --rm api alembic upgrade head

# 3. Run the test suites
cd backend && pytest -q
cd laptop-scanner/scanner-agent && pytest -q

# 4. Exercise the newly merged vuln surface
#    POST /api/cases/{case_id}/nessus-parity/compare
#    GET  /api/scanner-agent/jobs/next?agent_instance_id=<id>
```
