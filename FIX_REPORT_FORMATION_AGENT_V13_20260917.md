# V13 - Report Evidence/Content Agent + Report Formation Agent split

## Why this change exists
The supplied forensic reports teach two separate responsibilities that should not be mixed:

1. **Forensic reasoning/content** - artifacts -> Objective -> Procedure -> Observation -> Annexure -> Analysis Summary.
2. **Document formation** - place the already-approved content on A4 pages, use remaining page space, and create PDF/DOCX without changing the words.

The previous `report_generator_agent` mixed both responsibilities. V13 splits them.

## Agent 1 - Report Evidence & Content Agent
Existing agent id remains `report_generator_agent` for backward compatibility, but its duty is now forensic content only.

Responsibilities:
- resolve every selected Case Intake objective;
- use AXIOM KB and supplied report-reference corpus;
- collect record-level artifacts rather than generic totals;
- classify, exclude noise, deduplicate and correlate;
- create Objective / Procedure / Observation;
- create matching Annexure evidence;
- create Analysis Summary from finalized observations;
- preserve the simple `This means ...` explanation;
- never expose raw XML/JSON/binary evidence or device banners such as `Laptop [1]`.

It no longer owns A4 pagination or PDF/DOCX formation.

## Agent 2 - NEW Report Formation Agent
New service: `backend/app/services/report_formation_agent.py`

New action-agent id: `report_formation_agent`

Responsibilities:
- take the exact saved `report_sections.content_md` used by the UI;
- never rewrite, summarize, add, delete or reorder forensic content;
- pack content into 210 x 297 mm A4 pages;
- use remaining page space before starting a continuation page;
- never split a table row;
- keep headings with following content;
- keep complete O/P/O panels together when possible;
- create PDF and DOCX from the same canonical section snapshot;
- attach a SHA-256 `ui_content_sha256` fingerprint to exports.

## Training added for formation
New knowledge file:

`backend/app/knowledge/report_reference_corpus/report_formation_training_v1.json`

It uses the supplied Ex-1 through Ex-5 reports plus the RRP/Mr. Seger report as layout exemplars. It learns layout methodology only; names, dates, counts, URLs and conclusions are never reused as current-case facts.

## UI/PDF/DOCX parity
`report_export.py` now fingerprints the exact ordered saved UI sections before export.

Stored export metadata includes:
- `ui_content_sha256`
- `formation_agent_version`
- `content_parity: saved-ui-sections`

PDF and DOCX no longer perform an export-only Section C sanitization pass. Section C is sanitized at generation time, so export cannot silently change content after the examiner has reviewed it in the UI.

## Compatibility
Older imports of `TABLE_PAGE_UNITS`, `chunk_table_rows`, `table_row_units` and `wrap_table_cell` from `report_generator_agent` still work, but the implementation ownership moved to `report_formation_agent`.

`report_markdown_html.py` now imports those layout helpers directly from the Formation Agent.

## Frontend
The Report Editor subtitle now shows the two-agent model:
- Report Evidence & Content Agent creates forensic findings.
- Report Formation Agent packs the exact UI content and creates PDF/DOCX.

## Validation
Focused backend regression run:

`49 passed`

This includes:
- formation-agent snapshot/parity tests;
- five-report reference-training tests;
- report-generator tests;
- Markdown/PDF layout helpers;
- DOCX export;
- export filename/download behavior;
- letterhead tests.

The full frontend build was also attempted. It is currently blocked by pre-existing project-wide TypeScript/React typing errors in `src/pages/vuln/dashboards/VulnDashboardsPage.tsx` (`JSX.IntrinsicElements`/`React` namespace), unrelated to the Report Editor subtitle change.

## Deployment
No database migration is required.

Rebuild/recreate at least:
- `api`
- `worker-report`
- `frontend`

If your deployment loads action-agent definitions in another worker, rebuild that worker as well.
