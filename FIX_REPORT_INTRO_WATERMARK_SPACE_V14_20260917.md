# Aetheris Report Agent V14 - Introduction, Watermark and Page-Space Fix

Date: 2026-09-17

## What this patch fixes

V14 retrains the existing two-agent report workflow from the supplied forensic report exemplars and fixes the visible Introduction-page problems reported in the UI/export:

1. The Report Evidence & Content Agent now receives explicit forensic writing-style guidance learned from all five supplied examiner reports (Ex-1 through Ex-5). The guidance teaches how Objective, Procedure and Observation are written, but forbids copying case-specific names, dates, counts, URLs, hashes, devices or conclusions.
2. The Report Formation Agent training is upgraded to `report-formation-training-v2.0` and includes all five supplied DOCX reports plus the RRP PDF as a formation-validation reference.
3. Introduction is now a formal letter page in UI, PDF and DOCX:
   - one normal text-line (about 4-6 mm) of clearance after the letterhead;
   - centered, uppercase, bold and underlined `INTRODUCTION` title;
   - date aligned right;
   - compact `To` / recipient block aligned left;
   - centered Subject line with only `Subject:` emphasized;
   - compact Dear Sir / engagement text;
   - bold Scope of Work and Terms and Condition(s) labels;
   - right-aligned analyst/company sign-off;
   - no card, rounded box, dashboard shadow or exaggerated empty gaps.
4. The Polaron watermark is now deliberately very faint in all three renderers. The watermark PNG alpha is baked to a maximum of 16/255 (about 6.3%), and the UI no longer applies a second arbitrary opacity value.
5. Table pagination no longer stops at a fixed 12-row ceiling. Wrapped row height plus remaining printable A4 space now decides how many rows fit. A row is still kept intact.
6. PDF print CSS now allows a table to begin in remaining page space rather than moving a complete table block to the next page. Table rows remain `page-break-inside: avoid`, and table headers are configured as repeating header groups.
7. PDF body width is now the actual printable width defined by `@page` margins. This prevents right-aligned dates/sign-offs from extending outside the page.
8. DOCX now uses the same formal Introduction layout and the same faint watermark as UI/PDF. The watermark is a centered floating header image behind document text.

## Training / agent changes

### Report Evidence & Content Agent

Active reference corpus: `backend/app/knowledge/report_reference_corpus/five_forensic_reports_v1.json`

Corpus version is now `five-reports-v1.1` and contains a `writing_style` section. The style rules require factual, concise forensic language and enforce the sequence:

`Objective -> Procedure -> current-case evidence -> Observation -> limitation/plain meaning`

The style guidance is included in `reference_exemplar_guidance`, so the report wording agent receives it with each matched objective.

### Report Formation Agent

Active training corpus: `backend/app/knowledge/report_reference_corpus/report_formation_training_v2.json`

Agent version: `report-formation-v2.0`

The formation agent remains forbidden to rewrite report content. It controls only layout mechanics, pagination, header/footer/watermark placement and PDF/DOCX formation from the canonical saved UI section snapshot.

## Main files changed

- `backend/app/knowledge/report_reference_corpus/five_forensic_reports_v1.json`
- `backend/app/knowledge/report_reference_corpus/report_formation_training_v2.json` (new)
- `backend/app/services/report_reference_kb.py`
- `backend/app/services/axiom_forensic_kb.py`
- `backend/app/services/report_objectives_observation_service.py`
- `backend/app/services/report_formation_agent.py`
- `backend/app/services/report_renderer.py`
- `backend/app/services/report_export.py`
- `backend/app/services/report_markdown_html.py`
- `backend/app/services/report_docx_export.py`
- `backend/app/services/action_agents.py`
- `backend/app/services/agent_duties.py`
- `backend/app/static/report/watermark.png`
- `frontend/src/components/forensic/ReportDocumentPreview.tsx`
- `frontend/src/lib/reportPagination.ts`
- `frontend/src/index.css`
- `frontend/public/report/watermark.png`
- report-agent regression tests under `backend/tests/`

## Validation performed

Focused V14 regression group:

```text
32 passed
```

Broader report test group:

```text
124 passed, 6 failed
```

The same six failures were reproduced unchanged against the untouched V13 package, so they are pre-existing and unrelated to this patch. They concern catalog/test expectation drift (`_workbook_path`, controlled objective wording, old procedure/prompt expectations, and one mobile title expectation).

The frontend production build cannot complete in the supplied V13/V14 archive because its bundled `node_modules` is incomplete. The untouched V13 package fails immediately with the same missing `vite`, `@vitejs/plugin-react`, `react`, `react-router-dom`, and `clsx` modules. This patch does not introduce that dependency problem.

## Visual QA performed

A generated DOCX Introduction was rendered through LibreOffice and inspected as PNG. It renders on one A4 page with centered underlined Introduction, right-aligned date, compact formal letter spacing, centered subject, faint background watermark and right-aligned sign-off without clipping.

A generated HTML/PDF Introduction was also rendered and inspected. The prior printable-width overflow was corrected so right-aligned content remains inside the page.

## Deployment

Use the complete `aethris_fixed_v14.zip` as the updated project package, or apply `aethris-fixes-v14.patch` to the V13 tree and copy the two updated binary `watermark.png` files if your patch tool does not apply binary patches.

After deployment, rebuild/restart the backend and frontend using the same deployment procedure used for V13. Install frontend dependencies (`npm ci` or your normal dependency restore) before running the frontend build because the supplied archive contains only an incomplete `node_modules` directory.
