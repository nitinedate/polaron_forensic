# Aetheris report + WhatsApp forensic fixes (2026-09-16)

## 1. Objective / Procedure / Observation titles

- RPT catalog keys such as `RPT-O920` (and legacy `RPT-0920`) are no longer used as visible report headings.
- The report agent resolves the title from `public.reports_objective` first, then falls back to the built-in report catalog.
- Intake/saved snapshots are repaired during report-objective resolution, so stale snapshots containing only an RPT key are hydrated before generation.
- Planning/progress text also uses the resolved title rather than the RPT key.

## 2. A4 page packing

- OPO pagination now uses a calibrated page budget plus per-card chrome overhead.
- The next complete OPO panel is placed on the current page when it fits.
- A panel moves to the next page only when the remaining space cannot hold it; an oversized panel can still split safely.

## 3. Evidence-backed observations

- Observation drafting is explicitly instructed to use exact artifact-backed facts when evidence exists (for example count, recovered name, timestamp, communication/file type).
- Wording remains simple (2-5 short sentences), with no unsupported claims, internal paths, tool jargon, or invented facts.

## 4. WhatsApp-style mobile review

- The left pane remains a contact/group list.
- Clicking a contact/group loads the complete thread into the right pane rather than replacing the list with single-message rows.
- Messages are shown as WhatsApp-style bubbles in chronological server order.
- Each message displays sender, date/time and a stable SHA-256 forensic record hash.
- Deleted/recovered messages are highlighted in red.
- All / Current / Deleted / Media / Calls filters remain available.
- Thread API page size supports large conversation retrieval (up to 8,000 records per page, with frontend paging).

## Validation

- Modified Python modules compile successfully with `python -m py_compile`.
- Targeted regression tests for title hydration, OPO pagination, WhatsApp UI contract, and stable SHA-256 message hashes: **5 passed**.
- A broader two-file test run produced **19 passed, 1 failed**; the failure is the pre-existing `test_person_merge_across_apps` grouping expectation and is unrelated to these changes.
- Full TypeScript compilation was not used as a pass criterion because this extracted project does not have its frontend npm dependencies installed in the working environment.
