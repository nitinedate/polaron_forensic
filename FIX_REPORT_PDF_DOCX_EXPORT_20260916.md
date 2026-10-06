# Aetheris forensic report export fix - PDF + DOCX only

Date: 2026-09-16

## Requirement

The forensic Report Editor must provide downloadable PDF and DOCX versions of the same approved report. HTML must not be presented or stored as a report export format. The downloadable files should use the Polaron A4 letterhead and a human-readable case/subject filename, rather than a generic `forensic-report-<id>-...` name.

Reference comparison used during the change:

- `RRP E Mr.Seger Forensic Report(20260916-073712).pdf` - examiner/reference report (21 pages).
- `forensic-report-b8c65154-pdf-20260916-071213.pdf` - platform generated report (48 pages).

The reference is more compact, while the platform report intentionally contains more generated artifact/annexure material. This change does not discard evidentiary content just to force the same page count; it fixes export formats and visual/document consistency.

## Changes

### 1. PDF and DOCX are the report downloads

`backend/app/services/report_export.py`

- Public report formats are PDF and DOCX.
- HTML was removed from the report export media map and supported report format set.
- A failed PDF render now returns an export failure. It never stores HTML under a PDF-looking workflow.
- HTML, where used by `xhtml2pdf`, is transient in-memory renderer input only and is never stored or downloadable.
- The defensibility bundle now contains DOCX + PDF + JSON manifest, not an HTML report.
- Export metadata stores the final human-readable download filename.

### 2. Native editable DOCX added

`backend/app/services/report_docx_export.py`

The DOCX is built from the exact saved report sections used by PDF export and contains:

- ISO A4 paper.
- 44 mm report header band and 26 mm footer reservation.
- Polaron header artwork on every page.
- Confidential stamp.
- Polaron footer artwork and Word page-number field.
- Times New Roman forensic-report typography.
- Native editable Word paragraphs and tables.
- Gold table headers and deliberate column sizing for URL/evidence tables.
- Repeated table headers across page breaks.
- Table rows configured not to split unnecessarily.
- Objective / Procedure / Observation labels and bullet procedures as real Word content.
- Duplicate saved section headings suppressed.

### 3. PDF rendering cleanup

`backend/app/services/report_markdown_html.py`

- Bold, italic and inline-code markers are rendered instead of leaking literal Markdown characters into PDF.
- `-` and `•` bullet records render as bullet lists.
- Existing A4/table pagination fixes remain in force.

`backend/app/services/report_export.py`

- Leading saved headings that duplicate the formal exporter section heading are stripped for PDF as well as DOCX.
- This addresses duplicated headings seen in generated output such as Analysis Summary / Appendix.

### 4. Human-readable filenames

New downloads use a case-aware name such as:

- `RRP - Mr. Seger Forensic Report.pdf`
- `RRP - Mr. Seger Forensic Report.docx`

The organization/requesting agency and first case subject are taken from Case Intake. Invalid filename characters are removed.

### 5. Browser now honors server filenames

`frontend/src/lib/api.ts`

The binary-download helper now reads `Content-Disposition` and uses the filename returned by the server. Previously the report API could return the correct MIME type/name while JavaScript still forced a generic `.bin` fallback filename.

### 6. Report Editor UI

`frontend/src/pages/forensic/ReportEditorPage.tsx`

Visible report actions are now explicit:

- Download PDF
- Download DOCX
- Defensibility pack

The HTML report download action is removed.

### 7. Old HTML export rows

`backend/app/routers/report.py`

Existing historical `report_exports` rows with `format='html'` are hidden from the forensic report export lists and export counts. They are not automatically deleted from storage/database by this patch because deleting historical evidence/export records should be an explicit administrative action.

## Validation

Focused export/layout tests:

- 19 passed.
- Python compilation passed for the changed backend modules.
- DOCX was rendered through LibreOffice using the standard render-and-verify workflow.
- All 4 synthetic QA pages were visually inspected: header/stamp/footer are not clipped, table rows continue correctly, page numbers render, and Objective/Procedure/Observation content is editable and clean.

Broader `tests/test_report*.py` run:

- 90 passed.
- 3 existing failures were reproduced unchanged on the V4 base package and are unrelated to this export patch:
  - legacy `_workbook_path` catalog-sync test;
  - mobile O043 title expectation mismatch;
  - report objective/procedure catalog cardinality expectation mismatch.

Frontend dependency packages are not included in the extracted package, so a full Vite build could not be run in this environment. TypeScript syntax checks on the edited files produced only expected missing-module/environment errors and no syntax errors.

## Deployment

Rebuild/recreate at least the API, report worker and frontend images. Do not use `docker compose down -v`.

After deployment, approve the report and use **Download PDF** or **Download DOCX**. New exports will be real PDF/DOCX files with friendly filenames. Historical HTML exports remain hidden.
