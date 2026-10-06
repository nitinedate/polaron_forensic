# Aetheris V7 — Section C / AXIOM Objective-Evidence Synchronization

Date: 2026-09-16

## Problems fixed

1. A legacy device banner (`Laptop [1]`) could appear as a separate card at the top of Section C.
2. Observation prose could leak extractor payloads such as raw AppX `BlockMap` XML / serialized JSON.
3. A title could receive unrelated catalog totals, for example `0 items (Remote Desktop Protocol (RDP))` and `196 file occurrences (Microsoft Excel Documents)` under **File Access and Handling**.
4. Generic observations could be reused across different objectives even when the evidence did not answer that objective.
5. The report objective record kept the client-facing Objective/Procedure but could lose AXIOM fields needed by the observation planner.
6. Observations needed a short explanation that a non-technical reader can understand.

## Root causes

### `Laptop [1]`
Old report snapshots stored a Section C device label and the frontend O/P/O parser could turn that label into its own card. The parser removed a leading bullet before classifying the line, but the old device-line detector did not recognize the resulting `Laptop [1]` form. The export path also had no common Section C sanitizer.

### Raw XML / serialized extractor payload
RAG evidence can contain parser source content, including XML, JSON and AppX package metadata. Those chunks were useful internally for indexing but were not always rejected before client-facing prose was assembled.

### RDP / Excel totals inside File Access
Candidate artifact categories were being added to the observation context with their raw descriptions/counts. Broad RAG queries such as document/media queries could also retrieve nearby inventory totals. The model then treated those totals as though they answered the objective.

### AXIOM detail being lost
The live AXIOM catalog contains detailed procedure text, required observation fields, expected output fields, minimum corroboration and limitations. Some report-template serialization paths preserved only title/objective/procedure/evidence prompt. The Observation agent therefore sometimes had the human-facing question but not the examiner-level evidence requirements.

## V7 implementation

### 1. Remove device-only banner everywhere

A shared `sanitize_section_c_markdown()` now removes legacy standalone device banners before Section C is previewed/exported. It recognizes plain, bullet, heading and bold variants such as:

- `Laptop [1]`
- `- Laptop [1]`
- `**Desktop [1]**`
- `### Device [1]`

The React preview also suppresses legacy device-only lines. The report template no longer invents `Laptop [1]` as a fallback label.

### 2. Never expose raw XML / JSON / extractor blobs

Observation and RAG filters reject:

- XML declarations (`<?xml ...?>`)
- AppX `BlockMap` XML and Microsoft AppX namespaces
- serialized extractor arrays/objects containing raw `text`, `blob`, `content` or XML payloads
- internal paths/registry/log/tool jargon already covered by the technical-leak filter

Raw payloads are excluded from `simplify_evidence_detail()` and from objective-specific RAG evidence before they can become report prose.

### 3. Do not use unrelated raw catalog totals as findings

Client observations reject patterns such as:

- `0 items (Remote Desktop Protocol (RDP))`
- `196 file occurrences (Microsoft Excel Documents)`
- `Count: 00`

For strict objectives, candidate artifact totals are context only. The raw collector description is not appended to the Observation context.

For **File Access and Handling**, an RDP hit is explicitly irrelevant. A generic Office-document count is also not sufficient. The evidence must contain strong file-action signals such as a specific file plus opened/modified/renamed/copied/deleted evidence, or a relevant LNK/Jump List/recent-document trace that supports the action.

If the system only has a raw payload or unrelated count, V7 fails closed: it says the exact finding could not be established instead of converting bad evidence into a false `Nothing suspicious was found` conclusion.

### 4. AXIOM synchronization for report objectives

For every report objective linked to an AXIOM objective, the internal report-agent record now refreshes the live AXIOM detail and carries:

- `axiom_objective_id`
- AXIOM statement/question
- detailed AXIOM procedure
- required observation fields
- expected output fields
- minimum corroboration
- limitations

The client-facing Objective and Procedure can remain short/simple. The detailed AXIOM procedure is internal evidence-planning guidance.

The evidence contract merges those AXIOM requirements into:

- required fields
- evidence questions
- RAG queries
- minimum corroboration
- prohibited/limitation rules

The Observation prompt receives the same live AXIOM plan. This keeps the chain:

**Objective → AXIOM procedure → required evidence fields → scoped artifacts/RAG → corroboration → Observation → simple explanation**

instead of:

**Objective → nearby artifact count → generic Observation**

### 5. Title-specific retrieval

Reference/data-leakage objectives now require strong, objective-specific evidence signals before a RAG hit is accepted. Examples:

- File Access: file identity + supported action/time/user/application
- USB: distinct physical removable-storage identity + connection time; copy requires separate file evidence
- Cloud: distinct service/access evidence; visit is separate from upload/download/sync
- Deleted Files: distinct deleted file + deletion metadata
- Email Accounts: distinct address/account state, not email-message count
- WhatsApp: WhatsApp use and company-related download are separate facts unless directly linked

### 6. Simple explanation for every Observation

Client-safe observations end with a short `This means ...` sentence. Important objectives have title-specific explanations. Other AXIOM objectives use the safe default:

`This means the conclusion is limited to the evidence recovered for this specific question.`

The explanation is intended for HR, legal, management or another reader without forensic knowledge.

## Example correction

Rejected input:

> Relevant traces were found on the computer for this question. 0 items (Remote Desktop Protocol (RDP)). 196 file occurrences (Microsoft Excel Documents). This includes activity that may be unauthorized or against policy.

Safe fallback when exact file-action evidence is not grounded:

> File-related records were found, but the available evidence was not specific enough to state which relevant files were opened, changed, copied, renamed, or deleted. General document, shortcut, or recent-item totals were not used as proof of a file action. This means a file action is reported only when the evidence identifies the specific file and the action performed on it.

When current-case evidence does identify a file/action/time/user, the report agent uses those grounded facts instead of this fallback.

## Main files changed

- `backend/app/services/report_generator_agent.py`
- `backend/app/services/report_template.py`
- `backend/app/services/report_template_service.py`
- `backend/app/services/evidence_contract_planner.py`
- `backend/app/services/report_objective_evidence.py`
- `backend/app/services/report_objectives_observation_service.py`
- `backend/app/services/report_observation_style.py`
- `backend/app/services/report_export.py`
- `backend/app/services/report_docx_export.py`
- `frontend/src/components/forensic/ReportDocumentPreview.tsx`

## Validation

Focused V7 regression suite:

- 55 passed
- Python compilation passed for all modified backend modules

Broad report / structured-observation suite:

- 104 passed
- 3 failures

The same three failures reproduce on the unchanged V6 base and are unrelated to V7:

1. catalog-sync test expects removed `_workbook_path`
2. mobile O043 title expectation differs from current mobile title
3. static procedure test compares 37 catalog objectives with 27 static procedure entries

Manual evidence-safety validation confirms:

- raw AppX XML simplifies to an empty evidence detail
- RDP zero-count is rejected for File Access
- Excel generic count is rejected for File Access
- a recent-document record that identifies a specific file action is accepted
- bad raw-count observation is replaced with an objective-specific inconclusive explanation

## Deployment

Rebuild/recreate at least:

- `api`
- `worker-report`
- `frontend`

Then use **Recreate Report** so saved Section C is regenerated with the new AXIOM-scoped evidence plan. No PostgreSQL schema migration is required.
