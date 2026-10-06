# Aetheris V8 — Report Agent / AXIOM Knowledge Base Integration

Date: 2026-09-16

## Goal

Use the attached `aetheris_axiom_kb_starter` project as the authoritative forensic reporting knowledge source for Aetheris Report Agent, instead of maintaining a second set of hand-written objectives, procedures, artifact mappings, count rules, exclusions, observation prompts, and mobile-report narratives inside the existing Aetheris code.

## Source of truth

The supplied knowledge base is vendored unchanged at:

- `backend/app/knowledge/axiom_kb/axiom_forensic_kb.json`

Documentation from the supplied project is preserved at:

- `docs/axiom_kb/STARTER_README.md`
- `docs/axiom_kb/ARTIFACT_CATALOG.md`
- `docs/axiom_kb/PROCEDURES.md`
- `docs/axiom_kb/REPORT_MATRIX.md`

Runtime validation confirms the supplied seed contains:

- 18 procedures
- 58 report definitions
- 56 canonical AXIOM artifact families
- 3 global exclusions

Knowledge-base SHA-256 fingerprint:

`43ead46f4dc20b73de34333353d480ff8fa5877ec87a743a4cc92ce2339a4753`

The V8 runtime validates report IDs, procedure references, artifact-family references, relationship types, count units, and exclusion rules before the KB is used.

## Architecture used in Aetheris

The attached starter includes its own demonstration FastAPI/PostgreSQL project. V8 does **not** deploy that demonstration API or create a second forensic database. Aetheris already has case intake, jobs, artifact collection, PostgreSQL persistence, RAG, PDF/DOCX export, UI, workers, and evidence provenance.

Instead, V8 integrates the starter at the semantic/reporting layer:

`Aetheris collectors and job evidence`

→ `Canonical AXIOM family normalization`

→ `Attached KB report definition`

→ `Allowed PRIMARY / supporting / corroborating / contextual evidence`

→ `Global exclusions`

→ `Normalization`

→ `PRIMARY-only counting`

→ `Report-specific semantic deduplication`

→ `Correlation / limitations / examiner-review checks`

→ `Deterministic evidence brief`

→ `Report Agent wording only`

→ `Observation + simple explanation`

This follows the supplied starter's stated control flow:

`Report Title -> Objective -> Controlled Procedure -> Allowed AXIOM Artifact Families -> Exclusion -> Normalization -> Primary-only Counting -> Deduplication -> Correlation -> Observation -> Simple Explanation -> Examiner Review`

## Critical Report Agent rule

The LLM is now the **last writing step only**. It is not allowed to:

- decide which artifact family answers an objective,
- choose a raw database count,
- sum unrelated artifact totals,
- use a supporting artifact as the answer,
- invent evidence,
- infer a file transfer merely from a device connection or website visit,
- expose raw XML/package payloads or internal evidence paths.

The deterministic KB/report engine decides what evidence is allowed before the writing model receives the brief.

## New services

### `axiom_forensic_kb.py`

Loads and validates the supplied JSON and provides:

- canonical AXIOM family and alias resolution,
- objective-to-KB-report mapping,
- direct versus supporting report mapping,
- controlled objective text,
- controlled procedures,
- evidence questions and RAG search terms,
- global exclusions from the supplied seed,
- raw XML/package payload blocking,
- KB integrity validation and fingerprinting,
- Report Agent system rules.

### `axiom_forensic_report_engine.py`

Bridges the existing Aetheris evidence store to the attached KB semantics:

- adapts `job_axiom_artifact_results` and current provenance,
- normalizes common AXIOM field aliases,
- normalizes URLs/domains/email addresses,
- redacts sensitive fields,
- suppresses raw serialized XML/JSON/package content,
- performs report-specific semantic deduplication,
- counts PRIMARY evidence only,
- prevents supporting/corroborating records from inflating counts,
- applies parent/refined and recovery-state examiner-review rules,
- creates the deterministic evidence brief,
- exposes only deterministic `allowed_counts` to the wording model,
- validates the final observation and fails closed if it violates the brief.

## Direct versus supporting evidence

A broad Aetheris objective can map to multiple supplied KB reports. V8 distinguishes reports that can directly answer the business question from reports that only provide context.

Examples:

- Generic `USB and External Device Usage`: `USB_DEVICES` can directly establish connected USB-device evidence.
- `Connection of External Hard Disks`: raw USB records are **not** a direct external-HDD count because the family can contain hubs, cameras, interfaces, input devices, or internal/related records. The engine requires suitable physical-device evidence/correlation instead of using the raw total.
- `Access to Cloud Storage Services`: generic browser-history totals are supporting evidence; they cannot become a count of cloud services or proof of upload/download.
- `Use of WhatsApp Web and Download of RRP Files`: generic chat/browser totals cannot prove company-file transfer through WhatsApp.

## Observation generation

V8 replaced the previous generic observation pipeline with a deterministic evidence-brief flow.

A generated Observation must now:

1. answer the selected objective rather than repeat nearby inventory totals;
2. use only evidence families allowed by the attached KB;
3. state only counts present in deterministic `allowed_counts`;
4. distinguish direct evidence from supporting/corroborating context;
5. preserve limitations from the KB;
6. exclude raw XML/package/manifest/BlockMap material;
7. avoid internal paths and query language;
8. avoid labels such as `Laptop [1]`;
9. end with a short non-technical `This means ...` explanation;
10. fail closed to a safe objective-specific statement when the evidence is insufficient.

## Examples of now-rejected observation content

The following can no longer be used as the answer to an unrelated objective:

- `0 items (Remote Desktop Protocol (RDP))` inside File Access and Handling,
- `196 file occurrences (Microsoft Excel Documents)` as proof that a file was copied/opened/deleted,
- a total USB artifact count as the number of external hard disks,
- total browser-history records as proof of cloud upload/download,
- generic Web Chat URL counts as proof of WhatsApp file transfer,
- raw AppX `BlockMap` XML or package manifests.

## Global exclusions

The runtime global exclusions are compiled from the attached KB JSON rather than a second hard-coded list. The supplied exclusions cover AppX BlockMap XML, AppX manifest/package XML, and raw XML declarations. Additional raw structured-payload safety checks prevent those payloads from reaching report prose even when embedded inside serialized evidence fields.

## Existing code removed/reduced

The main duplicated hand-written semantic modules were replaced by KB-generated facades or deterministic services. Across ten major semantic files, V8 reduced approximately:

- **5,500 lines → 2,093 lines**
- **3,407 lines removed**
- approximately **61.9% reduction**

The largest removals include old manually maintained:

- objective procedures,
- evidence contracts,
- LLM evidence-contract planning,
- RAG/query hint catalogs,
- examination narratives,
- observation style/gold text,
- structured-observation count logic,
- Section C observation generation,
- mobile objective/narrative/evidence-question duplicates.

The standalone second LLM evidence-contract planner was removed from the runtime path. A legacy database evidence prompt is not merged with the new KB; the KB contract overwrites it.

## Code intentionally retained

The following Aetheris code remains because it performs a different responsibility and is still required:

- case intake and selected objective IDs,
- PostgreSQL case/job/evidence storage,
- disk/mobile/scanner evidence collectors,
- artifact inventory and extraction counters,
- RAG storage/retrieval as supporting evidence retrieval,
- evidence provenance,
- frontend report editor/preview,
- A4 pagination,
- PDF and DOCX rendering/export,
- worker/API orchestration,
- existing Section B extraction/inventory metadata.

Legacy objective/catalog tables may remain for IDs, backward compatibility, administration, or saved case selections, but they are no longer the authoritative runtime source for forensic objective/procedure/evidence semantics in Section C.

## Mobile reporting

Mobile ingestion/platform metadata remains in Aetheris because it controls extraction/UI behavior. Duplicate hand-written mobile objective statements, evidence questions, and examination narratives were removed and are generated through the same attached KB semantics used for disk reports.

## Known KB coverage gaps

V8 does not silently substitute unrelated evidence when the supplied seed has no exact report definition. Such cases are surfaced as limitations / examiner-review requirements. Examples may include highly specific clipboard/print activity, patch-inventory details, alternate data stream-specific analysis, shadow-copy-specific questions, or another objective not represented by the 58 supplied reports.

This is intentional. An unsupported objective must not be answered with the nearest convenient artifact count.

## Tests and validation

### Attached starter tests

- Starter `tests/test_counting.py`: **3 passed**

### V8 semantic integration suite

- Report Agent / objective evidence / procedure / narrative / observation / mobile / KB integration: **69 passed**

### V8 export and safety suite

- KB integration, external-storage deduplication, report HTML renderer safety, letterhead, PDF download, DOCX export: **37 passed**

### Compilation and KB integrity

- Python service/knowledge compilation: passed
- KB integrity errors: `[]`
- Seed counts: `18 procedures / 58 reports / 56 artifact families / 3 exclusions`

Two unrelated issues already present before this integration remain outside V8 scope: an old catalog-ingest test referring to a removed `_workbook_path` helper and a disk/mobile extraction-filter bleed case. V8 does not claim to fix those unrelated problems.

## Deployment

No PostgreSQL schema migration is required for this integration.

Rebuild/recreate at minimum:

- `api`
- `worker-report`
- `worker-agent` if it loads agent-duty metadata in your deployment

A frontend rebuild is not required specifically for V8 because this integration is backend/report-agent semantic work, although rebuilding the full application is safe if that is your normal deployment process.

After deployment, use **Recreate / Regenerate Report**. Existing saved report prose will not retroactively acquire the new KB-controlled observations until regeneration.

## Maintenance rule going forward

Forensic reporting knowledge should be changed in the supplied AXIOM KB source (artifact families, procedures, reports, exclusions and counting semantics), then validated by the V8 loader. Do not add another hard-coded objective/procedure/observation catalog back into Aetheris services.
