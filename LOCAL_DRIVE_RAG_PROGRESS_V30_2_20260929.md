# Polaron V30.2 — Local-drive evidence selection and RAG progress

## Evidence selection

The evidence picker no longer presents separate client/server modes.

- One **Select evidence directory** flow is shown.
- It lists HDD, SSD, USB/pendrive, external drives and mapped network drives visible in the local forensic environment.
- The examiner opens a drive, navigates to the evidence directory and clicks **Use this directory**.
- Processing reads the selected path in place; there is no separate download screen for this workflow.
- Client/server residency wording and source-mode instructions were removed from the visible selection UI.

Existing zero-copy backend metadata remains internal so evidence safety and cleanup rules are preserved.

## Mobile RAG progress

Mobile processing now has its own compact RAG progress panel rather than using the Disk-style pipeline presentation.

The panel reports individual percentages for:

1. Evidence directory selected
2. Extraction
3. Artifact materialization
4. Parsing
5. OCR
6. Chunking
7. Vector embedding
8. Entity extraction
9. Knowledge graph
10. Annotation
11. Ontology
12. Artifact inventory
13. RAG ready

Each stage shows its live percentage. When a stage reaches completion it is marked with a green check.
The panel reads the existing orchestration agent state from `job.pipeline_progress.orchestration.agents`, so it reflects backend progress rather than simulated UI timers.

## Validation

- Updated TS/TSX files passed TypeScript syntax transpilation with TypeScript 5.6/ES2020 settings.
- Full dependency-backed frontend build was not run because `npm ci` could not finish within the sandbox timeout.
- Backend processing code was not changed in this revision.
