# Polaron V30.1 - Server/client evidence routing fix

## Fixed behavior

### Server-attached HDD/SSD/USB/pendrive
- Browser-selected E01/E02/... files are first resolved against server-visible drives by **filename + exact byte size**.
- If the exact set exists on the forensic server, the source is registered as `server_local` and processed **in place / zero-copy**.
- Download Agent is not started.
- Client transfer activity is cleared/hidden.
- No browser staging copy and no automatic deletion of the original evidence.
- Server metadata persists `transport_mode=zero_copy`, `transfer_required=false`, and `download_required=false`.

### Client-side evidence
- If the selected image cannot be resolved on the server and the console is being used remotely, it uses the explicit browser/client transfer path.
- Download Agent opens before the first byte and the pipeline remains gated until the complete manifest is received and verified.

### Safety
- On localhost/server console, an unresolved disk-image selection fails closed instead of uploading a large E01 back to the same server.
- Existing backend gate still rejects client upload if a server-local evidence path has already been registered.
- Stale mobile metadata no longer reclassifies a `host_disk` job as Android/iOS.
- Stale client-transfer session logs/progress are cleared when a server source is selected.

## Key files changed
- backend/app/services/host_evidence.py
- frontend/src/components/forensic/HostEvidencePanel.tsx
- frontend/src/components/forensic/JobActivityPanel.tsx
- frontend/src/pages/forensic/JobDetailPage.tsx
- frontend/src/lib/jobUploadSession.ts
- frontend/src/lib/orchestrationStages.ts

## Validation
- `backend/tests/test_server_local_zero_copy_v30.py`: **9 passed**.
- Python compilation of changed backend service: passed.
- Broader source/residency/download suites passed except unrelated existing environment/static-version assertions; some pipeline-orchestrator tests require `psycopg2`, which is absent in this sandbox.
- Full frontend build could not be executed because this extracted archive does not contain an installed frontend dependency set (`vite`, React typings, etc.).
