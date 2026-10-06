# Frontend build fix V29.1 - 2026-09-25

This patch fixes the six TypeScript errors reported by `docker compose build frontend`.

## Fixes

1. `HostEvidencePanel.tsx` TS2367 errors
   - Split the old broad mobile flag into:
     - `isLiveMobileSource` for live USB phone acquisition only.
     - `isMobileEvidenceSource` for mobile imports/backups and UI wording.
   - Android/iOS backup modes now remain eligible for the server evidence browser instead of being incorrectly narrowed out as live-phone mode.

2. `src/lib/api.ts` TS6133
   - Removed unused `inferApiService` import.

3. `MobileArtifactsPage.tsx` TS6133
   - Removed unused `FileText` icon import.

4. `MobileReportPage.tsx` TS2550
   - Replaced ES2021-only `replaceAll("_", " ")` with ES2020-compatible `split("_").join(" ")`.

## Rebuild

From the project root:

```powershell
docker compose build --no-cache frontend
docker compose up -d frontend
```

For HTTPS:

```powershell
docker compose -f docker-compose.https.yml build --no-cache frontend
docker compose -f docker-compose.https.yml up -d frontend
```

Then hard-refresh the browser with `Ctrl+Shift+R`.

## Validation

- All four changed TypeScript/TSX files pass TypeScript 5.8.3 syntax transpilation using ES2020.
- A focused TypeScript narrowing regression confirms Android/iOS backup comparisons are valid when only the live-mobile branch is excluded.
- No `.replaceAll()` calls remain under `frontend/src`.
- Full package installation/build could not be executed in the sandbox because `npm install` timed out before dependencies were available.


## V29.2 startup correction
The unified Enterprise Console is the `services/gateway` service. Do not use `docker compose up -d frontend` for the main console because the root `frontend` is a legacy service and starts its API infrastructure dependencies. Use `scripts/rebuild-ui.ps1 -NoCache` instead.
