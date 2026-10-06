# Artifact page + dashboard render fix V31.1 - 2026-09-26

## Problems fixed

1. `/forensic/jobs/<job-id>/artifacts` could render a completely blank page with
   `Cannot read properties of undefined (reading 'toLocaleString')`.
2. The artifact category API returned a legacy `{key,label,count}` shape while the
   React page required `{category,sub_category,count,total}`.
3. Partial/mixed-version evidence payloads could contain missing numeric fields and
   crash artifact-related React components during render.
4. The unified Dashboard queried Android/iOS `/api/jobs` summaries even when those
   isolated services were stopped, producing repeated 404/502 entries in Chrome.
5. Dashboard donut colors were too saturated/dark in the light theme.

## Changes

- Backend artifact categories now return the React category-tree contract with a
  numeric `total`, optional platform and `pending_chunk`.
- Frontend also normalizes legacy category responses so frontend/backend can be
  deployed in either order without a blank page.
- Artifact explorer, category tree, preview/media properties, evidence coverage and
  artifact board paths use safe numeric conversion/formatting for partial payloads.
- A top-level React error boundary provides a visible recovery screen instead of a
  blank white application if a future render exception escapes a feature component.
- Unified Dashboard uses `/api/dashboard/jobs`, a dashboard-only health-tolerant
  summary endpoint. The gateway converts 404/502/503/504 for this summary endpoint
  only into an empty HTTP 200 response with `service_available=false`. Operational
  `/api/jobs` and job-processing endpoints remain strict and still surface failures.
- The mobile summary displays that its services are offline when neither isolated
  mobile backend is reachable.
- Donut slices and matching legend dots render at 62% opacity for a lighter/pastel
  appearance. Bar and radial charts are intentionally unchanged.

## Validation

- Python compile check passed for the modified backend routers.
- 63 focused backend/static regression tests passed, including artifact browsing,
  artifact preview/listing, V28 workflow, V30 server-local zero-copy and V29 theme
  donut coverage.
- All modified TypeScript/TSX source files passed TypeScript parser/transpile syntax
  validation. A full npm dependency build was not run in the sandbox because the
  dependency install did not complete within the available execution window.

## Deploy

Rebuild the gateway/UI after replacing the project:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\rebuild-ui.ps1 -NoCache
```

Because the backend artifact-category contract and dashboard summary route also
changed, rebuild/restart Disk Forensics and any running mobile API containers (or
run the normal full stack rebuild script). Then hard-refresh Chrome with
`Ctrl+Shift+R` so the old `index-*.js` bundle is not reused.
