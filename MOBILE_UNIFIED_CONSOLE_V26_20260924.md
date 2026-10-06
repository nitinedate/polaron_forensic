# Aetheris Mobile Forensics Unified Console V26 — 2026-09-24

## Problem
The Enterprise Console exposed Disk Forensics and Vulnerability menus but did not expose the new separated Android/iOS mobile workflows. The backend separation from V24/V25 existed, but unified UI navigation was restricted to dedicated mobile frontend deployments.

## V26 behavior
The unified Enterprise Console now includes a first-class **Mobile Forensics** group:

1. **Mobile Overview** — combined operational view of Android and iOS job directories. It does not merge backend state.
2. **Device → Image** — platform chooser, then isolated Android or iOS live acquisition.
3. **Images → RAG** — import an already acquired Android/iOS image, backup, ZIP or supported extraction package and run the corresponding mobile extraction/parse/OCR/RAG pipeline.
4. **Mobile Jobs** — combined directory with every job link pinned to its owning mobile backend.
5. **Mobile RAG** — selects an Android or iOS job and opens the mobile-only RAG panel for that job.
6. **Mobile Reports** — selects an Android or iOS job and opens its mobile report route; Disk report routes are not reused.

The Disk menu is labelled **Disk Forensics** in unified mode to make the product boundary clear.

## Routing and isolation
Unified routes pin the platform in the URL:

- `/mobile/android/...` -> `mobile-android`
- `/mobile/ios/...` -> `mobile-ios`

Dedicated mobile frontends continue to use `/mobile/...` and their configured service identity.

Cross-product job fallback remains disabled. A 404 from Android is not retried against iOS or Disk, and vice versa.

## Device isolation
The mobile acquisition page now filters both server-proxied and direct Windows HostDrive discovery by the active platform. Therefore:

- Android acquisition only displays Android devices/adapters.
- iOS acquisition only displays iOS devices/adapters.

This closes a UI-side isolation gap where locally detected devices could otherwise be merged back after backend filtering.

## Dashboard
The unified dashboard retrieves Android and iOS job summaries independently and presents them as Mobile jobs while preserving their service identity. Disk jobs remain a separate dashboard series.

## Validation
- `backend/tests/test_mobile_unified_console_v26.py`: **8 passed**.
- Combined mobile platform/isolation/semaphore UI contract suite: **46 passed**.
- All changed TypeScript/TSX files passed TypeScript syntax transpilation.
- A full Vite dependency-resolution build is not available in this sandbox because the supplied source tree does not include installed frontend npm dependencies. This is an environment limitation, not a TypeScript syntax failure.

## Deployment note
Rebuild/redeploy the main frontend after applying V26. No Android/iOS database, Redis, MinIO or queue merge is required. The unified UI reaches the already separated mobile services through the existing gateway service header routing.

## Rebuild the Enterprise Console frontend
From the project root:

```powershell
docker compose build frontend
docker compose up -d frontend
```

For the HTTPS stack use the same compose file used by the deployment, for example:

```powershell
docker compose -f docker-compose.https.yml build frontend
docker compose -f docker-compose.https.yml up -d frontend
```

After the container is rebuilt, hard-refresh the browser so an older cached JavaScript bundle does not keep the previous sidebar.
