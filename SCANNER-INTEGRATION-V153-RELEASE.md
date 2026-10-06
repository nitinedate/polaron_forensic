# Scanner integration 1.5.3 / project release 6

This document records the scanner integration introduced in release 6. Current Disk/Mobile key capture and huddle cleanup are described in `WHATSAPP-KEY-INTAKE-RELEASE.md` (release 7).

The attached Laptop Scanner and canonical embedded agent are updated together. Release 6 retains the Disk/Mobile extraction, parsing, recovery, media, text RAG and report implementation from release 5, adds complete process documents, and fixes Laptop/central Vulnerability integration.

## Apply the code

First update the central project folder from `polaron-disk-mobile-serial.zip`, preserving local environment files and data. From the central project root run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Apply-Scanner-Integration.ps1
```

The script uses `services/vuln/docker-compose.yml`, rebuilds/recreates `api`, `worker-nessus` and `frontend`, and checks integration imports. It preserves database/feed volumes. For an existing custom deployment pass its correct `-ProjectName` and `-ComposeOverrides`; use `-IncludeGateway` only when your gateway also needs to rebuild. The runtime readiness-column check and migration `037_firm_vuln_readiness.sql` support existing databases.

Then extract the laptop ZIP into its existing scanner folder, preserving local `.env`, runtime identity/tokens and LAN fingerprint. From that folder run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Apply-Scanner-v1.5.3.ps1
```

For a fresh scanner installation use `Start-Laptop.cmd`. The update retains explicit scan-profile overrides in `.env`; confirm the printed effective profile. Full TCP scope uses `PORT_PROFILE=full`, `GVM_OPTIMIZE_TEST=no`; default UDP scope is `UDP_PROFILE=priority`.

## Fixed behavior

- The central packager no longer deletes the modern embedded agent and copies an older repo-root agent. It validates and packages the canonical source while excluding real secrets, runtime identity, LAN fingerprints, backup copies, caches and scan logs.
- Every assigned IP is represented in progress snapshots, including waiting hosts. The central service scopes and locks snapshot merges, protects terminal coverage and late polling, and exposes percent/state to the UI.
- Only the authenticated scanner receives its heartbeat/readiness update. Unready edge scanners cannot launch new jobs; legacy unknown readiness remains compatible only in the claim path.
- Incomplete per-host coverage cannot be converted to a clean API result by top-level `Done`/`partial=false`. Stored evidence, orchestration and response flags agree.
- Runtime/Compose/sample Full defaults are aligned, worker floor is five, critical pressure pauses new admissions, and stale version inputs cannot hide the actual 1.5.3 source build.
- Numeric CVSS version basis and source signals are retained; descriptions do not impose severity floors. The custom contextual risk score keeps native VPR/EPSS separate and never fabricates threat probability from CVSS.

## Service guide implementation

All 52 entries from the attached service guide are registered under `aetheris-services-2.1`, plus configuration family `CFG-IP-FORWARDING`. Full TCP is default; named catalog modes include 88 TCP ports and priority UDP includes 30 ports (17 baseline, six additional guide transports, seven existing ports). Custom additions, UDP off/full and explicit local GMP SSH/SMB/SNMP/ESXi credential UUIDs are transported in a sanitized, immutable job policy. SSH credential ports can be configured separately.

Native OpenVAS/feed methods perform checks. Task snapshots retain effective/excluded range and counts, config/scanner IDs, feeds, applied preferences, credential binding status, source time and SHA-256. Source-backed family results are persisted, shown in Scan Details, exported through coverage CSV/JSON and included in a PDF/DOCX report appendix. Missing score and product/version context are retained; the API/UI distinguishes Unscored from measured zero and respects stored CVSS basis.

No quiet endpoint or Done task becomes a per-rule pass. DHCP/SSDP/mDNS network collectors, a new IPv4/IPv6 configuration collector, a dedicated per-SNI TLS cache/legacy TLS engine, and a live-validated independent 52-rule suite are not implemented. IP-forwarding evidence evaluation requires authenticated states for both address families and device-role policy. Native credential success, vendor/device applicability and exact original Nessus parity still need source-backed live validation.

The readiness launch query now selects the fields it uses. Progress sequences are restored on resume and retain a fence across fresh retries, so earlier-task events cannot reopen a new assessment. Real environment files and generated private certificate material are excluded from the delivered code bundle; existing target-host configuration is preserved when extracting an update. Fresh deployments should use the existing certificate/bootstrap scripts.

## Validation and remaining acceptance

- 102 standalone agent tests; 107 embedded agent tests; 175 focused central/report tests passed.
- PostgreSQL-compatible WASM execution verified migration, heartbeat isolation, assigned/excluded target scope, durable percent/state, owner fencing and severity-basis SQL. This is not a live production database load test.
- Vulnerability and Unified frontend builds passed TypeScript/Vite. Python 3.11 syntax and changed PowerShell grammar passed; native Windows execution was not available.
- Archive integrity, canonical agent parity, source-preserved Disk/Mobile pipeline files, PDF page/text/bounds and ODT XML/ZIP structure are checked during packaging.
- Real Windows/Docker/Greenbone performance/coverage and live phone/GPU acceptance remain pending. Matching WhatsApp keys and real acquired bytes are still required.

Optional central adapters retain documented limits: ZAP is passive and reads at most 500 alerts per URL; Trivy accepts image references; Wazuh target-to-agent mapping is not implemented. These are distinct from the portable OpenVAS agent and are not depicted as successful universal scans.

## Documents and regeneration

`docs/process-flows` contains three separate PDFs (Disk: 24 pages; Mobile: 28; Vulnerability Scanner: 28), the 25-page updated Service Implementation Guide, the complete coverage CSV, a scanner ODT, and structured diagram data plus `build_flows.py`. The PDF flows are exact vector diagrams, not generated imagery. The ODT text/tables are editable; its diagrams are embedded pictures.

Run `python build_flows.py` from `docs/process-flows` with ReportLab and PyMuPDF installed. It reads the JSON data and writes the documents to `flow-deliverables` beside that directory. The PDF is the visually inspected fixed-layout reference. No native LibreOffice/Word rendering was available for the ODT.

Read `LIVE-PHONE-GPU-VERIFICATION.md` and run `scripts/Test-Live-Phone-GPU.ps1` on the real authorized host/phone for the separate forensic hardware acceptance. Existing forensic deployment instructions remain in `DISK-MOBILE-SERIAL-RELEASE.md`.
