# Laptop Scanner 1.5.3-v45.7

The scanner uses the modern canonical agent, consistent Full defaults, five–six adaptive IP slots and complete per-IP progress. This release also implements policy and evidence integration for every one of the 52 service families in the attached service guide, plus IP forwarding.

## Apply

Extract the updated scanner source into its existing folder, preserving `.env`, scanner-agent/runtime, tokens and the local LAN fingerprint. Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Apply-Scanner-v1.5.3.ps1
```

Update the central source too and run `scripts/Apply-Scanner-Integration.ps1` from the central project root. Both scripts rebuild/recreate application/agent containers and preserve existing data/feed volumes. Use `Start-Laptop.cmd` for first installation. Effective local profile overrides remain visible; Full defaults to all TCP ports and 30 priority UDP ports.

## Scope and evidence

- The ordered 52-service registry is `scanner-agent/agent/service_catalog.json`. Named catalog modes include 88 TCP ports; custom TCP/UDP ports add scope. UDP priority/full/off is respected for every mode.
- Central `settings_json` is snapshotted in the job and transported without raw secrets. Explicit local Greenbone vault UUIDs bind SSH/SMB/SNMP/ESXi credentials; `ssh_credential_port` supports custom SSH endpoints. Binding is distinct from authentication success; detection continues when binding fails.
- Each task records actual range/counts/exclusions, config/scanner IDs, feed versions, applied preferences, credential status, start time and SHA-256. Resume retains known snapshots and marks legacy unknown scope honestly.
- Paged native results yield source-backed finding/observation/not-tested/unsupported family states and explicit endpoint confidence. The central service recomputes/scopes the data; Scan Details and CSV/JSON/report appendix expose it.
- Missing native scores remain marked Unscored; numeric CVSS provenance and native VPR/EPSS are retained. The custom weighted risk score is separate from Tenable VPR.
- Complete per-IP snapshots retain waiting/failed/skipped/incomplete distinctions, monotonic sequence across resume/retry, bounded percent and task IDs. Delayed old-task progress cannot overwrite a newer assessment. High-percent forced tail harvesting stays off by default.
- Source version is authoritative; resource pressure pauses new admissions; port discovery never narrows configured scope. Packages exclude logs, caches, backup trees, scanner secrets and runtime identity.

## Validation and limits

102 standalone tests, 107 embedded agent tests and 175 focused central/report tests passed. PostgreSQL-compatible WASM behavior, Vuln/Unified builds, Python 3.11 syntax, changed PowerShell grammar, archive integrity and document checks passed.

All native product/check execution depends on feed/configuration, endpoint fingerprint, access and report evidence. No per-rule pass is inferred from silence. New DHCP/SSDP/mDNS collectors, an IPv4/IPv6 configuration acquisition collector or a dedicated legacy/SNI TLS engine are not implemented. The forwarding evaluator requires authenticated IPv4/IPv6 states and device-role policy. Exact original Nessus parity and live validation of all 52 families remain target-fixture work.

Native Windows/Docker/Greenbone and live phone/GPU acceptance were not available. Matching WhatsApp key material remains required. See the updated Service Implementation Guide, complete service CSV, three separate flow PDFs, scanner ODT and `SCANNER-INTEGRATION-V153-RELEASE.md` in the central bundle.
