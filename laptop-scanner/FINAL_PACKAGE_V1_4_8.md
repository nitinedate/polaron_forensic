# Aetheris Laptop Scanner v1.4.8 Final

v1.4.8 keeps all TLS, token-runtime, Greenbone initialization, and 15-18 IP/hour changes from v1.4.7 and fixes a Greenbone GMP response-shape compatibility bug that could leave jobs queued at 5% after OSPd had already finished loading VTs.

Key readiness changes:

- `get_nvts(..., extended=True)` is used when supported.
- Both `<nvt_count>` and `<info_count>` response schemas are recognized.
- When gvmd exposes NVT objects and feed versions but omits a total count, the inventory gate is considered positive evidence; full scanner readiness still requires the configured `Full and fast` scan config.
- A trustworthy count below `GVM_MIN_NVT_COUNT` still blocks scans.
- No Greenbone volumes are deleted and the hotfix does not restart OSPd.
