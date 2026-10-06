# Aetheris Laptop Scanner v1.5.0 — Nessus-aligned data fidelity

## Purpose

v1.5.0 keeps the v1.4.9 performance/concurrency design and changes only result fidelity and traceability.

### Fixed critical-severity loss

Older report parsing used:

```python
float(nvt.findtext("cvss_base") or result.findtext("severity") or 0)
```

The XML string `0.0` is truthy in Python, so a Greenbone result such as `cvss_base=0.0` plus `result/severity=9.8` was incorrectly stored as `0.0`. This could turn a Critical result into Info.

v1.5.0 parses all available numeric CVSS candidates, preserves them for audit, and chooses the highest valid 0–10 technical score. It also records the source used (`result.severity`, `nvt.cvss_base`, etc.).

### Nessus CVSS severity only

Displayed technical severity is now independent of Greenbone legacy `threat` text:

- Critical: 9.0–10.0
- High: 7.0–8.9
- Medium: 4.0–6.9
- Low: 0.1–3.9
- Info: 0

Greenbone threat, QoD, CVSS candidates, CVSS source, CVEs and references are retained as trace data but do not rewrite technical severity.

### Complete host result visibility

Info results remain attached to their exact host. The central UI now shows Info and Total columns per IP so an assessed host no longer appears to have "nothing" simply because all of its observations are informational.

### Risk Number

The central v1.5.0 patch calculates a separate 0–100 contextual Risk Number. It is not labelled as Tenable VPR. If a real VPR or EPSS input is available it is used as a threat-likelihood input; otherwise threat likelihood remains 0/unknown rather than being fabricated from CVSS.

No Greenbone volumes, feeds, reports, runtime token, scanner instance ID, or performance settings are reset by this release.
