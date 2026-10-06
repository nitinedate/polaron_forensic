# Process flow documents

Five separate PDFs describe the supplied source paths, decryption and report generation:

- `Disk-Process-Flows.pdf` — 24 pages.
- `Mobile-Process-Flows.pdf` — 32 pages, including WhatsApp key intake, ten-layout routing, derived payload registration and report generation.
- `WhatsApp-Decryption-Test-Cases.pdf` — 11 pages; original .crypt plus CRYPT5/7/8/9/10/11/12/14/15, matching material, modern authentication, legacy integrity limits, artifact/RAG/report flow and executable positive/negative cases.
- `Vulnerability-Scanner-Process-Flows.pdf` — 28 pages, including the Laptop OpenVAS and separate central adapter paths.

- `Aetheris-Scanner-Service-Implementation-Guide-Updated.pdf` — 25 pages; all 52 service families plus IP forwarding, policy/audit, native-feed limitations and report flow.
- `Aetheris-Service-Coverage-List.csv` — complete source-ordered service list.

`Vulnerability-Scanner-Process-Flows.odt` provides editable text/tables and embedded diagrams. The PDF is the visually inspected fixed-layout reference. A native ODT application was not available for rendering acceptance.

To regenerate, install `requirements.txt` into a suitable Python environment and run `python build_flows.py`. The script consumes `disk.json`, `mobile.json`, `scanner.json`, `service_guide.json` and `whatsapp.json`, uses the bundled licensed fonts, and writes to `flow-deliverables` beside this directory. `update_whatsapp_release9.py` is the source update for the new mobile/keyed-recovery diagrams. All diagrams are exact vector geometry in the PDFs. JSON node positions, descriptions and transitions are the editable diagram source.

A completed processing/scan status is distinct from proven source or target coverage. Actual live Windows/Docker/Greenbone, phone and GPU checks remain target-host acceptance work. Encrypted WhatsApp backups need matching key material; unsupported other encryption routes are explicitly external.

Release 7 adds the private WhatsApp key-to-Intake flow and retires Observe/Performance/Repair huddles. Captured classic 158-byte key files derive bytes 126–157 as 64 hexadecimal characters; full files and SHA-256 provenance are retained.
