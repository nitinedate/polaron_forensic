# Aetheris Central Project - Scanner Validation

Package: rag_new2_UPDATED_v1.2.6

Included scanner updates:
- Internal/external target reachability fix (TCP connection-refused is reachable, not unreachable)
- Durable edge scan-result evidence and completed-job recovery
- Scan assessment accounting for assessed/skipped targets
- Scanner network identity and portable/persistent/remote role handling
- Scan Details verification fields: Assessed, Skipped, Assessment, Clean eligible
- Verification notice removed from generated vulnerability report
- Scanner configuration and test documentation under docs/scanner

Validation performed:
- Python compile: PASS
- Focused Central scanner/evidence/report tests: 25 passed

Live .env, agent tokens, recovery credentials, recovery snapshots, caches, diagnostics and frontend node_modules are intentionally excluded.
