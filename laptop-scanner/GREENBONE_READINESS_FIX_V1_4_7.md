# Aetheris Laptop Scanner v1.4.7 - Greenbone readiness fix

This build treats the Greenbone service socket and the Greenbone vulnerability-test feed as separate readiness gates.

Changes:

- Removed `USER`/`PASSWORD` environment injection from the official `gvmd` container. The official container creates `admin/admin` by default; Aetheris sets the Feed Import Owner explicitly instead of triggering duplicate user creation.
- OSPd readiness now fails closed until gvmd can positively see the NVT inventory. A live Unix socket alone is not considered scan-ready.
- `Full and fast` is checked only after the NVT inventory is available.
- The repair flow does not restart `ospd-openvas` while the initial VT load is active. Repeated restarts can extend first-start initialization.
- The agent heartbeat includes a human-readable readiness reason so the central server can distinguish `online` from `scan ready`.
- Startup treats exit code 10 as `feed still loading`, not a fatal scanner failure. Existing queued jobs remain untouched and are claimed automatically after readiness.
