# Aetheris Laptop Scanner v1.4.7 Final

v1.4.7 adds a fail-closed Greenbone readiness gate on top of the v1.4.6 TLS/token-runtime fixes.

- A live gvmd/OSPd socket is **not** treated as scan-ready.
- The agent waits for a trustworthy NVT inventory before checking `Full and fast`.
- While the initial VT feed is loading, the agent heartbeats `openvas_ready=false` and does not claim new jobs.
- The safe repair does not restart `ospd-openvas` during initial VT loading.
- Removed custom `USER`/`PASSWORD` injection from the official `gvmd` container.
- Existing queued jobs are preserved and become claimable automatically when readiness passes.
