# Aetheris Laptop Scanner v1.4.5 — Final complete package

This package is intended to be extracted directly as `D:\laptop-scanner`. It includes all scanner-agent source, Docker Compose, Greenbone/OpenVAS services, startup/repair scripts, `.env`, `.env.example`, an empty writable `scanner-agent/.agent-token`, and a bootstrap `.lan-fingerprint`.

## Production defaults

- `CENTRAL_API_URL=https://122.179.140.167`
- `TENANT_SLUG=a`
- `VERIFY_TLS=true`
- `SCANNER_ROLE=portable`
- `AGENT_VERSION=1.4.5`
- Greenbone target: `Full and fast`
- Target throughput profile: 15–18 IP/hour when target/network/feed/hardware permit.

## Important security behavior

The package contains **no emailed access token and no bound agent token**. `Start-Laptop.cmd` prompts for a fresh emailed access token, performs login/bind through the Linux Docker/OpenSSL bootstrap, writes the returned scanner token to `scanner-agent/.agent-token`, and stores the scanner ID in `.env`.

If `.env` is deleted, v1.4.5 automatically recreates it from `.env.example` instead of aborting.

## Install

1. Stop the old scanner stack without deleting volumes: `docker compose stop` from the old folder.
2. Rename the old `D:\laptop-scanner` to a backup folder.
3. Extract this package so the final path is exactly `D:\laptop-scanner`.
4. Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Final-Install-v1.4.5.ps1 -Root D:\laptop-scanner`.
5. Run `.\Test-Docker-TLS-v1.4.0.ps1`.
6. Run `.\Start-Laptop.cmd` and paste a **fresh** emailed access token.

Do not use `docker compose down -v`; it deletes Greenbone volumes/feed state.
