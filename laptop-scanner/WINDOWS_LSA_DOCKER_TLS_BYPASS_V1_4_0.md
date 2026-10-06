# Aetheris Laptop Scanner v1.4.0 — Windows LSA/Schannel bypass

## Problem fixed

On some Windows laptops, both `curl.exe` and .NET TLS fail before HTTP is sent with errors such as:

- `SEC_E_INTERNAL_ERROR (0x80090304)`
- `The Local Security Authority cannot be contacted`
- `Could not create SSL/TLS secure channel`

When this happens, changing token-login code cannot fix the problem because both Windows clients ultimately use SSPI/Schannel.

## v1.4.0 architecture

The scanner already requires Docker Desktop with Linux containers, so v1.4.0 moves the control-plane bootstrap into Linux:

```text
Start-Laptop.cmd (Windows)
        |
        | starts/checks Docker only
        v
scanner-bootstrap (Linux container)
        |
        | Python httpx + OpenSSL + CA bundle
        v
Central Aetheris HTTPS
        |
        +-- /api/health
        +-- /api/auth/token-login
        +-- /api/scanners/bind-client-token
        +-- /api/scanner-agent/heartbeat
        |
        v
Windows writes .env + scanner-agent/.agent-token
        |
        v
Normal scanner-agent container starts
```

Windows Schannel/SSPI is no longer used for the Aetheris server authentication path.

## Security

- The emailed access token is read interactively on Windows and passed to the helper over STDIN, not as a command-line argument.
- The helper does not log the token.
- Redirects are resolved using `/api/health` before the token is requested.
- Token-bearing requests do not auto-follow redirects.
- `VERIFY_TLS=true` remains the production default.
- If the certificate does not match the configured IP/hostname, the helper reports the certificate subject/SAN and refuses authentication.

## Diagnostic

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Docker-TLS-v1.4.0.ps1
```

A successful result includes:

```text
[OK] Docker Linux engine is ready.
[OK] TLS=TLSv1.2 ...
[OK] HTTP 200
Canonical: https://<server>
Transport: docker-httpx-openssl
[OK] Windows Schannel/LSA is no longer on the scanner authentication path.
```

If certificate verification fails, use the DNS name shown under `DNS SAN` in `CENTRAL_API_URL` and keep `VERIFY_TLS=true`.
