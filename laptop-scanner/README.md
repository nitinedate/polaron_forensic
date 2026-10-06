# v1.4.6 final token runtime fix

The scanner-agent token is now shared through a directory bind: `scanner-agent/runtime` -> `/run/aetheris-agent`. The active token file is `/run/aetheris-agent/agent-token`. Startup automatically removes only an old scanner-agent container that still uses the legacy `/app/.agent-token` file bind, preserving all Greenbone containers and named volumes.

# Aetheris Laptop Scanner v1.4.5 Final

## Important: Windows LSA/Schannel bypass

v1.4.0 no longer uses Windows `curl.exe`, .NET `HttpClient`, or `SslStream` for central-server authentication. `Start-Laptop.cmd` now performs the HTTPS preflight, emailed-token login, scanner binding, and initial heartbeat inside a Linux Docker helper using Python `httpx` + OpenSSL. This fixes laptops where Windows SSPI/Schannel reports `The Local Security Authority cannot be contacted` even though TCP 443 is reachable.

Run this first:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Docker-TLS-v1.4.0.ps1
```

If it passes, run `Start-Laptop.cmd`. If it reports a certificate hostname mismatch, set `CENTRAL_API_URL` to the HTTPS DNS name printed under the certificate DNS SAN. Keep `VERIFY_TLS=true` for production.

See `WINDOWS_LSA_DOCKER_TLS_BYPASS_V1_4_0.md` for the complete flow.

# Aetheris site scanner (Persistent Edge appliance or Portable laptop)

Deploy this folder on a **Windows laptop** (Portable Assessment) or an **always-on box left on the customer LAN** (Persistent Edge). Register the matching role in **Service 3 (Vulnerabilities) → Scanners**. The agent talks **only** to the vuln API (`/health` role `vuln-api`). It does not use the forensic or mobile-extraction stacks.

```text
Browser / central UI
        |
        v
https://122.179.140.167:443
        |
        | Nginx /api/* -> central api:8080
        v
Central API  <--- outbound HTTPS poll / upload ---  Scanner Agent (this laptop)
                                                       |
                                                  Local OpenVAS
                                                       |
                                                  Client LAN targets
```

## Prerequisites (laptop)

1. Windows 10/11
2. Docker Desktop installed (WSL2 backend)
3. 8 GB+ RAM free; laptop plugged in
4. Laptop connected to the network that can reach the authorized scan targets
5. Central HTTPS API reachable from the laptop:

```powershell
.\Test-Windows-TLS-v1.3.7.ps1
```

Expected response contains `"status":"ok"`, `"service":"aetheris"`, and `"role":"vuln-api"` (legacy `"central-api"` is still accepted). Local split: `http://host.docker.internal:3003/api/health`.

## One-time setup

1. On any Aetheris login page, request an **access token** for a firm admin that can manage scanners (`scan:policy_manage`).
   The same token is emailed once and works on Forensic, Mobile extract, and this laptop. Start-Laptop asks for that token and binds it as `AGENT_TOKEN`.

2. The final package already includes `.env`. If it is ever missing, v1.4.5 automatically recreates it from `.env.example`. Production defaults are:

```env
CENTRAL_API_URL=https://122.179.140.167
TENANT_SLUG=a
AGENT_TOKEN=replace-me
VERIFY_TLS=true
# persistent_edge for an always-on site box; portable for a roaming laptop
SCANNER_ROLE=portable
```

Important: `CENTRAL_API_URL` is the **site root**, not `/api`. The agent automatically calls `/api/scanner-agent/...`. The client also tolerates a manually entered trailing `/api` and normalizes it.

3. Double-click **`Start-Laptop.cmd`**. Paste the **access token from the login email**. The laptop links only after that token is accepted.

The startup script first validates `https://122.179.140.167/api/health`, asks for a fresh emailed token, binds the returned scanner agent token, starts Docker Desktop when necessary, and then starts Local OpenVAS + the scanner agent. Do not store the emailed access token in `.env`.

First Greenbone/OpenVAS startup downloads images and feeds and can take a long time.

## Why port 8080 is not discovered anymore

The hardened central deployment binds FastAPI as `127.0.0.1:8080` and exposes the application through Nginx on TCP 443. Therefore another laptop should use:

```text
https://122.179.140.167
```

not:

```text
http://<central-lan-ip>:8080
```

The old `CENTRAL_API_URL=AUTO` + `CENTRAL_API_PORT=8080` LAN discovery is retained only as an explicit legacy fallback for deployments that intentionally expose 8080 on the LAN. Do **not** expose 8080 merely to make discovery work.

## Daily use

**Persistent Edge:** leave the appliance on the customer LAN. Set `SCANNER_ROLE=persistent_edge` in `.env` to match the scanner role in the UI. There is no roam abort; do not move the box between sites while a job is running.

**Portable Assessment:** stay on the original LAN until the job completes. `Start-Laptop.cmd` writes `.lan-fingerprint` from the Windows default gateway. If the laptop moves to another network mid-scan, the agent stops OpenVAS and fails the job — it does **not** scan the new network under the same job. Resume the same job after you return.

1. Join the client/target Wi-Fi or Ethernet.
2. Confirm the central API if needed:

```powershell
.\Test-Windows-TLS-v1.3.7.ps1
```

3. Double-click **`Start-Laptop.cmd`** and paste the **access token from the login email**. The laptop uses the same token as the three web products.
4. On the central UI, launch a scan, select this edge scanner, enter the authorized client target IPs, and launch.

Target IPs are entered in the **central browser UI**, not on the laptop.

## Useful commands

```powershell
cd <this-folder>
docker compose ps
docker compose logs -f scanner-agent
docker compose logs --tail=100 gvmd ospd-openvas
```

To stop services without deleting containers or volumes:

```powershell
docker compose stop
```

## Troubleshooting

If startup says the central API is unreachable, test:

```powershell
.\Test-Windows-TLS-v1.3.7.ps1
Test-NetConnection 122.179.140.167 -Port 443
```

If the HTTPS URL works in a browser but not from this scanner laptop, check the laptop's proxy/firewall/DNS/network route and, when both machines are on the same LAN, the router's NAT loopback/hairpin-NAT support.

If the token is rejected with HTTP 401, create or rotate the `edge_agent` scanner token in the central UI and update `AGENT_TOKEN` in `.env`.

If OpenVAS logs `Unable to check signature /var/lib/openvas/plugins/sha256sums.asc`, recreate `openvasd` so it mounts the NASL feed volume (`gvm_vt_data`). The hourly warning is openvasd checking plugins even in `service_notus` mode; it is not itself a laptop LAN-move failure. `neither api-key nor mTLS configured` is expected on the internal Docker network.

## Notes

- No inbound firewall rule to the laptop is required for central communication; the agent initiates outbound HTTPS.
- First OpenVAS feed sync may take 30-90+ minutes.
- Do not run two edge jobs against the same host at once.
- Only scan systems and networks you are authorized to assess.

## v1.3.5 throughput profile — 15–18 IPs/hour

The portable scanner keeps **one Greenbone task per IP** so a slow or failed host cannot block its peers. The default scheduler is deliberately sized for a stable 15–18 completed IPs/hour rather than the earlier aggressive 10-task fan-out.

- 4-core host: up to 4 concurrent IP tasks.
- 5–8 cores: up to 5 concurrent IP tasks (about 15 IP/hour when an average host takes 20 minutes).
- 9+ cores: up to 6 concurrent IP tasks (about 18 IP/hour at the same 20-minute average).
- Thermal/RAM pressure reduces **new admissions only**. Existing Greenbone tasks are not killed.

The fast profile now defaults to `PORT_PROFILE=fast`, `GVM_OPTIMIZE_TEST=yes`, `GVM_MAX_HOSTS=1`, and `GVM_MAX_CHECKS=8`. Before Greenbone starts an IP, the agent probes the same fast service-port range used by the central scanner. If ports answer, only those ports are supplied to OpenVAS. If none answer, the **full fast candidate range is retained**; the IP is not dropped. `SKIP_UNREACHABLE_TARGETS=false` is therefore the safe default.

Important tuning variables:

```env
SCAN_SLO_MIN_HOSTS_PER_HOUR=15
SCAN_SLO_HOSTS_PER_HOUR=18
SCAN_EXPECTED_HOST_MINUTES=20
SCAN_IP_PARALLELISM=auto
SCAN_IP_MAX_PARALLELISM=6
PORT_PROFILE=fast
PORT_DISCOVERY_ENABLED=true
GVM_MAX_HOSTS=1
GVM_MAX_CHECKS=8
GVM_OPTIMIZE_TEST=yes
SKIP_UNREACHABLE_TARGETS=false
```

Actual throughput still depends on open services, target responsiveness, firewalls, Greenbone feed state, laptop CPU/RAM/thermals, and network latency. The scheduler logs both the target range and the projected rate at startup.

Per-IP audit logs remain under `./logs/ip/<job-id>/<ip>.jsonl`. A failed IP releases only its own slot and the next waiting IP starts immediately.


## v1.3.7: Windows Schannel / LSA TLS startup fix

Windows inbox `curl.exe` uses Schannel. On some Windows systems it can fail before any HTTP request is sent with `SEC_E_INTERNAL_ERROR (0x80090304) - The Local Security Authority cannot be contacted`. v1.3.7 removes `curl.exe` from the authentication/binding path and uses `.NET HttpClient` with automatic client-certificate selection disabled. Redirect discovery still happens before the emailed token is requested, and secret-bearing POSTs do not auto-follow redirects.

Diagnostic:

```powershell
.\Test-Windows-TLS-v1.3.7.ps1
```

Expected startup line:

```text
[INFO] Central reachable at https://... (HTTP 200, transport=dotnet-httpclient).
```

If the diagnostic still reports a certificate failure, use the HTTPS DNS name or IP address actually present in the server certificate and keep `VERIFY_TLS=true`. If it still reports `SEC_E_INTERNAL_ERROR`, reboot Windows and verify `CryptSvc` and `KeyIso` are running; that indicates a machine-wide Windows TLS problem rather than an Aetheris API error.

## v1.3.6: HTTP 308 / HTTP-to-HTTPS startup fix

If `Start-Laptop.cmd` reports the central as reachable with `HTTP 308` and then fails `POST /api/auth/token-login` with `HTTP 308`, the configured `CENTRAL_API_URL` is pointing at an HTTP endpoint that the gateway redirects to HTTPS.

v1.3.6 resolves the redirect **before** asking for or sending the emailed access token. The resolver performs a no-secret GET to `/api/health`, follows up to five HTTP/HTTPS redirects, determines the final canonical API base URL, and persists it back to `.env` as `CENTRAL_API_URL`. Token login, scanner binding, heartbeat, job polling, progress, and result upload then all use that canonical endpoint.

Expected startup output:

```text
[OK] Central redirect resolved: http://server -> https://server
[INFO] Central reachable at https://server (HTTP 200). Asking for the emailed access token.
[INFO] Signing in with the emailed access token (...).
[OK] Token login accepted. Binding this laptop to the same access token.
```

To inspect the redirect manually without sending any token:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Show-Central-Redirect-v1.3.7.ps1
```

Keep `VERIFY_TLS=true` for production. If HTTPS uses a certificate issued to a DNS hostname, configure `CENTRAL_API_URL` with that hostname instead of the raw IP address.

## v1.4.2 Greenbone repair path fix

If an older `Repair-Greenbone-Feed.cmd` fails with `Resolve-Path : Illegal characters in path` and shows a root such as `D:\laptop-scanner"`, apply the v1.4.2 hotfix. The wrapper now strips the `%~dp0` trailing slash and the PowerShell script also normalizes the root defensively.

## v1.4.3 Greenbone Docker argument fix
If Greenbone repair prints the top-level Docker CLI help, install v1.4.3. It removes the PowerShell `$Args` automatic-variable collision and validates `docker compose config --services` before repair. See `GREENBONE_DOCKER_ARGUMENT_FIX_V1_4_3.md`.

## v1.4.4 token-path recovery

If token binding succeeds but Windows reports access denied for `scanner-agent/.agent-token`, run `Repair-Agent-Token-Path-v1.4.4.ps1`. v1.4.4 also prevents Docker Compose from recreating that host path as a directory.


## v1.5.1: Full TCP + UDP coverage metadata for central Nessus severity

The current production default is `PORT_PROFILE=full`, so OpenVAS receives TCP `1-65535`. High-value UDP ports are included with `UDP_PROFILE=priority`; set `UDP_PROFILE=full` only when exhaustive UDP coverage is required and the longer runtime is acceptable. The older v1.3.5 fast-profile section above remains historical documentation and can still be selected explicitly with `PORT_PROFILE=fast`.

Laptop findings now preserve explicit `cvss_v2`, `cvss_v3`, and `cvss_v4` values independently when Greenbone provides them. The central server remains authoritative for final Nessus-compatible severity and Risk Number.

Focused validation after rebuilding the scanner image:

```powershell
docker compose exec -T scanner-agent python -m pytest -q /app/tests/test_nessus_compat_v151.py
```
