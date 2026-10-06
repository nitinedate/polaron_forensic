# Public HTTPS for Aetheris (gateway architecture)

## Goal

Browse and run laptop scanner against:

```text
https://122.179.141.248
```

on TCP **80** (ACME + redirect) and **443** (TLS), forwarded to this Windows host at **192.168.1.16**.

```text
Internet → 122.179.141.248:443
           │  router DNAT
           ▼
        192.168.1.16:443  (Docker aetheris-gateway)
           │
           ├─ UI (SPA)
           ├─ /api/vuln|scanner-agent → host:8082 (vuln)
           └─ /api/*                  → host:8083 (forensic) / 8081 / 8084 by header
```

## One-time router / ISP

On the Airtel router (or firewall):

| WAN | Protocol | LAN destination |
|-----|----------|-----------------|
| 122.179.141.248:80 | TCP | 192.168.1.16:80 |
| 122.179.141.248:443 | TCP | 192.168.1.16:443 |

Confirm the server NIC has `192.168.1.16`. Disable or avoid double-NAT / CGNAT if Let's Encrypt HTTP-01 fails from outside.

## Prerequisites

1. Docker Desktop running
2. Product stacks up (`aetheris-forensic`, `aetheris-vuln`, …) so backends listen on 8083 / 8082 / …
3. Gateway image available (`aetheris-gateway`)
4. PowerShell **as Administrator**

## Run (trusted Let's Encrypt IP cert)

```powershell
cd E:\projects\GIT\polaron

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 `
  -Email you@yourfirm.com `
  -ForceRecreate
```

Optional staging first:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 `
  -Email you@yourfirm.com -Staging
```

## Run (self-signed — works without public ACME)

Browsers will warn; laptop agent needs `VERIFY_TLS=false` or trust the cert.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-public-https.ps1 -SelfSigned -ForceRecreate
```

## Renew later

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deployment\windows-ip-https\renew-gateway-ip-cert.ps1
```

Schedule that weekly via Task Scheduler if using Let's Encrypt short-lived IP certs.

## Laptop scanner `.env`

```env
CENTRAL_API_URL=https://122.179.141.248
TENANT_SLUG=platform
AGENT_TOKEN=<emailed access token>
VERIFY_TLS=true
SCANNER_ROLE=portable
```

## Files

| File | Role |
|------|------|
| `scripts/setup-public-https.ps1` | Full setup (firewall, cert, gateway up) |
| `deployment/windows-ip-https/docker-compose.gateway-public-https.yml` | Bind 80/443 + cert volumes |
| `deployment/windows-ip-https/nginx.gateway.https.conf` | TLS + same routing as local gateway |
| `deployment/windows-ip-https/bootstrap-gateway-ip-cert.ps1` | Thin wrapper around setup |
| `deployment/windows-ip-https/renew-gateway-ip-cert.ps1` | Renew + nginx reload |

Local UI remains at `http://192.168.1.16:3001` / `http://localhost:3001`.
