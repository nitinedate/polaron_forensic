# Windows Docker startup — first-launch configuration fix

Use the launchers from the existing project root. They compile the application
on every launch and retain Docker's dependency cache.

| Launcher | Website | Certificates | Public ports |
| --- | --- | --- | --- |
| `start_docker_local.cmd` | `http://localhost:3000/` and `http://localhost:3001/` | None required for local HTTP | None; gateway binds to loopback |
| `start_docker_nitin.cmd` | `https://future-softtech.co.in/` and `https://122.179.140.167/` by default | Separate trusted domain and IP certificates | TCP 80 and 443 |
| `start_docker_prod.cmd` | `https://122.179.141.248/` by default | Trusted IP certificate; no domain required | TCP 80 and 443 |

Both public addresses are editable defaults, not automatic detection of your
ISP address. Set the actual public static IP for each Windows machine.

## Install and launch

1. Merge the updated project or startup patch into your existing project.
   Preserve `.env`, evidence, backup directories, database volumes and scanner
   tokens. Run this deployment after active extraction/scan jobs finish.
2. Start Docker Desktop in **Linux container mode**. Docker Compose **2.24.4+
   with Buildx/BuildKit** is required. Existing NVIDIA/WSL requirements for the
   product's GPU services still apply.
3. Launching any profile creates a missing root `.env` from `.env.example`,
   with fresh JWT and shared client-token signing secrets. All product stacks
   use this same root file. Existing `.env` values are preserved exactly.
   Missing `script_docker/start_docker.settings.json` is also created from its
   example. SMTP credentials and other host-specific settings can be entered
   in the generated files. No pre-generated signing secret is distributed.
   `tools/host-python-requirements.txt` is now included for the Windows USB kit.
4. For public HTTPS, reserve the Windows PC's LAN address and forward router
   **TCP 80 → Windows TCP 80** and **TCP 443 → Windows TCP 443**. Allow both
   inbound ports in Windows Firewall. Running the launcher as Administrator
   creates the named firewall rules. The ISP must allow inbound public TCP 80
   for certificate validation and renewal.
5. For Nitin, the configured domain's DNS A record must point to the configured
   static IP. Any AAAA record must also reach the challenge-serving host.
   Production does not require DNS.

Run one profile from PowerShell:

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_local.cmd
```

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_nitin.cmd
```

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_prod.cmd
```

On the first public launch, enter the email address for Let's Encrypt.
The selected host settings and email are saved in
`script_docker/start_docker.settings.json`; later launches reuse them. You can
edit that automatically created file or copy `start_docker.settings.example.json` and edit its
`nitin` and `prod` settings before starting. Keep `prod.domain` empty.

To use different host settings, replace the placeholders below with your real
values. Arguments override saved settings and are saved for future launches:

```powershell
.\script_docker\start_docker_prod.cmd -PublicIP "YOUR_STATIC_PUBLIC_IP" -AcmeEmail "admin@your-company.com"
.\script_docker\start_docker_nitin.cmd -PublicIP "YOUR_STATIC_PUBLIC_IP" -Domain "your-domain.example" -AcmeEmail "admin@your-company.com"
```

`CERTBOT_EMAIL` can supply the email without a prompt. Set
`$env:AETHERIS_NO_PAUSE = "1"` before launching to suppress the final CMD pause
in automated runs. Failures propagate a nonzero exit code.

## What rebuilds and what stays cached

| Component | Every ordinary launch | Dependency changes |
| --- | --- | --- |
| Shared backend | New build ID; Python application compilation; image reused across the four API stacks | OS/Python/Torch layers rebuild when their inputs change |
| Scanner worker | Python application compilation with its own cached dependency stage | Scanner binaries and Python dependencies rebuild when their inputs change |
| Unified, Android and iOS UIs | Three fresh TypeScript/Vite builds | One shared `npm ci` layer from `package-lock.json`; npm downloads are cached |
| Database, Redis, MinIO, nginx and scanner vendor images | Existing images reused; missing images pulled | Update deliberately during maintenance |
| Certificates | Existing ACME lineages reused; Certbot renews only when due | New certificate issued for a new IP/domain or required renewal |

The first build of the updated Dockerfiles installs any missing or newly
changed dependencies. Later launches keep those layers cached. Removing Docker
images/build cache or changing requirements/lockfiles requires rebuilding them.

The shared backend is compiled once, then tagged for Android and iOS. The
launcher first verifies compatible backend context, Dockerfile and Torch
channel settings. This prevents four duplicate backend application builds.

For an explicit dependency maintenance rebuild:

```powershell
.\script_docker\start_docker_prod.cmd -RefreshDependencies
```

`-RefreshDependencies` pulls build base images and rebuilds dependency layers.
Ordinary launches never set `--no-cache` or `--pull` for application builds.
The legacy positional `cache` option now means the ordinary cached mode.
`nocache`, `no-cache` and `-NoCache` remain explicit maintenance aliases.

## HTTPS and renewal

The public profiles use pinned **Certbot v5.8.0** in Linux Docker and the
production Let's Encrypt ACME endpoint. IP issuance uses `--ip-address` and
the required `shortlived` profile. IP certificates last about six days, so
the `certbot-renewer` service checks renewal every six hours and reloads nginx
only after successful renewal. It shares nginx's PID namespace and does not
mount the Docker socket.

The first acquisition uses an HTTP-only bootstrap on TCP 80 if the current
gateway cannot already serve the ACME webroot. The bootstrap is removed before
the public gateway starts. Later acquisitions can use the live gateway without
stopping it for the HTTP challenge. A public launch briefly pauses only the
renewal sidecar to avoid concurrent Certbot locks, then recreates it with nginx.

Certificates/accounts persist in `aetheris-gateway_certbot_etc`; challenges
persist in `aetheris-gateway_certbot_www`. Existing self-signed PEM files are
preserved, but the new gateway uses separate ACME-managed certificate names.
No self-signed fallback is generated. Startup verifies certificate SANs,
private-key pairing, expiry and the HTTPS trust chain/hostname. The final trust
probe runs in Linux Docker while connecting to the Windows host, so it uses
the public IP/domain identity without disabling TLS verification. It also verifies
the gateway's proxied backend health endpoint. Windows overrides keep Docker
Desktop's native `host.docker.internal` routing.

Public HTTP redirects to the configured HTTPS identity while retaining the
HTTP-01 challenge location. Infrastructure/API ports remain loopback-bound.
For public profiles, compact Android/iOS UIs also bind to loopback; users
access mobile pages through the unified HTTPS website.

Containers/images for other projects and unrelated Windows port listeners are
left running. A TCP 80/443 conflict fails with the owner name. Reconfigure that
owner before retrying. The scripts preserve data volumes and do not prune cache.
The existing `-AutoRecoverEngine` option is opt-in for a stuck Docker Desktop
engine; ordinary launches do not restart the engine automatically.

## Diagnostics

The volume-startup follow-up is described in `DOCKER-VOLUME-PROBE-FIX.md`.
Optional absent legacy volumes are skipped through the native-command capture
helper. First-use PostgreSQL/pgAdmin volumes are created after a confirmed
missing-volume response. Other Docker errors remain failures. Legacy copies are
staged before being promoted and marked ready, allowing a failed copy to retry.

Prepare all required configuration files without requiring Docker or starting
any containers:

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_local.cmd -PrepareOnly
```

Validate the six product/shared/gateway Compose configurations and their paths
without builds, containers, public certificate requests or email prompts:

```powershell
.\script_docker\start_docker_local.cmd -ValidateOnly
.\script_docker\start_docker_nitin.cmd -ValidateOnly
.\script_docker\start_docker_prod.cmd -ValidateOnly
```

`script_docker/start_docker.required-files.json` lists 56 common startup/build
files and five additional HTTPS files. Missing templates, source files or
nginx/SQL bind-mount files are reported by name before building. Restore them
from the complete updated project. During real startup, missing Compose-resolved
runtime directories for evidence, scratch, backup, MinIO, Ollama and Hugging
Face are created. Missing static configuration files are never substituted
with empty directories. Existing evidence and database volumes are retained.

An existing empty `.env` or invalid settings JSON stops with an actionable
message rather than overwriting that file. Public forwarding/DNS hints are
only displayed for public deployment failures.

Certificate renewal logs, using the same gateway configuration as the launcher:

```powershell
docker compose --project-directory . --project-name aetheris-gateway -f services/gateway/docker-compose.yml -f deployment/windows-ip-https/docker-compose.gateway-local.yml -f deployment/windows-ip-https/docker-compose.gateway-public-https.yml logs --tail 80 certbot-renewer
```

Do not append `-k` to certificate/trust checks. If HTTP-01 fails, check router
forwarding, Windows Firewall, DNS for Nitin, and ISP inbound TCP 80 first.
Local route validation cannot prove that the ISP/router exposes the public port;
Let's Encrypt validates that externally during actual issuance.

## Validation for this release

- PowerShell 7.4.13 on Linux parser checks, 32 new first-launch file checks and
  31 existing offline startup behavior checks passed.
- Six complete first-launch scenarios passed with mocked Docker operations: local,
  production, Nitin, certificate reuse, cached mode and dependency refresh.
- Three clean installations passed prepare-only and validate-only checks:
  six configurations per profile, 18 checks using the official Compose 2.39.4
  CLI. These checks required no root `.env` or host settings at installation.
  Existing settings remained unchanged and validation created no runtime folders.
- 21 certificate/TLS tests passed, including IP/domain SANs, wrong keys,
  wrong identities, staging/self-signed/expired certificates and trust failures.
- Earlier release-8 checks: both generated nginx configurations passed nginx 1.27.5 checks. Isolated
  nginx tests served HTTP-01, proxied backend health, and validated three IP/domain TLS endpoints using
  a local test CA. These checks did not request public certificates.
- Backend, frontend and scanner application source and Docker dependency stages
  are unchanged by this file-initialization update. The prior build and forensic
  verification records remain historical; the new checks cover startup changes.

Native Windows Docker Desktop image builds, GPU services, public certificate
issuance and full container startup must still be verified on the target host.

Live Windows Docker Desktop builds/cache-hit measurements, public ACME issuance,
router reachability and a real six-hour renewal cycle remain deployment checks.
The downloaded PowerShell runtime verifies syntax/behavior on Linux; Windows
PowerShell 5.1 and Windows-specific firewall/engine calls need the actual host.

Sources checked on 6 October 2026:

- [Docker build cache invalidation](https://docs.docker.com/build/cache/invalidation/)
- [Let's Encrypt IP certificates in Certbot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)
- [Certbot user guide](https://certbot.eff.org/docs/using.html)

- [Docker Desktop host networking](https://docs.docker.com/desktop/features/networking/networking-how-tos/)
