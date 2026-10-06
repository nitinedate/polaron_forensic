# Docker startup required-files fix

The reported `env file E:\polaron-forensic\.env not found` failure is fixed in
the local, Nitin and production launchers. Startup now initializes configuration
before calling Docker Compose. It creates `.env` and
`script_docker/start_docker.settings.json` only when missing, preserving existing
files. New signing secrets are generated on the host and shared by all products.

The complete project includes the startup scripts, Compose files, Dockerfiles,
dependency manifests, nginx/ACME includes, database configuration and Windows
USB-kit requirements. Missing static dependencies fail with their file names.
Missing runtime storage folders are created from resolved Compose paths.

Extract the complete updated project into `E:\polaron-forensic`, merging with
the existing project. Keep existing `.env`, host settings, evidence, backup
folders and Docker volumes. The startup patch is for an already complete
installation; use the complete project if application source is missing.

Run one selected profile:

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_local.cmd
```

Or select `.\script_docker\start_docker_nitin.cmd` for domain plus IP HTTPS,
or `.\script_docker\start_docker_prod.cmd` for IP-only HTTPS. Configure the
actual public IP/domain in `script_docker/start_docker.settings.json`; public
profiles request an ACME email on first use unless supplied with `-AcmeEmail`.
Local mode serves `http://localhost:3000` without certificates.

Optional checks, from the same directory:

```powershell
.\script_docker\start_docker_local.cmd -PrepareOnly
.\script_docker\start_docker_local.cmd -ValidateOnly
.\script_docker\start_docker_nitin.cmd -ValidateOnly
.\script_docker\start_docker_prod.cmd -ValidateOnly
```

`-PrepareOnly` checks required files and initializes missing configuration without
Docker. `-ValidateOnly` validates Compose and paths without starting services or
requesting certificates. Ordinary launches rebuild application layers with a
fresh build ID and retain dependency cache. `-RefreshDependencies` remains the
explicit dependency-maintenance option.

Verification: 32 new file checks, 31 existing startup checks, six mocked complete
launcher scenarios, 18 official Compose configuration checks across three clean
profiles, and 21 TLS tests passed. These are Linux PowerShell/Compose and offline
checks; a Windows Docker Desktop deployment was not available here. The prior
WhatsApp recovery, Disk/Mobile pipeline and Laptop Scanner source are preserved.

More details: `script_docker/README.md`. Runnable behavior checks:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows_docker_file_checks.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows_docker_startup_checks.ps1
```
