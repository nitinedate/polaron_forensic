# Aetheris Laptop Scanner v1.4.3 - Greenbone Docker Argument Forwarding Fix

## Symptom

`Repair-Greenbone-Feed.cmd` reaches `Ensuring Greenbone feed and manager services are running`, then prints the top-level `docker` help instead of running `docker compose up ...`.

## Root cause

The PowerShell helper functions declared parameters named `$Args`. `$Args` is an automatic PowerShell variable containing unbound arguments. Using it as the native-command splat caused `docker.exe` to be invoked without the intended argument array.

## Fix

- `Run-Docker([string[]]$ArgumentList, ...)`
- `Compose([string[]]$ComposeArguments, ...)`
- all internal calls use `-ArgumentList` / `-ComposeArguments`
- Compose always receives `--project-directory <scanner-root>` and `-f <compose-file>`
- repair performs a fast preflight with `docker info`, `docker compose version`, and `docker compose ... config --services`
- required Greenbone services are checked before any repair/rebuild action
- no Docker volume is deleted

## Validate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Greenbone-Repair-Install-v1.4.3.ps1 -Root "D:\laptop-scanner"
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Greenbone-Docker-Forwarding-v1.4.3.ps1 -Root "D:\laptop-scanner"
```

Then run:

```powershell
.\Repair-Greenbone-Feed.cmd
```
