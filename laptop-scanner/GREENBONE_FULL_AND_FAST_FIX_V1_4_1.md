# Aetheris Laptop Scanner v1.4.1 - Greenbone `Full and fast` feed readiness fix

## Symptom

The scanner-agent successfully reaches the central Aetheris server (`heartbeat` and `logs` return HTTP 200), but logs repeat:

```text
Local OpenVAS not ready: Scan config not found: Full and fast. Available configs: none.
```

This means central connectivity and scanner-agent authentication are already working. The local `gvmd` database has not yet materialized the feed-backed scan configuration.

## Why it happens

Greenbone scan configurations are feed-backed data objects. `Full and fast` is only imported after:

1. VT/NVT data is present and loaded by `ospd-openvas` / `gvmd`.
2. A Greenbone user is configured as the **Feed Import Owner**.
3. gvmd imports/rebuilds its feed-backed data objects.

The Greenbone container socket being healthy is therefore not sufficient to declare the laptop scan-ready.

## v1.4.1 changes

- Adds `Repair-Greenbone-Feed.cmd` and `scripts/Repair-Greenbone-Feed-v1.4.1.ps1`.
- The repair never deletes Docker volumes.
- Verifies VT and GVMD data-object feed files exist.
- Configures the configured `GVM_USERNAME` as Feed Import Owner.
- Runs `gvmd --rebuild-gvmd-data=all`.
- Waits for the real GMP readiness check (`OpenVAS scanner + Full and fast`).
- If still incomplete, performs one safe `ospd-openvas`/`gvmd` reload and rebuild cycle.
- `Start-Laptop.cmd` now automatically runs this repair when `Full and fast` is missing unless `AUTO_REPAIR_GREENBONE=false`.
- The compose `gvmd` service now receives `GVM_USERNAME` / `GVM_PASSWORD`, keeping the Greenbone bootstrap user aligned with scanner-agent GMP credentials on new installs.

## One-click repair on an existing laptop

From the scanner directory:

```powershell
cd D:\laptop-scanner
.\Repair-Greenbone-Feed.cmd
```

Expected final output:

```text
READY scanner=<uuid> config=daba56c8-73ec-11df-a475-002264764cea name=Full and fast
REPAIR COMPLETE: Full and fast is available.
```

Then verify:

```powershell
docker compose exec -T scanner-agent python /app/check_greenbone_ready.py
```

## First-install timing

The initial Greenbone feed load can take several minutes and, on slower disks/CPUs, substantially longer. The repair intentionally keeps the scanner-agent heartbeat online while refusing vulnerability scan jobs until the required configuration exists.

Do not use `docker compose down -v` to solve this condition. Deleting volumes forces the feed/database initialization to start again.
