# Windows Docker volume startup fix

This update fixes the reported Windows PowerShell failure at
`move-processing-data-to-backup.ps1` while inspecting the optional
`aetheris-forensic_minio_data` volume. Docker's expected "no such volume"
message is captured with its exit code instead of stopping on stderr.

Fresh installations prepare the host backup directories and continue when old
MinIO, Ollama or Hugging Face volumes are absent. Existing PostgreSQL and
pgAdmin volumes are reused; missing ones are created. Daemon, permission and
creation errors still fail with their actual reason.

All native Docker calls in the migration use the existing capture helper.
Legacy-volume copying uses a separate staging directory, promotes it only on
success, and marks it ready afterwards. A failed copy leaves the source volume
intact and the destination unready; the next run copies again. Existing populated
backup folders are retained. Busy cleanup volumes produce a warning rather than
aborting a completed migration. Helper-image downloads occur only when a real
legacy volume needs copying and a suitable image is missing.

## Apply to the existing installation

Extract `polaron-docker-volume-probe-fix.zip` into `E:\polaron-forensic`, merging
its `scripts` and `tests` folders. Replace the three supplied scripts together.
The package does not contain `.env`, host settings, evidence or database data.
The complete updated project is `polaron-docker-startup-fixed.zip`.

Rerun the same selected launcher. For the local profile:

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_local.cmd
```

Nitin and production use their respective existing launchers. Application
compilation remains per launch; dependency caching remains enabled. This fix
does not require `-RefreshDependencies`.

## Verification

- 20 volume-probe checks pass, including simulated Windows PowerShell error
  records, existing/missing volumes, successful stderr, failed creation and
  preservation of terminating failures with a stale zero exit code.
- Eight offline native-command migration scenarios pass: fresh installation,
  idempotent relaunch, daemon failure, legacy copy, failed-copy retry, busy
  cleanup, populated backups and image-list failure. Seven main cases plus one
  retry scenario are recorded; idempotence is checked within the fresh case.
- 32 first-launch file checks, 31 existing startup checks and four PowerShell
  parser checks pass. Python test sources compile.

These checks run under PowerShell 7.4.13 on Linux with simulated error records
and a fake native Docker executable. Native Windows PowerShell 5.1 and Docker
Desktop deployment were not available for live acceptance.

Runnable checks on the Windows host:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows_docker_volume_checks.ps1
python .\tests\test_windows_backup_migration.py
```
