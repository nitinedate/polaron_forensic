Aetheris Dynamic Drive v4.1 Hotfix
=================================

Purpose
-------
Fixes deployment stopping at:
  HostDrive agent installation failed.

Root cause in v4
----------------
Task Scheduler setup/start was treated as a mandatory deployment step. On some
Windows configurations a ScheduledTasks cmdlet or Start-ScheduledTask can fail
because of Task Scheduler policy, account resolution, elevation/session details,
or endpoint security. That caused deploy-dynamic-drive-v4.ps1 to abort before it
reached the actual Docker/WSL exact-path recovery.

Changes
-------
1. Every Task Scheduler operation is now failure-contained.
2. The AtLogOn trigger no longer binds to $env:USERNAME, avoiding account-name
   resolution issues with Microsoft/AzureAD/domain/elevated shells.
3. If the scheduled task cannot be started, the installer automatically uses:
     - Startup-folder persistence, and
     - a hidden watcher process for the current session.
4. A one-shot refresh failure is no longer treated as an installation failure;
   exact-path WSL recovery runs later in the deployment.
5. deploy-dynamic-drive-v4.ps1 no longer aborts merely because watcher
   installation returned a non-zero exit code. It directly ensures localhost
   helper health and proceeds to the drive fix.
6. No PostgreSQL/Redis/MinIO/application Docker data volumes are removed.

Install
-------
Extract this hotfix over F:\rag_new2, replacing the two scripts, then run:

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-dynamic-drive-v4.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"

Expected progression
--------------------
The deployment must pass the HostDrive watcher stage and print:
  HostDrive helper is healthy on http://127.0.0.1:9876/health

Then it rebuilds the frontend and enters:
  === Verifying exact selected evidence path ===

If Docker direct G: sharing is stale, the v4 WSL/DrvFS recovery is then allowed
to run. The final success condition remains:
  PASS: G:\Ex.1 Darshan SSD 256

Validation performed
--------------------
- Existing dynamic-drive/backend regression suite: 25 passed.
- Static assertions verify the deployment no longer throws on watcher install
  failure and the installer always provides Task Scheduler/process/startup
  fallback behavior.
