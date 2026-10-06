# Quiet dependency waits — release 14

Pending agents remain in the progress/stage list but do not dispatch work or create repair issues until their prerequisites permit it. The serial pipeline still schedules only the first unfinished stage; a failed earlier stage cannot be bypassed.

Supervisor recommendations with action `wait`, `waiting`, `pending` or `blocked` now return a waiting status without publishing a task, writing a log or creating a recovery issue. progressAgent remains the single coordinator that checks readiness and handles real failures.

Informational/debug rows matching `[agent_id] wait— blocked: Waiting for ...` are no longer written to the pipeline log. Existing matching rows are excluded by the shared read predicate used by job logs, job log exports and unified Disk/Mobile logs. Existing database rows are not deleted. Genuine warning/error messages, active stage progress, completion, thermal pauses and evidence text remain visible. The filter is deliberately narrow; arbitrary text containing “waiting” is not hidden.

## Apply on the Windows host

Extract `polaron-quiet-agent-waits-fix.zip` into your current project root, replacing the supplied files. For the most recent reported root:

```powershell
Set-Location E:\projects\GIT\polaron2
.\script_docker\start_docker_local.cmd
```

Use your normal nitin/prod launcher instead if applicable. If installed under `E:\polaron-forensic`, use that directory instead. Refresh the log console after restarting the services; old informational wait rows will no longer appear.

## Verification

37 targeted waiting-log/retired-huddle tests passed, plus four existing serial stage-order/dispatch checks (37 unrelated serial tests deselected). Tests exercise waiting recommendations without DB/task/log calls, active dispatch, preservation of warning/error/evidence/progress rows, single and batch logging, and log-read filter construction. Python 3.11 grammar validation passes; runtime tests used Python 3.12/Linux. Live Windows/Celery/PostgreSQL/UI acceptance remains pending. No SQL migration or log deletion is needed.

All earlier SMTP, examiner-kit, Docker volume/cache, scanner, mobile/disk extraction and PDF files remain unchanged in this release except the named supervisor/logging modules and release documentation. Prior test results are historical, not rerun claims.
