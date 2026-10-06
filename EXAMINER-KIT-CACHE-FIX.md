# Windows examiner-kit pip cache fix — release 13

The reported `Permission denied` error names a wheel in `%LOCALAPPDATA%\pip\cache`, not a file in the project virtual environment. The exact cause (ACL, file lock or endpoint protection) is not established. The installer now passes `--no-cache-dir` to both pip upgrade and host-python requirements installation, avoiding reads/writes in that cache. No cache deletion, permission changes or administrator elevation are needed for this cache workaround.

This change applies only to the Windows host USB kit. Docker dependency caching remains enabled. An already working examiner kit skips pip installation as before. A new/rebuilt kit may download/build dependencies again. Network access and write permission to the project/temporary folder remain necessary.

The installer checks venv creation, pip upgrade and requirements exit codes individually. Healthy native stderr does not abort Windows PowerShell; genuine failures stop setup with their step name. The optional pywin32 postinstall can warn, but the existing final pymobiledevice3/win32security import check still gates successful setup. Failed Python probes restore the caller's error preference.

## Apply

Extract `polaron-examiner-kit-cache-fix.zip` into your actual project root, replacing `scripts\ensure-examiner-kit.ps1`. For the reported installation:

```powershell
Set-Location E:\projects\GIT\polaron2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\ensure-examiner-kit.ps1
if ($LASTEXITCODE -ne 0) { throw 'Examiner kit setup failed; inspect output above' }
.\script_docker\start_docker_local.cmd
```

Use your usual nitin/prod launcher instead if applicable. The normal launcher also invokes the examiner kit, so you can rerun it directly after applying the patch. Existing `.env` and settings are not part of this download. Do not delete or alter the user-wide pip cache.

## Checks

```powershell
Set-Location E:\projects\GIT\polaron2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows_examiner_kit_checks.ps1 -PythonExe .\tools\host-python\Scripts\python.exe
```

13 checks passed on PowerShell 7.4.13/Linux: cache-denied interpreter simulation with actual production pip calls, healthy stderr, pip upgrade failure, requirements failure, paths with spaces, error-preference restoration, real native stderr/exit status, and missing executable. Both supplied PowerShell files parse successfully. Native Windows PowerShell 5.1, live pip installation of Windows/mobile dependencies and USB/phone checks remain pending on the target host. No full product/SMTP/phone/GPU rerun was claimed for this script-only change.
