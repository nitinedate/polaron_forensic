# Aetheris Dynamic Drive Fix v4.4

## Root cause fixed

Docker Desktop on Windows can expose an external/removable drive such as `G:` as an empty bind mount even though Windows Explorer and PowerShell can read the disk. The older fallback mounted `G:` with DrvFs inside a normal WSL distro and then tried to use that path as though it were in Docker Desktop's daemon namespace. Docker Desktop isolates `docker-desktop` from normal WSL distributions, so that handoff can still be invisible to the Docker daemon.

v4.4 changes the fallback architecture:

1. Try normal Windows/Docker Desktop bind sharing first.
2. If it is empty/stale, find a WSL2 user distro that has Docker Desktop WSL Integration enabled.
3. From that same distro, try `/mnt/<drive>`.
4. If needed, mount the Windows drive with DrvFs at `/mnt/aetheris-host-drives/<drive>`.
5. Run the Docker probe from that same integrated WSL distro.
6. When the probe succeeds, run `docker compose` from the same WSL distro using a WSL-specific dynamic-drive override.
7. Recreate only `api`, `worker-disk`, `worker-mobile`, and `worker-report`.
8. Verify the exact selected path in all four containers before allowing the forensic pipeline to continue.

No evidence bytes are copied. Container evidence mounts remain read-only.

## One-time prerequisite for fallback mode

Docker Desktop must use the WSL 2 engine and at least one normal WSL2 distribution (for example Ubuntu) must have Docker Desktop WSL Integration enabled. In Docker Desktop: Settings -> Resources -> WSL Integration.

## Apply and test

Extract the hotfix into the project root and overwrite existing files. Then run PowerShell as Administrator:

```powershell
cd F:\rag_new2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\validate-dynamic-drive-v4.4.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
```

Success must end with the exact path readable in `api`, `worker-disk`, `worker-mobile`, and `worker-report`.

Do not run `docker compose down -v`.
