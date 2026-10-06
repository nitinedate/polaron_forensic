@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo ============================================================
echo Aetheris Laptop Scanner - GMP / Greenbone Repair v1.0.5
echo ============================================================
echo Non-destructive mode:
echo   - NO docker compose down
echo   - NO container removal or recreation
echo   - NO volume deletion
echo   - NO prune / remove-orphans
echo.
if not exist "docker-compose.yml" (
  echo [ERROR] Run this CMD from E:\rag_new2\laptop-scanner
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker Desktop engine is not running.
  exit /b 1
)
for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%I"
set "BACKUP=%CD%\backups\scanner-agent-%TS%"
set "WORK=%TEMP%\aetheris-agent-fix-%TS%"
mkdir "%BACKUP%" >nul 2>&1
mkdir "%WORK%" >nul 2>&1

echo [1/9] Locate existing scanner-agent container
set "CID="
for /f "delims=" %%C in ('docker compose ps -q scanner-agent 2^>nul') do if not defined CID set "CID=%%C"
if not defined CID for /f "delims=" %%C in ('docker ps --filter "name=scanner-agent" --format "{{.ID}}" 2^>nul') do if not defined CID set "CID=%%C"
if not defined CID (
  echo [ERROR] Existing scanner-agent container not found.
  echo This repair intentionally will not create/recreate a container.
  exit /b 2
)
echo [OK] Container: %CID%

echo [2/9] Back up current host and container agent files
if exist "scanner-agent\agent\gmp_local.py" copy /y "scanner-agent\agent\gmp_local.py" "%BACKUP%\gmp_local.py.host.bak" >nul
if exist "scanner-agent\agent\main.py" copy /y "scanner-agent\agent\main.py" "%BACKUP%\main.py.host.bak" >nul
if exist "scanner-agent\check_greenbone_ready.py" copy /y "scanner-agent\check_greenbone_ready.py" "%BACKUP%\check_greenbone_ready.py.host.bak" >nul
docker cp "%CID%:/app/agent/gmp_local.py" "%BACKUP%\gmp_local.py.container.bak" >nul 2>&1
docker cp "%CID%:/app/agent/main.py" "%BACKUP%\main.py.container.bak" >nul 2>&1
echo [OK] Backup: %BACKUP%

echo [3/9] Materialize corrected scanner-agent code
>"%WORK%\gmp_local.py.b64" echo IiIiTWluaW1hbCBsb2NhbCBHcmVlbmJvbmUgR01QIGNsaWVudCBmb3IgdGhlIGxhcHRvcCBh
>>"%WORK%\gmp_local.py.b64" echo Z2VudC4iIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBs
>>"%WORK%\gmp_local.py.b64" echo b2dnaW5nCmltcG9ydCBvcwppbXBvcnQgdGltZQpmcm9tIGNvbnRleHRsaWIgaW1wb3J0IGNv
>>"%WORK%\gmp_local.py.b64" echo bnRleHRtYW5hZ2VyCmZyb20gdHlwaW5nIGltcG9ydCBBbnksIEl0ZXJhdG9yCmZyb20gdXJs
>>"%WORK%\gmp_local.py.b64" echo bGliLnBhcnNlIGltcG9ydCB1cmxwYXJzZQoKbG9nID0gbG9nZ2luZy5nZXRMb2dnZXIoInNj
>>"%WORK%\gmp_local.py.b64" echo YW5uZXJfYWdlbnQuZ21wIikKCkZVTExfQU5EX0ZBU1RfSUQgPSAiZGFiYTU2YzgtNzNlYy0x
>>"%WORK%\gmp_local.py.b64" echo MWRmLWE0NzUtMDAyMjY0NzY0Y2VhIgoKRkFTVF9QT1JUUyA9ICgKICAgICJUOjIxLTIzLDI1
>>"%WORK%\gmp_local.py.b64" echo LDUzLDgwLDgxLDg4LDExMCwxMTEsMTM1LDEzOSwxNDMsMzg5LDQ0Myw0NDUsNDY1LDU4Nyw2
>>"%WORK%\gmp_local.py.b64" echo MzEsOTkzLDk5NSwiCiAgICAiMTQzMywxNTIxLDE3MjMsMjA0OSwzMDAwLDMzMDYsMzM4OSw1
>>"%WORK%\gmp_local.py.b64" echo NDMyLDU2NzIsNTkwMCw1OTg1LDYzNzksNjQ0Myw4MDAwLDgwMDgsIgogICAgIjgwODAsODA4
>>"%WORK%\gmp_local.py.b64" echo MSw4NDQzLDg4ODgsOTAwMCw5NDE4LDI3MDE3IgopCgoKZGVmIF9pbXBvcnRzKCk6CiAgICBm
>>"%WORK%\gmp_local.py.b64" echo cm9tIGd2bS5jb25uZWN0aW9ucyBpbXBvcnQgVExTQ29ubmVjdGlvbiwgVW5peFNvY2tldENv
>>"%WORK%\gmp_local.py.b64" echo bm5lY3Rpb24KCiAgICB0cnk6CiAgICAgICAgZnJvbSBndm0ucHJvdG9jb2xzLmdtcCBpbXBv
>>"%WORK%\gmp_local.py.b64" echo cnQgR01QCiAgICBleGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgZnJvbSBndm0ucHJvdG9j
>>"%WORK%\gmp_local.py.b64" echo b2xzLmdtcCBpbXBvcnQgR21wIGFzIEdNUCAgIyB0eXBlOiBpZ25vcmUKCiAgICAjIHB5dGhv
>>"%WORK%\gmp_local.py.b64" echo bi1ndm0gcmV0dXJucyBVVEYtOCBYTUwgc3RyaW5ncyBieSBkZWZhdWx0LiAgVGhpcyBhZ2Vu
>>"%WORK%\gmp_local.py.b64" echo dCB1c2VzCiAgICAjIEVsZW1lbnQveHBhdGggaGVscGVycyB0aHJvdWdob3V0LCBzbyByZXF1
>>"%WORK%\gmp_local.py.b64" echo ZXN0IGFuIGV0cmVlIHJlc3BvbnNlIHRyYW5zZm9ybQogICAgIyBleHBsaWNpdGx5LiAgUHJl
>>"%WORK%\gmp_local.py.b64" echo ZmVyIHRoZSBjb21tYW5kLWNoZWNraW5nIHRyYW5zZm9ybSBiZWNhdXNlIGl0IGFsc28gdHVy
>>"%WORK%\gmp_local.py.b64" echo bnMKICAgICMgbm9uLXN1Y2Nlc3MgR01QIHJlc3BvbnNlcyBpbnRvIFB5dGhvbiBleGNlcHRp
>>"%WORK%\gmp_local.py.b64" echo b25zIGluc3RlYWQgb2Ygc2lsZW50bHkKICAgICMgcmV0dXJuaW5nIGFuIGVycm9yIFhNTCBk
>>"%WORK%\gmp_local.py.b64" echo b2N1bWVudC4KICAgIHRyeToKICAgICAgICBmcm9tIGd2bS50cmFuc2Zvcm1zIGltcG9ydCBF
>>"%WORK%\gmp_local.py.b64" echo dHJlZUNoZWNrQ29tbWFuZFRyYW5zZm9ybQoKICAgICAgICB0cmFuc2Zvcm0gPSBFdHJlZUNo
>>"%WORK%\gmp_local.py.b64" echo ZWNrQ29tbWFuZFRyYW5zZm9ybSgpCiAgICBleGNlcHQgSW1wb3J0RXJyb3I6ICAjIGNvbXBh
>>"%WORK%\gmp_local.py.b64" echo dGliaWxpdHkgZmFsbGJhY2sgZm9yIG9sZGVyIHN1cHBvcnRlZCBidWlsZHMKICAgICAgICBm
>>"%WORK%\gmp_local.py.b64" echo cm9tIGd2bS50cmFuc2Zvcm1zIGltcG9ydCBFdHJlZVRyYW5zZm9ybQoKICAgICAgICB0cmFu
>>"%WORK%\gmp_local.py.b64" echo c2Zvcm0gPSBFdHJlZVRyYW5zZm9ybSgpCgogICAgcmV0dXJuIFRMU0Nvbm5lY3Rpb24sIFVu
>>"%WORK%\gmp_local.py.b64" echo aXhTb2NrZXRDb25uZWN0aW9uLCBHTVAsIHRyYW5zZm9ybQoKCkBjb250ZXh0bWFuYWdlcgpk
>>"%WORK%\gmp_local.py.b64" echo ZWYgX3Nlc3Npb24oCiAgICAqLAogICAgc29ja2V0X3BhdGg6IHN0ciB8IE5vbmUsCiAgICBo
>>"%WORK%\gmp_local.py.b64" echo b3N0OiBzdHIsCiAgICBwb3J0OiBpbnQsCiAgICB1c2VybmFtZTogc3RyLAogICAgcGFzc3dv
>>"%WORK%\gmp_local.py.b64" echo cmQ6IHN0ciwKICAgIHZlcmlmeTogYm9vbCA9IEZhbHNlLAopIC0+IEl0ZXJhdG9yW0FueV06
>>"%WORK%\gmp_local.py.b64" echo CiAgICBUTFNDb25uZWN0aW9uLCBVbml4U29ja2V0Q29ubmVjdGlvbiwgR01QLCB0cmFuc2Zv
>>"%WORK%\gmp_local.py.b64" echo cm0gPSBfaW1wb3J0cygpCiAgICBpZiBzb2NrZXRfcGF0aDoKICAgICAgICBjb25uID0gVW5p
>>"%WORK%\gmp_local.py.b64" echo eFNvY2tldENvbm5lY3Rpb24ocGF0aD1zb2NrZXRfcGF0aCkKICAgIGVsc2U6CiAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo Y29ubiA9IFRMU0Nvbm5lY3Rpb24oaG9zdG5hbWU9aG9zdCwgcG9ydD1wb3J0LCB0aW1lb3V0
>>"%WORK%\gmp_local.py.b64" echo PTYwLCB2ZXJpZnk9dmVyaWZ5KQoKICAgICMgcHl0aG9uLWd2bSBtYW5hZ2VzIGNvbm5lY3Rp
>>"%WORK%\gmp_local.py.b64" echo b24gbGlmZWN5Y2xlIGF0IHRoZSBwcm90b2NvbCBsYXllci4KICAgICMgVW5peFNvY2tldENv
>>"%WORK%\gmp_local.py.b64" echo bm5lY3Rpb24gaXRzZWxmIGlzIG5vdCBhIGNvbnRleHQgbWFuYWdlciBpbiBjdXJyZW50IDI2
>>"%WORK%\gmp_local.py.b64" echo LngKICAgICMgcmVsZWFzZXMsIHNvIGB3aXRoIGNvbm46YCByYWlzZXMgVHlwZUVycm9yLiBH
>>"%WORK%\gmp_local.py.b64" echo TVAuX19lbnRlcl9fIGNvbm5lY3RzIGFuZAogICAgIyBHTVAuX19leGl0X18gZGlzY29ubmVj
>>"%WORK%\gmp_local.py.b64" echo dHMgdGhlIHN1cHBsaWVkIGNvbm5lY3Rpb24uCiAgICB3aXRoIEdNUChjb25uZWN0aW9uPWNv
>>"%WORK%\gmp_local.py.b64" echo bm4sIHRyYW5zZm9ybT10cmFuc2Zvcm0pIGFzIGdtcDoKICAgICAgICBnbXAuYXV0aGVudGlj
>>"%WORK%\gmp_local.py.b64" echo YXRlKHVzZXJuYW1lLCBwYXNzd29yZCkKICAgICAgICB5aWVsZCBnbXAKCgpkZWYgX2ZpbmRf
>>"%WORK%\gmp_local.py.b64" echo Y29uZmlnX2lkKGdtcDogQW55LCBuYW1lOiBzdHIgPSAiRnVsbCBhbmQgZmFzdCIpIC0+IHN0
>>"%WORK%\gmp_local.py.b64" echo cjoKICAgICIiIlJldHVybiB0aGUgcmVxdWVzdGVkIHNjYW4gY29uZmlnLCB0b2xlcmF0aW5n
>>"%WORK%\gmp_local.py.b64" echo IHRoZSBjYW5vbmljYWwgZmVlZCBVVUlELgoKICAgIEdyZWVuYm9uZSBzaGlwcyBGdWxsIGFu
>>"%WORK%\gmp_local.py.b64" echo ZCBmYXN0IHRocm91Z2ggdGhlIEdWTUQgZGF0YSBmZWVkLiAgRHVyaW5nIHRoZQogICAgaW5p
>>"%WORK%\gmp_local.py.b64" echo dGlhbCBmZWVkIGltcG9ydCB0aGUgY29uZmlnIG1heSB0ZW1wb3JhcmlseSBiZSBhYnNlbnQg
>>"%WORK%\gmp_local.py.b64" echo ZXZlbiB0aG91Z2ggZ3ZtZAogICAgYW5kIHRoZSBPU1Agc2Nhbm5lciBhcmUgcmVhY2hhYmxl
>>"%WORK%\gmp_local.py.b64" echo LgogICAgIiIiCiAgICByZXNwID0gZ21wLmdldF9zY2FuX2NvbmZpZ3MoKQogICAgYXZhaWxh
>>"%WORK%\gmp_local.py.b64" echo YmxlOiBsaXN0W3N0cl0gPSBbXQogICAgd2FudGVkID0gbmFtZS5zdHJpcCgpLmNhc2Vmb2xk
>>"%WORK%\gmp_local.py.b64" echo KCkKICAgIGZvciBub2RlIGluIHJlc3AueHBhdGgoImNvbmZpZyIpOgogICAgICAgIGNpZCA9
>>"%WORK%\gmp_local.py.b64" echo IChub2RlLmdldCgiaWQiKSBvciAiIikuc3RyaXAoKQogICAgICAgIGNvbmZpZ19uYW1lID0g
>>"%WORK%\gmp_local.py.b64" echo KG5vZGUuZmluZHRleHQoIm5hbWUiKSBvciAiIikuc3RyaXAoKQogICAgICAgIGlmIGNvbmZp
>>"%WORK%\gmp_local.py.b64" echo Z19uYW1lOgogICAgICAgICAgICBhdmFpbGFibGUuYXBwZW5kKGNvbmZpZ19uYW1lKQogICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgIGlmIGNpZCBhbmQgKGNvbmZpZ19uYW1lLmNhc2Vmb2xkKCkgPT0gd2FudGVkIG9yIGNp
>>"%WORK%\gmp_local.py.b64" echo ZCA9PSBGVUxMX0FORF9GQVNUX0lEKToKICAgICAgICAgICAgcmV0dXJuIGNpZAogICAgc3Vt
>>"%WORK%\gmp_local.py.b64" echo bWFyeSA9ICIsICIuam9pbihhdmFpbGFibGVbOjhdKSBpZiBhdmFpbGFibGUgZWxzZSAibm9u
>>"%WORK%\gmp_local.py.b64" echo ZSIKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigKICAgICAgICBmIlNjYW4gY29uZmlnIG5vdCBm
>>"%WORK%\gmp_local.py.b64" echo b3VuZDoge25hbWV9LiBBdmFpbGFibGUgY29uZmlnczoge3N1bW1hcnl9LiAiCiAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo IkdyZWVuYm9uZSBmZWVkIGRhdGEgaXMgc3RpbGwgbG9hZGluZyBvciB0aGUgRmVlZCBJbXBv
>>"%WORK%\gmp_local.py.b64" echo cnQgT3duZXIvZGF0YS1vYmplY3QgcmVidWlsZCBpcyBtaXNzaW5nLiIKICAgICkKCgpkZWYg
>>"%WORK%\gmp_local.py.b64" echo X2ZpbmRfc2Nhbm5lcl9pZChnbXA6IEFueSkgLT4gc3RyOgogICAgcmVzcCA9IGdtcC5nZXRf
>>"%WORK%\gmp_local.py.b64" echo c2Nhbm5lcnMoKQogICAgZm9yIG5vZGUgaW4gcmVzcC54cGF0aCgic2Nhbm5lciIpOgogICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgIG4gPSAobm9kZS5maW5kdGV4dCgibmFtZSIpIG9yICIiKS5sb3dlcigpCiAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo aWYgIm9wZW52YXMiIGluIG4gb3IgImRlZmF1bHQiIGluIG46CiAgICAgICAgICAgIHNpZCA9
>>"%WORK%\gmp_local.py.b64" echo IG5vZGUuZ2V0KCJpZCIpCiAgICAgICAgICAgIGlmIHNpZDoKICAgICAgICAgICAgICAgIHJl
>>"%WORK%\gmp_local.py.b64" echo dHVybiBzdHIoc2lkKQogICAgbm9kZSA9IHJlc3AuZmluZCgic2Nhbm5lciIpCiAgICBpZiBu
>>"%WORK%\gmp_local.py.b64" echo b2RlIGlzIG5vdCBOb25lIGFuZCBub2RlLmdldCgiaWQiKToKICAgICAgICByZXR1cm4gc3Ry
>>"%WORK%\gmp_local.py.b64" echo KG5vZGUuZ2V0KCJpZCIpKQogICAgcmFpc2UgUnVudGltZUVycm9yKCJObyBPcGVuVkFTIHNj
>>"%WORK%\gmp_local.py.b64" echo YW5uZXIgZm91bmQgaW4gR3JlZW5ib25lIikKCgpkZWYgX3Rhc2tfc3RhdHVzKGdtcDogQW55
>>"%WORK%\gmp_local.py.b64" echo LCB0YXNrX2lkOiBzdHIpIC0+IHR1cGxlW3N0ciwgZmxvYXQsIEFueV06CiAgICByZXNwID0g
>>"%WORK%\gmp_local.py.b64" echo Z21wLmdldF90YXNrKHRhc2tfaWQpCiAgICB0YXNrID0gcmVzcC5maW5kKCJ0YXNrIikKICAg
>>"%WORK%\gmp_local.py.b64" echo IGlmIHRhc2sgaXMgTm9uZToKICAgICAgICByZXR1cm4gInVua25vd24iLCAwLjAsIE5vbmUK
>>"%WORK%\gmp_local.py.b64" echo ICAgIHN0YXR1cyA9ICh0YXNrLmZpbmR0ZXh0KCJzdGF0dXMiKSBvciAidW5rbm93biIpLnN0
>>"%WORK%\gmp_local.py.b64" echo cmlwKCkubG93ZXIoKQogICAgdHJ5OgogICAgICAgIHByb2dyZXNzID0gZmxvYXQodGFzay5m
>>"%WORK%\gmp_local.py.b64" echo aW5kdGV4dCgicHJvZ3Jlc3MiKSBvciAwKQogICAgZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVl
>>"%WORK%\gmp_local.py.b64" echo RXJyb3IpOgogICAgICAgIHByb2dyZXNzID0gMC4wCiAgICByZXR1cm4gc3RhdHVzLCBwcm9n
>>"%WORK%\gmp_local.py.b64" echo cmVzcywgdGFzawoKCmRlZiBfcmVzdWx0cyhnbXA6IEFueSwgdGFza19pZDogc3RyKSAtPiBs
>>"%WORK%\gmp_local.py.b64" echo aXN0W2RpY3Rbc3RyLCBBbnldXToKICAgIF8sIF8sIHRhc2sgPSBfdGFza19zdGF0dXMoZ21w
>>"%WORK%\gmp_local.py.b64" echo LCB0YXNrX2lkKQogICAgcmVwb3J0X2lkID0gTm9uZQogICAgaWYgdGFzayBpcyBub3QgTm9u
>>"%WORK%\gmp_local.py.b64" echo ZToKICAgICAgICBmb3IgeHBhdGggaW4gKCJjdXJyZW50X3JlcG9ydC9yZXBvcnQiLCAibGFz
>>"%WORK%\gmp_local.py.b64" echo dF9yZXBvcnQvcmVwb3J0Iik6CiAgICAgICAgICAgIGVsZW0gPSB0YXNrLmZpbmQoeHBhdGgp
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgICAgIGlmIGVsZW0gaXMgbm90IE5vbmUgYW5kIGVsZW0uZ2V0KCJpZCIpOgog
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgICAgcmVwb3J0X2lkID0gZWxlbS5nZXQoImlkIikKICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgIGJyZWFrCiAgICBpZiBub3QgcmVwb3J0X2lkOgogICAgICAgIHJldHVybiBbXQogICAg
>>"%WORK%\gmp_local.py.b64" echo cmVwb3J0ID0gZ21wLmdldF9yZXBvcnQoCiAgICAgICAgcmVwb3J0X2lkPXJlcG9ydF9pZCwK
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICBmaWx0ZXJfc3RyaW5nPSJyb3dzPS0xIiwKICAgICAgICBpZ25vcmVfcGFnaW5h
>>"%WORK%\gmp_local.py.b64" echo dGlvbj1UcnVlLAogICAgICAgIGRldGFpbHM9VHJ1ZSwKICAgICkKICAgIHZ1bG5zOiBsaXN0
>>"%WORK%\gmp_local.py.b64" echo W2RpY3Rbc3RyLCBBbnldXSA9IFtdCiAgICBmb3IgcmVzIGluIHJlcG9ydC54cGF0aCgiLi8v
>>"%WORK%\gmp_local.py.b64" echo cmVzdWx0cy9yZXN1bHQiKToKICAgICAgICBudnQgPSByZXMuZmluZCgibnZ0IikKICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICBpZiBudnQgaXMgTm9uZToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBvaWQgPSBu
>>"%WORK%\gmp_local.py.b64" echo dnQuZ2V0KCJvaWQiKSBvciAiIgogICAgICAgIG5hbWUgPSBudnQuZmluZHRleHQoIm5hbWUi
>>"%WORK%\gmp_local.py.b64" echo KSBvciByZXMuZmluZHRleHQoIm5hbWUiKSBvciAiIgogICAgICAgIGZhbWlseSA9IG52dC5m
>>"%WORK%\gmp_local.py.b64" echo aW5kdGV4dCgiZmFtaWx5Iikgb3IgIiIKICAgICAgICB0cnk6CiAgICAgICAgICAgIGN2c3Mg
>>"%WORK%\gmp_local.py.b64" echo PSBmbG9hdChudnQuZmluZHRleHQoImN2c3NfYmFzZSIpIG9yIHJlcy5maW5kdGV4dCgic2V2
>>"%WORK%\gmp_local.py.b64" echo ZXJpdHkiKSBvciAwKQogICAgICAgIGV4Y2VwdCAoVHlwZUVycm9yLCBWYWx1ZUVycm9yKToK
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgY3ZzcyA9IDAuMAogICAgICAgIGN2ZSA9IE5vbmUKICAgICAgICBmb3Ig
>>"%WORK%\gmp_local.py.b64" echo cmVmIGluIG52dC54cGF0aCgicmVmcy9yZWYiKToKICAgICAgICAgICAgaWYgKHJlZi5nZXQo
>>"%WORK%\gmp_local.py.b64" echo InR5cGUiKSBvciAiIikubG93ZXIoKSA9PSAiY3ZlIjoKICAgICAgICAgICAgICAgIGN2ZSA9
>>"%WORK%\gmp_local.py.b64" echo IHJlZi5nZXQoImlkIikKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgcG9ydF9yYXcg
>>"%WORK%\gmp_local.py.b64" echo PSByZXMuZmluZHRleHQoInBvcnQiKSBvciAiIgogICAgICAgIHBvcnQgPSBOb25lCiAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgcHJvdG9jb2wgPSBOb25lCiAgICAgICAgaWYgIi8iIGluIHBvcnRfcmF3OgogICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICBwb3J0X3BhcnQsIHByb3RvY29sID0gcG9ydF9yYXcuc3BsaXQoIi8iLCAxKQogICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBwb3J0ID0gaW50KHBvcnRfcGFydCkKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgICAgICAgICBwb3J0ID0gTm9u
>>"%WORK%\gmp_local.py.b64" echo ZQogICAgICAgIHRocmVhdCA9IChyZXMuZmluZHRleHQoInRocmVhdCIpIG9yICIiKS5sb3dl
>>"%WORK%\gmp_local.py.b64" echo cigpCiAgICAgICAgc2V2ZXJpdHkgPSAiaW5mbyIKICAgICAgICBpZiB0aHJlYXQgaW4geyJj
>>"%WORK%\gmp_local.py.b64" echo cml0aWNhbCIsICJoaWdoIiwgIm1lZGl1bSIsICJsb3ciLCAiaW5mbyJ9OgogICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICBzZXZlcml0eSA9ICJpbmZvIiBpZiB0aHJlYXQgPT0gImxvZyIgZWxzZSB0aHJlYXQKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICBlbGlmIGN2c3MgPj0gOToKICAgICAgICAgICAgc2V2ZXJpdHkgPSAiY3JpdGljYWwi
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgZWxpZiBjdnNzID49IDc6CiAgICAgICAgICAgIHNldmVyaXR5ID0gImhpZ2gi
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgZWxpZiBjdnNzID49IDQ6CiAgICAgICAgICAgIHNldmVyaXR5ID0gIm1lZGl1
>>"%WORK%\gmp_local.py.b64" echo bSIKICAgICAgICBlbGlmIGN2c3MgPiAwOgogICAgICAgICAgICBzZXZlcml0eSA9ICJsb3ci
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgdnVsbnMuYXBwZW5kKAogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAi
>>"%WORK%\gmp_local.py.b64" echo cGx1Z2luX2lkIjogb2lkLAogICAgICAgICAgICAgICAgIm52dF9vaWQiOiBvaWQsCiAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAicGx1Z2luX2ZhbWlseSI6IGZhbWlseSwKICAgICAgICAgICAgICAgICJj
>>"%WORK%\gmp_local.py.b64" echo dmUiOiBjdmUsCiAgICAgICAgICAgICAgICAic2NvcmUiOiBjdnNzLAogICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgImN2c3MiOiBjdnNzLAogICAgICAgICAgICAgICAgInNldmVyaXR5Ijogc2V2ZXJpdHks
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgICAgICAgICAicGx1Z2luX25hbWUiOiBuYW1lLAogICAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ImRlc2NyaXB0aW9uIjogcmVzLmZpbmR0ZXh0KCJkZXNjcmlwdGlvbiIpIG9yICIiLAogICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgInN5bm9wc2lzIjogbmFtZSwKICAgICAgICAgICAgICAgICJzb2x1dGlv
>>"%WORK%\gmp_local.py.b64" echo biI6ICIiLAogICAgICAgICAgICAgICAgInBvcnQiOiBwb3J0LAogICAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo InByb3RvY29sIjogcHJvdG9jb2wsCiAgICAgICAgICAgICAgICAiaG9zdCI6IHJlcy5maW5k
>>"%WORK%\gmp_local.py.b64" echo dGV4dCgiaG9zdCIpIG9yIE5vbmUsCiAgICAgICAgICAgIH0KICAgICAgICApCiAgICByZXR1
>>"%WORK%\gmp_local.py.b64" echo cm4gdnVsbnMKCgpjbGFzcyBMb2NhbE9wZW5WQVM6CiAgICBkZWYgX19pbml0X18oc2VsZikg
>>"%WORK%\gmp_local.py.b64" echo LT4gTm9uZToKICAgICAgICBzZWxmLnNvY2tldF9wYXRoID0gKG9zLmVudmlyb24uZ2V0KCJH
>>"%WORK%\gmp_local.py.b64" echo Vk1fU09DS0VUX1BBVEgiKSBvciAiIikuc3RyaXAoKSBvciBOb25lCiAgICAgICAgdXJsID0g
>>"%WORK%\gmp_local.py.b64" echo KG9zLmVudmlyb24uZ2V0KCJHVk1fVVJMIikgb3IgIiIpLnN0cmlwKCkKICAgICAgICBzZWxm
>>"%WORK%\gmp_local.py.b64" echo Lmhvc3QsIHNlbGYucG9ydCA9ICIxMjcuMC4wLjEiLCA5MzkwCiAgICAgICAgaWYgdXJsIGFu
>>"%WORK%\gmp_local.py.b64" echo ZCBub3Qgc2VsZi5zb2NrZXRfcGF0aDoKICAgICAgICAgICAgaWYgIjovLyIgbm90IGluIHVy
>>"%WORK%\gmp_local.py.b64" echo bDoKICAgICAgICAgICAgICAgIHVybCA9IGYidGxzOi8ve3VybH0iCiAgICAgICAgICAgIHBh
>>"%WORK%\gmp_local.py.b64" echo cnNlZCA9IHVybHBhcnNlKHVybCkKICAgICAgICAgICAgc2VsZi5ob3N0ID0gcGFyc2VkLmhv
>>"%WORK%\gmp_local.py.b64" echo c3RuYW1lIG9yICIxMjcuMC4wLjEiCiAgICAgICAgICAgIHNlbGYucG9ydCA9IHBhcnNlZC5w
>>"%WORK%\gmp_local.py.b64" echo b3J0IG9yIDkzOTAKICAgICAgICAgICAgaWYgcGFyc2VkLnNjaGVtZSA9PSAidW5peCI6CiAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgICBzZWxmLnNvY2tldF9wYXRoID0gcGFyc2VkLnBhdGggb3IgTm9uZQog
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgIHNlbGYudXNlcm5hbWUgPSBvcy5lbnZpcm9uLmdldCgiR1ZNX1VTRVJOQU1FIikg
>>"%WORK%\gmp_local.py.b64" echo b3IgImFkbWluIgogICAgICAgIHNlbGYucGFzc3dvcmQgPSBvcy5lbnZpcm9uLmdldCgiR1ZN
>>"%WORK%\gmp_local.py.b64" echo X1BBU1NXT1JEIikgb3IgImFkbWluIgogICAgICAgIHNlbGYucG9ydF9wcm9maWxlID0gKG9z
>>"%WORK%\gmp_local.py.b64" echo LmVudmlyb24uZ2V0KCJQT1JUX1BST0ZJTEUiKSBvciAiZmFzdCIpLnN0cmlwKCkubG93ZXIo
>>"%WORK%\gmp_local.py.b64" echo KQogICAgICAgIHNlbGYucGx1Z2luc190aW1lb3V0ID0gaW50KG9zLmVudmlyb24uZ2V0KCJQ
>>"%WORK%\gmp_local.py.b64" echo TFVHSU5TX1RJTUVPVVRfU0VDIikgb3IgNjApCiAgICAgICAgc2VsZi5zY2FubmVyX3BsdWdp
>>"%WORK%\gmp_local.py.b64" echo bnNfdGltZW91dCA9IGludChvcy5lbnZpcm9uLmdldCgiU0NBTk5FUl9QTFVHSU5TX1RJTUVP
>>"%WORK%\gmp_local.py.b64" echo VVRfU0VDIikgb3IgMTIwKQogICAgICAgIHNlbGYuc2Nhbl9jb25maWdfbmFtZSA9IChvcy5l
>>"%WORK%\gmp_local.py.b64" echo bnZpcm9uLmdldCgiR1ZNX1NDQU5fQ09ORklHIikgb3IgIkZ1bGwgYW5kIGZhc3QiKS5zdHJp
>>"%WORK%\gmp_local.py.b64" echo cCgpCgogICAgZGVmIHJlYWR5KHNlbGYpIC0+IGJvb2w6CiAgICAgICAgdHJ5OgogICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICB3aXRoIF9zZXNzaW9uKAogICAgICAgICAgICAgICAgc29ja2V0X3BhdGg9c2VsZi5z
>>"%WORK%\gmp_local.py.b64" echo b2NrZXRfcGF0aCwKICAgICAgICAgICAgICAgIGhvc3Q9c2VsZi5ob3N0LAogICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgcG9ydD1zZWxmLnBvcnQsCiAgICAgICAgICAgICAgICB1c2VybmFtZT1zZWxmLnVz
>>"%WORK%\gmp_local.py.b64" echo ZXJuYW1lLAogICAgICAgICAgICAgICAgcGFzc3dvcmQ9c2VsZi5wYXNzd29yZCwKICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgKSBhcyBnbXA6CiAgICAgICAgICAgICAgICBfZmluZF9zY2FubmVyX2lkKGdtcCkK
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgICAgIF9maW5kX2NvbmZpZ19pZChnbXAsIHNlbGYuc2Nhbl9jb25maWdf
>>"%WORK%\gmp_local.py.b64" echo bmFtZSkKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgRXhjZXB0aW9u
>>"%WORK%\gmp_local.py.b64" echo IGFzIGV4YzoKICAgICAgICAgICAgIyBBIHNjYW5uZXIgc29ja2V0IGNhbiBiZSBoZWFsdGh5
>>"%WORK%\gmp_local.py.b64" echo IGJlZm9yZSBndm1kIGhhcyBpbXBvcnRlZCB0aGUKICAgICAgICAgICAgIyBmZWVkLXByb3Zp
>>"%WORK%\gmp_local.py.b64" echo ZGVkIHNjYW4gY29uZmlncy4gIFRyZWF0IHRoYXQgYXMgbm90LXJlYWR5LCBub3QgYXMgYW4K
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgIyBleGVjdXRhYmxlIHNjYW4gZmFpbHVyZS4KICAgICAgICAgICAgbG9n
>>"%WORK%\gmp_local.py.b64" echo Lndhcm5pbmcoIkxvY2FsIE9wZW5WQVMgbm90IHJlYWR5OiAlcyIsIGV4YykKICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgcmV0dXJuIEZhbHNlCgogICAgZGVmIHN0YXJ0X3NjYW4oc2VsZiwgKiwgbmFtZTogc3Ry
>>"%WORK%\gmp_local.py.b64" echo LCB0YXJnZXRzOiBsaXN0W3N0cl0pIC0+IHN0cjoKICAgICAgICBob3N0X2xpc3QgPSBbdC5z
>>"%WORK%\gmp_local.py.b64" echo dHJpcCgpIGZvciB0IGluIHRhcmdldHMgaWYgdCBhbmQgdC5zdHJpcCgpXQogICAgICAgIGlm
>>"%WORK%\gmp_local.py.b64" echo IG5vdCBob3N0X2xpc3Q6CiAgICAgICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIkF0IGxlYXN0
>>"%WORK%\gmp_local.py.b64" echo IG9uZSB0YXJnZXQgaXMgcmVxdWlyZWQiKQogICAgICAgIHBvcnRfcmFuZ2UgPSBGQVNUX1BP
>>"%WORK%\gmp_local.py.b64" echo UlRTIGlmIHNlbGYucG9ydF9wcm9maWxlICE9ICJmdWxsIiBlbHNlICJUOjEtNjU1MzUiCiAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgd2l0aCBfc2Vzc2lvbigKICAgICAgICAgICAgc29ja2V0X3BhdGg9c2VsZi5zb2Nr
>>"%WORK%\gmp_local.py.b64" echo ZXRfcGF0aCwKICAgICAgICAgICAgaG9zdD1zZWxmLmhvc3QsCiAgICAgICAgICAgIHBvcnQ9
>>"%WORK%\gmp_local.py.b64" echo c2VsZi5wb3J0LAogICAgICAgICAgICB1c2VybmFtZT1zZWxmLnVzZXJuYW1lLAogICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICBwYXNzd29yZD1zZWxmLnBhc3N3b3JkLAogICAgICAgICkgYXMgZ21wOgogICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICBjb25maWdfaWQgPSBfZmluZF9jb25maWdfaWQoZ21wLCBzZWxmLnNjYW5fY29uZmln
>>"%WORK%\gmp_local.py.b64" echo X25hbWUpCiAgICAgICAgICAgIHNjYW5uZXJfaWQgPSBfZmluZF9zY2FubmVyX2lkKGdtcCkK
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgdGFyZ2V0ID0gZ21wLmNyZWF0ZV90YXJnZXQoCiAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICBuYW1lPWYie25hbWV9LXRndC17aW50KHRpbWUudGltZSgpKX0iLAogICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgaG9zdHM9aG9zdF9saXN0LAogICAgICAgICAgICAgICAgcG9ydF9yYW5nZT1wb3J0X3Jh
>>"%WORK%\gmp_local.py.b64" echo bmdlLAogICAgICAgICAgICApCiAgICAgICAgICAgIHRhcmdldF9pZCA9IHRhcmdldC5nZXQo
>>"%WORK%\gmp_local.py.b64" echo ImlkIikKICAgICAgICAgICAgaWYgbm90IHRhcmdldF9pZDoKICAgICAgICAgICAgICAgIHJh
>>"%WORK%\gmp_local.py.b64" echo aXNlIFJ1bnRpbWVFcnJvcigiRmFpbGVkIHRvIGNyZWF0ZSBHcmVlbmJvbmUgdGFyZ2V0IikK
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgcHJlZnMgPSB7CiAgICAgICAgICAgICAgICAibWF4X2NoZWNrcyI6ICIy
>>"%WORK%\gmp_local.py.b64" echo MCIsCiAgICAgICAgICAgICAgICAibWF4X2hvc3RzIjogIjQiLAogICAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo Im9wdGltaXplX3Rlc3QiOiAieWVzIiwKICAgICAgICAgICAgICAgICJ0aG9yb3VnaF90ZXN0
>>"%WORK%\gmp_local.py.b64" echo cyI6ICJubyIsCiAgICAgICAgICAgICAgICAic2FmZV9jaGVja3MiOiAieWVzIiwKICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICJwbHVnaW5zX3RpbWVvdXQiOiBzdHIoc2VsZi5wbHVnaW5zX3RpbWVvdXQp
>>"%WORK%\gmp_local.py.b64" echo LAogICAgICAgICAgICAgICAgInNjYW5uZXJfcGx1Z2luc190aW1lb3V0Ijogc3RyKHNlbGYu
>>"%WORK%\gmp_local.py.b64" echo c2Nhbm5lcl9wbHVnaW5zX3RpbWVvdXQpLAogICAgICAgICAgICB9CiAgICAgICAgICAgIHRy
>>"%WORK%\gmp_local.py.b64" echo eToKICAgICAgICAgICAgICAgIHRhc2sgPSBnbXAuY3JlYXRlX3Rhc2soCiAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgbmFtZT1uYW1lWzoxMjhdLAogICAgICAgICAgICAgICAgICAgIGNvbmZpZ19p
>>"%WORK%\gmp_local.py.b64" echo ZD1jb25maWdfaWQsCiAgICAgICAgICAgICAgICAgICAgdGFyZ2V0X2lkPXN0cih0YXJnZXRf
>>"%WORK%\gmp_local.py.b64" echo aWQpLAogICAgICAgICAgICAgICAgICAgIHNjYW5uZXJfaWQ9c2Nhbm5lcl9pZCwKICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgICBwcmVmZXJlbmNlcz1wcmVmcywKICAgICAgICAgICAgICAgICkKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBwcmVmX2V4YzoKICAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo IGxvZy53YXJuaW5nKCJjcmVhdGVfdGFzayB3aXRoIHByZWZlcmVuY2VzIGZhaWxlZCAoJXMp
>>"%WORK%\gmp_local.py.b64" echo OyByZXRyeWluZyBiYXJlIiwgcHJlZl9leGMpCiAgICAgICAgICAgICAgICB0YXNrID0gZ21w
>>"%WORK%\gmp_local.py.b64" echo LmNyZWF0ZV90YXNrKAogICAgICAgICAgICAgICAgICAgIG5hbWU9bmFtZVs6MTI4XSwKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgICAgICAgICBjb25maWdfaWQ9Y29uZmlnX2lkLAogICAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgIHRhcmdldF9pZD1zdHIodGFyZ2V0X2lkKSwKICAgICAgICAgICAgICAgICAgICBzY2Fu
>>"%WORK%\gmp_local.py.b64" echo bmVyX2lkPXNjYW5uZXJfaWQsCiAgICAgICAgICAgICAgICApCiAgICAgICAgICAgIHRhc2tf
>>"%WORK%\gmp_local.py.b64" echo aWQgPSB0YXNrLmdldCgiaWQiKQogICAgICAgICAgICBpZiBub3QgdGFza19pZDoKICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigiRmFpbGVkIHRvIGNyZWF0ZSBHcmVlbmJv
>>"%WORK%\gmp_local.py.b64" echo bmUgdGFzayIpCiAgICAgICAgICAgIGdtcC5zdGFydF90YXNrKHN0cih0YXNrX2lkKSkKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgbG9nLmluZm8oIlN0YXJ0ZWQgbG9jYWwgT3BlblZBUyB0YXNrICVzIGhvc3Rz
>>"%WORK%\gmp_local.py.b64" echo PSVzIiwgdGFza19pZCwgaG9zdF9saXN0KQogICAgICAgICAgICByZXR1cm4gc3RyKHRhc2tf
>>"%WORK%\gmp_local.py.b64" echo aWQpCgogICAgZGVmIHBvbGwoc2VsZiwgdGFza19pZDogc3RyKSAtPiBkaWN0W3N0ciwgQW55
>>"%WORK%\gmp_local.py.b64" echo XToKICAgICAgICB3aXRoIF9zZXNzaW9uKAogICAgICAgICAgICBzb2NrZXRfcGF0aD1zZWxm
>>"%WORK%\gmp_local.py.b64" echo LnNvY2tldF9wYXRoLAogICAgICAgICAgICBob3N0PXNlbGYuaG9zdCwKICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo cG9ydD1zZWxmLnBvcnQsCiAgICAgICAgICAgIHVzZXJuYW1lPXNlbGYudXNlcm5hbWUsCiAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgIHBhc3N3b3JkPXNlbGYucGFzc3dvcmQsCiAgICAgICAgKSBhcyBnbXA6CiAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICAgICAgIHN0YXR1cywgcHJvZ3Jlc3MsIF8gPSBfdGFza19zdGF0dXMoZ21wLCB0YXNr
>>"%WORK%\gmp_local.py.b64" echo X2lkKQogICAgICAgICAgICBtYXBwZWQgPSAicnVubmluZyIKICAgICAgICAgICAgaWYgc3Rh
>>"%WORK%\gmp_local.py.b64" echo dHVzIGluIHsiZG9uZSIsICJmaW5pc2hlZCIsICJzdWNjZWVkZWQifToKICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgIG1hcHBlZCA9ICJjb21wbGV0ZWQiCiAgICAgICAgICAgIGVsaWYgc3RhdHVzIGluIHsi
>>"%WORK%\gmp_local.py.b64" echo c3RvcHBlZCIsICJpbnRlcnJ1cHRlZCJ9OgogICAgICAgICAgICAgICAgbWFwcGVkID0gInN0
>>"%WORK%\gmp_local.py.b64" echo b3BwZWQiCiAgICAgICAgICAgIGVsaWYgc3RhdHVzIGluIHsiZmFpbGVkIiwgImludGVybmFs
>>"%WORK%\gmp_local.py.b64" echo IGVycm9yIiwgImRlbGV0ZSByZXF1ZXN0ZWQifToKICAgICAgICAgICAgICAgIG1hcHBlZCA9
>>"%WORK%\gmp_local.py.b64" echo ICJmYWlsZWQiCiAgICAgICAgICAgIHZ1bG5zOiBsaXN0W2RpY3Rbc3RyLCBBbnldXSA9IFtd
>>"%WORK%\gmp_local.py.b64" echo CiAgICAgICAgICAgIGlmIG1hcHBlZCBpbiB7ImNvbXBsZXRlZCIsICJzdG9wcGVkIiwgImZh
>>"%WORK%\gmp_local.py.b64" echo aWxlZCJ9OgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIHZ1bG5z
>>"%WORK%\gmp_local.py.b64" echo ID0gX3Jlc3VsdHMoZ21wLCB0YXNrX2lkKQogICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2Vw
>>"%WORK%\gmp_local.py.b64" echo dGlvbjoKICAgICAgICAgICAgICAgICAgICBsb2cud2FybmluZygiQ291bGQgbm90IHJlYWQg
>>"%WORK%\gmp_local.py.b64" echo cmVzdWx0cyBmb3IgJXMiLCB0YXNrX2lkLCBleGNfaW5mbz1UcnVlKQogICAgICAgICAgICBy
>>"%WORK%\gmp_local.py.b64" echo ZXR1cm4geyJzdGF0dXMiOiBtYXBwZWQsICJnbXBfc3RhdHVzIjogc3RhdHVzLCAicHJvZ3Jl
>>"%WORK%\gmp_local.py.b64" echo c3MiOiBwcm9ncmVzcywgInZ1bG5lcmFiaWxpdGllcyI6IHZ1bG5zfQoKICAgIGRlZiBzdG9w
>>"%WORK%\gmp_local.py.b64" echo KHNlbGYsIHRhc2tfaWQ6IHN0cikgLT4gTm9uZToKICAgICAgICB0cnk6CiAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo IHdpdGggX3Nlc3Npb24oCiAgICAgICAgICAgICAgICBzb2NrZXRfcGF0aD1zZWxmLnNvY2tl
>>"%WORK%\gmp_local.py.b64" echo dF9wYXRoLAogICAgICAgICAgICAgICAgaG9zdD1zZWxmLmhvc3QsCiAgICAgICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICBwb3J0PXNlbGYucG9ydCwKICAgICAgICAgICAgICAgIHVzZXJuYW1lPXNlbGYudXNlcm5h
>>"%WORK%\gmp_local.py.b64" echo bWUsCiAgICAgICAgICAgICAgICBwYXNzd29yZD1zZWxmLnBhc3N3b3JkLAogICAgICAgICAg
>>"%WORK%\gmp_local.py.b64" echo ICApIGFzIGdtcDoKICAgICAgICAgICAgICAgIGdtcC5zdG9wX3Rhc2sodGFza19pZCkKICAg
>>"%WORK%\gmp_local.py.b64" echo ICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBsb2cud2FybmluZygic3RvcF90
>>"%WORK%\gmp_local.py.b64" echo YXNrIGZhaWxlZCBmb3IgJXMiLCB0YXNrX2lkLCBleGNfaW5mbz1UcnVlKQo=
certutil -f -decode "%WORK%\gmp_local.py.b64" "%WORK%\gmp_local.py" >nul
if errorlevel 1 goto :decodefail
>"%WORK%\main.py.b64" echo IiIiUG9sbCBjZW50cmFsIEFQSSBmb3IgZWRnZSBzY2FuIGpvYnMgYW5kIHJ1biB0aGVtIG9u
>>"%WORK%\main.py.b64" echo IGxvY2FsIE9wZW5WQVMuIiIiCgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25z
>>"%WORK%\main.py.b64" echo CgppbXBvcnQgbG9nZ2luZwppbXBvcnQgb3MKaW1wb3J0IHN5cwppbXBvcnQgdGltZQpmcm9t
>>"%WORK%\main.py.b64" echo IHBhdGhsaWIgaW1wb3J0IFBhdGgKZnJvbSB0eXBpbmcgaW1wb3J0IEFueQoKZnJvbSBhZ2Vu
>>"%WORK%\main.py.b64" echo dC5hcGlfY2xpZW50IGltcG9ydCBDZW50cmFsQXBpCmZyb20gYWdlbnQuZ21wX2xvY2FsIGlt
>>"%WORK%\main.py.b64" echo cG9ydCBMb2NhbE9wZW5WQVMKCmxvZ2dpbmcuYmFzaWNDb25maWcoCiAgICBsZXZlbD1sb2dn
>>"%WORK%\main.py.b64" echo aW5nLklORk8sCiAgICBmb3JtYXQ9IiUoYXNjdGltZSlzICUobGV2ZWxuYW1lKXMgJShuYW1l
>>"%WORK%\main.py.b64" echo KXMgJShtZXNzYWdlKXMiLAopCmxvZyA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCJzY2FubmVyX2Fn
>>"%WORK%\main.py.b64" echo ZW50IikKCgpkZWYgX2Vudl9ib29sKG5hbWU6IHN0ciwgZGVmYXVsdDogYm9vbCA9IFRydWUp
>>"%WORK%\main.py.b64" echo IC0+IGJvb2w6CiAgICByYXcgPSAob3MuZW52aXJvbi5nZXQobmFtZSkgb3IgIiIpLnN0cmlw
>>"%WORK%\main.py.b64" echo KCkubG93ZXIoKQogICAgaWYgbm90IHJhdzoKICAgICAgICByZXR1cm4gZGVmYXVsdAogICAg
>>"%WORK%\main.py.b64" echo cmV0dXJuIHJhdyBpbiB7IjEiLCAidHJ1ZSIsICJ5ZXMiLCAib24ifQoKCmRlZiBfcmVhZF9h
>>"%WORK%\main.py.b64" echo Z2VudF90b2tlbigpIC0+IHN0cjoKICAgICIiIlJldHVybiB0aGUgbGl2ZSBhZ2VudCB0b2tl
>>"%WORK%\main.py.b64" echo biB3aXRob3V0IHJlcXVpcmluZyBjb250YWluZXIgcmVjcmVhdGlvbi4KCiAgICBEb2NrZXIg
>>"%WORK%\main.py.b64" echo ZW52aXJvbm1lbnQgdmFyaWFibGVzIGFyZSBmaXhlZCB3aGVuIGEgY29udGFpbmVyIGlzIGNy
>>"%WORK%\main.py.b64" echo ZWF0ZWQuICBUaGUKICAgIG9wZXJhdG9yIG1heSByb3RhdGUgYW4gZWRnZS1hZ2VudCB0b2tl
>>"%WORK%\main.py.b64" echo biBsYXRlciB3aXRob3V0IGRlbGV0aW5nL3JlY3JlYXRpbmcKICAgIHRoaXMgY29udGFpbmVy
>>"%WORK%\main.py.b64" echo LCBzbyBSZXBhaXItQWdlbnQtQXV0aCBjb3BpZXMgdGhlIGFjY2VwdGVkIHRva2VuIHRvIHRo
>>"%WORK%\main.py.b64" echo aXMKICAgIHByaXZhdGUgZmlsZSBhbmQgcmVzdGFydHMgdGhlIHNhbWUgY29udGFpbmVyLgog
>>"%WORK%\main.py.b64" echo ICAgIiIiCiAgICB0b2tlbl9maWxlID0gUGF0aChvcy5lbnZpcm9uLmdldCgiQUdFTlRfVE9L
>>"%WORK%\main.py.b64" echo RU5fRklMRSIpIG9yICIvYXBwLy5hZ2VudC10b2tlbiIpCiAgICB0cnk6CiAgICAgICAgaWYg
>>"%WORK%\main.py.b64" echo dG9rZW5fZmlsZS5pc19maWxlKCk6CiAgICAgICAgICAgIHZhbHVlID0gdG9rZW5fZmlsZS5y
>>"%WORK%\main.py.b64" echo ZWFkX3RleHQoZW5jb2Rpbmc9InV0Zi04LXNpZyIpLnN0cmlwKCkKICAgICAgICAgICAgaWYg
>>"%WORK%\main.py.b64" echo dmFsdWU6CiAgICAgICAgICAgICAgICByZXR1cm4gdmFsdWUKICAgIGV4Y2VwdCBPU0Vycm9y
>>"%WORK%\main.py.b64" echo OgogICAgICAgIGxvZy53YXJuaW5nKCJVbmFibGUgdG8gcmVhZCBBR0VOVF9UT0tFTl9GSUxF
>>"%WORK%\main.py.b64" echo PSVzOyBmYWxsaW5nIGJhY2sgdG8gZW52aXJvbm1lbnQiLCB0b2tlbl9maWxlKQogICAgcmV0
>>"%WORK%\main.py.b64" echo dXJuIChvcy5lbnZpcm9uLmdldCgiQUdFTlRfVE9LRU4iKSBvciAiIikuc3RyaXAoKQoKCgpk
>>"%WORK%\main.py.b64" echo ZWYgX3JlYWRfYWdlbnRfdmVyc2lvbigpIC0+IHN0cjoKICAgICIiIlJldHVybiBhIHJ1bnRp
>>"%WORK%\main.py.b64" echo bWUtcGF0Y2hlZCB2ZXJzaW9uIHdpdGhvdXQgcmVjcmVhdGluZyB0aGUgY29udGFpbmVyLiIi
>>"%WORK%\main.py.b64" echo IgogICAgdmVyc2lvbl9maWxlID0gUGF0aChvcy5lbnZpcm9uLmdldCgiQUdFTlRfVkVSU0lP
>>"%WORK%\main.py.b64" echo Tl9GSUxFIikgb3IgIi9hcHAvLmFnZW50LXZlcnNpb24iKQogICAgdHJ5OgogICAgICAgIGlm
>>"%WORK%\main.py.b64" echo IHZlcnNpb25fZmlsZS5pc19maWxlKCk6CiAgICAgICAgICAgIHZhbHVlID0gdmVyc2lvbl9m
>>"%WORK%\main.py.b64" echo aWxlLnJlYWRfdGV4dChlbmNvZGluZz0idXRmLTgtc2lnIikuc3RyaXAoKQogICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICBpZiB2YWx1ZToKICAgICAgICAgICAgICAgIHJldHVybiB2YWx1ZQogICAgZXhjZXB0IE9T
>>"%WORK%\main.py.b64" echo RXJyb3I6CiAgICAgICAgbG9nLndhcm5pbmcoIlVuYWJsZSB0byByZWFkIEFHRU5UX1ZFUlNJ
>>"%WORK%\main.py.b64" echo T05fRklMRT0lczsgZmFsbGluZyBiYWNrIHRvIGVudmlyb25tZW50IiwgdmVyc2lvbl9maWxl
>>"%WORK%\main.py.b64" echo KQogICAgcmV0dXJuIChvcy5lbnZpcm9uLmdldCgiQUdFTlRfVkVSU0lPTiIpIG9yICIxLjAu
>>"%WORK%\main.py.b64" echo NSIpLnN0cmlwKCkgb3IgIjEuMC41IgoKZGVmIF9jZmcoKSAtPiBkaWN0W3N0ciwgQW55XToK
>>"%WORK%\main.py.b64" echo ICAgIGJhc2UgPSAob3MuZW52aXJvbi5nZXQoIkNFTlRSQUxfQVBJX1VSTCIpIG9yICIiKS5z
>>"%WORK%\main.py.b64" echo dHJpcCgpCiAgICB0ZW5hbnQgPSAob3MuZW52aXJvbi5nZXQoIlRFTkFOVF9TTFVHIikgb3Ig
>>"%WORK%\main.py.b64" echo IiIpLnN0cmlwKCkKICAgIHRva2VuID0gX3JlYWRfYWdlbnRfdG9rZW4oKQogICAgaWYgbm90
>>"%WORK%\main.py.b64" echo IGJhc2Ugb3Igbm90IHRlbmFudCBvciBub3QgdG9rZW46CiAgICAgICAgbG9nLmVycm9yKCJD
>>"%WORK%\main.py.b64" echo RU5UUkFMX0FQSV9VUkwsIFRFTkFOVF9TTFVHLCBhbmQgQUdFTlRfVE9LRU4vQUdFTlRfVE9L
>>"%WORK%\main.py.b64" echo RU5fRklMRSBhcmUgcmVxdWlyZWQiKQogICAgICAgIHN5cy5leGl0KDEpCiAgICByZXR1cm4g
>>"%WORK%\main.py.b64" echo ewogICAgICAgICJhcGkiOiBDZW50cmFsQXBpKAogICAgICAgICAgICBiYXNlX3VybD1iYXNl
>>"%WORK%\main.py.b64" echo LAogICAgICAgICAgICB0ZW5hbnQ9dGVuYW50LAogICAgICAgICAgICB0b2tlbj10b2tlbiwK
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgdmVyaWZ5X3Rscz1fZW52X2Jvb2woIlZFUklGWV9UTFMiLCBUcnVlKSwK
>>"%WORK%\main.py.b64" echo ICAgICAgICApLAogICAgICAgICJvcGVudmFzIjogTG9jYWxPcGVuVkFTKCksCiAgICAgICAg
>>"%WORK%\main.py.b64" echo InBvbGwiOiBtYXgoNSwgaW50KG9zLmVudmlyb24uZ2V0KCJQT0xMX0lOVEVSVkFMX1NFQyIp
>>"%WORK%\main.py.b64" echo IG9yIDE1KSksCiAgICAgICAgImhlYXJ0YmVhdCI6IG1heCgxNSwgaW50KG9zLmVudmlyb24u
>>"%WORK%\main.py.b64" echo Z2V0KCJIRUFSVEJFQVRfSU5URVJWQUxfU0VDIikgb3IgNjApKSwKICAgICAgICAic3RhbGxf
>>"%WORK%\main.py.b64" echo cGN0IjogZmxvYXQob3MuZW52aXJvbi5nZXQoIlNUQUxMX1BST0dSRVNTX1BDVCIpIG9yIDk1
>>"%WORK%\main.py.b64" echo KSwKICAgICAgICAic3RhbGxfc2VjIjogaW50KG9zLmVudmlyb24uZ2V0KCJTVEFMTF9TRUMi
>>"%WORK%\main.py.b64" echo KSBvciAxODApLAogICAgICAgICJ2ZXJzaW9uIjogX3JlYWRfYWdlbnRfdmVyc2lvbigpLAog
>>"%WORK%\main.py.b64" echo ICAgfQoKCmRlZiBfcnVuX2pvYihjZmc6IGRpY3Rbc3RyLCBBbnldLCBqb2I6IGRpY3Rbc3Ry
>>"%WORK%\main.py.b64" echo LCBBbnldKSAtPiBOb25lOgogICAgYXBpOiBDZW50cmFsQXBpID0gY2ZnWyJhcGkiXQogICAg
>>"%WORK%\main.py.b64" echo b3BlbnZhczogTG9jYWxPcGVuVkFTID0gY2ZnWyJvcGVudmFzIl0KICAgIGpvYl9pZCA9IHN0
>>"%WORK%\main.py.b64" echo cihqb2JbImlkIl0pCiAgICB0YXJnZXRzID0gW3RbInRhcmdldCJdIGZvciB0IGluIChqb2Iu
>>"%WORK%\main.py.b64" echo Z2V0KCJ0YXJnZXRzIikgb3IgW10pIGlmIHQuZ2V0KCJ0YXJnZXQiKV0KICAgIGlmIG5vdCB0
>>"%WORK%\main.py.b64" echo YXJnZXRzOgogICAgICAgIGFwaS5wYXRjaF9qb2Ioam9iX2lkLCB7InN0YXR1cyI6ICJmYWls
>>"%WORK%\main.py.b64" echo ZWQiLCAiZXJyb3IiOiAiTm8gdGFyZ2V0cyBpbiBqb2IifSkKICAgICAgICByZXR1cm4KCiAg
>>"%WORK%\main.py.b64" echo ICBsb2cuaW5mbygiQ2xhaW1lZCBqb2IgJXMgdGFyZ2V0cz0lcyIsIGpvYl9pZCwgdGFyZ2V0
>>"%WORK%\main.py.b64" echo cykKICAgIGFwaS5wYXRjaF9qb2Ioam9iX2lkLCB7InN0YXR1cyI6ICJydW5uaW5nIiwgInBy
>>"%WORK%\main.py.b64" echo b2dyZXNzX3BjdCI6IDUsICJtZXNzYWdlIjogIlN0YXJ0aW5nIGxvY2FsIE9wZW5WQVMifSkK
>>"%WORK%\main.py.b64" echo ICAgIHRyeToKICAgICAgICB0YXNrX2lkID0gb3BlbnZhcy5zdGFydF9zY2FuKG5hbWU9ZiJl
>>"%WORK%\main.py.b64" echo ZGdlLXtqb2JfaWRbOjhdfSIsIHRhcmdldHM9dGFyZ2V0cykKICAgIGV4Y2VwdCBFeGNlcHRp
>>"%WORK%\main.py.b64" echo b24gYXMgZXhjOgogICAgICAgIGxvZy5leGNlcHRpb24oIkZhaWxlZCB0byBzdGFydCBPcGVu
>>"%WORK%\main.py.b64" echo VkFTIGZvciBqb2IgJXMiLCBqb2JfaWQpCiAgICAgICAgYXBpLnBhdGNoX2pvYihqb2JfaWQs
>>"%WORK%\main.py.b64" echo IHsic3RhdHVzIjogImZhaWxlZCIsICJlcnJvciI6IHN0cihleGMpWzoxNTAwXX0pCiAgICAg
>>"%WORK%\main.py.b64" echo ICAgcmV0dXJuCgogICAgYXBpLnBhdGNoX2pvYigKICAgICAgICBqb2JfaWQsCiAgICAgICAg
>>"%WORK%\main.py.b64" echo ewogICAgICAgICAgICAic3RhdHVzIjogInJ1bm5pbmciLAogICAgICAgICAgICAicHJvZ3Jl
>>"%WORK%\main.py.b64" echo c3NfcGN0IjogMTAsCiAgICAgICAgICAgICJtZXNzYWdlIjogIk9wZW5WQVMgcnVubmluZyIs
>>"%WORK%\main.py.b64" echo CiAgICAgICAgICAgICJleHRlcm5hbF9zY2FuX2lkIjogdGFza19pZCwKICAgICAgICB9LAog
>>"%WORK%\main.py.b64" echo ICAgKQoKICAgIGxhc3RfcHJvZ3Jlc3MgPSAtMS4wCiAgICBsYXN0X2NoYW5nZSA9IHRpbWUu
>>"%WORK%\main.py.b64" echo bW9ub3RvbmljKCkKICAgIHBvbGwgPSBjZmdbInBvbGwiXQogICAgc3RhbGxfcGN0ID0gY2Zn
>>"%WORK%\main.py.b64" echo WyJzdGFsbF9wY3QiXQogICAgc3RhbGxfc2VjID0gY2ZnWyJzdGFsbF9zZWMiXQoKICAgIHdo
>>"%WORK%\main.py.b64" echo aWxlIFRydWU6CiAgICAgICAgdGltZS5zbGVlcChwb2xsKQogICAgICAgIGRldGFpbHMgPSBv
>>"%WORK%\main.py.b64" echo cGVudmFzLnBvbGwodGFza19pZCkKICAgICAgICBzdGF0dXMgPSBkZXRhaWxzWyJzdGF0dXMi
>>"%WORK%\main.py.b64" echo XQogICAgICAgIHByb2dyZXNzID0gZmxvYXQoZGV0YWlscy5nZXQoInByb2dyZXNzIikgb3Ig
>>"%WORK%\main.py.b64" echo MCkKICAgICAgICBpZiBwcm9ncmVzcyAhPSBsYXN0X3Byb2dyZXNzOgogICAgICAgICAgICBs
>>"%WORK%\main.py.b64" echo YXN0X3Byb2dyZXNzID0gcHJvZ3Jlc3MKICAgICAgICAgICAgbGFzdF9jaGFuZ2UgPSB0aW1l
>>"%WORK%\main.py.b64" echo Lm1vbm90b25pYygpCiAgICAgICAgYXBpLnBhdGNoX2pvYigKICAgICAgICAgICAgam9iX2lk
>>"%WORK%\main.py.b64" echo LAogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAic3RhdHVzIjogInJ1bm5pbmciLAog
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgInByb2dyZXNzX3BjdCI6IHByb2dyZXNzLAogICAgICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgIm1lc3NhZ2UiOiBmIk9wZW5WQVMge2RldGFpbHMuZ2V0KCdnbXBfc3RhdHVzJykgb3Ig
>>"%WORK%\main.py.b64" echo c3RhdHVzfSIsCiAgICAgICAgICAgICAgICAiZXh0ZXJuYWxfc2Nhbl9pZCI6IHRhc2tfaWQs
>>"%WORK%\main.py.b64" echo CiAgICAgICAgICAgIH0sCiAgICAgICAgKQoKICAgICAgICBpZiBzdGF0dXMgPT0gImNvbXBs
>>"%WORK%\main.py.b64" echo ZXRlZCI6CiAgICAgICAgICAgIGFwaS51cGxvYWRfcmVzdWx0cygKICAgICAgICAgICAgICAg
>>"%WORK%\main.py.b64" echo IGpvYl9pZCwKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAidnVsbmVy
>>"%WORK%\main.py.b64" echo YWJpbGl0aWVzIjogZGV0YWlscy5nZXQoInZ1bG5lcmFiaWxpdGllcyIpIG9yIFtdLAogICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgICJzdGF0dXMiOiAiY29tcGxldGVkIiwKICAgICAgICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAiZXh0ZXJuYWxfc2Nhbl9pZCI6IHRhc2tfaWQsCiAgICAgICAgICAgICAgICB9LAog
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICApCiAgICAgICAgICAgIGxvZy5pbmZvKCJKb2IgJXMgY29tcGxldGVkIHdp
>>"%WORK%\main.py.b64" echo dGggJWQgdnVsbnMiLCBqb2JfaWQsIGxlbihkZXRhaWxzLmdldCgidnVsbmVyYWJpbGl0aWVz
>>"%WORK%\main.py.b64" echo Iikgb3IgW10pKQogICAgICAgICAgICByZXR1cm4KCiAgICAgICAgaWYgc3RhdHVzIGluIHsi
>>"%WORK%\main.py.b64" echo ZmFpbGVkIiwgInN0b3BwZWQifToKICAgICAgICAgICAgdnVsbnMgPSBkZXRhaWxzLmdldCgi
>>"%WORK%\main.py.b64" echo dnVsbmVyYWJpbGl0aWVzIikgb3IgW10KICAgICAgICAgICAgcGFydGlhbCA9IHN0YXR1cyA9
>>"%WORK%\main.py.b64" echo PSAic3RvcHBlZCIgb3IgYm9vbCh2dWxucykKICAgICAgICAgICAgYXBpLnVwbG9hZF9yZXN1
>>"%WORK%\main.py.b64" echo bHRzKAogICAgICAgICAgICAgICAgam9iX2lkLAogICAgICAgICAgICAgICAgewogICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICJ2dWxuZXJhYmlsaXRpZXMiOiB2dWxucywKICAgICAgICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAic3RhdHVzIjogImNvbXBsZXRlZCIgaWYgdnVsbnMgZWxzZSAiZmFpbGVkIiwKICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgICAiZXh0ZXJuYWxfc2Nhbl9pZCI6IHRhc2tfaWQsCiAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgInBhcnRpYWwiOiBwYXJ0aWFsLAogICAgICAgICAgICAgICAgICAgICJw
>>"%WORK%\main.py.b64" echo YXJ0aWFsX3JlYXNvbiI6IGYidGFzayB7c3RhdHVzfSBhdCB7cHJvZ3Jlc3M6LjBmfSUiLAog
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgICAgICJlcnJvciI6IE5vbmUgaWYgdnVsbnMgZWxzZSBmIk9wZW5W
>>"%WORK%\main.py.b64" echo QVMgZW5kZWQgd2l0aCBzdGF0dXMge2RldGFpbHMuZ2V0KCdnbXBfc3RhdHVzJyl9IiwKICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICkKICAgICAgICAgICAgcmV0dXJuCgogICAg
>>"%WORK%\main.py.b64" echo ICAgIGlmICgKICAgICAgICAgICAgc3RhbGxfc2VjID4gMAogICAgICAgICAgICBhbmQgcHJv
>>"%WORK%\main.py.b64" echo Z3Jlc3MgPj0gc3RhbGxfcGN0CiAgICAgICAgICAgIGFuZCAodGltZS5tb25vdG9uaWMoKSAt
>>"%WORK%\main.py.b64" echo IGxhc3RfY2hhbmdlKSA+PSBzdGFsbF9zZWMKICAgICAgICApOgogICAgICAgICAgICBsb2cu
>>"%WORK%\main.py.b64" echo d2FybmluZygiSm9iICVzIHN0YWxsZWQgYXQgJS4wZiUlIOKAlCBzdG9wcGluZyBhbmQgaGFy
>>"%WORK%\main.py.b64" echo dmVzdGluZyIsIGpvYl9pZCwgcHJvZ3Jlc3MpCiAgICAgICAgICAgIG9wZW52YXMuc3RvcCh0
>>"%WORK%\main.py.b64" echo YXNrX2lkKQogICAgICAgICAgICB0aW1lLnNsZWVwKDMpCiAgICAgICAgICAgIGRldGFpbHMg
>>"%WORK%\main.py.b64" echo PSBvcGVudmFzLnBvbGwodGFza19pZCkKICAgICAgICAgICAgYXBpLnVwbG9hZF9yZXN1bHRz
>>"%WORK%\main.py.b64" echo KAogICAgICAgICAgICAgICAgam9iX2lkLAogICAgICAgICAgICAgICAgewogICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICJ2dWxuZXJhYmlsaXRpZXMiOiBkZXRhaWxzLmdldCgidnVsbmVyYWJpbGl0
>>"%WORK%\main.py.b64" echo aWVzIikgb3IgW10sCiAgICAgICAgICAgICAgICAgICAgInN0YXR1cyI6ICJjb21wbGV0ZWQi
>>"%WORK%\main.py.b64" echo LAogICAgICAgICAgICAgICAgICAgICJleHRlcm5hbF9zY2FuX2lkIjogdGFza19pZCwKICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgICAicGFydGlhbCI6IFRydWUsCiAgICAgICAgICAgICAgICAgICAg
>>"%WORK%\main.py.b64" echo InBhcnRpYWxfcmVhc29uIjogZiJzdGFsbGVkIHtzdGFsbF9zZWN9cyBhdCA+PXtzdGFsbF9w
>>"%WORK%\main.py.b64" echo Y3R9JSIsCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICApCiAgICAgICAgICAgIHJl
>>"%WORK%\main.py.b64" echo dHVybgoKCmRlZiBtYWluKCkgLT4gTm9uZToKICAgIGNmZyA9IF9jZmcoKQogICAgYXBpOiBD
>>"%WORK%\main.py.b64" echo ZW50cmFsQXBpID0gY2ZnWyJhcGkiXQogICAgb3BlbnZhczogTG9jYWxPcGVuVkFTID0gY2Zn
>>"%WORK%\main.py.b64" echo WyJvcGVudmFzIl0KICAgIG5leHRfaGVhcnRiZWF0ID0gMC4wCiAgICBsYXN0X3JlYWR5OiBi
>>"%WORK%\main.py.b64" echo b29sIHwgTm9uZSA9IE5vbmUKICAgIGxvZy5pbmZvKAogICAgICAgICJTY2FubmVyIGFnZW50
>>"%WORK%\main.py.b64" echo IHN0YXJ0aW5nIHRlbmFudD0lcyBhcGk9JXMiLAogICAgICAgIG9zLmVudmlyb24uZ2V0KCJU
>>"%WORK%\main.py.b64" echo RU5BTlRfU0xVRyIpLAogICAgICAgIG9zLmVudmlyb24uZ2V0KCJDRU5UUkFMX0FQSV9VUkwi
>>"%WORK%\main.py.b64" echo KSwKICAgICkKICAgIHdoaWxlIFRydWU6CiAgICAgICAgbm93ID0gdGltZS5tb25vdG9uaWMo
>>"%WORK%\main.py.b64" echo KQogICAgICAgIHRyeToKICAgICAgICAgICAgIyBSZWFkaW5lc3MgaXMgY2hlY2tlZCBiZWZv
>>"%WORK%\main.py.b64" echo cmUgam9iIHBvbGxpbmcuICBndm1kIGNhbiBhY2NlcHQgR01QCiAgICAgICAgICAgICMgY29u
>>"%WORK%\main.py.b64" echo bmVjdGlvbnMgYmVmb3JlIHRoZSBmZWVkLXByb3ZpZGVkIEZ1bGwgYW5kIGZhc3QgY29uZmln
>>"%WORK%\main.py.b64" echo IGhhcwogICAgICAgICAgICAjIGJlZW4gaW1wb3J0ZWQ7IGNsYWltaW5nIGEgam9iIGluIHRo
>>"%WORK%\main.py.b64" echo YXQgc3RhdGUgb25seSB0dXJucyBhIG5vcm1hbAogICAgICAgICAgICAjIGZpcnN0LXN0YXJ0
>>"%WORK%\main.py.b64" echo IGZlZWQgZGVsYXkgaW50byBhIGZhaWxlZCBjZW50cmFsIGpvYi4KICAgICAgICAgICAgcmVh
>>"%WORK%\main.py.b64" echo ZHkgPSBvcGVudmFzLnJlYWR5KCkKICAgICAgICAgICAgaWYgbm93ID49IG5leHRfaGVhcnRi
>>"%WORK%\main.py.b64" echo ZWF0IG9yIHJlYWR5ICE9IGxhc3RfcmVhZHk6CiAgICAgICAgICAgICAgICBhcGkuaGVhcnRi
>>"%WORK%\main.py.b64" echo ZWF0KHZlcnNpb249Y2ZnWyJ2ZXJzaW9uIl0sIG9wZW52YXNfcmVhZHk9cmVhZHkpCiAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICBuZXh0X2hlYXJ0YmVhdCA9IG5vdyArIGNmZ1siaGVhcnRiZWF0Il0KICAg
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgIGxhc3RfcmVhZHkgPSByZWFkeQogICAgICAgICAgICBpZiBub3QgcmVh
>>"%WORK%\main.py.b64" echo ZHk6CiAgICAgICAgICAgICAgICBsb2cud2FybmluZygiTG9jYWwgT3BlblZBUy9mZWVkIG5v
>>"%WORK%\main.py.b64" echo dCByZWFkeSDigJQgbm90IGNsYWltaW5nIGpvYnM7IHdpbGwgcmV0cnkiKQogICAgICAgICAg
>>"%WORK%\main.py.b64" echo ICAgICAgdGltZS5zbGVlcChjZmdbInBvbGwiXSkKICAgICAgICAgICAgICAgIGNvbnRpbnVl
>>"%WORK%\main.py.b64" echo CgogICAgICAgICAgICBqb2IgPSBhcGkubmV4dF9qb2IoKQogICAgICAgICAgICBpZiBqb2I6
>>"%WORK%\main.py.b64" echo CiAgICAgICAgICAgICAgICBfcnVuX2pvYihjZmcsIGpvYikKICAgICAgICAgICAgZWxzZToK
>>"%WORK%\main.py.b64" echo ICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoY2ZnWyJwb2xsIl0pCiAgICAgICAgZXhjZXB0
>>"%WORK%\main.py.b64" echo IEV4Y2VwdGlvbjoKICAgICAgICAgICAgbG9nLmV4Y2VwdGlvbigiQWdlbnQgbG9vcCBlcnJv
>>"%WORK%\main.py.b64" echo ciIpCiAgICAgICAgICAgIHRpbWUuc2xlZXAoY2ZnWyJwb2xsIl0pCgoKaWYgX19uYW1lX18g
>>"%WORK%\main.py.b64" echo PT0gIl9fbWFpbl9fIjoKICAgIG1haW4oKQo=
certutil -f -decode "%WORK%\main.py.b64" "%WORK%\main.py" >nul
if errorlevel 1 goto :decodefail
>"%WORK%\check_greenbone_ready.py.b64" echo ZnJvbSBhZ2VudC5nbXBfbG9jYWwgaW1wb3J0IExvY2FsT3BlblZBUywgX2ZpbmRfY29uZmln
>>"%WORK%\check_greenbone_ready.py.b64" echo X2lkLCBfZmluZF9zY2FubmVyX2lkLCBfc2Vzc2lvbgoKbyA9IExvY2FsT3BlblZBUygpCnRy
>>"%WORK%\check_greenbone_ready.py.b64" echo eToKICAgIHdpdGggX3Nlc3Npb24oc29ja2V0X3BhdGg9by5zb2NrZXRfcGF0aCwgaG9zdD1v
>>"%WORK%\check_greenbone_ready.py.b64" echo Lmhvc3QsIHBvcnQ9by5wb3J0LCB1c2VybmFtZT1vLnVzZXJuYW1lLCBwYXNzd29yZD1vLnBh
>>"%WORK%\check_greenbone_ready.py.b64" echo c3N3b3JkKSBhcyBnbXA6CiAgICAgICAgc2Nhbm5lcl9pZCA9IF9maW5kX3NjYW5uZXJfaWQo
>>"%WORK%\check_greenbone_ready.py.b64" echo Z21wKQogICAgICAgIGNvbmZpZ19pZCA9IF9maW5kX2NvbmZpZ19pZChnbXAsIG8uc2Nhbl9j
>>"%WORK%\check_greenbone_ready.py.b64" echo b25maWdfbmFtZSkKICAgIHByaW50KGYiUkVBRFkgc2Nhbm5lcj17c2Nhbm5lcl9pZH0gY29u
>>"%WORK%\check_greenbone_ready.py.b64" echo ZmlnPXtjb25maWdfaWR9IG5hbWU9e28uc2Nhbl9jb25maWdfbmFtZX0iKQpleGNlcHQgRXhj
>>"%WORK%\check_greenbone_ready.py.b64" echo ZXB0aW9uIGFzIGV4YzoKICAgIHByaW50KGYiTk9UX1JFQURZIHtleGN9IikKICAgIHJhaXNl
>>"%WORK%\check_greenbone_ready.py.b64" echo IFN5c3RlbUV4aXQoMikK
certutil -f -decode "%WORK%\check_greenbone_ready.py.b64" "%WORK%\check_greenbone_ready.py" >nul
if errorlevel 1 goto :decodefail
echo 1.0.5>"%WORK%\.agent-version"
echo [OK] Corrected GMP session, etree transform and readiness-gate code prepared

echo [4/9] Update host source tree
if not exist "scanner-agent\agent" mkdir "scanner-agent\agent" >nul 2>&1
copy /y "%WORK%\gmp_local.py" "scanner-agent\agent\gmp_local.py" >nul || goto :copyfail
copy /y "%WORK%\main.py" "scanner-agent\agent\main.py" >nul || goto :copyfail
copy /y "%WORK%\check_greenbone_ready.py" "scanner-agent\check_greenbone_ready.py" >nul || goto :copyfail
echo [OK] Host source updated; original files are in %BACKUP%

echo [5/9] Hot-patch the EXISTING scanner-agent container
docker cp "%WORK%\gmp_local.py" "%CID%:/app/agent/gmp_local.py" || goto :copyfail
docker cp "%WORK%\main.py" "%CID%:/app/agent/main.py" || goto :copyfail
docker cp "%WORK%\check_greenbone_ready.py" "%CID%:/app/check_greenbone_ready.py" || goto :copyfail
docker cp "%WORK%\.agent-version" "%CID%:/app/.agent-version" || goto :copyfail
docker exec "%CID%" python -m py_compile /app/agent/gmp_local.py /app/agent/main.py /app/check_greenbone_ready.py
if errorlevel 1 (
  echo [ERROR] Python compile validation failed; container was NOT restarted.
  exit /b 3
)
docker exec "%CID%" sh -c "grep -Eq '^[[:space:]]*with[[:space:]]+conn[[:space:]]*:' /app/agent/gmp_local.py && exit 9 || exit 0"
if errorlevel 1 (
  echo [ERROR] Old invalid "with conn:" statement is still present.
  exit /b 4
)
echo [OK] Running container has fixed UnixSocketConnection lifecycle code

echo [6/9] Restart ONLY the existing scanner-agent container
docker restart "%CID%" >nul || exit /b 5
timeout /t 8 /nobreak >nul
echo [OK] Same scanner-agent container restarted

echo [7/9] Check Greenbone readiness
set "READYFILE=%WORK%\ready.txt"
docker exec "%CID%" python /app/check_greenbone_ready.py >"%READYFILE%" 2>&1
set "READYRC=%ERRORLEVEL%"
type "%READYFILE%"
if "%READYRC%"=="0" goto :ready

findstr /I /C:"No OpenVAS scanner found" "%READYFILE%" >nul
if not errorlevel 1 (
  echo [INFO] Registering local OpenVAS scanner without deleting anything...
  docker compose exec -T -u gvmd gvmd gvmd --create-scanner="OpenVAS Default" --scanner-type="OpenVAS" --scanner-host="/run/ospd/ospd-openvas.sock" --no-default-certs
  echo.
)

findstr /I /C:"Scan config not found" "%READYFILE%" >nul
if not errorlevel 1 (
  echo [INFO] Full and fast is not imported yet. Repairing feed owner/data objects...
  set "ADMIN_UUID="
  for /f "tokens=2" %%U in ('docker compose exec -T -u gvmd gvmd gvmd --get-users --verbose 2^>nul ^| findstr /B /I "admin "') do if not defined ADMIN_UUID set "ADMIN_UUID=%%U"
  if defined ADMIN_UUID (
    echo [INFO] Feed Import Owner: admin !ADMIN_UUID!
    docker compose exec -T -u gvmd gvmd gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value !ADMIN_UUID!
  ) else (
    echo [WARN] Could not determine admin UUID automatically.
  )
  echo [INFO] Rebuilding gvmd feed-backed data objects...
  docker compose exec -T -u gvmd gvmd gvmd --rebuild-gvmd-data=all
  echo.
)

echo [8/9] Wait for scanner + Full and fast to become available
set /a TRY=0
:readyloop
set /a TRY+=1
docker exec "%CID%" python /app/check_greenbone_ready.py >"%READYFILE%" 2>&1
if not errorlevel 1 goto :ready
type "%READYFILE%"
if !TRY! GEQ 18 goto :notready
echo [INFO] Greenbone not ready yet - retry !TRY!/18 in 10 seconds...
timeout /t 10 /nobreak >nul
goto :readyloop

:ready
echo [OK] Greenbone scanner and Full and fast are READY
type "%READYFILE%" 2>nul
docker restart "%CID%" >nul
timeout /t 8 /nobreak >nul

echo [9/9] Verify heartbeat/version and recent logs
docker compose logs --tail=80 scanner-agent 2>&1
echo.
echo ============================================================
echo REPAIR COMPLETE
echo ============================================================
echo Expected now:
echo   - no UnixSocketConnection context-manager exception
echo   - heartbeat HTTP 200
echo   - scanner reports agent version 1.0.5
echo   - Greenbone READY before the agent claims a job
echo.
echo The old failed central job remains historical.
echo Launch a NEW scan from the Aetheris UI.
echo No containers or volumes were deleted or recreated.
exit /b 0

:notready
echo.
echo [ERROR] Scanner-agent code is fixed, but Greenbone is still NOT_READY.
echo Current readiness:
type "%READYFILE%"
echo.
echo Recent gvmd / ospd logs:
docker compose logs --tail=120 gvmd ospd-openvas 2>&1
echo.
echo Do NOT launch a new scan until the readiness line says READY.
exit /b 6

:decodefail
echo [ERROR] Could not decode embedded repair payload.
exit /b 7

:copyfail
echo [ERROR] Could not apply patched scanner-agent files.
echo Backup remains at: %BACKUP%
exit /b 8
