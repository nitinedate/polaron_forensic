@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "TASK_ID=%~1"
if not defined TASK_ID set "TASK_ID=12143f78-afe0-4e37-8eb1-13cab3616c4e"
set "TARGET=%~2"
if not defined TARGET set "TARGET=192.168.1.11"

for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%I"
set "OUT=%CD%\diagnostics\openvas-proof-%TS%"
set "ZIP=%CD%\diagnostics\openvas-proof-%TS%.zip"
mkdir "%OUT%" >nul 2>&1

echo ============================================================
echo Aetheris OpenVAS Task/Report Proof Collector
echo Task  : %TASK_ID%
echo Target: %TARGET%
echo ============================================================
echo This does not stop, restart, recreate, remove, or delete anything.
echo.

docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker Desktop is not running.
  exit /b 1
)

set "CID="
for /f "delims=" %%C in ('docker compose ps -q scanner-agent 2^>nul') do if not defined CID set "CID=%%C"
if not defined CID (
  echo [ERROR] scanner-agent container not found.
  exit /b 2
)

echo [1/6] Build direct GMP probe
>"%OUT%\probe.b64" echo ZnJvbSBjb2xsZWN0aW9ucyBpbXBvcnQgQ291bnRlcgpmcm9tIGx4bWwgaW1wb3J0IGV0cmVl
>>"%OUT%\probe.b64" echo CmZyb20gYWdlbnQuZ21wX2xvY2FsIGltcG9ydCBMb2NhbE9wZW5WQVMsIF9zZXNzaW9uCgpU
>>"%OUT%\probe.b64" echo QVNLX0lEID0gIl9fVEFTS19JRF9fIgoKb3YgPSBMb2NhbE9wZW5WQVMoKQpwcmludChmIlRB
>>"%OUT%\probe.b64" echo U0tfSUQ9e1RBU0tfSUR9IikKcHJpbnQoZiJHTVBfU09DS0VUPXtvdi5zb2NrZXRfcGF0aH0i
>>"%OUT%\probe.b64" echo KQoKd2l0aCBfc2Vzc2lvbigKICAgIHNvY2tldF9wYXRoPW92LnNvY2tldF9wYXRoLAogICAg
>>"%OUT%\probe.b64" echo aG9zdD1vdi5ob3N0LAogICAgcG9ydD1vdi5wb3J0LAogICAgdXNlcm5hbWU9b3YudXNlcm5h
>>"%OUT%\probe.b64" echo bWUsCiAgICBwYXNzd29yZD1vdi5wYXNzd29yZCwKKSBhcyBnbXA6CiAgICByZXNwb25zZSA9
>>"%OUT%\probe.b64" echo IGdtcC5nZXRfdGFzayhUQVNLX0lEKQogICAgdGFzayA9IHJlc3BvbnNlLmZpbmQoInRhc2si
>>"%OUT%\probe.b64" echo KQogICAgaWYgdGFzayBpcyBOb25lOgogICAgICAgIG5vZGVzID0gcmVzcG9uc2UueHBhdGgo
>>"%OUT%\probe.b64" echo Ii4vL3Rhc2siKQogICAgICAgIHRhc2sgPSBub2Rlc1swXSBpZiBub2RlcyBlbHNlIE5vbmUK
>>"%OUT%\probe.b64" echo CiAgICBpZiB0YXNrIGlzIE5vbmU6CiAgICAgICAgcHJpbnQoIlRBU0tfRk9VTkQ9Tk8iKQog
>>"%OUT%\probe.b64" echo ICAgICAgIHJhaXNlIFN5c3RlbUV4aXQoMjApCgogICAgcHJpbnQoIlRBU0tfRk9VTkQ9WUVT
>>"%OUT%\probe.b64" echo IikKICAgIHByaW50KCJUQVNLX05BTUU9IiArIHN0cih0YXNrLmZpbmR0ZXh0KCJuYW1lIikg
>>"%OUT%\probe.b64" echo b3IgIiIpKQogICAgcHJpbnQoIlRBU0tfU1RBVFVTPSIgKyBzdHIodGFzay5maW5kdGV4dCgi
>>"%OUT%\probe.b64" echo c3RhdHVzIikgb3IgIiIpKQogICAgcHJpbnQoIlRBU0tfUFJPR1JFU1M9IiArIHN0cih0YXNr
>>"%OUT%\probe.b64" echo LmZpbmR0ZXh0KCJwcm9ncmVzcyIpIG9yICIiKSkKCiAgICB0YXJnZXQgPSB0YXNrLmZpbmQo
>>"%OUT%\probe.b64" echo InRhcmdldCIpCiAgICBpZiB0YXJnZXQgaXMgbm90IE5vbmU6CiAgICAgICAgcHJpbnQoIlRB
>>"%OUT%\probe.b64" echo UkdFVF9JRD0iICsgc3RyKHRhcmdldC5nZXQoImlkIikgb3IgIiIpKQogICAgICAgIHByaW50
>>"%OUT%\probe.b64" echo KCJUQVJHRVRfTkFNRT0iICsgc3RyKHRhcmdldC5maW5kdGV4dCgibmFtZSIpIG9yICIiKSkK
>>"%OUT%\probe.b64" echo CiAgICByZXBvcnRfaWRzID0gW10KICAgIGZvciBwYXRoIGluICgiY3VycmVudF9yZXBvcnQv
>>"%OUT%\probe.b64" echo cmVwb3J0IiwgImxhc3RfcmVwb3J0L3JlcG9ydCIpOgogICAgICAgIGVsZW0gPSB0YXNrLmZp
>>"%OUT%\probe.b64" echo bmQocGF0aCkKICAgICAgICBpZiBlbGVtIGlzIG5vdCBOb25lIGFuZCBlbGVtLmdldCgiaWQi
>>"%OUT%\probe.b64" echo KToKICAgICAgICAgICAgcmVwb3J0X2lkcy5hcHBlbmQoKHBhdGgsIGVsZW0uZ2V0KCJpZCIp
>>"%OUT%\probe.b64" echo KSkKCiAgICBwcmludCgiUkVQT1JUX0lEUz0iICsgcmVwcihyZXBvcnRfaWRzKSkKCiAgICBp
>>"%OUT%\probe.b64" echo ZiBub3QgcmVwb3J0X2lkczoKICAgICAgICBwcmludCgiVkVSRElDVD1VTlZFUklGSUVEX05P
>>"%OUT%\probe.b64" echo X1JFUE9SVF9JRCIpCiAgICAgICAgcHJpbnQoIlRBU0tfWE1MX0JFR0lOIikKICAgICAgICBw
>>"%OUT%\probe.b64" echo cmludChldHJlZS50b3N0cmluZyh0YXNrLCBlbmNvZGluZz0idW5pY29kZSIpWzoyNTAwMF0p
>>"%OUT%\probe.b64" echo CiAgICAgICAgcHJpbnQoIlRBU0tfWE1MX0VORCIpCiAgICAgICAgcmFpc2UgU3lzdGVtRXhp
>>"%OUT%\probe.b64" echo dCgyMSkKCiAgICByZXBvcnRfaWQgPSByZXBvcnRfaWRzWzBdWzFdCiAgICBwcmludCgiUkVQ
>>"%OUT%\probe.b64" echo T1JUX0lEX1NFTEVDVEVEPSIgKyByZXBvcnRfaWQpCgogICAgcmVwb3J0ID0gZ21wLmdldF9y
>>"%OUT%\probe.b64" echo ZXBvcnQoCiAgICAgICAgcmVwb3J0X2lkPXJlcG9ydF9pZCwKICAgICAgICBmaWx0ZXJfc3Ry
>>"%OUT%\probe.b64" echo aW5nPSJyb3dzPS0xIiwKICAgICAgICBpZ25vcmVfcGFnaW5hdGlvbj1UcnVlLAogICAgICAg
>>"%OUT%\probe.b64" echo IGRldGFpbHM9VHJ1ZSwKICAgICkKCiAgICByZXN1bHRzID0gcmVwb3J0LnhwYXRoKCIuLy9y
>>"%OUT%\probe.b64" echo ZXN1bHRzL3Jlc3VsdCIpCiAgICBwcmludCgiUkFXX1JFU1VMVF9DT1VOVD0iICsgc3RyKGxl
>>"%OUT%\probe.b64" echo bihyZXN1bHRzKSkpCgogICAgaG9zdHMgPSBbXQogICAgdGhyZWF0cyA9IENvdW50ZXIoKQog
>>"%OUT%\probe.b64" echo ICAgc2V2ZXJpdGllcyA9IENvdW50ZXIoKQogICAgbmFtZXMgPSBDb3VudGVyKCkKCiAgICBm
>>"%OUT%\probe.b64" echo b3IgcmVzdWx0IGluIHJlc3VsdHM6CiAgICAgICAgaG9zdCA9IChyZXN1bHQuZmluZHRleHQo
>>"%OUT%\probe.b64" echo Imhvc3QiKSBvciAiIikuc3RyaXAoKQogICAgICAgIGlmIGhvc3Q6CiAgICAgICAgICAgIGhv
>>"%OUT%\probe.b64" echo c3RzLmFwcGVuZChob3N0KQoKICAgICAgICB0aHJlYXQgPSAocmVzdWx0LmZpbmR0ZXh0KCJ0
>>"%OUT%\probe.b64" echo aHJlYXQiKSBvciAiIikuc3RyaXAoKQogICAgICAgIHNldmVyaXR5ID0gKHJlc3VsdC5maW5k
>>"%OUT%\probe.b64" echo dGV4dCgic2V2ZXJpdHkiKSBvciAiIikuc3RyaXAoKQogICAgICAgIHRocmVhdHNbdGhyZWF0
>>"%OUT%\probe.b64" echo XSArPSAxCiAgICAgICAgc2V2ZXJpdGllc1tzZXZlcml0eV0gKz0gMQoKICAgICAgICBudnQg
>>"%OUT%\probe.b64" echo PSByZXN1bHQuZmluZCgibnZ0IikKICAgICAgICBpZiBudnQgaXMgbm90IE5vbmU6CiAgICAg
>>"%OUT%\probe.b64" echo ICAgICAgIG5hbWUgPSAobnZ0LmZpbmR0ZXh0KCJuYW1lIikgb3IgIiIpLnN0cmlwKCkKICAg
>>"%OUT%\probe.b64" echo ICAgICAgICAgaWYgbmFtZToKICAgICAgICAgICAgICAgIG5hbWVzW25hbWVdICs9IDEKCiAg
>>"%OUT%\probe.b64" echo ICBwcmludCgiVU5JUVVFX1JFU1VMVF9IT1NUUz0iICsgcmVwcihzb3J0ZWQoc2V0KGhvc3Rz
>>"%OUT%\probe.b64" echo KSkpKQogICAgcHJpbnQoIlRIUkVBVF9DT1VOVFM9IiArIHJlcHIoZGljdCh0aHJlYXRzKSkp
>>"%OUT%\probe.b64" echo CiAgICBwcmludCgiU0VWRVJJVFlfQ09VTlRTPSIgKyByZXByKGRpY3Qoc2V2ZXJpdGllcykp
>>"%OUT%\probe.b64" echo KQoKICAgIHJlcG9ydF9ub2RlcyA9IHJlcG9ydC54cGF0aCgiLi8vcmVwb3J0IikKICAgIG1h
>>"%OUT%\probe.b64" echo aW5fcmVwb3J0ID0gcmVwb3J0X25vZGVzWzBdIGlmIHJlcG9ydF9ub2RlcyBlbHNlIE5vbmUK
>>"%OUT%\probe.b64" echo CiAgICBpZiBtYWluX3JlcG9ydCBpcyBub3QgTm9uZToKICAgICAgICBwcmludCgiUkVQT1JU
>>"%OUT%\probe.b64" echo X1NDQU5fU1RBUlQ9IiArIHN0cihtYWluX3JlcG9ydC5maW5kdGV4dCgic2Nhbl9zdGFydCIp
>>"%OUT%\probe.b64" echo IG9yICIiKSkKICAgICAgICBwcmludCgiUkVQT1JUX1NDQU5fRU5EPSIgKyBzdHIobWFpbl9y
>>"%OUT%\probe.b64" echo ZXBvcnQuZmluZHRleHQoInNjYW5fZW5kIikgb3IgIiIpKQogICAgICAgIHByaW50KCJSRVBP
>>"%OUT%\probe.b64" echo UlRfSE9TVF9TVEFSVD0iICsgc3RyKG1haW5fcmVwb3J0LmZpbmR0ZXh0KCJob3N0L3N0YXJ0
>>"%OUT%\probe.b64" echo Iikgb3IgIiIpKQogICAgICAgIHByaW50KCJSRVBPUlRfSE9TVF9FTkQ9IiArIHN0cihtYWlu
>>"%OUT%\probe.b64" echo X3JlcG9ydC5maW5kdGV4dCgiaG9zdC9lbmQiKSBvciAiIikpCgogICAgaG9zdF9ub2RlcyA9
>>"%OUT%\probe.b64" echo IHJlcG9ydC54cGF0aCgiLi8vaG9zdHMvaG9zdCIpCiAgICBob3N0X3RleHRzID0gW10KICAg
>>"%OUT%\probe.b64" echo IGZvciBob3N0X25vZGUgaW4gaG9zdF9ub2RlczoKICAgICAgICB0ZXh0ID0gKGhvc3Rfbm9k
>>"%OUT%\probe.b64" echo ZS50ZXh0IG9yICIiKS5zdHJpcCgpCiAgICAgICAgaWYgdGV4dDoKICAgICAgICAgICAgaG9z
>>"%OUT%\probe.b64" echo dF90ZXh0cy5hcHBlbmQodGV4dCkKCiAgICBwcmludCgiUkVQT1JUX0hPU1RfTk9ERV9DT1VO
>>"%OUT%\probe.b64" echo VD0iICsgc3RyKGxlbihob3N0X25vZGVzKSkpCiAgICBwcmludCgiUkVQT1JUX0hPU1RfTk9E
>>"%OUT%\probe.b64" echo RV9URVhUPSIgKyByZXByKGhvc3RfdGV4dHNbOjEwMF0pKQoKICAgIGRldGFpbHMgPSByZXBv
>>"%OUT%\probe.b64" echo cnQueHBhdGgoIi4vL2hvc3QvZGV0YWlsIikKICAgIGludGVyZXN0aW5nX2RldGFpbHMgPSBb
>>"%OUT%\probe.b64" echo XQogICAgZm9yIGRldGFpbCBpbiBkZXRhaWxzOgogICAgICAgIG5hbWUgPSAoZGV0YWlsLmZp
>>"%OUT%\probe.b64" echo bmR0ZXh0KCJuYW1lIikgb3IgIiIpLnN0cmlwKCkKICAgICAgICB2YWx1ZSA9IChkZXRhaWwu
>>"%OUT%\probe.b64" echo ZmluZHRleHQoInZhbHVlIikgb3IgIiIpLnN0cmlwKCkKICAgICAgICBzb3VyY2VfbmFtZSA9
>>"%OUT%\probe.b64" echo IChkZXRhaWwuZmluZHRleHQoInNvdXJjZS9uYW1lIikgb3IgIiIpLnN0cmlwKCkKICAgICAg
>>"%OUT%\probe.b64" echo ICB0ZXh0ID0gZiJ7bmFtZX09e3ZhbHVlfSBzb3VyY2U9e3NvdXJjZV9uYW1lfSIuc3RyaXAo
>>"%OUT%\probe.b64" echo KQogICAgICAgIGxvdyA9IHRleHQubG93ZXIoKQogICAgICAgIGlmIGFueSh3b3JkIGluIGxv
>>"%OUT%\probe.b64" echo dyBmb3Igd29yZCBpbiAoImRlYWQiLCAiYWxpdmUiLCAiaG9zdCIsICJpY21wIiwgInRjcCIs
>>"%OUT%\probe.b64" echo ICJhcnAiLCAic2NhbiIpKToKICAgICAgICAgICAgaW50ZXJlc3RpbmdfZGV0YWlscy5hcHBl
>>"%OUT%\probe.b64" echo bmQodGV4dCkKCiAgICBwcmludCgiSU5URVJFU1RJTkdfSE9TVF9ERVRBSUxTPSIgKyByZXBy
>>"%OUT%\probe.b64" echo KGludGVyZXN0aW5nX2RldGFpbHNbOjEwMF0pKQoKICAgIHByaW50KCJSRVNVTFRfU0FNUExF
>>"%OUT%\probe.b64" echo X0JFR0lOIikKICAgIGZvciBpbmRleCwgcmVzdWx0IGluIGVudW1lcmF0ZShyZXN1bHRzWzo1
>>"%OUT%\probe.b64" echo MF0sIDEpOgogICAgICAgIG52dCA9IHJlc3VsdC5maW5kKCJudnQiKQogICAgICAgIHByaW50
>>"%OUT%\probe.b64" echo KHsKICAgICAgICAgICAgImluZGV4IjogaW5kZXgsCiAgICAgICAgICAgICJob3N0IjogcmVz
>>"%OUT%\probe.b64" echo dWx0LmZpbmR0ZXh0KCJob3N0IiksCiAgICAgICAgICAgICJwb3J0IjogcmVzdWx0LmZpbmR0
>>"%OUT%\probe.b64" echo ZXh0KCJwb3J0IiksCiAgICAgICAgICAgICJ0aHJlYXQiOiByZXN1bHQuZmluZHRleHQoInRo
>>"%OUT%\probe.b64" echo cmVhdCIpLAogICAgICAgICAgICAic2V2ZXJpdHkiOiByZXN1bHQuZmluZHRleHQoInNldmVy
>>"%OUT%\probe.b64" echo aXR5IiksCiAgICAgICAgICAgICJxb2QiOiByZXN1bHQuZmluZHRleHQoInFvZC92YWx1ZSIp
>>"%OUT%\probe.b64" echo LAogICAgICAgICAgICAibmFtZSI6IG52dC5maW5kdGV4dCgibmFtZSIpIGlmIG52dCBpcyBu
>>"%OUT%\probe.b64" echo b3QgTm9uZSBlbHNlIHJlc3VsdC5maW5kdGV4dCgibmFtZSIpLAogICAgICAgICAgICAib2lk
>>"%OUT%\probe.b64" echo IjogbnZ0LmdldCgib2lkIikgaWYgbnZ0IGlzIG5vdCBOb25lIGVsc2UgTm9uZSwKICAgICAg
>>"%OUT%\probe.b64" echo ICB9KQogICAgcHJpbnQoIlJFU1VMVF9TQU1QTEVfRU5EIikKCiAgICBpZiBsZW4ocmVzdWx0
>>"%OUT%\probe.b64" echo cykgPT0gMCBhbmQgbGVuKGhvc3Rfbm9kZXMpID09IDAgYW5kIG5vdCBpbnRlcmVzdGluZ19k
>>"%OUT%\probe.b64" echo ZXRhaWxzOgogICAgICAgIHByaW50KCJWRVJESUNUPVVOVkVSSUZJRURfRU1QVFlfUkVQT1JU
>>"%OUT%\probe.b64" echo X05PX0hPU1RfRVZJREVOQ0UiKQogICAgZWxpZiBsZW4ocmVzdWx0cykgPT0gMCBhbmQgKGxl
>>"%OUT%\probe.b64" echo bihob3N0X25vZGVzKSA+IDAgb3IgaW50ZXJlc3RpbmdfZGV0YWlscyk6CiAgICAgICAgcHJp
>>"%OUT%\probe.b64" echo bnQoIlZFUkRJQ1Q9WkVST19SRVNVTFRTX1dJVEhfSE9TVF9FVklERU5DRV9SRVZJRVdfREVU
>>"%OUT%\probe.b64" echo QUlMUyIpCiAgICBlbGlmIGxlbihyZXN1bHRzKSA+IDA6CiAgICAgICAgcHJpbnQoIlZFUkRJ
>>"%OUT%\probe.b64" echo Q1Q9UkVQT1JUX0hBU19SRVNVTFRTIikKICAgIGVsc2U6CiAgICAgICAgcHJpbnQoIlZFUkRJ
>>"%OUT%\probe.b64" echo Q1Q9VU5WRVJJRklFRCIpCg==
certutil -f -decode "%OUT%\probe.b64" "%OUT%\probe-template.py" >nul
if errorlevel 1 (echo [ERROR] Could not decode probe payload.& exit /b 3)
powershell -NoProfile -Command "$p=Get-Content -Raw -LiteralPath '%OUT%\probe-template.py'; $p=$p.Replace('__TASK_ID__','%TASK_ID%'); [IO.File]::WriteAllText('%OUT%\probe.py',$p,(New-Object Text.UTF8Encoding($false)))"

echo [2/6] Query exact Greenbone task and report through GMP
docker exec -i "%CID%" python - <"%OUT%\probe.py" >"%OUT%\openvas-task-report-proof.txt" 2>&1
set "PROBE_RC=%ERRORLEVEL%"
type "%OUT%\openvas-task-report-proof.txt"
echo.

echo [3/6] Capture scanner-agent evidence
docker compose logs --since 12h --tail=5000 scanner-agent >"%OUT%\scanner-agent.log" 2>&1
findstr /I /C:"%TASK_ID%" /C:"%TARGET%" /C:"completed with" /C:"Could not read results" "%OUT%\scanner-agent.log" >"%OUT%\scanner-agent-correlated.txt" 2>&1

echo [4/6] Capture gvmd / ospd evidence
docker compose logs --since 12h --tail=5000 gvmd >"%OUT%\gvmd.log" 2>&1
docker compose logs --since 12h --tail=5000 ospd-openvas >"%OUT%\ospd-openvas.log" 2>&1
findstr /I /C:"%TASK_ID%" /C:"%TARGET%" /C:"Host scan finished" /C:"Scan finished" "%OUT%\gvmd.log" "%OUT%\ospd-openvas.log" >"%OUT%\greenbone-correlated.txt" 2>&1

echo [5/6] Capture current target reachability
ping -n 4 "%TARGET%" >"%OUT%\target-ping.txt" 2>&1
powershell -NoProfile -Command "$t='%TARGET%'; 22,53,80,135,139,443,445,3389 | %% { $r=Test-NetConnection -ComputerName $t -Port $_ -WarningAction SilentlyContinue; [pscustomobject]@{Target=$t;Port=$_;Tcp=$r.TcpTestSucceeded;RemoteAddress=$r.RemoteAddress} } | Format-Table -AutoSize" >"%OUT%\target-common-ports.txt" 2>&1
docker compose exec -T scanner-agent sh -c "command -v nmap >/dev/null 2>&1 && nmap -Pn --top-ports 25 --host-timeout 60s %TARGET% || true" >"%OUT%\target-nmap.txt" 2>&1

echo [6/6] Package
echo ProbeExitCode=%PROBE_RC%>"%OUT%\SUMMARY.txt"
findstr /B /C:"TASK_" /C:"REPORT_" /C:"RAW_RESULT_COUNT=" /C:"UNIQUE_RESULT_HOSTS=" /C:"INTERESTING_HOST_DETAILS=" /C:"VERDICT=" "%OUT%\openvas-task-report-proof.txt" >>"%OUT%\SUMMARY.txt" 2>nul
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath '%ZIP%' -Force" >nul 2>&1
echo.
echo ============================================================
echo RESULT SUMMARY
echo ============================================================
type "%OUT%\SUMMARY.txt"
echo.
echo ZIP: %ZIP%
echo Upload this ZIP to ChatGPT.
exit /b 0
