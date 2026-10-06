@echo off
setlocal
cd /d "%~dp0"
echo === V45.4 deployment check (laptop scanner) ===
echo.
echo [0] Host folder bound into the running agent (THIS is the folder that must contain the V45 files):
docker inspect aetheris-laptop-scanner-agent-1 --format "{{range .Mounts}}{{.Source}}  =^>  {{.Destination}}{{println}}{{end}}" 2>nul
echo.
echo [1] openvas.conf inside the scanner (expect plugins_timeout = 320, scanner_plugins_timeout = 36000):
docker compose exec -T openvas cat /etc/openvas/openvas.conf
echo.
echo [2] scanner-agent environment:
docker compose exec -T scanner-agent sh -c "env | grep -E '^(PORT_PROFILE|UDP_PROFILE|PLUGINS_TIMEOUT_SEC|SCANNER_PLUGINS_TIMEOUT_SEC|GVM_OPTIMIZE_TEST|GVM_MAX_CHECKS|SCAN_IP_MAX_PARALLELISM|SCAN_DEGRADED_RETRY|AGENT_VERSION)=' | sort"
echo.
echo [3] build stamp inside the running container (expect 1.5.1-v45.5):
docker compose exec -T scanner-agent python -c "from agent import AGENT_BUILD; print('AGENT_BUILD', AGENT_BUILD)"
echo.
echo [4] agent banner / profile lines from the log:
docker compose logs --tail 2000 scanner-agent 2>nul | findstr /C:"AGENT BUILD" /C:"DEGRADED SCAN CONFIG" /C:"OpenVAS quality profile" /C:"coverage_retry" /C:"coverage_incomplete"
echo.
echo A healthy V45.5 agent prints: AGENT BUILD 1.5.1-v45.5 ... plugins_timeout=320s scanner_plugins_timeout=36000s ... coverage_guard=on
echo If any of [1]-[4] disagrees, run Deploy-V45-Laptop.cmd.
pause
