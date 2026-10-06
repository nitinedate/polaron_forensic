#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

echo "[1/3] Edge scanner tests"
(
  cd laptop-scanner/scanner-agent
  pytest -q
)

echo "[2/3] Central per-IP progress tests"
pytest -q backend/tests/test_scanner_agent_target_progress.py

echo "[3/3] Vulnerability capacity tests"
pytest -q backend/tests/test_vuln_capacity.py

echo "PASS: vulnerability performance regression suite"
