#!/usr/bin/env python3
"""Static source-contract guard; live engine acceptance is a separate check."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    pack = read("scripts/pack-laptop-scanner-zip.ps1")
    require('$agentSrc = Join-Path $pkg "scanner-agent"' in pack, "canonical laptop source missing")
    require("Legacy repo-root scanner-agent detected but intentionally NOT copied" in pack, "legacy-source fence missing")
    require("agent\\target_progress.py" in pack and "tests\\test_target_progress.py" in pack, "progress implementation/tests omitted")
    env = read("laptop-scanner/.env.example")
    compose = read("laptop-scanner/docker-compose.yml")
    gmp = read("laptop-scanner/scanner-agent/agent/gmp_local.py")
    main_agent = read("laptop-scanner/scanner-agent/agent/main.py")
    require("PORT_PROFILE=full" in env and "PORT_PROFILE: ${PORT_PROFILE:-full}" in compose, "Full profile defaults diverge")
    require('os.environ.get("PORT_PROFILE") or "full"' in gmp, "runtime default must retain Full coverage")
    require("GVM_OPTIMIZE_TEST=no" in env, "Full sample profile must not enable optimized test pruning")
    require("_effective_scan_policy(scan_policy, self.port_profile, self.udp_profile)" in gmp
            and 'port_range = snapshot["port_range"]' in gmp
            and "discovered_range = None" in main_agent, "engine must use versioned policy, not discovered-only ports")
    require("policy_snapshots" in gmp and "service_coverage" in gmp, "service policy/evidence audit missing")
    require('"service_count": 52' in read("laptop-scanner/scanner-agent/agent/service_catalog.json"), "guide service scope missing")
    require('"target_progress":' in main_agent and "build_target_progress" in main_agent, "agent does not send complete snapshots")
    require("HIGH_PROGRESS_STALL_SEC=0" in env, "degraded high-percent harvest must be opt-in")
    require("IP_WORKERS_MIN = 5" in read("laptop-scanner/scanner-agent/agent/capacity.py"), "operational floor must be five IP workers")
    router = read("backend/app/routers/scanner_agent.py")
    jobs = read("backend/app/services/scanner_agent_jobs.py")
    ui = read("frontend/src/pages/vuln/ScanJobsPage.tsx")
    require("target_progress: dict[str, dict[str, Any]] | None = None" in router, "progress API contract missing")
    require("_merge_edge_target_progress" in jobs and 'orch["target_progress"] = merged' in jobs and "FOR UPDATE" in jobs, "atomic scoped progress persistence missing")
    require("Per-IP scan activity" in ui and "progress_pct" in ui, "UI per-IP percent missing")
    require("scannerIsScanReady" in ui and "edge_scanner_not_ready" in read("backend/app/routers/vuln.py"), "UI/API readiness fence missing")
    require("nessus-aligned-weighted-1" in read("backend/app/services/vuln_risk.py"), "documented contextual risk model missing")
    require("expected_current_version" not in pack, "packager contains an unrelated storage contract")
    print("PASS: canonical packaging; versioned 52-service scope/audit; Full coverage; five-worker floor; durable per-IP progress; readiness fences; version-aware severity/contextual risk")
    print("Live Windows, Docker/Greenbone and phone/GPU acceptance still require the target host.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
