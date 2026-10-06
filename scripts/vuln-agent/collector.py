#!/usr/bin/env python3
"""Lightweight vuln scan agent — inventory collection only (FR-14).

NOT behavioral EDR: no process kill, quarantine, or response actions.
Collects installed packages and running process names, then POSTs to platform API.

Usage:
  python collector.py --api-url http://localhost:8080 --agent-id <uuid> --case-id <uuid> --token <jwt>
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from typing import Any

try:
    import httpx
except ImportError:
    print("Install httpx: pip install httpx", file=sys.stderr)
    sys.exit(1)


def collect_packages() -> list[dict[str, Any]]:
    system = platform.system().lower()
    if system == "linux":
        try:
            out = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True, timeout=120)
            pkgs = []
            for line in out.splitlines()[:2000]:
                if "\t" in line:
                    name, ver = line.split("\t", 1)
                    pkgs.append({"name": name, "version": ver})
            return pkgs
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
    if system == "windows":
        try:
            ps = (
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
                "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                "| Select-Object DisplayName, DisplayVersion | ConvertTo-Json"
            )
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps], text=True, timeout=120)
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            return [{"name": d.get("DisplayName"), "version": d.get("DisplayVersion")} for d in data if d.get("DisplayName")][:2000]
        except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
            pass
    return []


def collect_processes() -> list[dict[str, Any]]:
    system = platform.system().lower()
    if system == "linux":
        try:
            out = subprocess.check_output(["ps", "-eo", "comm="], text=True, timeout=30)
            return [{"name": line.strip()} for line in out.splitlines() if line.strip()][:500]
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
    if system == "windows":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", "Get-Process | Select-Object -ExpandProperty ProcessName | ConvertTo-Json"],
                text=True,
                timeout=30,
            )
            data = json.loads(out)
            if isinstance(data, str):
                data = [data]
            return [{"name": n} for n in data][:500]
        except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
            pass
    return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Vuln agent inventory collector (not EDR)")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--hostname", default=platform.node())
    args = parser.parse_args()

    inventory = {
        "platform": platform.platform(),
        "packages": collect_packages(),
        "processes": collect_processes(),
        "collector": "vuln-agent/1.0",
        "edr_mode": False,
    }

    headers = {"Authorization": f"Bearer {args.token}", "Content-Type": "application/json"}
    base = args.api_url.rstrip("/")

    with httpx.Client(timeout=60.0) as client:
        inv_resp = client.post(
            f"{base}/api/vuln/agents/{args.agent_id}/inventory",
            headers=headers,
            json={"case_id": args.case_id, "hostname": args.hostname, "inventory": inventory},
        )
        inv_resp.raise_for_status()
        print("Inventory:", inv_resp.json())

        findings = []
        for pkg in inventory["packages"][:50]:
            name = (pkg.get("name") or "").lower()
            if any(k in name for k in ("openssl", "log4j", "openssh")):
                findings.append(
                    {
                        "plugin_id": f"AGENT-PKG-{hash(name) % 100000}",
                        "synopsis": f"Installed package: {pkg.get('name')} {pkg.get('version') or ''}".strip(),
                        "severity": "medium",
                        "cvss": 5.0,
                    }
                )
        if findings:
            find_resp = client.post(
                f"{base}/api/vuln/agents/{args.agent_id}/findings",
                headers=headers,
                json={"case_id": args.case_id, "findings": findings},
            )
            find_resp.raise_for_status()
            print("Findings:", find_resp.json())


if __name__ == "__main__":
    main()
