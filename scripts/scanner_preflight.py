#!/usr/bin/env python3
"""Scanner connectivity preflight intended to run inside worker-nessus."""

from __future__ import annotations

import os
import socket
import sys
from urllib.parse import urlparse


def check_tcp(label: str, raw_url: str, default_port: int) -> tuple[bool, str]:
    if not raw_url:
        return False, f"{label}: URL not configured"
    parsed = urlparse(raw_url if "://" in raw_url else f"tcp://{raw_url}")
    host = parsed.hostname or ""
    port = parsed.port or default_port
    if not host:
        return False, f"{label}: invalid URL {raw_url!r}"
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{label}: DNS failed for {host}: {exc}"
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError as exc:
        return False, f"{label}: {host}:{port} resolved but connection failed: {exc}"
    ips = sorted({item[4][0] for item in addresses})
    return True, f"{label}: {host}:{port} OK ({', '.join(ips[:3])})"


def main() -> int:
    failures = 0
    print("Vulnerability scanner preflight")
    print(f"GVM_URL={os.getenv('GVM_URL', '')}")
    print(f"GVM_SOCKET_PATH={os.getenv('GVM_SOCKET_PATH', '')}")

    try:
        from app.services.greenbone_client import GreenboneClient

        client = GreenboneClient()
        status = client.server_status()
        if status.get("status") == "ok":
            print(f"PASS Greenbone/GMP: {status}")
            readiness = client.scan_readiness()
            if readiness.get("status") == "ok":
                print(f"PASS Greenbone scan readiness: {readiness}")
            else:
                failures += 1
                print(f"FAIL Greenbone scan readiness: {readiness}")
        else:
            failures += 1
            print(f"FAIL Greenbone/GMP: {status}")
    except Exception as exc:
        failures += 1
        print(f"FAIL Greenbone/GMP: {exc}")

    checks = [
        ("ZAP", os.getenv("ZAP_API_URL", ""), 8080),
        ("Trivy", os.getenv("TRIVY_SERVER_URL", ""), 4954),
        ("Wazuh", os.getenv("WAZUH_API_URL", ""), 55000),
    ]
    for label, url, port in checks:
        ok, message = check_tcp(label, url, port)
        print(("PASS " if ok else "WARN ") + message)

    try:
        import shutil

        print(f"{'PASS' if shutil.which('nmap') else 'WARN'} nmap CLI: {shutil.which('nmap') or 'not installed'}")
        print(f"{'PASS' if shutil.which('trivy') else 'WARN'} trivy CLI: {shutil.which('trivy') or 'not installed'}")
        print(f"{'PASS' if shutil.which('nuclei') else 'WARN'} nuclei CLI: {shutil.which('nuclei') or 'not installed (engine will be skipped)'}")
    except Exception as exc:
        print(f"WARN CLI checks failed: {exc}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
