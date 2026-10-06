#!/usr/bin/env python3
"""Phase 2 E2E: firm admin creates job, registers host path, polls until disk_ready."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("API_BASE", "http://localhost:8080").rstrip("/")
TENANT = os.environ.get("E2E_TENANT", "acme")
EMAIL = os.environ.get("E2E_ADMIN_EMAIL", "")
PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "")
EVIDENCE_PATH = os.environ.get("E2E_EVIDENCE_PATH", "")


def _request(method: str, path: str, headers: dict, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"{API}{path}", data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    if not EMAIL or not PASSWORD:
        print("Set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD", file=sys.stderr)
        return 1
    if not EVIDENCE_PATH:
        print("Set E2E_EVIDENCE_PATH to a folder with disk segment files", file=sys.stderr)
        return 1

    headers = {"X-Tenant": TENANT}
    try:
        login = _request("POST", "/api/auth/login", headers, {"email": EMAIL, "password": PASSWORD})
        headers["Authorization"] = f"Bearer {login['access_token']}"

        job = _request("POST", "/api/jobs", headers, {"type": "host_disk"})
        job_id = job["id"]
        print(f"Created job {job_id}")

        _request(
            "POST",
            f"/api/jobs/{job_id}/evidence/ingest-path",
            headers,
            {"path": EVIDENCE_PATH, "source_type": "disk", "auto_process": True},
        )
        print("Registered segments and queued disk build")

        deadline = time.time() + 3600
        while time.time() < deadline:
            data = _request("GET", f"/api/jobs/{job_id}", headers)
            status = data["status"]
            pct = data.get("progress_pct", 0)
            print(f"  status={status} progress={pct}%")
            if status == "disk_ready":
                print(f"Extracted disk: {data.get('extracted_disk_uri')}")
                return 0
            if status == "failed":
                print(f"Failed: {data.get('error')}", file=sys.stderr)
                return 1
            time.sleep(5)
    except urllib.error.HTTPError as exc:
        print(exc.read().decode(), file=sys.stderr)
        return 1

    print("Timed out waiting for disk_ready", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
