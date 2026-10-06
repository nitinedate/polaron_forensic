"""Bridge Docker API → examiner host drive helper for USB mobile detection/acquire.

The Device Wizard runs inside the API container, which has no USB and usually no
adb/idevice binaries. Live phones are visible only on the Windows host where
``scripts/host-drive-helper.ps1`` runs (port 9876) with ``tools/platform-tools``
and ``tools/libimobiledevice``.

When local tooling is missing, acquisition endpoints consult the host helper.
Long acquires are started asynchronously so ``/health`` stays responsive.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("mobile_acquire.host_bridge")

# Host helper job ids are Guid N (32 hex). Docker registry ids are 16 hex.
_HOST_JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$", re.I)

DEFAULT_HELPER_URL = "http://host.docker.internal:9876"
DEFAULT_ACQUIRE_TIMEOUT_SEC = 0.0
POLL_INTERVAL_SEC = 2.0
_TERMINAL_PROGRESS = frozenset({"complete", "completed", "failed", "cancelled", "done"})
_ACTIVE_HELPER_URL: str | None = None


def _candidate_helper_urls() -> list[str]:
    configured = (os.environ.get("HOST_DRIVE_HELPER_URL") or DEFAULT_HELPER_URL).rstrip("/")
    out: list[str] = []
    for value in (
        configured,
        DEFAULT_HELPER_URL,
        "http://gateway.docker.internal:9876",
        "http://172.17.0.1:9876",
        "http://192.168.65.254:9876",
    ):
        value = value.rstrip("/")
        if value and value not in out:
            out.append(value)
    return out


def helper_base_url() -> str:
    return _ACTIVE_HELPER_URL or _candidate_helper_urls()[0]


def is_host_job_id(run_id: str | None) -> bool:
    return bool(_HOST_JOB_ID_RE.match(str(run_id or "").strip()))


def fetch_helper_jobs() -> list[dict[str, Any]]:
    """Running USB collections owned by the Windows host helper (not this API process)."""
    if not helper_reachable():
        return []
    data = _get_json("/acquisition/jobs", timeout_sec=8.0)
    if not data:
        return []
    jobs = data.get("jobs")
    return list(jobs) if isinstance(jobs, list) else []


def fetch_helper_job(job_id: str) -> dict[str, Any] | None:
    if not job_id or not helper_reachable():
        return None
    data = _get_json(f"/acquisition/job/{job_id}", timeout_sec=8.0)
    if not data:
        return None
    status = str(data.get("status") or "").lower()
    if status in ("not_found", "missing"):
        return None
    if data.get("job_id") is None:
        data["job_id"] = job_id
    return data


def helper_job_as_run(job: dict[str, Any], *, detail: bool = False) -> dict[str, Any]:
    """Shape a helper job like AcquisitionRun.summary()/detail() for the wizard."""
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    rec = result.get("acquisition_record") if isinstance(result.get("acquisition_record"), dict) else {}
    status_raw = str(job.get("status") or "running").lower()
    if status_raw in ("completed", "failed", "cancelled"):
        status = status_raw
    else:
        status = "running"
    def _as_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    files_seen = _as_int(job.get("files_seen") or rec.get("file_count") or rec.get("files_seen"))
    bytes_done = _as_int(job.get("bytes_done") or rec.get("output_size") or rec.get("bytes_done"))
    pct_raw = job.get("progress_pct")
    if pct_raw in (None, "", 0, 0.0):
        pct_raw = result.get("progress_pct")
    try:
        progress_pct = float(pct_raw) if pct_raw not in (None, "") else None
    except (TypeError, ValueError):
        progress_pct = None
    if progress_pct is not None and progress_pct <= 0:
        progress_pct = None
    detail_text = str(
        job.get("detail")
        or result.get("detail")
        or ("Collection in progress on this PC" if status == "running" else status)
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary: dict[str, Any] = {
        "run_id": str(job.get("job_id") or job.get("run_id") or ""),
        "run_name": str(job.get("run_name") or result.get("run_name") or ""),
        "case_id": str(job.get("case_id") or result.get("case_id") or ""),
        "evidence_id": str(job.get("evidence_id") or ""),
        "adapter": str(job.get("adapter") or result.get("adapter") or "android_mtp"),
        "device_id": str(job.get("device_id") or ""),
        "examiner": "",
        "status": status,
        "started_utc": str(job.get("started_utc") or now),
        "ended_utc": job.get("ended_utc") if status != "running" else None,
        "cancel_requested": False,
        "progress": {
            "stage": "acquire" if status == "running" else status,
            "item": str(job.get("item") or result.get("item") or ("collecting" if status == "running" else status)),
            "detail": detail_text,
            "category": str(job.get("category") or result.get("category") or ""),
            "bytes_done": bytes_done,
            "bytes_total": None,
            "progress_pct": progress_pct,
            "progress_mode": "bytes" if progress_pct is not None else "estimated",
            "files_seen": files_seen,
            "output_path": str(job.get("output_path") or result.get("output_path") or ""),
            "case_path": str(job.get("case_path") or result.get("case_path") or ""),
            "media_path": str(job.get("media_path") or result.get("media_path") or ""),
            "updated_utc": now,
        },
        "error": job.get("error") or result.get("error"),
        "host_job": True,
        "host_job_id": str(job.get("job_id") or ""),
    }
    from app.services.mobile_platform_agents import detect_mobile_platform, owner_agent_id, owner_agent_label

    family = detect_mobile_platform(summary.get("adapter"), job, result)
    if family:
        summary["owner_agent"] = owner_agent_id(family)
        summary["owner_agent_label"] = owner_agent_label(family)
        summary["os_family"] = family
    if detail:
        return {**summary, "result": result or None}
    return summary


def helper_reachable(timeout_sec: float = 2.0) -> bool:
    global _ACTIVE_HELPER_URL
    last_exc: Exception | None = None
    for base in _candidate_helper_urls():
        try:
            req = urllib.request.Request(f"{base}/health", method="GET")
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                if bool(data.get("ok")):
                    _ACTIVE_HELPER_URL = base
                    return True
        except Exception as exc:
            last_exc = exc
            continue
    _ACTIVE_HELPER_URL = None
    if last_exc is not None:
        log.debug("host helper unreachable: %s", last_exc)
    return False


def _get_json(path: str, *, timeout_sec: float = 30.0) -> dict[str, Any] | None:
    url = f"{helper_base_url()}{path}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        log.warning("host helper GET %s failed: %s", path, exc)
        return None


def _post_json(path: str, body: dict[str, Any], *, timeout_sec: float = 1800.0) -> dict[str, Any] | None:
    url = f"{helper_base_url()}{path}"
    raw = json.dumps(body).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
            return json.loads(detail)
        except Exception:
            log.warning("host helper POST %s HTTP %s", path, exc.code)
            return {"ok": False, "error": f"host helper HTTP {exc.code}"}
    except Exception as exc:
        log.warning("host helper POST %s failed: %s", path, exc)
        return None


def _windows_to_docker_path(path: str) -> Path | None:
    cr = (path or "").strip().replace("\\", "/")
    if len(cr) >= 2 and cr[1] == ":" and cr[0].isalpha():
        letter = cr[0].lower()
        rest = cr[2:].lstrip("/")
        return Path("/host") / letter / rest if rest else Path("/host") / letter
    if cr.startswith("/host/"):
        return Path(cr)
    return None


def _read_progress_file(progress_file: str | None) -> dict[str, Any] | None:
    """Read host progress JSON via Docker bind mounts (or direct path)."""
    if not progress_file:
        return None
    candidates: list[Path] = []
    mapped = _windows_to_docker_path(progress_file)
    if mapped is not None:
        candidates.append(mapped)
    candidates.append(Path(progress_file))
    # Common case-root relative form used by the wizard.
    name = Path(progress_file.replace("\\", "/")).name
    if name.startswith(".acq_progress_"):
        candidates.append(Path("/host/e/rag_new2/evidence/cases") / name)
        candidates.append(Path("/evidence/cases") / name)
    for cand in candidates:
        try:
            if not cand.is_file():
                continue
            data = json.loads(cand.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None


def fetch_host_adapters() -> list[dict[str, Any]]:
    data = _get_json("/acquisition/adapters", timeout_sec=3.0)
    if not data:
        # Helper /health can be up while a queued probe used to hang. Treat MTP
        # as available so Docker does not report empty USB tooling.
        return [
            {"name": "android_mtp", "os_family": "android", "available": True,
             "reason": "Windows MTP/WPD on examiner host", "via": "host"},
            {"name": "android_adb", "os_family": "android", "available": True,
             "reason": "Host USB helper", "via": "host"},
            {"name": "ios_lockdown", "os_family": "ios", "available": True,
             "reason": "Host USB helper", "via": "host"},
        ]
    return list(data.get("adapters") or [])


def fetch_host_devices() -> tuple[list[dict[str, Any]], list[str]]:
    data = _get_json("/acquisition/devices", timeout_sec=3.0)
    if not data:
        mobile = _get_json("/mobile-devices", timeout_sec=3.0) or {}
        raw = list(mobile.get("mobile_devices") or [])
        mapped: list[dict[str, Any]] = []
        for item in raw:
            os_hint = str(item.get("os_hint") or "android")
            mapped.append({
                "adapter": "ios_lockdown" if os_hint == "ios" else "android_mtp",
                "device_id": item.get("id") or item.get("instance_id") or "",
                "label": item.get("name") or "Phone",
                "status": "wpd",
                "os_family": os_hint,
                "instance_id": item.get("instance_id") or "",
                "connection": item.get("connection") or "mtp",
            })
        if mapped:
            return mapped, []
        return [], [
            "Host drive helper did not return devices. Plug the phone into the PC "
            "running the helper (office server or this workstation) with a data cable. "
            "No extra adapter is required."
        ]
    return list(data.get("devices") or []), list(data.get("warnings") or [])


def merge_adapters(local: list[dict[str, Any]], host: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer host availability for phone adapters when Docker lacks USB tools."""
    by_name = {a["name"]: dict(a) for a in local}
    for h in host:
        name = h.get("name")
        if not name:
            continue
        cur = by_name.get(name) or {
            "name": name,
            "os_family": h.get("os_family") or "",
            "available": False,
            "reason": "",
        }
        if h.get("available") and not cur.get("available"):
            cur["available"] = True
            cur["reason"] = h.get("reason") or "Available via examiner host drive helper (USB)."
            cur["via"] = "host"
        elif h.get("available"):
            cur["via"] = cur.get("via") or "host"
            if not cur.get("reason"):
                cur["reason"] = h.get("reason") or ""
        elif not cur.get("available"):
            cur["reason"] = h.get("reason") or cur.get("reason") or (
                "adb/idevice not found in API container; start host drive helper on the PC."
            )
        by_name[name] = cur
    return list(by_name.values())


def host_preview(adapter: str, device_id: str) -> dict[str, Any] | None:
    return _post_json(
        "/acquisition/preview",
        {"adapter": adapter, "device_id": device_id},
        timeout_sec=120.0,
    )


def _coerce_job_result(status: dict[str, Any]) -> dict[str, Any] | None:
    result = status.get("result")
    if isinstance(result, dict) and (
        result.get("paths")
        or result.get("run_name")
        or result.get("stage_reached")
        or "ok" in result
    ):
        return result
    if "ok" in status and ("paths" in status or "run_name" in status):
        return {k: v for k, v in status.items() if k not in ("status", "job_id", "result_file", "result_bytes")}
    return None


def host_cancel_job(job_id: str = "", progress_file: str = "") -> dict[str, Any] | None:
    """Ask the host helper to kill the acquire process tree immediately."""
    body: dict[str, Any] = {}
    if job_id:
        body["job_id"] = job_id
    if progress_file:
        body["progress_file"] = progress_file
    return _post_json("/acquisition/cancel", body, timeout_sec=8.0)


def host_remove_job(
    job_id: str = "",
    *,
    run_name: str = "",
    case_id: str = "",
    progress_file: str = "",
    paths: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Stop the host acquire and delete this run's folders and staging backup."""
    body: dict[str, Any] = {}
    if job_id:
        body["job_id"] = job_id
    if run_name:
        body["run_name"] = run_name
    if case_id:
        body["case_id"] = case_id
    if progress_file:
        body["progress_file"] = progress_file
    if paths:
        body["paths"] = paths
    return _post_json("/acquisition/remove", body, timeout_sec=60.0)


def _cancelled_result(detail: str = "Cancelled by examiner") -> dict[str, Any]:
    return {
        "ok": False,
        "run_name": "",
        "stage_reached": "cancelled",
        "paths": {},
        "errors": [detail],
        "warnings": [
            "Collection was stopped. Any files already written stay in the case folder "
            "and can be recovered as an interrupted extraction."
        ],
        "acquisition_record": {"output_size": 0},
        "evidence_package": {"run_name": "", "complete": False, "extraction_data": []},
    }


def host_run_acquire(
    payload: dict[str, Any],
    *,
    should_cancel: Any = None,
    on_job: Any = None,
) -> dict[str, Any] | None:
    """Run full UFED-aligned acquire on the host (long timeout).

    Starts an async job on the helper so ``/health`` stays up, then polls until
    the result file is written. Must exceed the longest adapter timeout
    (iOS backup communicate = 8h).

    Large result JSON is NOT inlined over HTTP (that hung the UI for hours after
    a successful ~80GB iPhone pull). Instead we watch the progress file for
    ``stage=complete`` and return a slim result so the registry can recover
    sealed paths from disk.
    """
    timeout_sec = float(
        os.environ.get("HOST_ACQUIRE_TIMEOUT_SEC") or DEFAULT_ACQUIRE_TIMEOUT_SEC
    )
    progress_file = str(payload.get("progress_file") or "").strip() or None
    adapter = str(payload.get("adapter") or "").lower()
    run_path = "/acquisition/run"
    if "mtp" in adapter:
        run_path = "/acquisition/run?native=mtp"
    elif "ios" in adapter:
        run_path = "/acquisition/run?native=ios"
    start = _post_json(run_path, payload, timeout_sec=120.0)
    if not start:
        return None

    # Legacy sync helper: full result in the POST response.
    if not start.get("async") and (
        start.get("stage_reached")
        or start.get("paths")
        or start.get("run_name")
        or ("ok" in start and not start.get("job_id"))
    ):
        return start

    job_id = str(start.get("job_id") or "").strip()
    if not job_id:
        return start
    if callable(on_job):
        try:
            on_job(job_id)
        except Exception:
            log.debug("on_job callback failed", exc_info=True)
    if not progress_file:
        progress_file = str(start.get("progress") or "").strip() or None

    deadline = None if timeout_sec <= 0 else time.time() + timeout_sec
    last_err: str | None = None
    while deadline is None or time.time() < deadline:
        if callable(should_cancel):
            try:
                cancelled = bool(should_cancel())
            except Exception:
                cancelled = False
            if cancelled:
                host_cancel_job(job_id, progress_file or "")
                return _cancelled_result()
        # Fast path: progress file says complete — do not wait on a multi‑MB result body.
        prog = _read_progress_file(progress_file)
        if prog and str(prog.get("stage") or "").strip().lower() in _TERMINAL_PROGRESS:
            stage = str(prog.get("stage") or "complete").strip().lower()
            ok = stage not in ("failed", "cancelled")
            return {
                "ok": ok,
                "run_name": str(prog.get("run_name") or ""),
                "stage_reached": "complete" if ok else stage,
                "paths": {},
                "errors": [] if ok else [str(prog.get("detail") or "Host acquisition failed")],
                "warnings": [
                    "Host progress reported completion; sealed evidence paths will be "
                    "recovered from the case folder."
                ],
                "acquisition_record": {
                    "output_size": int(prog.get("bytes_done") or 0),
                },
                "evidence_package": {
                    "run_name": str(prog.get("run_name") or ""),
                    "complete": ok,
                    "extraction_data": [],
                },
            }

        status = _get_json(f"/acquisition/job?id={job_id}", timeout_sec=60.0)
        if not status:
            last_err = "Host helper job poll failed"
            time.sleep(POLL_INTERVAL_SEC)
            continue
        state = str(status.get("status") or "").lower()
        if state in ("completed", "failed", "cancelled"):
            result = _coerce_job_result(status)
            if isinstance(result, dict):
                # Slim helper responses intentionally omit paths — callers recover from disk.
                return result
            if state == "cancelled":
                return _cancelled_result(str(status.get("error") or "Cancelled by examiner"))
            return {
                "ok": False,
                "error": status.get("error") or "Host acquisition job finished without result",
                "errors": [status.get("error") or "Host acquisition job finished without result"],
                "stage_reached": "failed",
                "paths": {},
            }
        if state == "not_found":
            # Helper may have been restarted after completion — trust progress file / disk recovery.
            prog = _read_progress_file(progress_file)
            if prog and str(prog.get("stage") or "").strip().lower() in _TERMINAL_PROGRESS:
                return {
                    "ok": True,
                    "run_name": str(prog.get("run_name") or ""),
                    "stage_reached": "complete",
                    "paths": {},
                    "warnings": [
                        "Host job id was lost after helper restart; recovering from progress/disk."
                    ],
                    "errors": [],
                    "acquisition_record": {"output_size": int(prog.get("bytes_done") or 0)},
                    "evidence_package": {
                        "run_name": str(prog.get("run_name") or ""),
                        "complete": True,
                        "extraction_data": [],
                    },
                }
            return {
                "ok": False,
                "error": f"Host acquisition job {job_id} not found",
                "errors": [f"Host acquisition job {job_id} not found"],
                "stage_reached": "failed",
                "paths": {},
            }
        time.sleep(POLL_INTERVAL_SEC)

    return {
        "ok": False,
        "error": last_err or f"Host acquisition timed out after {int(timeout_sec)}s",
        "errors": [last_err or f"Host acquisition timed out after {int(timeout_sec)}s"],
        "stage_reached": "failed",
        "paths": {},
        "warnings": [
            "Timed out waiting for the host helper. If the phone backup is still "
            "running, evidence may still be written — check 02_Original_Extraction."
        ],
    }
