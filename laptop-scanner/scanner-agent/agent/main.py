"""Poll the central API for edge scan jobs and run them on local OpenVAS."""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone

import httpx

from concurrent.futures import Future, ThreadPoolExecutor

from pathlib import Path
from typing import Any

from agent.api_client import CentralApi
from agent.capacity import IP_WORKERS_MIN, probe_laptop_capacity
from agent.gmp_local import LocalOpenVAS
from agent.ip_audit import emit_ip_event
from agent.ip_semaphore import AdaptiveIPSemaphore
from agent.job_identity import (
    host_set,
    leftover_blocks_skip_complete,
    network_key,
    plan_resume_chunks,
    remaining_hosts,
    stored_task_entries,
)
from agent.lan_fingerprint import (
    capture_lan_fingerprint,
    is_docker_nat_fingerprint,
    lan_changed,
    should_watch_lan,
)
from agent.log_shipper import install_log_shipper, set_current_job_id
from agent.target_progress import build_target_progress
from agent.service_policy import clip_policy_snapshots

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("scanner_agent")


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _read_agent_token() -> str:
    token_file = Path(os.environ.get("AGENT_TOKEN_FILE") or "/run/aetheris-agent/agent-token")
    try:
        if token_file.is_file():
            value = token_file.read_text(encoding="utf-8-sig").strip()
            if value:
                return value
    except OSError:
        log.warning("Unable to read AGENT_TOKEN_FILE=%s; falling back to environment", token_file)
    return (os.environ.get("AGENT_TOKEN") or "").strip()


def _agent_build() -> str:
    try:
        from agent import AGENT_BUILD

        return str(AGENT_BUILD)
    except Exception:
        return "unknown"


def _read_agent_version() -> str:
    build = _agent_build()
    if build != "unknown":
        # Source build is authoritative; a retained deployment env/version file
        # must not advertise old code after a source-only laptop update.
        release, _, suffix = build.partition("-")
        return release + ("+" + suffix if suffix else "")
    version_file = Path(os.environ.get("AGENT_VERSION_FILE") or "/app/.agent-version")
    try:
        if version_file.is_file():
            value = version_file.read_text(encoding="utf-8-sig").strip()
            if value:
                return value
    except OSError:
        log.warning("Unable to read AGENT_VERSION_FILE=%s; falling back to environment", version_file)
    base = (os.environ.get("AGENT_VERSION") or "1.5.3").strip() or "1.5.3"
    return base if build == "unknown" or base.endswith(build.split("-", 1)[-1]) else f"{base}+{build.split('-', 1)[-1]}"


def _cfg() -> dict[str, Any]:
    base = (os.environ.get("CENTRAL_API_URL") or "").strip()
    tenant = (os.environ.get("TENANT_SLUG") or "").strip()
    token = _read_agent_token()
    if not base or not tenant or not token:
        log.error("CENTRAL_API_URL, TENANT_SLUG, and AGENT_TOKEN/AGENT_TOKEN_FILE are required")
        sys.exit(1)
    return {
        "api": CentralApi(
            base_url=base,
            tenant=tenant,
            token=token,
            verify_tls=_env_bool("VERIFY_TLS", True),
        ),
        "openvas": LocalOpenVAS(),
        "poll": max(5, int(os.environ.get("POLL_INTERVAL_SEC") or 15)),
        "heartbeat": max(15, int(os.environ.get("HEARTBEAT_INTERVAL_SEC") or 60)),
        # Queue dispatch is intentionally separate from GMP polling. A short
        # dispatcher interval lets a newly queued job fill an available worker
        # slot without waiting for an unrelated scan's next GMP poll.
        "queue_poll": max(1, min(30, int(os.environ.get("QUEUE_POLL_INTERVAL_SEC") or 3))),
        # Bounded concurrency prevents head-of-line blocking without spawning an
        # unbounded number of OpenVAS scans. Tune for laptop capacity; 1..8.
        "max_concurrent_jobs": max(1, min(8, int(os.environ.get("MAX_CONCURRENT_SCAN_JOBS") or 1))),
        # A hung NVT (TCP 445 connect loop) freezes one IP at 90-98%.
        # Harvest that tail from the report already written. 0 disables it.
        "high_progress_warn_sec": max(60, int(os.environ.get("HIGH_PROGRESS_WARN_SEC") or 300)),
        "high_progress_stall_sec": _env_stall_sec(),
        "high_progress_stall_pct": max(80, min(99, int(os.environ.get("HIGH_PROGRESS_STALL_PCT") or 90))),
        # Optional absolute safety ceiling. This is NOT a progress-based timeout.
        # Set to 0 to disable. Default is disabled; configure explicitly if desired.
        "max_scan_runtime_sec": max(0, int(os.environ.get("MAX_SCAN_RUNTIME_SEC") or 0)),
        "version": _read_agent_version(),
    }


def _env_stall_sec() -> int:
    raw = os.environ.get("HIGH_PROGRESS_STALL_SEC")
    if raw is None or str(raw).strip() == "":
        return 45
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 45


def ip_tail_should_harvest(progress: float, unchanged_sec: float, *, stall_sec: int, stall_pct: int) -> bool:
    """True when one IP is frozen in the OpenVAS tail (typically 90-98%)."""
    if stall_sec <= 0:
        return False
    try:
        pct = int(float(progress))
    except (TypeError, ValueError):
        return False
    return pct >= int(stall_pct) and unchanged_sec >= float(stall_sec)


def seal_tail_harvest(details: dict[str, Any], host: str, *, reason: str) -> bool:
    """Accept a frozen tail only when this IP is already in the report.

    Returning False leaves the scan running. A climbing scan is never sealed.
    """
    import ipaddress
    from datetime import datetime, timezone

    vulns = list(details.get("vulnerabilities") or [])
    ev = dict(details.get("evidence") or {})
    report_id = str(ev.get("report_id") or "").strip()
    if not report_id:
        return False

    def _norm(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text.casefold()

    wanted = _norm(host)
    hosts: set[str] = set()
    for item in list(ev.get("assessed_hosts") or []) + [row.get("host") for row in vulns]:
        normalized = _norm(str(item or ""))
        if normalized:
            hosts.add(normalized)
    if not wanted or wanted not in hosts:
        return False

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assessed = sorted(hosts)
    ev["report_id"] = report_id
    ev["task_status"] = "done"
    ev["assessed_hosts"] = assessed
    ev["hosts_attempted"] = max(int(ev.get("hosts_attempted") or 0), len(assessed), 1)
    ev["hosts_assessed"] = len(assessed)
    ev["missing_ip_targets"] = []
    ev["target_identity_ok"] = True
    ev["report_result_count"] = len(vulns)
    ev["report_read_error"] = None
    ev["scan_start"] = ev.get("scan_start") or now
    ev["scan_end"] = ev.get("scan_end") or now
    ev["assessment_complete"] = True
    ev["assessment_verdict"] = "tail_stall_harvest"
    details["evidence"] = ev
    details["vulnerabilities"] = vulns
    details["status"] = "completed"
    details["gmp_status"] = "done"
    details["partial"] = True
    details["partial_reason"] = reason
    return True


def _patch_job_best_effort(api: CentralApi, job_id: str, payload: dict[str, Any]) -> bool | None:
    """Return True on success, False when the update should be retried, None when the job is gone."""
    try:
        api.patch_job(job_id, payload)
        return True
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 404:
            log.error(
                "Central API has no job %s for this scanner; progress cannot be saved",
                job_id,
            )
            return None
        log.warning(
            "Central API progress update failed for job %s; scan will continue and retry on the next poll",
            job_id,
            exc_info=True,
        )
        return False
    except Exception:
        log.warning(
            "Central API progress update failed for job %s; scan will continue and retry on the next poll",
            job_id,
            exc_info=True,
        )
        return False


def _upload_results_reliably(api: CentralApi, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    delay = 2.0
    while True:
        try:
            return api.upload_results(job_id, payload)
        except Exception as exc:
            if not api.is_retryable(exc):
                raise
            log.warning(
                "Central API result upload temporarily unavailable for job %s; retrying in %.0fs",
                job_id,
                delay,
                exc_info=True,
            )
            time.sleep(delay)
            delay = min(delay * 2.0, 60.0)


def _result_payload(
    *,
    details: dict[str, Any],
    task_id: str,
    status: str,
    partial: bool = False,
    partial_reason: str | None = None,
    error: str | None = None,
    skipped_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = dict(details.get("evidence") or {})
    raw_task = str(
        evidence.get("task_status") or details.get("gmp_status") or ""
    ).strip().lower()
    # Central verifier expects GMP terminal statuses, not agent "completed".
    if raw_task in {"completed", "complete", "success"}:
        raw_task = "done"
    elif not raw_task and status == "completed":
        raw_task = "done"
    skipped = skipped_hosts if skipped_hosts is not None else (evidence.get("skipped_hosts") or [])
    return {
        "vulnerabilities": details.get("vulnerabilities") or [],
        "status": status,
        "external_scan_id": task_id,
        "partial": bool(partial),
        "partial_reason": partial_reason,
        "error": error,
        "report_id": evidence.get("report_id"),
        "task_status": raw_task or None,
        "hosts_attempted": int(evidence.get("hosts_attempted") or 0),
        "hosts_assessed": int(evidence.get("hosts_assessed") or 0),
        "assessed_hosts": evidence.get("assessed_hosts") or [],
        "skipped_hosts": skipped,
        "report_result_count": int(evidence.get("report_result_count") or 0),
        "plugin_error_count": int(evidence.get("plugin_error_count") or 0),
        "plugin_error_details": evidence.get("plugin_error_details") or [],
        "host_coverage": evidence.get("host_coverage") or {},
        "service_coverage": evidence.get("service_coverage") or {},
        "policy_snapshots": evidence.get("policy_snapshots") or {},
        "degraded_hosts": evidence.get("degraded_hosts") or [],
        "scan_start": evidence.get("scan_start"),
        "scan_end": evidence.get("scan_end"),
        "assessment_complete": bool(evidence.get("assessment_complete")),
        "assessment_verdict": evidence.get("assessment_verdict"),
        "alive_test": evidence.get("alive_test"),
        "report_read_error": evidence.get("report_read_error"),
    }


def _parse_external_task_ids(raw: Any) -> list[str]:
    """Accept a single task id string or a JSON list of chunk task ids."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            import json

            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
    return [text]


def _encode_external_task_ids(task_ids: list[str]) -> str:
    import json

    clean = [str(t).strip() for t in task_ids if str(t).strip()]
    if len(clean) <= 1:
        return clean[0] if clean else ""
    return json.dumps(clean)


def _merge_chunk_details(
    chunk_results: list[tuple[list[str], dict[str, Any]]],
    *,
    all_targets: list[str],
    skipped_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Merge per-chunk OpenVAS poll payloads into one upload-shaped details dict."""
    import ipaddress

    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_report_ids: set[str] = set()
    assessed: set[str] = set()
    plugin_errors: list[Any] = []
    host_coverage: dict[str, dict[str, Any]] = {}
    service_coverage: dict[str, Any] = {}
    policy_snapshots: dict[str, Any] = {}
    report_ids: list[str] = []
    gmp_statuses: list[str] = []
    statuses: list[str] = []
    progresses: list[float] = []
    scan_starts: list[str] = []
    scan_ends: list[str] = []
    alive_test = ""
    report_read_errors: list[str] = []
    result_count = 0
    complete_chunks = 0
    skipped = [dict(x) for x in (skipped_hosts or []) if isinstance(x, dict)]
    skipped_set: set[str] = set()
    for item in skipped:
        host = str(item.get("host") or "").strip()
        if not host:
            continue
        try:
            skipped_set.add(str(ipaddress.ip_address(host)))
        except ValueError:
            skipped_set.add(host.casefold())

    for _chunk_targets, details in chunk_results:
        ev = details.get("evidence") or {}
        report_key = str(ev.get("report_id") or "").strip()
        if report_key and report_key in seen_report_ids:
            # Resume/retry can accidentally surface the exact same Greenbone
            # report twice. Skip the duplicate report as a unit while preserving
            # all distinct rows inside the first copy.
            continue
        if report_key:
            seen_report_ids.add(report_key)
        status = str(details.get("status") or "running")
        statuses.append(status)
        progresses.append(float(details.get("progress") or 0))
        for v in details.get("vulnerabilities") or []:
            # Forensic completeness: Greenbone can legitimately emit multiple
            # distinct result rows with the same plugin/host/port summary.  Only
            # dedupe when the scanner supplied a stable result identifier.
            result_id = str(
                v.get("result_id") or v.get("greenbone_result_id") or v.get("id") or ""
            ).strip()
            if result_id:
                key = f"result:{result_id}"
                if key in seen:
                    continue
                seen.add(key)
            vulns.append(v)
        for h in ev.get("assessed_hosts") or []:
            assessed.add(str(h).strip())
        result_count += int(ev.get("report_result_count") or 0)
        plugin_errors.extend(ev.get("plugin_error_details") or [])
        for cov_host, cov in (ev.get("host_coverage") or {}).items():
            if isinstance(cov, dict):
                host_coverage[str(cov_host)] = cov
        for cov_host, cov in (ev.get("service_coverage") or {}).items():
            if cov_host in all_targets and isinstance(cov, dict):
                service_coverage[str(cov_host)] = cov
        policy_snapshots.update(clip_policy_snapshots(ev.get("policy_snapshots"), all_targets))
        if ev.get("report_id"):
            report_ids.append(str(ev["report_id"]))
        raw_task = str(ev.get("task_status") or details.get("gmp_status") or "").strip().lower()
        if raw_task:
            gmp_statuses.append(raw_task)
        if ev.get("scan_start"):
            scan_starts.append(str(ev["scan_start"]))
        if ev.get("scan_end"):
            scan_ends.append(str(ev["scan_end"]))
        if ev.get("alive_test") and not alive_test:
            alive_test = str(ev["alive_test"])
        if ev.get("report_read_error"):
            report_read_errors.append(str(ev["report_read_error"])[:400])
        if status == "completed" and ev.get("assessment_complete"):
            complete_chunks += 1

    if any(s == "failed" for s in statuses) and not any(s == "running" for s in statuses):
        mapped = "failed"
    elif any(s == "stopped" for s in statuses) and not any(s == "running" for s in statuses):
        mapped = "stopped"
    elif statuses and all(s == "completed" for s in statuses):
        mapped = "completed"
    elif not chunk_results and skipped:
        # All targets eliminated as unreachable — nothing to scan.
        mapped = "completed"
    else:
        mapped = "running"

    terminal_gmp = {"done", "finished", "succeeded"}
    if not chunk_results and skipped:
        merged_task_status = "done"
    elif gmp_statuses and all(s in terminal_gmp for s in gmp_statuses):
        merged_task_status = "done"
    elif gmp_statuses and any(s in {"failed", "internal error"} for s in gmp_statuses):
        merged_task_status = next(s for s in gmp_statuses if s in {"failed", "internal error"})
    elif mapped == "completed":
        merged_task_status = "done"
    else:
        merged_task_status = gmp_statuses[0] if gmp_statuses else mapped

    required_targets: list[str] = []
    for target in all_targets:
        try:
            tip = str(ipaddress.ip_address(str(target).strip()))
        except ValueError:
            tip = str(target).strip()
            if tip.casefold() in skipped_set:
                continue
            required_targets.append(tip)
            continue
        if tip in skipped_set:
            continue
        required_targets.append(tip)

    normalized_assessed: set[str] = set()
    for host in assessed:
        try:
            normalized_assessed.add(str(ipaddress.ip_address(host)))
        except ValueError:
            if host:
                normalized_assessed.add(host.casefold())
    missing = [t for t in required_targets if t not in normalized_assessed]

    # Hosts we intended to scan but OpenVAS never evidenced → eliminate as unreachable.
    if mapped == "completed" and missing:
        for host in missing:
            skipped.append({"host": host, "reason": "unreachable"})
            skipped_set.add(host)
        required_targets = [t for t in required_targets if t not in skipped_set]
        missing = []

    coverage_ok = (
        mapped == "completed"
        and not missing
        and not report_read_errors
        and (
            (bool(report_ids) and bool(scan_starts) and bool(scan_ends))
            or (not required_targets and bool(skipped))
        )
    )
    assessment_complete = coverage_ok and (
        not required_targets
        or complete_chunks == len(chunk_results)
        or (len(chunk_results) > 0 and not missing)
    )

    progress = sum(progresses) / max(len(progresses), 1) if progresses else (100.0 if assessment_complete else 0.0)
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "status": mapped,
        "gmp_status": merged_task_status,
        "progress": progress,
        "vulnerabilities": vulns,
        "evidence": {
            "report_id": report_ids[0] if report_ids else ("skipped-unreachable" if skipped and not required_targets else None),
            "report_ids": report_ids,
            "task_status": merged_task_status,
            "progress": progress,
            "hosts_attempted": len(required_targets),
            "hosts_assessed": len(normalized_assessed) if normalized_assessed else 0,
            "assessed_hosts": sorted(assessed),
            "skipped_hosts": skipped,
            "missing_ip_targets": missing,
            "report_result_count": result_count,
            "plugin_error_count": len(plugin_errors),
            "plugin_error_details": plugin_errors[:50],
            "host_coverage": host_coverage,
            "service_coverage": service_coverage,
            "policy_snapshots": policy_snapshots,
            "degraded_hosts": sorted(
                h for h, c in host_coverage.items() if str((c or {}).get("verdict") or "").startswith("degraded")
            ),
            "scan_start": min(scan_starts) if scan_starts else (now_iso if assessment_complete and skipped else None),
            "scan_end": max(scan_ends) if scan_ends else (now_iso if assessment_complete and skipped else None),
            "assessment_complete": assessment_complete,
            "assessment_verdict": (
                "all_targets_unreachable_skipped"
                if assessment_complete and not required_targets and skipped
                else ("assessed" if assessment_complete else ("partial_or_running" if mapped == "running" else "incomplete_coverage"))
            ),
            "alive_test": alive_test or None,
            "report_read_error": "; ".join(report_read_errors[:3]) if report_read_errors else None,
            "chunk_count": len(chunk_results),
        },
    }


def _skipped_ip_details(host: str, reason: str, *, error: str | None = None, task_id: str | None = None) -> dict[str, Any]:
    """Terminal synthetic result for one omitted IP without failing sibling IPs."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "status": "completed",
        "gmp_status": "done",
        "progress": 100.0,
        "vulnerabilities": [],
        "evidence": {
            "task_status": "done",
            "assessment_complete": True,
            "assessment_verdict": "skipped_ip_error",
            "hosts_attempted": 0,
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": now,
            "scan_end": now,
            "skip_reason": reason,
            "skip_error": error,
            "task_id": task_id,
            "host": host,
        },
        "_agent_skip_reason": reason,
        "_agent_skip_error": error,
    }


def _run_job(cfg: dict[str, Any], job: dict[str, Any]) -> None:
    set_current_job_id(str(job.get("id") or "") or None)
    try:
        _run_job_body(cfg, job)
    finally:
        shipper = cfg.get("log_shipper")
        if shipper is not None:
            try:
                shipper.maybe_flush(force=True)
            except Exception:
                pass
        set_current_job_id(None)


def _run_job_body(cfg: dict[str, Any], job: dict[str, Any]) -> None:
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    job_id = str(job["id"])
    selected_targets = [t["target"] for t in (job.get("targets") or []) if t.get("target")]
    if not selected_targets:
        _patch_job_best_effort(api, job_id, {"status": "failed", "error": "No targets in job"})
        return

    if hasattr(openvas, "policy_snapshots"):
        openvas.policy_snapshots.update(clip_policy_snapshots(job.get("policy_snapshots"), selected_targets))
    prior_seq = job.get("progress_event_seq") or 0
    prior_seq = prior_seq if isinstance(prior_seq, int) and not isinstance(prior_seq, bool) and 0 <= prior_seq < 2**53 - 1 else 0
    sequence = max([prior_seq] + [int(s["event_seq"]) for s in (job.get("target_progress") or {}).values()
                          if isinstance(s, dict) and isinstance(s.get("event_seq"), int)
                          and not isinstance(s["event_seq"], bool) and 0 <= s["event_seq"] < 2**53 - 1])

    def target_snapshot(**kwargs: Any) -> dict[str, Any]:
        nonlocal sequence
        sequence += 1
        return build_target_progress(selected_targets, event_seq=sequence, **kwargs)

    from agent.reachability import partition_targets

    reach = partition_targets(selected_targets, job_id=job_id)
    skipped_hosts: list[dict[str, Any]] = list(reach.get("skipped_hosts") or [])
    reachable = list(reach.get("reachable") or [])
    # Resume from leftover work: do not rescan hosts this job already assessed.
    targets = remaining_hosts(
        selected=reachable,
        assessed=list(job.get("assessed_hosts") or []),
    )
    scanner_role = str(
        job.get("scanner_role") or os.environ.get("SCANNER_ROLE") or "portable"
    ).strip().lower()
    watch_lan = should_watch_lan(scanner_role)
    origin_fp = capture_lan_fingerprint() if watch_lan else {}
    orig_reachable = list(reachable)
    lan_misses = 0
    if watch_lan:
        log.info(
            "Portable LAN fingerprint for job %s gateway=%s subnet=%s source=%s",
            job_id,
            origin_fp.get("gateway") or "unknown",
            origin_fp.get("subnet") or "unknown",
            origin_fp.get("source") or "none",
        )
    if skipped_hosts:
        log.info(
            "Job %s eliminated %d unreachable IP(s); scanning %d reachable",
            job_id,
            len(skipped_hosts),
            len(targets),
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": 3,
                "message": (
                    f"Skipped {len(skipped_hosts)} unreachable IP(s); "
                    f"scanning {len(targets)} reachable"
                ),
            },
        )

    nets = network_key(selected_targets)
    if len(nets) > 1:
        log.warning(
            "Job %s targets span %d networks (%s); hosts off this LAN will be skipped",
            job_id,
            len(nets),
            ", ".join(sorted(nets)[:8]),
        )

    capacity = probe_laptop_capacity(force=True)
    stored = stored_task_entries(
        chunk_tasks=list(job.get("chunk_tasks") or []),
        external_scan_id=job.get("external_scan_id"),
    )
    live_hosts: dict[str, list[str] | None] = {}
    for item in stored:
        tid = str(item.get("task_id") or "").strip()
        if tid:
            live_hosts[tid] = openvas.get_task_hosts(tid)
    chunks, resume_map, dropped_tasks = plan_resume_chunks(
        job_hosts=selected_targets,
        remaining=targets,
        stored_tasks=stored,
        live_hosts=live_hosts,
        chunk_size=int(capacity["chunk_size"]),
    )
    if dropped_tasks:
        log.warning(
            "Job %s dropped %d OpenVAS task(s) that were missing or not this job's hosts: %s",
            job_id,
            len(dropped_tasks),
            ",".join(dropped_tasks[:6]),
        )

    if not chunks:
        if leftover_blocks_skip_complete(
            dropped_tasks=dropped_tasks,
            live_hosts=live_hosts,
            job_hosts=selected_targets,
        ):
            _patch_job_best_effort(
                api,
                job_id,
                {
                    "status": "failed",
                    "error": (
                        "Cannot resume: leftover OpenVAS task(s) belong to a different "
                        "host set or could not be read. Will not complete as skipped."
                    ),
                },
            )
            log.error(
                "Job %s refused to finish as skipped; leftover task(s) were the wrong network or unreadable: %s",
                job_id,
                ",".join(dropped_tasks[:6]),
            )
            return
        if dropped_tasks:
            log.info(
                "Job %s discarding %d stale OpenVAS task id(s) that no longer exist: %s",
                job_id,
                len(dropped_tasks),
                ",".join(dropped_tasks[:6]),
            )
            _patch_job_best_effort(
                api,
                job_id,
                {"external_scan_id": "", "chunk_tasks": []},
            )
        # Every selected IP was unreachable or already assessed, with nothing to harvest.
        merged = _merge_chunk_details([], all_targets=selected_targets, skipped_hosts=skipped_hosts)
        payload = _result_payload(
            details=merged,
            task_id="",
            status="completed",
            partial=False,
            skipped_hosts=skipped_hosts,
        )
        _upload_results_reliably(api, job_id, payload)
        log.info("Job %s completed with all %d target(s) skipped as unreachable", job_id, len(selected_targets))
        return

    # One permit == one IP.  Normal operation never drops below the requested
    # five-IP floor; a critical capacity plan pauses new admissions instead.
    ip_workers = max(1, min(max(IP_WORKERS_MIN, int(capacity["ip_workers"])), len(chunks)))
    for idx, chunk in enumerate(chunks):
        host = str(chunk[0]) if chunk else f"chunk-{idx}"
        emit_ip_event(job_id, host, "queued", chunk_index=idx, semaphore_limit=ip_workers)


    if resume_map:
        log.warning(
            "Resuming job %s with %d OpenVAS task(s) across %d host(s) from this job only",
            job_id,
            len(resume_map),
            sum(len(c) for c in chunks),
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": job.get("progress_pct"),
                "message": f"Resuming {len(resume_map)} OpenVAS task(s) for this network",
                "external_scan_id": _encode_external_task_ids(list(resume_map.values())),
                "chunk_tasks": [
                    {"task_id": tid, "hosts": chunks[idx]} for idx, tid in resume_map.items()
                ],
            },
        )
    else:
        log.info(
            "Claimed job %s targets=%d chunks=%d ip_workers=%d chunk_size=%d hot=%s",
            job_id,
            len(targets),
            len(chunks),
            ip_workers,
            capacity["chunk_size"],
            capacity["hot"],
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": 5,
                "message": f"Starting local OpenVAS ({len(chunks)} capacity-sized chunk(s))",
            },
        )

    # Wave fan-out: at most ip_workers OpenVAS tasks in flight. On resume, all
    # known task ids are already running so they enter the active set first.
    task_ids: list[str | None] = [None] * len(chunks)
    done_details: dict[int, dict[str, Any]] = {}
    pending: list[int] = list(range(len(chunks)))
    # A truncated port scan is reported incomplete. Re-running the same host
    # repeats the same Nmap kill, so the automatic re-run is off unless
    # SCAN_DEGRADED_RETRY is set.
    degraded_retries: dict[int, int] = {}
    degraded_retry_budget = max(0, int(os.environ.get("SCAN_DEGRADED_RETRY") or 0))
    in_flight: dict[int, str] = {}
    ip_started_mono: dict[int, float] = {}
    ip_last_state: dict[int, tuple[str, int]] = {}
    ip_progress_since: dict[int, tuple[int, float]] = {}
    slot_sem = AdaptiveIPSemaphore(max_permits=int(capacity.get("configured_ceiling") or 10))

    for idx, tid in resume_map.items():
        task_ids[idx] = tid
        in_flight[idx] = tid
        ip_started_mono[idx] = time.monotonic()
        if idx in pending:
            pending.remove(idx)
        host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
        emit_ip_event(job_id, host, "resumed", task_id=tid, chunk_index=idx)
    slot_sem.restore(len(in_flight))

    def _chunk_tasks_blob() -> list[dict[str, Any]]:
        return [
            {"task_id": tid, "hosts": list(chunks[idx])}
            for idx, tid in enumerate(task_ids)
            if tid
        ]

    def _append_skipped(host: str, reason: str, error: str | None = None) -> None:
        if not any(str(x.get("host") or "") == host for x in skipped_hosts):
            item: dict[str, Any] = {"host": host, "reason": reason}
            if error:
                item["error"] = error[:500]
            skipped_hosts.append(item)

    def _start_chunk(idx: int) -> str:
        existing = task_ids[idx]
        if existing:
            return existing
        chunk = list(chunks[idx])
        host = str(chunk[0]) if chunk else f"chunk-{idx}"
        if not host_set(chunk) <= host_set(selected_targets):
            raise RuntimeError(
                f"Refusing OpenVAS chunk {idx} for job {job_id}: hosts are not this job's targets"
            )
        emit_ip_event(job_id, host, "start_attempt", chunk_index=idx)

        discovered_range: str | None = None
        if getattr(openvas, "port_profile", "full") != "full":
            try:
                from agent.port_discovery import discovery_plan

                port_plan = discovery_plan(chunk)
                discovered_range = str(port_plan.get("port_range") or "").strip() or None
                open_by_host = port_plan.get("open_ports") or {}
                host_open = list(open_by_host.get(host) or [])
                emit_ip_event(
                    job_id,
                    host,
                    "port_discovery",
                    open_ports=host_open,
                    open_port_count=len(host_open),
                    port_range=discovered_range,
                    fallback=bool(port_plan.get("fallback")),
                    chunk_index=idx,
                )
                if host_open:
                    log.info(
                        "Job %s IP %s: discovery saw %d open TCP port(s) %s; "
                        "OpenVAS still scans the full Nessus-style service catalog",
                        job_id,
                        host,
                        len(host_open),
                        discovered_range,
                    )
                else:
                    log.info(
                        "Job %s IP %s: no candidate port answered the pre-probe; "
                        "OpenVAS still scans the full Nessus-style service catalog",
                        job_id,
                        host,
                    )
                # Do not pass the narrowed discovery range. A partial answer
                # (SMB only) used to delete SSH and TLS from the assessment.
                discovered_range = None
            except Exception as exc:
                # Discovery is an optimization only. Never drop an authorized target
                # because a quick pre-probe or local socket operation failed.
                emit_ip_event(
                    job_id, host, "port_discovery_error",
                    error=f"{exc.__class__.__name__}: {exc}", chunk_index=idx,
                )
                log.warning("Port discovery failed for %s; continuing with configured OpenVAS profile", host, exc_info=True)

        start_args = {"name": f"edge-{job_id[:8]}-c{idx}", "targets": chunk, "port_range": discovered_range}
        if job.get("scan_policy_request"):
            start_args["scan_policy"] = job["scan_policy_request"]
        tid = openvas.start_scan(**start_args)
        task_ids[idx] = tid
        if getattr(openvas, "policy_snapshots", None):
            _patch_job_best_effort(api, job_id, {"policy_snapshots": clip_policy_snapshots(openvas.policy_snapshots, selected_targets)})
        ip_started_mono[idx] = time.monotonic()
        emit_ip_event(job_id, host, "started", task_id=tid, chunk_index=idx)
        return tid

    def _fill_slots(workers: int, *, admission_paused: bool = False) -> None:
        if admission_paused:
            return
        live_limit = max(0, int(workers))
        while pending:
            if not slot_sem.try_acquire(live_limit):
                break
            idx = pending.pop(0)
            host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
            try:
                tid = _start_chunk(idx)
            except Exception as exc:
                # Per-IP best effort: omit only this IP, release its permit, and
                # immediately continue filling the same slot with the next IP.
                slot_sem.release()
                err = f"{exc.__class__.__name__}: {exc}"
                _append_skipped(host, "start_error", err)
                done_details[idx] = _skipped_ip_details(host, "start_error", error=err)
                emit_ip_event(job_id, host, "start_error", error=err, chunk_index=idx)
                log.warning("Skipping IP %s after OpenVAS start error; next IP may use the released slot", host, exc_info=True)
                continue
            in_flight[idx] = tid

    _fill_slots(ip_workers, admission_paused=bool(capacity.get("admission_paused")))

    def _external_blob() -> str:
        return _encode_external_task_ids([t for t in task_ids if t])

    external_blob = _external_blob()
    _patch_job_best_effort(
        api,
        job_id,
        {
            "status": "running",
            "progress_pct": 10,
            "message": (
                f"OpenVAS running ({len(in_flight)}/{len(chunks)} chunk(s) in flight, "
                f"{len(done_details)} done)"
            ),
            "external_scan_id": external_blob,
            "chunk_tasks": _chunk_tasks_blob(),
            "target_progress": target_snapshot(chunks=chunks,
                in_flight=in_flight, done_details=done_details, skipped_hosts=skipped_hosts,
                assessed_hosts=list(job.get("assessed_hosts") or [])),
        },
    )

    run_started = time.monotonic()
    last_progress = -1.0
    last_ip_status_sig: tuple[tuple[str, str, int], ...] | None = None
    last_change = run_started
    last_high_progress_notice = 0.0
    poll = cfg["poll"]
    high_progress_warn_sec = cfg["high_progress_warn_sec"]
    high_progress_stall_sec = int(cfg.get("high_progress_stall_sec") or 0)
    high_progress_stall_pct = int(cfg.get("high_progress_stall_pct") or 90)
    max_scan_runtime_sec = cfg["max_scan_runtime_sec"]

    while True:
        time.sleep(poll)
        if watch_lan:
            current_fp = capture_lan_fingerprint()
            left_lan = lan_changed(origin_fp, current_fp)
            if not left_lan and is_docker_nat_fingerprint(origin_fp) and orig_reachable:
                from agent.reachability import partition_targets as _reprobe

                still = _reprobe(orig_reachable)
                if not still.get("reachable"):
                    lan_misses += 1
                    left_lan = lan_misses >= 2
                else:
                    lan_misses = 0
            if left_lan:
                log.error(
                    "Portable scanner left original LAN for job %s (was %s now %s); stopping OpenVAS",
                    job_id,
                    origin_fp.get("gateway"),
                    current_fp.get("gateway"),
                )
                for tid in list(in_flight.values()):
                    try:
                        openvas.stop(tid)
                    except Exception:
                        log.warning("stop_task after LAN change failed for %s", tid, exc_info=True)
                _patch_job_best_effort(
                    api,
                    job_id,
                    {
                        "status": "failed",
                        "error": (
                            "Portable scanner left the original LAN mid-scan. OpenVAS was stopped. "
                            "Resume this same job after returning to the original network. "
                            "Targets were not merged with the new network."
                        ),
                    },
                )
                return
        capacity = probe_laptop_capacity()
        # Adaptive semaphore: >=5 permits whenever admission is allowed.  At a
        # critical thermal/memory state, new starts pause while in-flight IPs finish.
        ip_workers = max(1, min(max(IP_WORKERS_MIN, int(capacity["ip_workers"])), len(chunks)))

        # Poll in-flight chunks (bounded concurrency for GMP I/O).
        finished_idxs: list[int] = []
        poll_workers = max(1, min(ip_workers, len(in_flight) or 1))

        def _poll_one(idx: int) -> tuple[int, dict[str, Any]]:
            tid = in_flight[idx]
            host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
            try:
                return idx, openvas.poll(tid, expected_targets=chunks[idx])
            except Exception as exc:
                err = f"{exc.__class__.__name__}: {exc}"
                emit_ip_event(job_id, host, "poll_error", task_id=tid, error=err, chunk_index=idx)
                try:
                    openvas.stop(tid)
                    emit_ip_event(job_id, host, "stop_after_error", task_id=tid)
                except Exception as stop_exc:
                    emit_ip_event(
                        job_id, host, "stop_after_error_failed", task_id=tid,
                        error=f"{stop_exc.__class__.__name__}: {stop_exc}",
                    )
                return idx, _skipped_ip_details(host, "poll_error", error=err, task_id=tid)

        poll_results: dict[int, dict[str, Any]] = {}
        if in_flight:
            with ThreadPoolExecutor(max_workers=poll_workers, thread_name_prefix="aetheris-ip") as pool:
                futs = [pool.submit(_poll_one, idx) for idx in list(in_flight)]
                for fut in futs:
                    idx, details = fut.result()
                    host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
                    tid = in_flight.get(idx)
                    st = str(details.get("status") or "running").lower()
                    progress_i = int(float(details.get("progress") or 0))
                    state_key = (st, progress_i)
                    if ip_last_state.get(idx) != state_key:
                        ip_last_state[idx] = state_key
                        emit_ip_event(
                            job_id, host, "progress", task_id=tid, status=st,
                            progress=progress_i, chunk_index=idx,
                        )

                    skip_reason = str(details.get("_agent_skip_reason") or "").strip()
                    if skip_reason:
                        _append_skipped(host, skip_reason, str(details.get("_agent_skip_error") or "") or None)
                        poll_results[idx] = details
                        done_details[idx] = details
                        finished_idxs.append(idx)
                        continue

                    if st == "running" and high_progress_stall_sec > 0:
                        pct_i = int(float(details.get("progress") or 0))
                        mark = ip_progress_since.get(idx)
                        now_m = time.monotonic()
                        # Clock starts when this percent is first seen. Backdating
                        # made a live 94% look frozen and harvested the port scan
                        # before Nmap had written any ports.
                        if mark is None or pct_i > mark[0]:
                            ip_progress_since[idx] = (pct_i, now_m)
                        elif ip_tail_should_harvest(
                            pct_i,
                            now_m - mark[1],
                            stall_sec=high_progress_stall_sec,
                            stall_pct=high_progress_stall_pct,
                        ):
                            unchanged = now_m - mark[1]
                            log.warning(
                                "IP %s frozen at %s%% for %.0fs — reading the report already collected",
                                host,
                                pct_i,
                                unchanged,
                            )
                            harvested_box: dict[str, Any] = {}

                            def _read_report() -> None:
                                try:
                                    harvested_box["value"] = openvas.poll(
                                        tid,
                                        expected_targets=chunks[idx],
                                        include_running_report=True,
                                    )
                                except Exception as exc:
                                    harvested_box["error"] = exc

                            reader = threading.Thread(target=_read_report, daemon=True)
                            reader.start()
                            reader.join(40)
                            reason = f"frozen {int(unchanged)}s at {pct_i}%"
                            harvested = dict(harvested_box["value"]) if "value" in harvested_box else None
                            cov_verdict = ""
                            if harvested is not None:
                                cov = ((harvested.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                                cov_verdict = str(cov.get("verdict") or "")
                            if cov_verdict.startswith("degraded"):
                                log.warning(
                                    "IP %s is at %s%% and the port scan is still unfinished (%s); leaving the scan running",
                                    host,
                                    pct_i,
                                    cov_verdict,
                                )
                                ip_progress_since[idx] = (pct_i, now_m)
                            elif harvested is not None and seal_tail_harvest(harvested, host, reason=reason):
                                # The report is already saved. Release the hung check
                                # afterwards so a TCP 445 retry cannot run for days.
                                threading.Thread(target=lambda: openvas.stop(tid), daemon=True).start()
                                details = harvested
                                st = "completed"
                                emit_ip_event(
                                    job_id, host, "tail_harvest", task_id=tid, status="completed",
                                    progress=pct_i,
                                    vulnerabilities=len(details.get("vulnerabilities") or []),
                                    error=reason,
                                    duration_sec=round(now_m - ip_started_mono.get(idx, now_m), 3),
                                )
                            else:
                                log.warning(
                                    "IP %s is still at %s%% and the report has no host evidence yet; leaving the scan running",
                                    host,
                                    pct_i,
                                )
                                ip_progress_since[idx] = (pct_i, now_m - float(high_progress_stall_sec) + 20)

                    if st in {"failed", "stopped"}:
                        # Do not let one bad IP fail 49 healthy peers. Preserve any
                        # partial findings in the per-IP log, mark the host skipped,
                        # then release the permit for the next queued IP.
                        ev = details.get("evidence") or {}
                        err = str(ev.get("report_read_error") or details.get("error") or f"OpenVAS {st}")
                        _append_skipped(host, f"scan_{st}", err)
                        emit_ip_event(
                            job_id, host, "scan_failed", task_id=tid, status=st,
                            error=err, vulnerabilities=len(details.get("vulnerabilities") or []),
                            duration_sec=round(time.monotonic() - ip_started_mono.get(idx, time.monotonic()), 3),
                        )
                        preserved = list(details.get("vulnerabilities") or [])
                        normalized = _skipped_ip_details(host, f"scan_{st}", error=err, task_id=tid)
                        normalized["vulnerabilities"] = preserved
                        poll_results[idx] = normalized
                        done_details[idx] = normalized
                        finished_idxs.append(idx)
                    else:
                        poll_results[idx] = details
                        if st == "completed":
                            cov = ((details.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                            cov_verdict = str(cov.get("verdict") or "full")
                            if cov_verdict.startswith("degraded") and degraded_retries.get(idx, 0) < degraded_retry_budget:
                                degraded_retries[idx] = degraded_retries.get(idx, 0) + 1
                                log.warning(
                                    "Job %s IP %s: scan DEGRADED (%s) — %s; re-running once",
                                    job_id, host, cov_verdict, cov.get("reason"),
                                )
                                emit_ip_event(
                                    job_id, host, "coverage_retry", task_id=tid, verdict=cov_verdict,
                                    reason=cov.get("reason"), attempt=degraded_retries[idx], chunk_index=idx,
                                )
                                task_ids[idx] = None
                                poll_results.pop(idx, None)
                                in_flight.pop(idx, None)
                                slot_sem.release()
                                pending.append(idx)
                                continue
                            if cov_verdict.startswith("degraded"):
                                log.error(
                                    "Job %s IP %s: scan INCOMPLETE (%s) — %s",
                                    job_id, host, cov_verdict, cov.get("reason"),
                                )
                                emit_ip_event(
                                    job_id, host, "coverage_incomplete", task_id=tid, verdict=cov_verdict,
                                    reason=cov.get("reason"), chunk_index=idx,
                                )
                            done_details[idx] = details
                            finished_idxs.append(idx)
                            emit_ip_event(
                                job_id, host, "completed", task_id=tid, progress=100,
                                coverage=cov_verdict, agent_build=_agent_build(),
                                vulnerabilities=len(details.get("vulnerabilities") or []),
                                report_id=(details.get("evidence") or {}).get("report_id"),
                                report_results=(details.get("evidence") or {}).get("report_result_count"),
                                plugin_errors=(details.get("evidence") or {}).get("plugin_error_count"),
                                duration_sec=round(time.monotonic() - ip_started_mono.get(idx, time.monotonic()), 3),
                            )

        for idx in finished_idxs:
            in_flight.pop(idx, None)
            slot_sem.release()

        _fill_slots(ip_workers, admission_paused=bool(capacity.get("admission_paused")))

        external_blob = _external_blob()

        # Merge finished + still-running for progress; pending chunks count as 0%.
        live: list[tuple[list[str], dict[str, Any]]] = []
        for idx, chunk in enumerate(chunks):
            if idx in done_details:
                live.append((chunk, done_details[idx]))
            elif idx in poll_results:
                live.append((chunk, poll_results[idx]))
            elif idx in in_flight:
                live.append((chunk, {"status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}))
            else:
                live.append((chunk, {"status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}))

        merged = _merge_chunk_details(
            live, all_targets=selected_targets, skipped_hosts=skipped_hosts
        )
        # Keep running skip list in sync when merge eliminates more unreachable hosts.
        skipped_hosts = list((merged.get("evidence") or {}).get("skipped_hosts") or skipped_hosts)
        # Job is only terminal once every chunk has a terminal poll result.
        all_terminal = len(done_details) == len(chunks) and not pending and not in_flight
        if not all_terminal:
            # Keep status running while waves remain, even if early chunks failed.
            if any(
                str((done_details.get(i) or poll_results.get(i) or {}).get("status") or "") == "failed"
                for i in range(len(chunks))
            ) and not in_flight and not pending:
                pass  # fall through with merged status
            else:
                merged["status"] = "running"
                merged["gmp_status"] = "running"
                (merged.get("evidence") or {}).update({"assessment_complete": False})

        status = merged["status"]
        progress = float(merged.get("progress") or 0)
        # Weight progress by chunk completion so pending waves don't look stuck at 0.
        if chunks:
            done_weight = sum(
                100.0 if i in done_details else float((poll_results.get(i) or {}).get("progress") or 0)
                for i in range(len(chunks))
            )
            progress = done_weight / len(chunks)
            merged["progress"] = progress

        now = time.monotonic()
        if progress != last_progress:
            last_progress = progress
            last_change = now

        gmp_status = merged.get("gmp_status") or status
        target_progress = target_snapshot(chunks=chunks,
            in_flight=in_flight, done_details=done_details, poll_results=poll_results,
            skipped_hosts=skipped_hosts, assessed_hosts=list(job.get("assessed_hosts") or []))
        ip_rows = [{"ip": host, "status": state["status"], "progress": state["progress_pct"]}
                   for host, state in target_progress.items()]
        status_sig = tuple((row["ip"], row["status"], row["progress"]) for row in ip_rows)
        if status_sig != last_ip_status_sig:
            last_ip_status_sig = status_sig
            from agent.vuln_ports import port_document

            logging.getLogger("scanner_agent.ip").info(
                "IP_EVENT %s",
                json.dumps(
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "job_id": job_id,
                        "event": "scan_status",
                        "ports": port_document(),
                        "ips": ip_rows,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        unchanged_sec = max(0, int(now - last_change))
        message = (
            f"OpenVAS {gmp_status} ({len(in_flight)} in flight / "
            f"{len(done_details)}/{len(chunks)} IPs · semaphore={slot_sem.active}/{ip_workers})"
        )
        if capacity.get("admission_paused"):
            message += " · thermal admission pause"
        elif capacity.get("hot"):
            message += " · capacity floor=5"
        if status == "running" and progress >= 95 and unchanged_sec >= high_progress_warn_sec:
            message = (
                f"OpenVAS {gmp_status} at {progress:.0f}% - "
                f"waiting for Greenbone terminal status"
            )
            if now - last_high_progress_notice >= high_progress_warn_sec:
                log.info(
                    "Job %s still %s at %.0f%% for %ss; waiting for OpenVAS Done "
                    "(httpx PATCH lines are heartbeats, not progress)",
                    job_id,
                    gmp_status,
                    progress,
                    unchanged_sec,
                )
                last_high_progress_notice = now

        if _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": progress,
                "message": message,
                "external_scan_id": external_blob,
                "chunk_tasks": _chunk_tasks_blob(),
                "target_progress": target_progress,
            },
        ) is None:
            log.error(
                "Job %s is not on the central server for this scanner; stopping the local OpenVAS tasks",
                job_id,
            )
            for tid in list(in_flight.values()):
                openvas.stop(tid)
            return

        if all_terminal:
            # Re-merge only finished chunks for upload.
            final_live = [(chunks[i], done_details[i]) for i in range(len(chunks))]
            merged = _merge_chunk_details(
                final_live, all_targets=selected_targets, skipped_hosts=skipped_hosts
            )
            skipped_hosts = list((merged.get("evidence") or {}).get("skipped_hosts") or skipped_hosts)
            status = merged["status"]
            if status == "completed":
                evidence = merged.get("evidence") or {}
                complete = bool(evidence.get("assessment_complete"))
                missing = evidence.get("missing_ip_targets") or []
                if not complete and skipped_hosts and not missing:
                    complete = True
                    evidence["assessment_complete"] = True
                    merged["evidence"] = evidence
                payload = _result_payload(
                    details=merged,
                    task_id=external_blob,
                    status="completed",
                    partial=not complete,
                    partial_reason=(
                        None
                        if complete
                        else f"OpenVAS finished but assessed {int(evidence.get('hosts_assessed') or 0)} "
                        f"of {int(evidence.get('hosts_attempted') or len(targets))} target(s): "
                        f"{evidence.get('assessment_verdict') or 'missing host evidence'}"
                    ),
                    skipped_hosts=skipped_hosts,
                )
                _upload_results_reliably(api, job_id, payload)
                log.info(
                    "Job %s chunked scan done complete=%s vulns=%d hosts_assessed=%d skipped=%d",
                    job_id,
                    complete,
                    len(merged.get("vulnerabilities") or []),
                    int(evidence.get("hosts_assessed") or 0),
                    len(skipped_hosts),
                )
                return

            vulns = merged.get("vulnerabilities") or []
            payload = _result_payload(
                details=merged,
                task_id=external_blob,
                status="failed",
                partial=bool(vulns) or status == "stopped",
                partial_reason=f"task {status} at {progress:.0f}%",
                error=f"OpenVAS ended with status {merged.get('gmp_status')}",
                skipped_hosts=skipped_hosts,
            )
            _upload_results_reliably(api, job_id, payload)
            return

        if max_scan_runtime_sec > 0 and (now - run_started) >= max_scan_runtime_sec:
            log.error(
                "Job %s exceeded MAX_SCAN_RUNTIME_SEC=%ss; stopping in-flight chunk task(s)",
                job_id,
                max_scan_runtime_sec,
            )
            for tid in list(in_flight.values()):
                openvas.stop(tid)
            time.sleep(3)
            for idx in list(in_flight):
                details = openvas.poll(in_flight[idx], expected_targets=chunks[idx])
                done_details[idx] = details
            in_flight.clear()
            pending.clear()
            final_live = [
                (chunks[i], done_details[i])
                for i in range(len(chunks))
                if i in done_details
            ]
            # Mark never-started chunks as stopped empty so merge stays coherent.
            for i in range(len(chunks)):
                if i not in done_details:
                    final_live.append(
                        (
                            chunks[i],
                            {
                                "status": "stopped",
                                "progress": 0,
                                "vulnerabilities": [],
                                "evidence": {},
                            },
                        )
                    )
            merged = _merge_chunk_details(
                final_live, all_targets=selected_targets, skipped_hosts=skipped_hosts
            )
            payload = _result_payload(
                details=merged,
                task_id=external_blob,
                status="failed",
                partial=True,
                partial_reason=f"maximum runtime {max_scan_runtime_sec}s exceeded",
                error=(
                    f"OpenVAS exceeded maximum runtime {max_scan_runtime_sec}s "
                    f"while status={merged.get('gmp_status')} progress={float(merged.get('progress') or 0):.0f}%"
                ),
                skipped_hosts=list((merged.get("evidence") or {}).get("skipped_hosts") or skipped_hosts),
            )
            _upload_results_reliably(api, job_id, payload)
            return


def main() -> None:
    cfg = _cfg()
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    next_heartbeat = 0.0
    last_ready: bool | None = None
    configured_jobs = int(cfg["max_concurrent_jobs"])
    capacity = probe_laptop_capacity(force=True)
    max_workers = max(1, min(configured_jobs, int(capacity["max_concurrent_jobs"])))
    queue_poll = int(cfg["queue_poll"])
    log_shipper = install_log_shipper(api)
    cfg["log_shipper"] = log_shipper

    # Be defensive if a container was recreated from an older image between hotfixes.
    alive_test = getattr(openvas, "alive_test", None) or (os.environ.get("GVM_ALIVE_TEST") or "Consider Alive").strip()
    if not getattr(openvas, "alive_test", None):
        openvas.alive_test = alive_test

    log.info(
        "Scanner agent starting version=%s tenant=%s api=%s alive_test=%s agent_instance=%s",
        cfg["version"],
        os.environ.get("TENANT_SLUG"),
        os.environ.get("CENTRAL_API_URL"),
        alive_test,
        getattr(api, "agent_instance_id", ""),
    )
    log.info(
        "Progress policy: GMP task status is authoritative; no progress-based kill; "
        "high-progress warning=%ss max-runtime=%ss",
        cfg["high_progress_warn_sec"],
        cfg["max_scan_runtime_sec"],
    )
    # V45.4: unmistakable build + effective scan profile, then a hard self-check.
    # A truncating profile (port scanner killed before it finishes) produces 3
    # info results per host with plugin_errors=1 and looks "completed". Never run
    # that silently: refuse to claim jobs until the config is fixed.
    try:
        from agent import AGENT_BUILD
    except Exception:
        AGENT_BUILD = "unknown"
    degraded_retry = int(os.environ.get("SCAN_DEGRADED_RETRY") or 0)
    log.info(
        "AGENT BUILD %s | port_profile=%s udp_profile=%s plugins_timeout=%ss scanner_plugins_timeout=%ss "
        "optimize_test=%s max_checks=%s coverage_guard=on degraded_retry=%d",
        AGENT_BUILD,
        getattr(openvas, "port_profile", "?"),
        getattr(openvas, "udp_profile", "?"),
        getattr(openvas, "plugins_timeout", "?"),
        getattr(openvas, "scanner_plugins_timeout", "?"),
        getattr(openvas, "optimize_test", "?"),
        getattr(openvas, "max_checks", "?"),
        degraded_retry,
    )
    allow_degraded = (os.environ.get("ALLOW_DEGRADED_SCAN") or "false").strip().lower() in {"1", "true", "yes", "on"}
    spt = int(getattr(openvas, "scanner_plugins_timeout", 0) or 0)
    pt = int(getattr(openvas, "plugins_timeout", 0) or 0)
    while (spt < 1800 or pt < 120) and not allow_degraded:
        log.error(
            "DEGRADED SCAN CONFIG - scanner_plugins_timeout=%ss plugins_timeout=%ss would kill the port-scanner "
            "NVT before a full-port sweep finishes (hosts finish with ~3 informational results). "
            "Set SCANNER_PLUGINS_TIMEOUT_SEC=36000 and PLUGINS_TIMEOUT_SEC=320 in laptop-scanner/.env and "
            "recreate scanner-agent (Deploy-V45-Laptop.cmd). Not claiming jobs. Override: ALLOW_DEGRADED_SCAN=true",
            spt, pt,
        )
        time.sleep(60)
    log.info(
        "Capacity policy: jobs=%d (configured=%d) ip_workers=%d chunk_size=%d "
        "thermal=%s cpu_temp=%sC load_ratio=%.2f SCAN_IP_PARALLELISM=%s; queue-poll=%ss; "
        "throughput_target=%.1f-%.1f/h projected=%.1f/h expected_host=%.1fmin required_workers=%d",
        max_workers,
        configured_jobs,
        capacity["ip_workers"],
        capacity["chunk_size"],
        capacity.get("thermal_state"),
        capacity.get("cpu_temp_c") if capacity.get("cpu_temp_c") is not None else "?",
        float(capacity.get("load_ratio") or 0.0),
        os.environ.get("SCAN_IP_PARALLELISM") or "auto",
        queue_poll,
        float(capacity.get("throughput_min_hph") or 0.0),
        float(capacity.get("throughput_target_hph") or 0.0),
        float(capacity.get("projected_hosts_per_hour") or 0.0),
        float(capacity.get("expected_host_minutes") or 0.0),
        int(capacity.get("required_workers_for_slo") or 0),
    )
    if capacity.get("slo_at_risk"):
        log.warning(
            "Configured host concurrency projects %.1f IP/hour, below minimum SLO %.1f IP/hour; "
            "increase scanner CPU/RAM or reduce average host scan duration",
            float(capacity.get("projected_hosts_per_hour") or 0.0),
            float(capacity.get("throughput_min_hph") or 0.0),
        )

    # Future -> central job id. The active ids are sent with every claim so the
    # central API can resume orphaned running work without handing the same job
    # to two local threads. Network keys stay with the job so a second site's
    # RFC1918 range cannot start while another network is already scanning.
    active: dict[Future[None], str] = {}
    active_networks: dict[str, frozenset[str]] = {}

    with ThreadPoolExecutor(
        max_workers=max(configured_jobs, max_workers),
        thread_name_prefix="aetheris-scan",
    ) as pool:
        while True:
            now = time.monotonic()
            try:
                fresh = _read_agent_token()
                setter = getattr(api, "set_token", None)
                current = getattr(api, "_token", None) or ""
                if callable(setter) and fresh and fresh != current:
                    setter(fresh)
                    log.warning("Reloaded AGENT_TOKEN from token file")
                # Reap completed workers first so capacity is available to the
                # dispatcher immediately. Unexpected worker exceptions are left
                # recoverable: if an external_scan_id was already stored, the
                # central resume path will offer that same task again.
                for future, job_id in list(active.items()):
                    if not future.done():
                        continue
                    active.pop(future, None)
                    active_networks.pop(job_id, None)
                    try:
                        future.result()
                        log.info(
                            "Worker released slot for job %s (%d active)",
                            job_id,
                            len(active),
                        )
                    except Exception:
                        log.exception(
                            "Unhandled worker error for job %s; slot released and central resume logic may recover it",
                            job_id,
                        )

                capacity = probe_laptop_capacity()
                max_workers = max(1, min(configured_jobs, int(capacity["max_concurrent_jobs"])))
                try:
                    log_shipper.maybe_flush()
                except Exception:
                    pass

                ready = openvas.ready()
                readiness_detail = getattr(openvas, "last_readiness_detail", None)
                if now >= next_heartbeat or ready != last_ready:
                    try:
                        api.heartbeat(
                            version=cfg["version"],
                            openvas_ready=ready,
                            detail=readiness_detail,
                        )
                        last_ready = ready
                    except Exception as exc:
                        # Do not stall/crash the dispatcher on a slow central hop.
                        # Active OpenVAS workers keep running; claim attempts continue.
                        log.warning(
                            "Central heartbeat timed out or failed (%s); will retry — active=%d",
                            exc.__class__.__name__,
                            len(active),
                        )
                    next_heartbeat = now + cfg["heartbeat"]

                if not ready:
                    # Existing workers keep running; readiness only gates NEW
                    # claims. gvmd often takes minutes after compose-up before
                    # /run/gvmd/gvmd.sock accepts GMP (feed load). Retry quietly.
                    time.sleep(queue_poll)
                    continue

                if capacity.get("hot") and active:
                    # Do not claim a second job while the chassis is hot and a
                    # scan is already burning CPU/OpenVAS.
                    log.info(
                        "Capacity %s — holding new claims (active=%d ip_workers=%s temp=%sC load_ratio=%.2f)",
                        capacity.get("thermal_state") or "hot",
                        len(active),
                        capacity.get("ip_workers"),
                        capacity.get("cpu_temp_c") if capacity.get("cpu_temp_c") is not None else "?",
                        float(capacity.get("load_ratio") or 0.0),
                    )
                    time.sleep(queue_poll)
                    continue

                active_ids = list(active.values())
                slots = max_workers - len(active)
                # Fill every available worker slot in one pass. No queue item is
                # made to wait behind an unrelated active job when capacity is
                # available. The central claim itself is atomic/SKIP LOCKED.
                while slots > 0:
                    job = api.next_job(active_job_ids=active_ids)
                    if not job:
                        break

                    job_id = str(job.get("id") or "").strip()
                    if not job_id:
                        log.error(
                            "Central returned a scan job without an id; refusing claim payload=%r",
                            job,
                        )
                        break
                    if job_id in active_ids:
                        # Defensive compatibility guard for a stale/older central
                        # API that ignores active_job_ids. Do not start duplicate
                        # OpenVAS tasks from the same database job.
                        log.warning(
                            "Central returned already-active job %s; not starting a duplicate worker",
                            job_id,
                        )
                        break

                    job_targets = [
                        str(t.get("target") or "").strip()
                        for t in (job.get("targets") or [])
                        if str(t.get("target") or "").strip()
                    ]
                    incoming_key = network_key(job_targets)
                    active_keys = {active_networks[jid] for jid in active_ids if jid in active_networks}
                    if active_keys and incoming_key not in active_keys:
                        log.error(
                            "Refusing job %s — its network %s is not the in-flight network %s",
                            job_id,
                            ",".join(sorted(incoming_key)[:4]) or "(empty)",
                            ",".join(sorted(next(iter(active_keys)))[:4]),
                        )
                        break

                    future = pool.submit(_run_job, cfg, job)
                    active[future] = job_id
                    active_networks[job_id] = incoming_key
                    active_ids.append(job_id)
                    slots -= 1
                    log.info(
                        "Dispatched job %s (%d/%d active)",
                        job_id,
                        len(active),
                        max_workers,
                    )

                time.sleep(queue_poll)
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 401:
                    fresh = _read_agent_token()
                    setter = getattr(api, "set_token", None)
                    current = getattr(api, "_token", None) or (api.headers.get("Authorization") or "").replace("Bearer ", "", 1).strip()
                    if callable(setter) and fresh and fresh != current:
                        setter(fresh)
                        log.warning("Reloaded AGENT_TOKEN after 401")
                        continue
                    log.error(
                        "Central rejected AGENT_TOKEN (HTTP 401). Re-run Start-Laptop.cmd to auto-match it."
                    )
                    time.sleep(queue_poll)
                    continue
                log.exception("Dispatcher loop error")
                time.sleep(queue_poll)


if __name__ == "__main__":
    main()
