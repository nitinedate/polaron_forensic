"""Keep each edge scan job bound to its own hosts and network.

Resume must never attach an OpenVAS task by chunk index. Private ranges
overlap across sites, so a leftover task from another job would scan the
wrong network's IPs under this job's identity.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def normalize_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.casefold()


def host_set(hosts: list[str] | None) -> frozenset[str]:
    return frozenset(h for h in (normalize_host(x) for x in (hosts or [])) if h)


def network_key(targets: list[str] | None) -> frozenset[str]:
    """Stable network identity for a job's selected hosts.

    IPv4 addresses collapse to /24, IPv6 to /64, names stay literal. Two jobs
    with different keys must not run at the same time on one laptop scanner.
    """
    keys: set[str] = set()
    for raw in targets or []:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            keys.add(text.casefold())
            continue
        if isinstance(ip, ipaddress.IPv4Address):
            keys.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
        else:
            keys.add(str(ipaddress.ip_network(f"{ip}/64", strict=False)))
    return frozenset(keys)


def remaining_hosts(*, selected: list[str], assessed: list[str] | None) -> list[str]:
    """Hosts still owed by this job. Already-assessed IPs are not rescanned."""
    done = host_set(assessed)
    out: list[str] = []
    seen: set[str] = set()
    for host in selected:
        key = normalize_host(host)
        if not key or key in done or key in seen:
            continue
        seen.add(key)
        out.append(str(host).strip())
    return out


def stored_task_entries(
    *,
    chunk_tasks: list[Any] | None,
    external_scan_id: Any,
) -> list[dict[str, Any]]:
    """Unify stored chunk metadata and leftover GMP task ids for this job only."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in chunk_tasks or []:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("task_id") or "").strip()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        hosts = [str(h).strip() for h in (item.get("hosts") or []) if str(h).strip()]
        out.append({"task_id": tid, "hosts": hosts})
    raw_ids: list[str] = []
    if isinstance(external_scan_id, list):
        raw_ids = [str(x).strip() for x in external_scan_id if str(x).strip()]
    else:
        text = str(external_scan_id or "").strip()
        if text.startswith("["):
            try:
                import json

                parsed = json.loads(text)
                if isinstance(parsed, list):
                    raw_ids = [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                raw_ids = [text] if text else []
        elif text:
            raw_ids = [text]
    for tid in raw_ids:
        if tid not in seen:
            seen.add(tid)
            out.append({"task_id": tid, "hosts": []})
    return out


def plan_resume_chunks(
    *,
    job_hosts: list[str],
    remaining: list[str],
    stored_tasks: list[dict[str, Any]],
    live_hosts: dict[str, list[str] | None],
    chunk_size: int,
) -> tuple[list[list[str]], dict[int, str], list[str]]:
    """Bind OpenVAS tasks to this job by live host identity, never by index.

    A task is resumed only when GMP reports a non-empty host set that is a
    subset of *this* job's selected targets. Lookup failures are dropped
    rather than guessed. Remaining hosts not covered by a verified task are
    queued as new chunks. Expected hosts for a leftover task are the
    intersection with *remaining* so skipped unreachable IPs are not required
    in the report.
    """
    job = host_set(job_hosts)
    remaining_set = host_set(remaining)
    dropped: list[str] = []
    resume_pairs: list[tuple[list[str], str]] = []
    covered: set[str] = set()
    seen_tids: set[str] = set()

    for item in stored_tasks or []:
        tid = str((item or {}).get("task_id") or "").strip()
        if not tid or tid in seen_tids:
            continue
        seen_tids.add(tid)
        live = live_hosts.get(tid)
        if live is None:
            dropped.append(tid)
            continue
        identity = host_set(live)
        if not identity or not identity <= job:
            dropped.append(tid)
            continue
        # Poll coverage only for hosts this job still owes. A leftover GMP
        # target that still lists an unreachable IP must not require that IP
        # in the OpenVAS report.
        still_owed = [h for h in live if normalize_host(h) in remaining_set]
        ordered = still_owed or [h for h in live if normalize_host(h) in identity]
        if not ordered:
            ordered = sorted(identity)
        resume_pairs.append((ordered, tid))
        covered |= identity

    new_hosts = [h for h in remaining if normalize_host(h) not in covered]
    size = max(1, int(chunk_size or 1))
    new_chunks = [new_hosts[i : i + size] for i in range(0, len(new_hosts), size)]
    chunks: list[list[str]] = [list(hosts) for hosts, _ in resume_pairs] + new_chunks
    resume_map = {i: tid for i, (_, tid) in enumerate(resume_pairs)}
    return chunks, resume_map, dropped


def leftover_blocks_skip_complete(
    *,
    dropped_tasks: list[str],
    live_hosts: dict[str, list[str] | None],
    job_hosts: list[str],
) -> bool:
    """True when leftover GMP work looks like a different network, not a stale id.

    A missing OpenVAS task (404 / empty host list) must not block completing a
    job whose remaining targets were all unreachable. A live task whose hosts
    are not this job's set must still refuse to finish as skipped.
    """
    job = host_set(job_hosts)
    for tid in dropped_tasks or []:
        live = live_hosts.get(tid)
        if live is None:
            return True
        identity = host_set(live)
        if identity and not identity <= job:
            return True
    return False
