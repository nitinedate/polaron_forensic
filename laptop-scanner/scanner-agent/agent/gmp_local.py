"""Local Greenbone GMP client for the Aetheris laptop scanner agent."""

from __future__ import annotations

import logging
import math
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

from agent.service_policy import analyze_services, effective_policy, port_numbers

log = logging.getLogger("scanner_agent.gmp")

FULL_AND_FAST_ID = "daba56c8-73ec-11df-a475-002264764cea"
AETHERIS_SCAN_CONFIG = "Aetheris Full and fast"
NMAP_NVT_OID = "1.3.6.1.4.1.25623.1.0.14259"

# Legacy named TCP profiles remain available. The versioned service policy
# adds every explicit TCP service in the guide, including custom ports.
FAST_PORTS = (
    "T:21-23,T:25,T:53,T:80,T:81,T:88,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:631,T:993,T:995,T:1433,T:1521,T:1723,T:2049,"
    "T:3000,T:3306,T:3389,T:5432,T:5672,T:5900,T:5985,T:6379,T:6443,"
    "T:8080,T:8443,T:9000,T:9418,T:27017"
)

# Nessus-style vulnerability ports. Every IP uses this set when PORT_PROFILE=vuln.
# Dropped from the fast list because they produce informational results only
# (service banners, name lookups) and no vulnerability severity: 81, 88, 631,
# 1723, 3000, 5672, 9000, 9418. SSH, TLS, SMB, databases, RDP and the admin
# web ports stay, because those are where low/medium/high/critical findings are.
VULN_PORTS = (
    "T:21-23,T:25,T:53,T:80,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:993,T:995,T:1433,T:1521,T:2049,"
    "T:3306,T:3389,T:5432,T:5900,T:5985-5986,T:6379,T:6443,"
    "T:8080,T:8443,T:9200,T:27017"
)
# Kept for compatibility; the effective policy includes the guide UDP baseline.
VULN_UDP_PORTS = "U:161,U:623,U:11211"
_VULN_PROFILES = frozenset({"vuln", "nexus", "nessus"})

# High-value UDP services commonly relevant to infrastructure/IP assessment.
# GMP port_range requires each comma-separated range to carry T:/U: explicitly.
# Full UDP (1-65535) remains available through UDP_PROFILE=full, but is not the
# default because exhaustive UDP can dominate scan time on filtered networks.
PRIORITY_UDP_PORTS = (
    "U:53,U:67-69,U:88,U:111,U:123,U:137-138,U:161-162,U:389,U:500,U:514,U:520,U:623,U:902,U:1434,"
    "U:1701,U:1812-1813,U:1900,U:2049,U:3389,U:4500,U:4789,U:5004,U:5060,U:5353,U:11211"
)


def _normalize_udp_port_range(value: str) -> str:
    out: list[str] = []
    for raw in (value or "").split(","):
        token = raw.strip()
        if not token:
            continue
        if token.upper().startswith("U:"):
            token = token[2:].strip()
        if token:
            out.append(f"U:{token}")
    return ",".join(out)


def _udp_port_range(profile: str | None = None) -> str:
    raw = (profile if profile is not None else os.environ.get("UDP_PROFILE") or "priority").strip().lower()
    if raw in {"off", "none", "disabled", "false", "0"}:
        return ""
    if raw in {"full", "all", "1-65535"}:
        return "U:1-65535"
    custom = (os.environ.get("UDP_PORT_RANGE") or "").strip()
    if custom:
        return _normalize_udp_port_range(custom)
    return PRIORITY_UDP_PORTS


def _with_udp_range(tcp_range: str, udp_profile: str | None = None) -> str:
    base = (tcp_range or "").strip().rstrip(",")
    if not base:
        base = "T:1-65535"
    if any(part.strip().upper().startswith("U:") for part in base.split(",")):
        return base
    udp = _udp_port_range(udp_profile)
    return f"{base},{udp}" if udp else base


def _default_scan_port_range(port_profile: str, udp_profile: str | None = None) -> str:
    return _effective_scan_policy(None, port_profile, udp_profile)["port_range"]


def _effective_scan_policy(request: dict[str, Any] | None, port_profile: str,
                           udp_profile: str | None) -> dict[str, Any]:
    from agent.vuln_ports import port_document

    catalog = port_document()
    tcp = [port for item in catalog["tcp"] for port in port_numbers(item["ports"])]
    udp = port_numbers(PRIORITY_UDP_PORTS.replace("U:", ""))
    udp += [port for item in catalog["udp"] for port in port_numbers(item["ports"])]
    # Fast/Common add their historical common ports to the mandatory guide set.
    tcp += port_numbers(FAST_PORTS.replace("T:", ""))
    return effective_policy(request, port_profile=port_profile, udp_profile=udp_profile,
                            catalog_tcp=tcp, catalog_udp=udp)

def _report_filter_string(*, first: int | None = None, rows: int | None = None) -> str:
    """Fetch Greenbone results. Default is the full set (rows=-1)."""
    raw = (os.environ.get("GVM_REPORT_MIN_QOD") or "0").strip()
    try:
        min_qod = int(raw)
    except (TypeError, ValueError):
        min_qod = 0
    min_qod = max(0, min(100, min_qod))
    parts: list[str] = []
    if first is not None:
        parts.append(f"first={max(1, int(first))}")
    if rows is not None:
        parts.append(f"rows={int(rows)}")
    elif first is None:
        parts.append("rows=-1")
    parts.append(f"min_qod={min_qod}")
    return " ".join(parts)


def _gmp_connection_lost(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "remote closed",
            "connection reset",
            "broken pipe",
            "timed out",
            "timeout",
            "socket is closed",
            "not connected",
        )
    )


def _gmp_timeout() -> float:
    try:
        return max(30.0, float(os.environ.get("GVM_GMP_TIMEOUT") or 300))
    except (TypeError, ValueError):
        return 300.0


def _report_page_rows() -> int:
    try:
        return max(50, int(os.environ.get("GVM_REPORT_PAGE_ROWS") or 200))
    except (TypeError, ValueError):
        return 200


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _canonical_severity(threat: str | None, cvss: float) -> str:
    """Return Nessus-compatible CVSS severity only.

    Greenbone's legacy ``threat`` text is retained in the result payload for
    audit/debugging, but it must not change the technical severity shown by
    Polaron.  Nessus severity bands are driven by the numeric CVSS score.
    """
    del threat
    return _severity_from_cvss(cvss)


def _valid_cvss(value: Any) -> float | None:
    """Parse a valid 0..10 score without treating the string ``0.0`` as missing."""
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or score < 0.0 or score > 10.0:
        return None
    return score


def _best_cvss(nvt: Any, result: Any, tag_values: dict[str, str]) -> tuple[float, str, dict[str, float]]:
    """Choose the strongest numeric technical severity signal in a GMP result.

    Greenbone report variants are inconsistent: some put the usable score on
    ``result/severity`` while ``nvt/cvss_base`` is literally ``0.0``.  The old
    ``a or b`` parser considered the string ``0.0`` truthy and silently threw
    away the real result score.  Keep every parsed candidate for traceability
    and use the highest valid score, matching Nessus' highest-risk-factor
    presentation when multiple CVSS signals describe the same finding.
    """
    raw_candidates: list[tuple[str, Any]] = [
        ("result.severity", result.findtext("severity")),
        ("nvt.cvss_base", nvt.findtext("cvss_base")),
        ("nvt.cvss2_base", nvt.findtext("cvss2_base")),
        ("nvt.cvss_v2_base", nvt.findtext("cvss_v2_base")),
        ("nvt.cvss3_base", nvt.findtext("cvss3_base")),
        ("nvt.cvss_v3_base", nvt.findtext("cvss_v3_base")),
        ("nvt.cvss4_base", nvt.findtext("cvss4_base")),
        ("nvt.cvss_v4_base", nvt.findtext("cvss_v4_base")),
    ]
    for key in (
        "cvss_base", "cvss2_base", "cvss_v2_base",
        "cvss3_base", "cvss_v3_base", "cvss4_base", "cvss_v4_base"
    ):
        raw_candidates.append((f"tags.{key}", tag_values.get(key)))

    # Newer gvmd/NVT schemas can carry multiple CVSS generations under a
    # severities list. Preserve each score as an independent candidate so a
    # placeholder cvss_base=0.0 cannot hide an actual Critical result.
    try:
        for idx, value in enumerate(nvt.xpath(".//severities/severity/score/text()")):
            raw_candidates.append((f"nvt.severities[{idx}].score", value))
    except Exception:
        pass

    parsed: dict[str, float] = {}
    for source, value in raw_candidates:
        score = _valid_cvss(value)
        if score is not None:
            parsed[source] = score
    if not parsed:
        return 0.0, "none", {}

    # Prefer result.severity on a tie because it is the per-result score emitted
    # by gvmd; otherwise take the strongest valid technical score.
    max_score = max(parsed.values())
    tied = [name for name, score in parsed.items() if score == max_score]
    source = "result.severity" if "result.severity" in tied else tied[0]
    return max_score, source, parsed


def _versioned_cvss_scores(candidates: dict[str, float]) -> dict[str, float | None]:
    """Extract only explicitly versioned CVSS values for central normalization.

    ``cvss_base`` and Greenbone ``result/severity`` are deliberately left as
    generic scanner signals because their CVSS generation is not guaranteed by
    the GMP report shape. This prevents a legacy v2 score from being mislabeled
    as v3/v4 while still keeping the generic score available as a fallback.
    """
    names = {
        "cvss_v2": ("nvt.cvss2_base", "nvt.cvss_v2_base", "tags.cvss2_base", "tags.cvss_v2_base"),
        "cvss_v3": ("nvt.cvss3_base", "nvt.cvss_v3_base", "tags.cvss3_base", "tags.cvss_v3_base"),
        "cvss_v4": ("nvt.cvss4_base", "nvt.cvss_v4_base", "tags.cvss4_base", "tags.cvss_v4_base"),
    }
    out: dict[str, float | None] = {"cvss_v2": None, "cvss_v3": None, "cvss_v4": None}
    for version, sources in names.items():
        for source in sources:
            if source in candidates:
                out[version] = candidates[source]
                break
    return out


def _xml_result_nodes(report: Any) -> list[Any]:
    try:
        return list(report.xpath(".//results/result"))
    except Exception:
        return []


def _feed_count_from_xml(response: Any) -> int | None:
    """Best-effort total NVT count from GMP response metadata.

    Greenbone versions expose the count in slightly different shapes.  Returning
    None means "count unavailable", not zero.
    """
    if response is None or not hasattr(response, "xpath"):
        return None
    paths = (
        # Native <get_nvts> responses.
        ".//nvt_count/filtered/text()",
        ".//nvt_count/total/text()",
        ".//nvt_count/text()",
        ".//config/nvt_count/text()",
        # python-gvm may implement get_nvts() through GMP get_info unless
        # extended=True is requested.  gvmd 26.x then reports <info_count>
        # instead of <nvt_count>.  Treat both schemas equivalently.
        ".//info_count/filtered/text()",
        ".//info_count/total/text()",
        ".//info_count/text()",
    )
    values: list[int] = []
    for xpath in paths:
        try:
            for raw in response.xpath(xpath):
                try:
                    values.append(int(str(raw).strip()))
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
    return max(values) if values else None


def _minimum_nvt_count() -> int:
    try:
        return max(1, int(os.environ.get("GVM_MIN_NVT_COUNT") or 10000))
    except (TypeError, ValueError):
        return 10000


def _feed_health(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    """Return conservative Greenbone feed/config health evidence."""
    syncing = False
    versions: list[str] = []
    try:
        feeds = gmp.get_feeds()
        if hasattr(feeds, "xpath"):
            syncing = any(
                str(x or "").strip().lower() in {"1", "true", "yes"}
                for x in feeds.xpath(".//currently_syncing/text()")
            )
            versions = [str(v).strip() for v in feeds.xpath(".//feed/version/text()") if str(v).strip()]
    except Exception:
        log.debug("Unable to read Greenbone feed metadata", exc_info=True)

    nvt_count: int | None = None
    try:
        # Request the native NVT response first.  On python-gvm 26.x the
        # non-extended call can be backed by GMP get_info, which may omit the
        # nvt_count element that older readiness code expected.
        try:
            resp = gmp.get_nvts(filter_string="rows=1 first=1", extended=True)
        except TypeError:
            # Compatibility with older python-gvm implementations.
            resp = gmp.get_nvts(filter_string="rows=1 first=1")
        nvt_count = _feed_count_from_xml(resp)
        # If count metadata is absent, at least prove that one NVT exists.
        if nvt_count is None and hasattr(resp, "xpath") and resp.xpath(".//nvt"):
            nvt_count = -1  # present, total unknown
    except Exception:
        log.debug("Unable to read Greenbone NVT inventory", exc_info=True)

    config_nvt_count: int | None = None
    if config_id:
        getter = getattr(gmp, "get_scan_config", None)
        if callable(getter):
            try:
                config_nvt_count = _feed_count_from_xml(getter(config_id))
            except Exception:
                log.debug("Unable to read scan-config NVT count", exc_info=True)

    return {
        "syncing": syncing,
        "versions": versions,
        "nvt_count": nvt_count,
        "config_nvt_count": config_nvt_count,
    }


def _assert_feed_quality(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    health = _feed_health(gmp, config_id)
    if health["syncing"]:
        raise RuntimeError("Greenbone feed is still synchronizing; refusing to start a partial-quality scan")
    minimum = _minimum_nvt_count()
    for label in ("nvt_count", "config_nvt_count"):
        count = health.get(label)
        if isinstance(count, int) and count >= 0 and count < minimum:
            raise RuntimeError(
                f"Greenbone {label}={count} is below required minimum {minimum}; "
                "feed/config import is incomplete, so the scanner will not claim the job"
            )
    if health.get("nvt_count") is None:
        log.warning("Greenbone NVT total count is unavailable; continuing because feed sync is not active")
    return health



def _imports():
    from gvm.connections import TLSConnection, UnixSocketConnection

    try:
        from gvm.protocols.gmp import GMP
    except ImportError:
        from gvm.protocols.gmp import Gmp as GMP  # type: ignore

    try:
        from gvm.transforms import EtreeCheckCommandTransform

        transform = EtreeCheckCommandTransform()
    except ImportError:
        from gvm.transforms import EtreeTransform

        transform = EtreeTransform()

    return TLSConnection, UnixSocketConnection, GMP, transform


@contextmanager
def _session(
    *,
    socket_path: str | None,
    host: str,
    port: int,
    username: str,
    password: str,
    verify: bool = False,
    timeout: float | None = None,
) -> Iterator[Any]:
    TLSConnection, UnixSocketConnection, GMP, transform = _imports()
    timeout = _gmp_timeout() if timeout is None else max(1.0, float(timeout))
    if socket_path:
        try:
            conn = UnixSocketConnection(path=socket_path, timeout=timeout)
        except TypeError:
            conn = UnixSocketConnection(path=socket_path)
    else:
        conn = TLSConnection(hostname=host, port=port, timeout=timeout, verify=verify)

    # python-gvm manages connect/disconnect at the GMP protocol layer.
    # UnixSocketConnection itself is not a context manager in current 26.x.
    with GMP(connection=conn, transform=transform) as gmp:
        gmp.authenticate(username, password)
        yield gmp


def _find_config_id(gmp: Any, name: str = "Full and fast") -> str:
    resp = gmp.get_scan_configs()
    available: list[str] = []
    wanted = name.strip().casefold()
    for node in resp.xpath("config"):
        cid = (node.get("id") or "").strip()
        config_name = (node.findtext("name") or "").strip()
        if config_name:
            available.append(config_name)
        if cid and config_name.casefold() == wanted:
            return cid
        if cid == FULL_AND_FAST_ID and wanted in {"full and fast", FULL_AND_FAST_ID.casefold()}:
            return cid
    summary = ", ".join(available[:8]) if available else "none"
    raise RuntimeError(
        f"Scan config not found: {name}. Available configs: {summary}. "
        "Greenbone feed data is still loading or the Feed Import Owner/data-object rebuild is missing."
    )


def _find_scanner_id(gmp: Any) -> str:
    resp = gmp.get_scanners()
    for node in resp.xpath("scanner"):
        n = (node.findtext("name") or "").lower()
        if "openvas" in n or "default" in n:
            sid = node.get("id")
            if sid:
                return str(sid)
    node = resp.find("scanner")
    if node is not None and node.get("id"):
        return str(node.get("id"))
    raise RuntimeError("No OpenVAS scanner found in Greenbone")


def _apply_nmap_speed_prefs(gmp: Any, config_id: str) -> None:
    """SYN scan plus short retries. Connect()+UDP on every TCP port sits at ~15% for hours.

    The preference name must be the full ``oid:id:type:name`` string. A short name is
    stored with no NVT id, and OpenVAS then ignores it and stays on connect().
    """
    prefs = (
        (f"{NMAP_NVT_OID}:1:radio:TCP scanning technique :", "SYN scan"),
        (f"{NMAP_NVT_OID}:8:entry:Max Retries :", "2"),
        (f"{NMAP_NVT_OID}:23:checkbox:Defeat ICMP ratelimit", "yes"),
        (f"{NMAP_NVT_OID}:22:checkbox:Defeat RST ratelimit", "yes"),
    )
    for name, value in prefs:
        try:
            gmp.modify_scan_config_set_nvt_preference(
                config_id=config_id,
                name=name,
                nvt_oid=NMAP_NVT_OID,
                value=value,
            )
        except Exception as exc:
            # gvmd rejects preference edits while any task is using the config.
            # The SYN settings were saved when the config was created, so keep it.
            if "in use" in str(exc).lower():
                log.info(
                    "Scan config %s is in use; using the Nmap SYN settings already saved",
                    config_id,
                )
                return
            raise


def _ensure_portscan_config(gmp: Any, base_name: str) -> str:
    """Return a writable Full-and-fast clone whose Nmap NVT uses a SYN scan.

    The built-in config is predefined, so its Nmap technique stays connect().
    A connect scan of T:1-65535 plus UDP holds OpenVAS around 15% until nmap exits.
    """
    wanted = AETHERIS_SCAN_CONFIG.casefold()
    base_wanted = (base_name or "Full and fast").strip().casefold()
    resp = gmp.get_scan_configs(filter_string="rows=-1")
    existing = ""
    base_id = ""
    for node in resp.xpath("config"):
        cid = (node.get("id") or "").strip()
        config_name = (node.findtext("name") or "").strip()
        if not cid or not config_name:
            continue
        folded = config_name.casefold()
        if folded == wanted:
            existing = cid
        elif folded == base_wanted or cid == FULL_AND_FAST_ID and base_wanted == "full and fast":
            base_id = cid
    if existing:
        _apply_nmap_speed_prefs(gmp, existing)
        return existing
    if not base_id:
        base_id = _find_config_id(gmp, base_name or "Full and fast")
    cloned = gmp.clone_scan_config(base_id)
    new_id = str(cloned.get("id") or "").strip()
    if not new_id:
        raise RuntimeError("Greenbone did not return a cloned scan config id")
    gmp.modify_scan_config_set_name(new_id, AETHERIS_SCAN_CONFIG)
    _apply_nmap_speed_prefs(gmp, new_id)
    log.info("Created scan config %s (%s) with Nmap SYN scan", AETHERIS_SCAN_CONFIG, new_id)
    return new_id


def _ospd_feed_state(gmp: Any) -> dict[str, Any]:
    """Return conservative scanner-feed readiness evidence.

    A live OSP socket alone is not readiness.  The scanner is only ready to
    claim jobs after gvmd can see the NVT inventory populated from OSPd.
    """
    minimum = _minimum_nvt_count()
    try:
        health = _feed_health(gmp, None)
    except Exception as exc:
        return {
            "ready": False,
            "reason": "feed_probe_failed",
            "detail": f"Greenbone feed probe failed: {exc}",
            "nvt_count": None,
            "minimum": minimum,
        }

    count = health.get("nvt_count")
    if health.get("syncing"):
        return {
            "ready": False,
            "reason": "feed_syncing",
            "detail": "Greenbone feed is still synchronizing/loading; queued scans will start automatically when ready",
            "nvt_count": count,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    if count is None:
        return {
            "ready": False,
            "reason": "nvt_inventory_unavailable",
            "detail": "OSPd OpenVAS has not published its NVT inventory yet; initial VT loading is still in progress",
            "nvt_count": None,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    if count == -1:
        versions = health.get("versions") or []
        if versions:
            # Current gvmd/python-gvm combinations can expose NVT objects and
            # feed versions without a total-count element.  This is positive
            # inventory evidence, not an incomplete-feed signal.  Full scan
            # readiness still requires the configured scan config to exist in
            # LocalOpenVAS.ready(), so this does not fail open.
            return {
                "ready": True,
                "reason": "nvt_inventory_present_count_unavailable",
                "detail": "OSPd OpenVAS NVT inventory is present and feed versions are available; gvmd did not expose a total NVT count, so readiness will be confirmed by the scan-config gate",
                "nvt_count": count,
                "minimum": minimum,
                "versions": versions,
                "count_trustworthy": False,
            }
        return {
            "ready": False,
            "reason": "nvt_count_unavailable",
            "detail": "OSPd OpenVAS exposes NVT data but no feed version or trustworthy total count yet",
            "nvt_count": count,
            "minimum": minimum,
            "versions": versions,
        }
    if count < minimum:
        return {
            "ready": False,
            "reason": "nvt_inventory_loading",
            "detail": f"OSPd OpenVAS NVT inventory is still loading ({count}/{minimum} minimum)",
            "nvt_count": count,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    return {
        "ready": True,
        "reason": "ready",
        "detail": f"OSPd OpenVAS NVT inventory ready ({count} VTs)",
        "nvt_count": count,
        "minimum": minimum,
        "versions": health.get("versions") or [],
    }


def _ospd_feed_ready(gmp: Any) -> bool:
    """True only with positive NVT inventory evidence; never fail open."""
    return bool(_ospd_feed_state(gmp).get("ready"))


def _task_status(gmp: Any, task_id: str) -> tuple[str, float, Any]:
    resp = gmp.get_task(task_id)
    task = resp.find("task")
    if task is None:
        nodes = resp.xpath(".//task")
        task = nodes[0] if nodes else None
    if task is None:
        return "unknown", 0.0, None
    status = (task.findtext("status") or "unknown").strip().lower()
    try:
        progress = float(task.findtext("progress") or 0)
    except (TypeError, ValueError):
        progress = 0.0
    return status, progress, task


def _split_host_list(text: str | None) -> list[str]:
    hosts: list[str] = []
    for raw in str(text or "").replace("\n", ",").split(","):
        host = raw.strip()
        if host:
            hosts.append(host)
    return hosts


def _hosts_from_target_elem(target: Any) -> list[str]:
    if target is None:
        return []
    for xpath in ("hosts", "hosts/host", "ip"):
        text = target.findtext(xpath) if hasattr(target, "findtext") else None
        hosts = _split_host_list(text)
        if hosts:
            return hosts
    return _split_host_list(target.findtext("hosts") if hasattr(target, "findtext") else None)


def _hosts_from_task_elem(task: Any) -> list[str]:
    if task is None:
        return []
    target = task.find("target") if hasattr(task, "find") else None
    hosts = _hosts_from_target_elem(target)
    if hosts:
        return hosts
    return _split_host_list(task.findtext("hosts") if hasattr(task, "findtext") else None)


def _task_report_id(task: Any) -> str | None:
    if task is None:
        return None
    for xpath in ("current_report/report", "last_report/report"):
        elem = task.find(xpath)
        if elem is not None and elem.get("id"):
            return str(elem.get("id"))
    return None


def _inner_report(response: Any) -> Any:
    """Return the report element that contains scan/host/result evidence."""
    candidates = response.xpath(".//report") if hasattr(response, "xpath") else []
    for node in candidates:
        if (
            node.find("scan_run_status") is not None
            or node.find("hosts") is not None
            or node.find("results") is not None
            or node.find("scan_start") is not None
        ):
            return node
    return candidates[-1] if candidates else response


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _text_values(node: Any, xpath: str) -> list[str]:
    try:
        values = node.xpath(xpath)
    except Exception:
        return []
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            out.append(text)
    return out


def _plugin_error_details(report: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    """Extract structured Greenbone report error records for audit/reporting."""
    try:
        nodes = report.xpath("./errors/error")
        if not nodes:
            nodes = report.xpath(".//errors/error")
    except Exception:
        nodes = []

    details: list[dict[str, Any]] = []
    for err in nodes[: max(0, limit)]:
        nvt = err.find("nvt")
        host = (err.findtext("host") or "").strip() or None
        port = (err.findtext("port") or "").strip() or None
        description = (err.findtext("description") or "").strip()
        severity = (err.findtext("severity") or "").strip() or None
        nvt_oid = (nvt.get("oid") or "").strip() if nvt is not None else ""
        nvt_name = (nvt.findtext("name") or "").strip() if nvt is not None else ""
        if not nvt_name:
            nvt_name = (err.findtext("name") or "").strip()
        details.append(
            {
                "host": host,
                "port": port,
                "nvt_oid": nvt_oid or None,
                "nvt_name": nvt_name or None,
                "severity": severity,
                "description": description[:2000] if description else None,
            }
        )
    return details


def _report_evidence_from_xml(
    response: Any,
    *,
    report_id: str,
    task_status: str,
    progress: float,
    expected_targets: list[str],
    alive_test: str,
) -> dict[str, Any]:
    report = _inner_report(response)

    # Greenbone native XML contains direct report/host/ip and host_start/host /
    # host_end/host nodes for hosts that actually entered the scan. Result host
    # values are included as an additional source, but are not required for a
    # clean host because a successfully assessed host may have zero actionable
    # findings.
    host_ips = set(_text_values(report, "./host/ip/text()"))
    host_ips.update(_text_values(report, "./host_start/host/text()"))
    host_ips.update(_text_values(report, "./host_end/host/text()"))
    host_ips.update(_text_values(report, ".//results/result/host/text()"))
    host_ips.update(_text_values(report, ".//host/ip/text()"))
    # Some Greenbone builds stash the address on host/@ip or asset attributes.
    try:
        for node in report.xpath(".//host"):
            for attr in ("ip", "host"):
                val = (node.get(attr) or "").strip()
                if val:
                    host_ips.add(val)
            asset = node.find("asset")
            if asset is not None:
                for attr in ("asset_id", "id"):
                    val = (asset.get(attr) or "").strip()
                    if val and val.replace(".", "").isdigit() is False and ":" not in val:
                        continue
                    if val:
                        host_ips.add(val)
    except Exception:
        pass
    host_ips = {h.strip() for h in host_ips if h and str(h).strip()}

    host_count = _as_int(report.findtext("hosts/count"), len(host_ips))
    hosts_assessed = max(host_count, len(host_ips))
    result_nodes = _xml_result_nodes(report)
    materialized_result_count = len(result_nodes)
    full_result_count = _as_int(report.findtext("result_count/full"), -1)
    filtered_result_count = _as_int(report.findtext("result_count/filtered"), -1)
    legacy_result_count = _as_int(report.findtext("result_count"), -1)

    # GMP's <full> count is the number before the report filter is applied.
    # The <filtered> count describes the rows returned under <results>.  Using
    # <full> as the upload count produced false failures such as full=36 while
    # filtered/materialized/parsed=35.  The materialized count remains the
    # authoritative upload-integrity boundary when filtered metadata is absent.
    if filtered_result_count >= 0:
        result_count = filtered_result_count
    elif materialized_result_count > 0:
        result_count = materialized_result_count
    elif legacy_result_count >= 0:
        result_count = legacy_result_count
    else:
        result_count = 0
    plugin_error_details = _plugin_error_details(report)
    plugin_errors = max(_as_int(report.findtext("errors/count"), 0), len(plugin_error_details))
    # V45.4: explicit per-host coverage verdict (port scanner killed => degraded).
    host_coverage: dict[str, dict[str, Any]] = {}
    try:
        from agent.scan_coverage import coverage_from_report

        cov_hosts = [str(t).strip() for t in expected_targets if str(t).strip()] or sorted(host_ips)
        for cov_host in cov_hosts:
            host_coverage[cov_host] = coverage_from_report(report, host=cov_host, errors=plugin_error_details)
    except Exception:
        log.debug("coverage verdict failed for report %s", report_id, exc_info=True)
    scan_start = (report.findtext("scan_start") or "").strip() or None
    scan_end = (report.findtext("scan_end") or "").strip() or None
    run_status = (report.findtext("scan_run_status") or task_status or "").strip()

    targets = [str(t).strip() for t in expected_targets if str(t).strip()]
    target_count = len(targets)
    report_has_host_evidence = bool(host_ips)

    # For literal IP targets, require identity evidence from the report, not just
    # a host count.  This prevents a different/resolved host from satisfying the
    # coverage gate.  Hostnames and network expressions still require host
    # evidence/count, but their identity is not guessed here.
    import ipaddress

    literal_ip_targets: list[str] = []
    for target in targets:
        try:
            literal_ip_targets.append(str(ipaddress.ip_address(target)))
        except ValueError:
            pass
    normalized_hosts: set[str] = set()
    for host in host_ips:
        try:
            normalized_hosts.add(str(ipaddress.ip_address(host)))
        except ValueError:
            normalized_hosts.add(host.casefold())
    missing_ip_targets = [t for t in literal_ip_targets if t not in normalized_hosts]
    assessed_expected = [t for t in literal_ip_targets if t in normalized_hosts]
    # Wrong-host guard: at least one expected literal IP must appear. Hosts
    # OpenVAS did not find alive stay in missing_ip_targets for skip accounting.
    target_identity_ok = not literal_ip_targets or bool(assessed_expected)

    timestamps_ok = bool(scan_start and scan_end)
    plugin_health_ok = plugin_errors == 0

    # Completion/coverage and scanner warnings are different concepts.
    # Greenbone report <errors> entries are per-VT/scanner errors and can
    # coexist with a successfully completed task and full host coverage.
    # They must prevent a *clean* conclusion, but must not turn a fully
    # assessed host into a failed scan.
    #
    # OpenVAS "1 alive hosts of 2" is the same: the missing IP was not alive.
    # Require the assessed IPs to be expected targets, not that every expected
    # IP appears in the report.
    assessment_complete = (
        task_status in {"done", "finished", "succeeded"}
        and bool(report_id)
        and report_has_host_evidence
        and timestamps_ok
        and (
            (bool(literal_ip_targets) and bool(assessed_expected))
            or (not literal_ip_targets and target_count > 0 and hosts_assessed >= 1)
        )
    )
    clean_eligible = bool(assessment_complete and plugin_health_ok and not missing_ip_targets)

    if assessment_complete and plugin_errors > 0:
        verdict = "assessed_with_warnings"
        log.warning(
            "OpenVAS report %s completed target coverage with %d plugin/scanner error(s); "
            "marking completed-with-warnings (not clean-eligible)",
            report_id,
            plugin_errors,
        )
    elif assessment_complete and missing_ip_targets:
        verdict = "assessed_with_unreachable_skips"
    elif assessment_complete:
        verdict = "assessed"
    elif not report_id:
        verdict = "no_report"
    elif not report_has_host_evidence:
        verdict = "no_host_evidence"
    elif missing_ip_targets:
        verdict = "target_not_in_report"
    elif hosts_assessed < target_count:
        verdict = "partial_coverage"
    elif not timestamps_ok:
        verdict = "missing_scan_timestamps"
    else:
        verdict = "unverified"

    return {
        "report_id": report_id,
        "task_status": task_status,
        "scan_run_status": run_status,
        "progress": progress,
        "hosts_attempted": target_count,
        "hosts_assessed": hosts_assessed,
        "assessed_hosts": sorted(host_ips),
        "missing_ip_targets": missing_ip_targets,
        "target_identity_ok": target_identity_ok,
        "report_result_count": result_count,
        "report_result_count_full": full_result_count,
        "report_result_count_filtered": filtered_result_count,
        "report_materialized_result_count": materialized_result_count,
        "plugin_error_count": plugin_errors,
        "plugin_error_details": plugin_error_details,
        "host_coverage": host_coverage,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "assessment_complete": assessment_complete,
        "assessment_verdict": verdict,
        "plugin_health_ok": plugin_health_ok,
        "clean_eligible": clean_eligible,
        "alive_test": alive_test,
    }


def _vulnerabilities_from_report(response: Any) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for res in response.xpath(".//results/result"):
        nvt = res.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid") or ""
        name = nvt.findtext("name") or res.findtext("name") or ""
        family = nvt.findtext("family") or ""

        tags_raw = nvt.findtext("tags") or ""
        tag_values: dict[str, str] = {}
        for part in tags_raw.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value and key not in tag_values:
                tag_values[key] = value

        cvss, cvss_source, cvss_candidates = _best_cvss(nvt, res, tag_values)
        versioned_cvss = _versioned_cvss_scores(cvss_candidates)
        result_severity_raw = (res.findtext("severity") or "").strip() or None
        threat_raw = (res.findtext("threat") or "").strip() or None
        severity = _canonical_severity(threat_raw, cvss)

        cves: list[str] = []
        cwes: list[str] = []
        references: list[str] = []
        for ref in nvt.xpath("refs/ref"):
            rtype = (ref.get("type") or "").strip().lower()
            rid = (ref.get("id") or "").strip()
            if not rid:
                continue
            references.append(f"{rtype}:{rid}" if rtype else rid)
            if rtype == "cve":
                cve_id = rid.upper()
                if cve_id not in cves:
                    cves.append(cve_id)
            elif rtype == "cwe":
                cwe_id = rid.upper()
                if not cwe_id.startswith("CWE-") and cwe_id.isdigit():
                    cwe_id = f"CWE-{cwe_id}"
                if cwe_id not in cwes:
                    cwes.append(cwe_id)
        cve = cves[0] if cves else None
        cwe = cwes[0] if cwes else None

        port_raw = res.findtext("port") or ""
        port = None
        protocol = None
        if "/" in port_raw:
            port_part, protocol = port_raw.split("/", 1)
            try:
                port = int(port_part)
            except ValueError:
                port = None

        qod_raw = res.findtext("qod/value") or res.findtext("qod") or ""
        try:
            qod = float(qod_raw) if str(qod_raw).strip() else None
        except (TypeError, ValueError):
            qod = None
        qod_type = (res.findtext("qod/type") or "").strip() or None

        def _tag_float(*keys: str) -> float | None:
            for key in keys:
                raw = tag_values.get(key)
                if raw is None:
                    continue
                try:
                    return float(raw)
                except (TypeError, ValueError):
                    continue
            return None

        cvss_v2_vector = (tag_values.get("cvss_v2_vector") or tag_values.get("cvss2_vector") or None)
        cvss_v3_vector = (tag_values.get("cvss_v3_vector") or tag_values.get("cvss3_vector") or None)
        cvss_v4_vector = (tag_values.get("cvss_v4_vector") or tag_values.get("cvss4_vector") or None)
        cvss_vector = (
            cvss_v4_vector
            or cvss_v3_vector
            or cvss_v2_vector
            or tag_values.get("cvss_base_vector")
            or tag_values.get("cvss_vector")
            or None
        )
        exploit_maturity = (
            tag_values.get("exploit_maturity")
            or tag_values.get("exploit_code_maturity")
            or tag_values.get("exploit")
            or None
        )

        vulns.append(
            {
                "source_result_id": (res.get("id") or "").strip() or None,
                "result_id": (res.get("id") or "").strip() or None,
                "plugin_id": oid,
                "nvt_oid": oid,
                "plugin_family": family,
                "cve": cve,
                "cves": cves,
                "cwe": cwe,
                "cwes": cwes,
                "references": references,
                "score": cvss,
                "cvss": cvss,
                "cvss_v2": versioned_cvss["cvss_v2"],
                "cvss_v3": versioned_cvss["cvss_v3"],
                "cvss_v4": versioned_cvss["cvss_v4"],
                "cvss_source": cvss_source,
                "score_available": bool(cvss_candidates),
                "cvss_candidates": cvss_candidates,
                "cvss_vector": cvss_vector,
                "cvss_v2_vector": cvss_v2_vector,
                "cvss_v3_vector": cvss_v3_vector,
                "cvss_v4_vector": cvss_v4_vector,
                "greenbone_result_severity": result_severity_raw,
                "scanner_threat": threat_raw,
                "risk_factor": threat_raw,
                "severity": severity,
                "scan_engine": "openvas",
                "engine": "openvas",
                "qod": qod,
                "qod_type": qod_type,
                "vpr_score": _tag_float("vpr", "vpr_score"),
                "epss_percentile": _tag_float("epss_percentile", "epss"),
                "exploit_maturity": exploit_maturity,
                "plugin_name": name,
                "description": res.findtext("description") or tag_values.get("insight") or tag_values.get("summary") or "",
                "synopsis": tag_values.get("summary") or name,
                "solution": tag_values.get("solution") or "",
                "port": port,
                "protocol": protocol,
                "service": res.findtext("service") or tag_values.get("detected_protocol"),
                "product": res.findtext("product") or tag_values.get("detected_product"),
                "cpe": res.findtext("cpe") or tag_values.get("detected_cpe"),
                "version": res.findtext("version") or tag_values.get("detected_version"),
                "host": (res.findtext("host") or "").strip() or None,
            }
        )
    return vulns


def _get_report_once(gmp: Any, report_id: str, **kwargs: Any) -> Any:
    return gmp.get_report(report_id=report_id, **kwargs)


def _harvest_report_xml(gmp: Any, report_id: str) -> tuple[Any | None, list[dict[str, Any]], Exception | None]:
    """Load a Greenbone report without assuming one giant GMP reply.

    gvmd often closes the Unix socket when ``details=True`` + ``rows=-1`` is
    asked in one shot after a long scan. Metadata first, then paged results,
    then a full dump as last resort.
    """
    last_exc: Exception | None = None
    page_rows = _report_page_rows()

    meta = None
    for details, filt in (
        (False, _report_filter_string(first=1, rows=1)),
        (False, _report_filter_string(first=1, rows=10)),
    ):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=filt,
                ignore_pagination=False,
                details=details,
            )
            last_exc = None
            log.info("OpenVAS report %s metadata ok details=%s filter=%s", report_id, details, filt)
            break
        except Exception as exc:
            last_exc = exc
            log.warning(
                "get_report(%s) metadata details=%s filter=%s failed: %s",
                report_id,
                details,
                filt,
                exc,
            )
            if _gmp_connection_lost(exc):
                return None, [], last_exc

    vulns: list[dict[str, Any]] = []
    first = 1
    pages = 0
    while True:
        filt = _report_filter_string(first=first, rows=page_rows)
        chunk = None
        for details in (True, False):
            try:
                chunk = _get_report_once(
                    gmp,
                    report_id,
                    filter_string=filt,
                    ignore_pagination=False,
                    details=details,
                )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "get_report(%s, details=%s, first=%s) failed: %s",
                    report_id,
                    details,
                    first,
                    exc,
                )
                if _gmp_connection_lost(exc):
                    break
        if chunk is None:
            break
        if meta is None:
            meta = chunk
        try:
            page_vulns = _vulnerabilities_from_report(chunk)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities page first=%s: %s", first, exc)
            page_vulns = []
        vulns.extend(page_vulns)
        nodes = _xml_result_nodes(_inner_report(chunk))
        pages += 1
        if len(nodes) < page_rows:
            break
        first += page_rows
        if pages >= 500:
            log.warning("OpenVAS report %s page cap reached (%s pages)", report_id, pages)
            break

    if meta is None and pages == 0 and not (last_exc and _gmp_connection_lost(last_exc)):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=_report_filter_string(first=1, rows=page_rows),
                ignore_pagination=False,
                details=False,
            )
            last_exc = None
            vulns = _vulnerabilities_from_report(meta)
        except Exception as exc:
            last_exc = exc
            log.warning("get_report(%s) compact dump failed: %s", report_id, exc)

    return meta, vulns, last_exc


def _coverage_includes_parsed_results(evidence: dict[str, Any], vulns: list[dict[str, Any]]) -> None:
    """Fold paged findings into the coverage verdict.

    The metadata report is only the first result row, so a finished host can be
    marked ``degraded_no_ports`` with "0 NVTs" while the parsed report already
    holds hostname, traceroute, and OS rows. A completed task with no scanner
    error and no open service port is a finished scan, not an incomplete one.
    """
    coverage = evidence.get("host_coverage")
    if not isinstance(coverage, dict) or not coverage:
        return
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in vulns:
        host = str(row.get("host") or "").strip()
        if host:
            grouped.setdefault(host, []).append(row)
    hosts = [host for host, cov in coverage.items() if isinstance(cov, dict)]
    status = str(evidence.get("task_status") or evidence.get("scan_run_status") or "").lower()
    finished = status in {"done", "finished", "succeeded", "completed"}
    scanner_failed = int(evidence.get("plugin_error_count") or 0) > 0
    for host, cov in coverage.items():
        if not isinstance(cov, dict):
            continue
        rows = list(grouped.get(str(host).strip(), []))
        if not rows and len(hosts) == 1:
            rows = list(vulns)
        tcp = {int(p) for p in (cov.get("open_tcp_ports") or []) if str(p).isdigit()}
        udp = {int(p) for p in (cov.get("open_udp_ports") or []) if str(p).isdigit()}
        for row in rows:
            port = row.get("port")
            proto = str(row.get("protocol") or "").lower()
            if isinstance(port, int) and 1 <= port <= 65535:
                (udp if proto == "udp" else tcp).add(port)
        launched = max(int(cov.get("nvts_launched") or 0), len(rows))
        cov["open_tcp_ports"] = sorted(tcp)[:512]
        cov["open_udp_ports"] = sorted(udp)[:128]
        cov["nvts_launched"] = launched
        if str(cov.get("verdict") or "") != "degraded_no_ports":
            continue
        if cov.get("port_scanner_errors") or scanner_failed:
            cov["reason"] = (
                f"no open ports enumerated and only {launched} NVT(s) ran — "
                "host filtered, scanner timed out, or feed not loaded"
            )
            continue
        scored = any(
            str(row.get("severity") or "").lower() not in {"", "info", "log", "none"}
            for row in rows
        )
        if finished or tcp or udp or scored or launched >= 30:
            cov["verdict"] = "full"
            cov["reason"] = f"{len(tcp)} TCP / {len(udp)} UDP port(s), {launched} NVT(s) ran"


def _report_payload(
    gmp: Any,
    task_id: str,
    *,
    expected_targets: list[str],
    alive_test: str,
    task_status: str,
    progress: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _, _, task = _task_status(gmp, task_id)
    report_id = _task_report_id(task)
    if not report_id:
        evidence = {
            "report_id": None,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "no_report",
            "alive_test": alive_test,
        }
        return [], evidence

    response, paged_vulns, last_exc = _harvest_report_xml(gmp, report_id)
    if response is None:
        evidence = {
            "report_id": report_id,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "report_read_error",
            "alive_test": alive_test,
            "report_read_error": str(last_exc)[:1000] if last_exc else "get_report failed",
        }
        return [], evidence

    evidence = _report_evidence_from_xml(
        response,
        report_id=report_id,
        task_status=task_status,
        progress=progress,
        expected_targets=expected_targets,
        alive_test=alive_test,
    )
    vulns = paged_vulns
    if not vulns:
        try:
            vulns = _vulnerabilities_from_report(response)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities for report %s: %s", report_id, exc)
            vulns = []
            evidence["report_read_error"] = (
                ((evidence.get("report_read_error") or "") + f"; vuln_parse: {exc}")[:1000]
            )

    declared = int(evidence.get("report_result_count") or 0)
    full = int(evidence.get("report_result_count_full", -1))
    filtered = int(evidence.get("report_result_count_filtered", -1))
    materialized = int(evidence.get("report_materialized_result_count") or 0)
    parsed = len(vulns)
    if parsed and (materialized == 0 or materialized < parsed):
        evidence["report_materialized_result_count"] = parsed
        evidence["report_result_count"] = parsed
        materialized = parsed
        declared = parsed
    histogram: dict[str, int] = {}
    for row in vulns:
        sev = str(row.get("severity") or "info").lower()
        histogram[sev] = histogram.get(sev, 0) + 1
    log.info(
        "OpenVAS report %s result integrity full=%d filtered=%d materialized=%d parsed=%d severity=%s",
        report_id, full, filtered, materialized, parsed, histogram,
    )
    mismatch = ""
    # Paged harvest often returns fewer <results> in the metadata XML than the
    # combined pages. Do not fail coverage for that.
    if parsed > 0 and materialized == parsed:
        mismatch = ""
    elif filtered >= 0 and filtered != materialized and parsed == 0:
        mismatch = (
            f"filtered_result_count_mismatch filtered={filtered} "
            f"materialized={materialized}"
        )
    elif materialized != parsed:
        mismatch = f"parser_result_count_mismatch materialized={materialized} parsed={parsed}"
    elif declared != parsed:
        mismatch = f"result_count_mismatch returned={declared} parsed={parsed}"
    if mismatch:
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + mismatch)[:1000]
        )
        evidence["assessment_complete"] = False
        evidence["assessment_verdict"] = "result_count_mismatch"
    elif last_exc and (parsed == 0 or (filtered >= 0 and parsed < filtered)):
        err = str(last_exc)[:1000]
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + err)[:1000]
        )
    _coverage_includes_parsed_results(evidence, vulns)
    extra_hosts = {
        str(row.get("host") or "").strip()
        for row in vulns
        if str(row.get("host") or "").strip()
    }
    if extra_hosts:
        assessed = {str(h).strip() for h in (evidence.get("assessed_hosts") or []) if str(h).strip()}
        assessed.update(extra_hosts)
        evidence["assessed_hosts"] = sorted(assessed)
        evidence["hosts_assessed"] = max(int(evidence.get("hosts_assessed") or 0), len(assessed))
    evidence["service_coverage"] = {
        host: analyze_services(vulns, host=host, coverage=(evidence.get("host_coverage") or {}).get(host))
        for host in expected_targets
    }
    return vulns, evidence


class LocalOpenVAS:
    def __init__(self) -> None:
        self.socket_path = (os.environ.get("GVM_SOCKET_PATH") or "").strip() or None
        url = (os.environ.get("GVM_URL") or "").strip()
        self.host, self.port = "127.0.0.1", 9390
        if url and not self.socket_path:
            if "://" not in url:
                url = f"tls://{url}"
            parsed = urlparse(url)
            self.host = parsed.hostname or "127.0.0.1"
            self.port = parsed.port or 9390
            if parsed.scheme == "unix":
                self.socket_path = parsed.path or None
        self.username = os.environ.get("GVM_USERNAME") or "admin"
        self.password = os.environ.get("GVM_PASSWORD") or "admin"
        self.port_profile = (os.environ.get("PORT_PROFILE") or "full").strip().lower()
        self.udp_profile = (os.environ.get("UDP_PROFILE") or "priority").strip().lower()
        plugins_raw = int(os.environ.get("PLUGINS_TIMEOUT_SEC") or 0)
        scanner_raw = int(os.environ.get("SCANNER_PLUGINS_TIMEOUT_SEC") or 0)
        # V45 (Nessus parity). The previous 60 s / 90 s floors were added to stop
        # an SMB connect loop from pinning a host at 94-97 %, but
        # ``scanner_plugins_timeout`` is the budget for the *port-scanner* NVTs
        # (Nmap / find_service). A full T:1-65535 sweep needs minutes, so at 90 s
        # the scanner was killed, no services were discovered and every host
        # finished with only 3 informational results (plugin_errors=1).
        #
        # Use Greenbone's defaults (NVT 320 s, scanner NVTs 36 000 s). Hung
        # hosts are bounded by the agent-side watchdog instead
        # (MAX_SCAN_RUNTIME_SEC / STALL_SEC), which cancels the task and keeps
        # partial results rather than silently degrading coverage.
        if plugins_raw <= 0:
            plugins_raw = 320
        if scanner_raw <= 0:
            scanner_raw = 36000
        self.plugins_timeout = max(60, plugins_raw)
        self.scanner_plugins_timeout = max(self.plugins_timeout, scanner_raw)
        # V45: honour the configured per-host check concurrency. The old
        # ``max(configured, 16)`` silently overrode GVM_MAX_CHECKS=8, so eight
        # concurrent IP tasks became 128 NVT processes on a laptop.
        configured_checks = max(1, int(os.environ.get("GVM_MAX_CHECKS") or 8))
        self.max_hosts = max(1, int(os.environ.get("GVM_MAX_HOSTS") or 1))
        self.max_checks = min(configured_checks, 16)
        assessment = self.port_profile == "full" or self.port_profile in _VULN_PROFILES
        read_raw = max(1, int(os.environ.get("GVM_CHECKS_READ_TIMEOUT") or (10 if assessment else 5)))
        retry_raw = max(0, int(os.environ.get("GVM_TIMEOUT_RETRY") or (3 if assessment else 1)))
        sock_raw = max(1, int(os.environ.get("GVM_OPEN_SOCK_MAX_ATTEMPTS") or (5 if assessment else 2)))
        # The short fast profile keeps the aggressive socket caps. The
        # Nessus-style catalog uses the configured read and retry budget so
        # SMB, SSH, TLS, and database checks are not abandoned early.
        if self.max_hosts <= 1 and not assessment:
            read_raw = min(read_raw, 5)
            retry_raw = min(retry_raw, 1)
            sock_raw = min(sock_raw, 2)
        self.checks_read_timeout = read_raw
        self.timeout_retry = retry_raw
        self.open_sock_max_attempts = sock_raw
        self.scan_config_name = (os.environ.get("GVM_SCAN_CONFIG") or "Full and fast").strip()
        full_assessment = self.port_profile == "full"
        self.optimize_test = (
            os.environ.get("GVM_OPTIMIZE_TEST") or ("no" if full_assessment else "yes")
        ).strip().lower()
        # Use current OpenVAS scanner preference names.  A previous build sent
        # `thorough_tests`, which is not a current scanner preference and can
        # make gvmd reject the entire preference payload on some releases.
        self.safe_checks = (os.environ.get("GVM_SAFE_CHECKS") or "yes").strip().lower()
        self.expand_vhosts = (os.environ.get("GVM_EXPAND_VHOSTS") or "yes").strip().lower()
        self.test_empty_vhost = (os.environ.get("GVM_TEST_EMPTY_VHOST") or "yes").strip().lower()
        self.allow_bare_task_fallback = (
            os.environ.get("GVM_ALLOW_BARE_TASK_FALLBACK") or "false"
        ).strip().lower() in {"1", "true", "yes", "on"}
        # Explicitly authorized single-host scans must not be silently skipped
        # merely because ICMP/TCP discovery is blocked. python-gvm create_target
        # accepts the literal GMP alive-test string "Consider Alive".
        self.alive_test = (os.environ.get("GVM_ALIVE_TEST") or "Consider Alive").strip()
        self._next_not_ready_log = 0.0
        self.last_readiness_detail = "Greenbone readiness has not been checked yet"
        self.policy_snapshots: dict[str, dict[str, Any]] = {}

    def ready(self) -> bool:
        sock = (self.socket_path or "").strip()
        if sock and not os.path.exists(sock):
            self._log_not_ready("GMP socket not present yet (%s) — waiting for gvmd" % sock)
            return False
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _find_scanner_id(gmp)
                feed_state = _ospd_feed_state(gmp)
                if not feed_state.get("ready"):
                    self._log_not_ready(str(feed_state.get("detail") or "OSPd OpenVAS feed is still loading"))
                    return False
                config_id = _find_config_id(gmp, self.scan_config_name)
                health = _assert_feed_quality(gmp, config_id)
            count = health.get("nvt_count")
            self.last_readiness_detail = (
                f"Greenbone ready: {self.scan_config_name}; NVTs={count}"
                if count is not None
                else f"Greenbone ready: {self.scan_config_name}"
            )
            return True
        except Exception as exc:
            self._log_not_ready("Local OpenVAS not ready: %s" % exc)
            return False

    def _log_not_ready(self, message: str) -> None:
        self.last_readiness_detail = str(message)[:500]
        now = time.monotonic()
        if now < self._next_not_ready_log:
            return
        log.warning("%s", message)
        self._next_not_ready_log = now + 60.0

    def start_scan(self, *, name: str, targets: list[str], port_range: str | None = None,
                   scan_policy: dict[str, Any] | None = None) -> str:
        host_list = [t.strip() for t in targets if t and t.strip()]
        if not host_list:
            raise ValueError("At least one target is required")
        snapshot = _effective_scan_policy(scan_policy, self.port_profile, self.udp_profile)
        supplied_range = (port_range or "").strip()
        if supplied_range:
            port_range = _with_udp_range(supplied_range, self.udp_profile)
        else:
            port_range = snapshot["port_range"]
        try:
            from agent.control_plane import port_range_without_control_plane

            adjusted = port_range_without_control_plane(port_range, host_list)
            if adjusted != port_range:
                log.info("OpenVAS port_range excludes Aetheris control-plane HTTP ports")
                port_range = adjusted
        except Exception:
            log.debug("Control-plane port exclusion skipped", exc_info=True)
        snapshot["requested_port_range"] = snapshot["port_range"]
        for transport, key in (("T", "tcp_port_count"), ("U", "udp_port_count")):
            snapshot[key] = len({p for token in port_range.split(",") if token.startswith(transport + ":")
                                 for p in port_numbers(token[2:])})
        with _session(
            socket_path=self.socket_path,
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
        ) as gmp:
            try:
                config_id = _ensure_portscan_config(gmp, self.scan_config_name)
            except Exception:
                log.warning("Nmap SYN config unavailable; using %s", self.scan_config_name, exc_info=True)
                config_id = _find_config_id(gmp, self.scan_config_name)
            health = _assert_feed_quality(gmp, config_id)
            scanner_id = _find_scanner_id(gmp)
            bindings: dict[str, str] = {}
            credential_status: dict[str, str] = {}
            for kind, credential_id in snapshot["gmp_credential_refs"].items():
                try:
                    response = gmp.get_credential(credential_id)
                    if not response.xpath(".//credential[@id=$id]", id=credential_id):
                        raise ValueError("Credential reference is unavailable on this scanner")
                    bindings[f"{kind}_credential_id"] = credential_id
                    if kind == "ssh":
                        bindings["ssh_credential_port"] = snapshot["ssh_credential_port"]
                    credential_status[kind] = "bound; authentication success requires native report evidence"
                except Exception:
                    credential_status[kind] = "not-tested; local credential reference lookup failed"
            target_args = {"name": f"{name}-tgt-{int(time.time())}", "hosts": host_list,
                           "port_range": port_range, "alive_test": self.alive_test}
            try:
                target = gmp.create_target(**target_args, **bindings)
            except Exception as exc:
                if not bindings or not (isinstance(exc, TypeError) or "credential" in str(exc).lower()):
                    raise
                # Unauthenticated protocol detection still runs if credential
                # binding is unsupported; the gap is kept in the policy evidence.
                credential_status = {k: "not-tested; credential binding rejected" for k in credential_status}
                target = gmp.create_target(**target_args)
            target_id = target.get("id")
            if not target_id:
                raise RuntimeError("Failed to create Greenbone target")
            # These names are current OpenVAS scanner preferences.  Do not
            # send legacy/non-scanner keys: one rejected key can cause the
            # whole task preference payload to be rejected.
            prefs = {
                "max_checks": str(self.max_checks),
                "max_hosts": str(self.max_hosts),
                "checks_read_timeout": str(self.checks_read_timeout),
                "timeout_retry": str(self.timeout_retry),
                "open_sock_max_attempts": str(self.open_sock_max_attempts),
                "optimize_test": "no" if snapshot["port_profile"] == "full" else self.optimize_test,
                "safe_checks": self.safe_checks,
                "plugins_timeout": str(self.plugins_timeout),
                "scanner_plugins_timeout": str(self.scanner_plugins_timeout),
                "expand_vhosts": self.expand_vhosts,
                "test_empty_vhost": self.test_empty_vhost,
                "report_host_details": "yes",
            }
            log.info(
                "OpenVAS quality profile max_checks=%s max_hosts=%s "
                "checks_read_timeout=%ss timeout_retry=%s open_sock_max_attempts=%s "
                "plugins_timeout=%ss scanner_plugins_timeout=%ss optimize_test=%s "
                "safe_checks=%s expand_vhosts=%s test_empty_vhost=%s",
                self.max_checks,
                self.max_hosts,
                self.checks_read_timeout,
                self.timeout_retry,
                self.open_sock_max_attempts,
                self.plugins_timeout,
                self.scanner_plugins_timeout,
                self.optimize_test,
                self.safe_checks,
                self.expand_vhosts,
                self.test_empty_vhost,
            )
            applied_prefs = dict(prefs)
            preference_status = "full"
            try:
                task = gmp.create_task(
                    name=name[:128],
                    config_id=config_id,
                    target_id=str(target_id),
                    scanner_id=scanner_id,
                    preferences=prefs,
                )
            except Exception as pref_exc:
                # Retry once with the smallest quality-critical preference set.
                # Do not silently fall back to a bare task: that can change
                # optimize/thorough behavior and produce a misleadingly shallow
                # report that still reaches 100%.
                minimal_prefs = {
                    "max_checks": str(self.max_checks),
                    "max_hosts": str(self.max_hosts),
                    "optimize_test": prefs["optimize_test"],
                    "safe_checks": self.safe_checks,
                }
                log.warning(
                    "create_task full preferences failed (%s); retrying quality-critical preferences",
                    pref_exc,
                )
                try:
                    applied_prefs = dict(minimal_prefs)
                    preference_status = "quality-critical fallback"
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                        preferences=minimal_prefs,
                    )
                except Exception as minimal_exc:
                    if not self.allow_bare_task_fallback:
                        raise RuntimeError(
                            "Greenbone rejected required task quality preferences; refusing a bare/degraded scan. "
                            "Set GVM_ALLOW_BARE_TASK_FALLBACK=true only for diagnostic compatibility."
                        ) from minimal_exc
                    log.error(
                        "DEGRADED SCAN: Greenbone rejected task preferences (%s); bare fallback explicitly enabled",
                        minimal_exc,
                    )
                    applied_prefs = {}
                    preference_status = "degraded bare task explicitly enabled"
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                    )
            task_id = task.get("id")
            if not task_id:
                raise RuntimeError("Failed to create Greenbone task")
            start_response = gmp.start_task(str(task_id))
            snapshot.update({"port_range": port_range, "targets": host_list, "task_id": str(task_id),
                             "config_id": config_id, "scanner_id": scanner_id,
                             "scan_config_name": self.scan_config_name, "preferences": applied_prefs,
                             "preference_status": preference_status, "credential_status": credential_status,
                             "nvt_count": (health or {}).get("nvt_count"),
                             "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "snapshot_status": "captured_at_task_start"})
            try:
                feeds = gmp.get_feeds()
                snapshot["feed_versions"] = {str(f.findtext("type") or "unknown"): str(f.findtext("version") or "unknown")
                                             for f in feeds.xpath(".//feed")}
            except Exception:
                snapshot["feed_versions"] = {"status": "not available from GMP"}
            import hashlib
            import json
            snapshot["configuration_sha256"] = hashlib.sha256(json.dumps({k: v for k, v in snapshot.items() if k != "configuration_sha256"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.policy_snapshots[str(task_id)] = snapshot
            report_id = None
            try:
                report_id = start_response.findtext("report_id") or (
                    start_response[0].text if len(start_response) else None
                )
            except Exception:
                report_id = None
            log.info(
                "Started local OpenVAS task %s report=%s hosts=%s alive_test=%s "
                "port_profile=%s udp_profile=%s port_range=%s",
                task_id,
                report_id,
                host_list,
                self.alive_test,
                self.port_profile,
                self.udp_profile,
                port_range,
            )
            return str(task_id)

    def get_task_hosts(self, task_id: str) -> list[str] | None:
        """Return the hosts bound to an OpenVAS task, or None if unverifiable.

        None means the task is missing or GMP did not return a host list. Callers
        must not guess by chunk index — that is how one network's IPs get
        attached to another job.
        """
        tid = str(task_id or "").strip()
        if not tid:
            return None
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _, _, task = _task_status(gmp, tid)
                if task is None:
                    return None
                hosts = _hosts_from_task_elem(task)
                if hosts:
                    return hosts
                target = task.find("target") if hasattr(task, "find") else None
                target_id = (target.get("id") if target is not None else None) or None
                if not target_id:
                    return None
                try:
                    tresp = gmp.get_target(str(target_id))
                except Exception:
                    tresp = gmp.get_targets(filter_string=f"uuid={target_id}")
                tnode = tresp.find("target") if hasattr(tresp, "find") else None
                if tnode is None and hasattr(tresp, "xpath"):
                    nodes = tresp.xpath(".//target")
                    tnode = nodes[0] if nodes else None
                hosts = _hosts_from_target_elem(tnode)
                return hosts or None
        except Exception as exc:
            msg = str(exc).lower()
            status = str(getattr(exc, "status", "") or "")
            if status == "404" or "failed to find task" in msg:
                log.info("OpenVAS task %s is gone; treating leftover id as stale", tid)
                return []
            log.warning("Could not read hosts for OpenVAS task %s", tid, exc_info=True)
            return None

    def _session_kwargs(self) -> dict[str, Any]:
        return {
            "socket_path": self.socket_path,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }

    def poll(
        self,
        task_id: str,
        *,
        expected_targets: list[str] | None = None,
        include_running_report: bool = False,
    ) -> dict[str, Any]:
        targets = [str(t).strip() for t in (expected_targets or []) if str(t).strip()]
        with _session(**self._session_kwargs()) as gmp:
            status, progress, _ = _task_status(gmp, task_id)
        mapped = "running"
        # Greenbone stays at ~99% with status Processing while it writes the
        # report. That is not a failure — wait for Done, then harvest.
        if status in {"done", "finished", "succeeded"}:
            mapped = "completed"
        elif status in {"stopped", "interrupted", "stop requested"}:
            mapped = "stopped"
        elif status in {"failed", "internal error", "delete requested"}:
            mapped = "failed"
        elif status == "processing":
            mapped = "running"
            progress = max(progress, 99.0)

        vulns: list[dict[str, Any]] = []
        evidence: dict[str, Any] = {
            "report_id": None,
            "task_status": status,
            "progress": progress,
            "hosts_attempted": len(targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "assessment_complete": False,
            "assessment_verdict": "not_finished" if mapped == "running" else "pending_report",
            "alive_test": self.alive_test,
        }
        if mapped in {"completed", "stopped", "failed"} or include_running_report:
            last_exc: Exception | None = None
            for attempt in range(8):
                try:
                    # Never reuse a GMP socket after get_report. gvmd closes it
                    # under large XML and every retry on that handle fails fast.
                    with _session(**self._session_kwargs()) as gmp:
                        vulns, evidence = _report_payload(
                            gmp,
                            task_id,
                            expected_targets=targets,
                            alive_test=self.alive_test,
                            task_status=status,
                            progress=progress,
                        )
                    last_exc = None
                except Exception as exc:
                    last_exc = exc
                    evidence["assessment_verdict"] = "report_read_error"
                    evidence["report_read_error"] = str(exc)[:1000]
                    log.warning("Could not read results/evidence for %s (attempt %s)", task_id, attempt + 1)
                filtered_n = int(evidence.get("report_result_count_filtered") or 0)
                incomplete_results = bool(evidence.get("report_read_error")) and (
                    not evidence.get("scan_start")
                    or (filtered_n > 0 and len(vulns) < filtered_n)
                )
                if evidence.get("report_id") and not incomplete_results and (
                    evidence.get("assessment_complete")
                    or not evidence.get("report_read_error")
                ):
                    break
                if mapped != "completed":
                    break
                time.sleep(min(8, 2 + attempt))
                try:
                    with _session(**self._session_kwargs()) as gmp:
                        status, progress, _ = _task_status(gmp, task_id)
                    if status in {"done", "finished", "succeeded"}:
                        mapped = "completed"
                except Exception:
                    log.warning("Could not refresh task status for %s after harvest retry", task_id)
            if last_exc and not evidence.get("report_id"):
                log.warning("Could not read results/evidence for %s", task_id, exc_info=True)

        evidence["policy_snapshots"] = {task_id: self.policy_snapshots.get(task_id) or {
            "task_id": task_id, "targets": targets, "snapshot_status": "unknown-resumed-task",
            "reason": "Original task policy was not captured by this build"}}
        return {
            "status": mapped,
            "gmp_status": status,
            "progress": progress,
            "vulnerabilities": vulns,
            "evidence": evidence,
        }

    def stop(self, task_id: str) -> None:
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=8,
            ) as gmp:
                gmp.stop_task(task_id)
        except Exception:
            log.warning("stop_task failed for %s", task_id, exc_info=True)
