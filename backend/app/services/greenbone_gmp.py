"""Live Greenbone GMP operations via python-gvm.

The Greenbone community containers expose ``gvmd`` through a Unix domain
socket by default.  TCP/TLS is still supported for external Greenbone
installations, but the local Docker deployment should use the shared socket.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

log = logging.getLogger("greenbone_gmp")

DEFAULT_SCAN_CONFIG = "Full and fast"
# Greenbone requires each target to specify either a port list or an explicit
# port range. Prefer the feed-provided IANA TCP list when available and fall
# back to all TCP ports so target creation never omits this mandatory field.
DEFAULT_TARGET_PORT_RANGE = "T:1-65535"
# High-performance default: common service ports (Nmap-ish top set), not full IANA.
# Intentionally omit heavy app ports like 9200 (OpenSearch/ES) and 8888-class
# HTTP alt ports — Full-and-fast web NVTs often stall the last few percent
# hammering those endpoints (path-traversal / win.ini probes).
FAST_TARGET_PORT_RANGE = (
    "T:21-23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,631,993,995,"
    "1433,1521,1723,2049,3000,3306,3389,5432,5672,5900,5985,6379,6443,"
    "8080,8443,9000,9418,27017"
)
PREFERRED_PORT_LIST_NAMES = (
    "All IANA assigned TCP",
    "All TCP and Nmap top 100 UDP",
)
# Used only when GVM_PORT_PROFILE=full.
FULL_PORT_LIST_NAMES = PREFERRED_PORT_LIST_NAMES
# Greenbone's well-known default OpenVAS scanner UUID.  We still discover the
# scanner dynamically first so custom installations are supported.
DEFAULT_OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
DEFAULT_GVMD_SOCKET = "/run/gvmd/gvmd.sock"


def parse_tcp_ports_from_range(spec: str) -> list[int]:
    """Parse a Greenbone port_range string (T:80,443,8000-8002) into TCP ports."""
    ports: list[int] = []
    raw = (spec or "").strip()
    if raw.upper().startswith("T:"):
        raw = raw[2:]
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if token.upper().startswith("T:"):
            token = token[2:]
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            ports.extend(range(max(1, lo), min(65535, hi) + 1))
            continue
        try:
            ports.append(int(token))
        except ValueError:
            continue
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def ports_to_gvm_range(ports: list[int]) -> str:
    clean = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    if not clean:
        return FAST_TARGET_PORT_RANGE
    return "T:" + ",".join(str(p) for p in clean)


def probe_open_tcp_ports(
    hosts: list[str],
    ports: list[int] | None = None,
    timeout: float = 0.35,
) -> dict[str, list[int]]:
    """Fast parallel TCP connect probe. Used to shrink OpenVAS to live ports."""
    hosts_c = [h.strip() for h in hosts if str(h).strip()]
    port_list = ports or parse_tcp_ports_from_range(FAST_TARGET_PORT_RANGE)
    found: dict[str, list[int]] = {h: [] for h in hosts_c}

    def _one(host: str, port: int) -> tuple[str, int, bool]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return host, port, True
        except OSError:
            return host, port, False

    if not hosts_c or not port_list:
        return found
    workers = min(64, max(8, len(hosts_c) * min(12, len(port_list))))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_one, h, p) for h in hosts_c for p in port_list]
        for fut in as_completed(futs):
            host, port, ok = fut.result()
            if ok:
                found[host].append(port)
    for host in found:
        found[host] = sorted(set(found[host]))
    return found


class GreenboneFeedNotReadyError(RuntimeError):
    """Raised when GMP is reachable but feed-provided scan objects are not ready yet."""

    def __init__(self, message: str, *, available_configs: list[str] | None = None):
        super().__init__(message)
        self.available_configs = available_configs or []


def _parse_host_port(base_url: str, default_port: int = 9390) -> tuple[str, int]:
    """Parse a TCP GMP endpoint, accepting legacy ``gmp://`` URLs."""
    raw = (base_url or "").strip()
    if not raw:
        return "gvmd", default_port
    if "://" not in raw:
        raw = f"tls://{raw}"
    parsed = urlparse(raw)
    host = parsed.hostname or "gvmd"
    port = parsed.port or default_port
    return host, port


def parse_socket_path(base_url: str | None) -> str | None:
    """Return a Unix socket path when *base_url* is a unix:// endpoint."""
    raw = (base_url or "").strip()
    if not raw.lower().startswith("unix://"):
        return None
    parsed = urlparse(raw)
    # urlparse("unix:///run/gvmd/gvmd.sock").path is the desired path.
    path = parsed.path or ""
    if not path and parsed.netloc:
        path = f"/{parsed.netloc}"
    return path or None


def is_local_gvmd_tcp_url(base_url: str | None, default_port: int = 9390) -> bool:
    """Whether an old scanner URL points at this Compose project's gvmd."""
    raw = (base_url or "").strip()
    if not raw:
        return True
    if "://" not in raw:
        raw = f"tls://{raw}"
    parsed = urlparse(raw)
    return (parsed.hostname or "").lower() == "gvmd" and (parsed.port or default_port) == default_port


def _severity_from_threat(threat: str | None, cvss: float, synopsis: str = "") -> str:
    from app.services.aetheris_severity import classify_severity

    sev, _ = classify_severity(cvss=cvss, synopsis=synopsis, raw_severity=threat)
    return sev


def _imports():
    try:
        from gvm.connections import TLSConnection, UnixSocketConnection
        try:
            from gvm.protocols.gmp import GMP
        except ImportError:  # pragma: no cover - compatibility with older python-gvm
            from gvm.protocols.gmp import Gmp as GMP  # type: ignore
        try:
            from gvm.transforms import EtreeCheckCommandTransform
        except ImportError:  # pragma: no cover - compatibility with older python-gvm
            from gvm.transforms import EtreeTransform as EtreeCheckCommandTransform  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised in scanner image
        raise RuntimeError("python-gvm is not installed") from exc
    return TLSConnection, UnixSocketConnection, GMP, EtreeCheckCommandTransform


@contextmanager
def _gmp_session(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    verify: bool,
    socket_path: str | None = None,
) -> Iterator[Any]:
    """Open and authenticate a GMP session.

    ``verify`` is retained for API compatibility.  python-gvm's TLSConnection
    performs TLS according to its own connection configuration; local Compose
    deployments avoid TCP/TLS entirely and use the gvmd Unix socket.
    """
    TLSConnection, UnixSocketConnection, GMP, EtreeCheckCommandTransform = _imports()

    if socket_path:
        if not os.path.exists(socket_path):
            raise RuntimeError(
                f"gvmd Unix socket not found at {socket_path}. "
                "Start the Greenbone profile and ensure the worker mounts the gvmd socket volume."
            )
        connection = UnixSocketConnection(path=socket_path)
    else:
        connection = TLSConnection(hostname=host, port=port, timeout=120)

    transform = EtreeCheckCommandTransform()
    # python-gvm recommends the protocol context manager so connect/disconnect
    # are deterministic even when authentication or a GMP command fails.
    with GMP(connection=connection, transform=transform) as gmp:
        gmp.authenticate(username, password)
        yield gmp


def gmp_available() -> bool:
    try:
        import gvm  # noqa: F401

        return True
    except ImportError:
        return False


def _first_entity(response: Any, tag: str) -> Any | None:
    """Extract an entity from a GMP get_* response wrapper."""
    if response is None:
        return None
    try:
        if getattr(response, "tag", None) == tag:
            return response
        found = response.find(tag)
        if found is not None:
            return found
        nodes = response.xpath(tag)
        return nodes[0] if nodes else None
    except Exception:
        return None


def _response_version(response: Any) -> str:
    if response is None:
        return ""
    try:
        return response.findtext("version") or response.findtext("gmp/version") or ""
    except Exception:
        return str(response)


def gmp_ping(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    verify: bool = False,
    socket_path: str | None = None,
) -> dict[str, Any]:
    host, port = _parse_host_port(f"{host}:{port}" if host and ":" not in host else host, port)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        version = _response_version(gmp.get_version())
        result: dict[str, Any] = {"status": "ok", "version": version}
        if socket_path:
            result["socket_path"] = socket_path
            result["transport"] = "unix"
        else:
            result.update({"host": host, "port": port, "transport": "tls"})
        return result


def _scan_config_inventory(gmp: Any) -> list[dict[str, str]]:
    """Return every scan config currently visible through GMP.

    An empty list means gvmd is reachable/authenticated but its feed-provided
    data objects have not been imported yet (or the import failed).
    """
    response = gmp.get_scan_configs()
    result: list[dict[str, str]] = []
    for cfg in list(response.xpath("config")):
        config_id = str(cfg.get("id") or "").strip()
        name = (cfg.findtext("name") or "").strip()
        if config_id or name:
            result.append({"id": config_id, "name": name})
    return result


def _find_scan_config_id(gmp: Any, scan_config_name: str) -> str:
    requested = scan_config_name.strip()
    requested_folded = requested.casefold()

    # Fast path: ask gvmd for the requested name. Some versions treat this
    # filter loosely, therefore every returned name is still validated.
    try:
        configs = gmp.get_scan_configs(filter_string=f"name={requested}")
        nodes = list(configs.xpath("config"))
        for cfg in nodes:
            name = (cfg.findtext("name") or "").strip()
            if name.casefold() == requested_folded and cfg.get("id"):
                return str(cfg.get("id"))
    except Exception:
        log.debug("Filtered Greenbone scan-config lookup failed; retrying unfiltered", exc_info=True)

    inventory = _scan_config_inventory(gmp)
    for cfg in inventory:
        if cfg["name"].casefold() == requested_folded and cfg["id"]:
            return cfg["id"]

    available_names = [cfg["name"] for cfg in inventory if cfg["name"]]
    if available_names:
        message = (
            f"Greenbone is connected, but scan config '{requested}' is not available. "
            f"Available scan configs: {available_names}. "
            "Check GVM_SCAN_CONFIG or wait for the Greenbone data-object feed import to complete."
        )
    else:
        message = (
            f"No Greenbone scan config named '{requested}' is available because gvmd currently "
            "reports zero scan configs. The GMP connection works, but Greenbone feed/data objects "
            "have not finished importing (or the feed import failed)."
        )
    raise GreenboneFeedNotReadyError(message, available_configs=available_names)


def _find_openvas_scanner_id(gmp: Any) -> str:
    try:
        scanners = gmp.get_scanners()
        nodes = list(scanners.xpath("scanner"))
        for scanner in nodes:
            name = (scanner.findtext("name") or "").lower()
            scanner_type = (scanner.findtext("type") or "").lower()
            if "openvas" in name or "openvas" in scanner_type:
                scanner_id = scanner.get("id")
                if scanner_id:
                    return str(scanner_id)
        # The default scanner is normally present under the well-known UUID.
        for scanner in nodes:
            if scanner.get("id") == DEFAULT_OPENVAS_SCANNER_ID:
                return DEFAULT_OPENVAS_SCANNER_ID
    except Exception:
        log.debug("Unable to enumerate GVM scanners; using default OpenVAS scanner UUID", exc_info=True)
    return DEFAULT_OPENVAS_SCANNER_ID


def _find_preferred_port_list_id(gmp: Any, *, preferred_names: tuple[str, ...] | None = None) -> str | None:
    """Return a suitable feed-provided port-list UUID when available.

    ``gvmd`` rejects CREATE_TARGET when neither PORT_LIST nor PORT_RANGE is
    provided.  Community data objects normally provide predefined port lists,
    but startup/feed timing can temporarily make them unavailable.  This
    helper therefore treats port-list discovery as an optimization only; the
    caller has a deterministic explicit-port-range fallback.
    """
    names = preferred_names or PREFERRED_PORT_LIST_NAMES
    try:
        response = gmp.get_port_lists()
        nodes = list(response.xpath("port_list"))
    except Exception:
        log.warning("Unable to enumerate Greenbone port lists; using explicit TCP port range", exc_info=True)
        return None

    # Prefer exact canonical Greenbone list names first.
    by_name: dict[str, str] = {}
    for node in nodes:
        port_list_id = node.get("id")
        name = (node.findtext("name") or "").strip()
        if port_list_id and name:
            by_name[name.casefold()] = str(port_list_id)

    for preferred in names:
        port_list_id = by_name.get(preferred.casefold())
        if port_list_id:
            return port_list_id

    # Be tolerant of small feed naming changes while still preferring the
    # smaller IANA TCP set over an expensive all-TCP/all-UDP list.
    for node in nodes:
        name = (node.findtext("name") or "").strip().casefold()
        port_list_id = node.get("id")
        if port_list_id and "iana" in name and "tcp" in name and "udp" not in name:
            return str(port_list_id)

    return None


def _resolve_port_selection(gmp: Any) -> dict[str, str]:
    """Choose fast port range vs full IANA list from settings."""
    try:
        from app.config import get_settings

        settings = get_settings()
        profile = (getattr(settings, "gvm_port_profile", "fast") or "fast").strip().lower()
        override = (getattr(settings, "gvm_target_port_range", "") or "").strip()
    except Exception:
        profile, override = "fast", ""

    if override:
        return {"port_selection": "port_range", "port_range": override}

    if profile in {"full", "iana", "all"}:
        port_list_id = _find_preferred_port_list_id(gmp, preferred_names=FULL_PORT_LIST_NAMES)
        if port_list_id:
            return {"port_selection": "port_list", "port_list_id": port_list_id}
        return {"port_selection": "port_range", "port_range": DEFAULT_TARGET_PORT_RANGE}

    # Default high-performance profile: explicit common-port range (avoids scanning
    # the entire IANA TCP set, which is the main OpenVAS wall-clock cost).
    return {"port_selection": "port_range", "port_range": FAST_TARGET_PORT_RANGE}


def _task_performance_preferences() -> dict[str, str]:
    try:
        from app.config import get_settings

        settings = get_settings()
        max_checks = max(1, int(getattr(settings, "gvm_max_checks", 20) or 20))
        max_hosts = max(1, int(getattr(settings, "gvm_max_hosts", 4) or 4))
        optimize = bool(getattr(settings, "gvm_optimize_test", False))
        safe_checks = bool(getattr(settings, "gvm_safe_checks", True))
        checks_read_timeout = max(1, int(getattr(settings, "gvm_checks_read_timeout", 10) or 10))
        timeout_retry = max(0, int(getattr(settings, "gvm_timeout_retry", 3) or 0))
        open_sock_max_attempts = max(0, int(getattr(settings, "gvm_open_sock_max_attempts", 5) or 0))
        expand_vhosts = bool(getattr(settings, "gvm_expand_vhosts", True))
        test_empty_vhost = bool(getattr(settings, "gvm_test_empty_vhost", True))
        plugins_raw = int(getattr(settings, "gvm_plugins_timeout_sec", 0) or 0)
        scanner_raw = int(getattr(settings, "gvm_scanner_plugins_timeout_sec", 0) or 0)
        # OpenVAS requires a positive integer; 0 means "do not cap" → 30 days.
        plugins_timeout = 86400 * 30 if plugins_raw <= 0 else max(30, plugins_raw)
        scanner_plugins_timeout = (
            86400 * 30 if scanner_raw <= 0 else max(plugins_timeout, scanner_raw)
        )
    except Exception:
        max_checks, max_hosts, optimize, safe_checks = 20, 4, False, True
        checks_read_timeout, timeout_retry, open_sock_max_attempts = 10, 3, 5
        expand_vhosts, test_empty_vhost = True, True
        plugins_timeout, scanner_plugins_timeout = 86400 * 30, 86400 * 30
    try:
        from app.services.vuln_capacity import adaptive_gvm_max_hosts_checks

        max_hosts, max_checks = adaptive_gvm_max_hosts_checks()
    except Exception:
        pass
    return {
        "max_checks": str(max_checks),
        "max_hosts": str(max_hosts),
        "checks_read_timeout": str(checks_read_timeout),
        "timeout_retry": str(timeout_retry),
        "open_sock_max_attempts": str(open_sock_max_attempts),
        "optimize_test": "yes" if optimize else "no",
        "safe_checks": "yes" if safe_checks else "no",
        "expand_vhosts": "yes" if expand_vhosts else "no",
        "test_empty_vhost": "yes" if test_empty_vhost else "no",
        "report_host_details": "yes",
        # Slow NVTs are allowed to finish; 30d is the practical unlimited cap.
        "plugins_timeout": str(plugins_timeout),
        "scanner_plugins_timeout": str(scanner_plugins_timeout),
    }


def gmp_stop_task(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    task_id: str,
    verify: bool = False,
    socket_path: str | None = None,
) -> None:
    """Best-effort stop so near-complete stalled scans can be harvested."""
    host, port = _parse_host_port(host, port)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        try:
            gmp.stop_task(task_id)
            log.info("Requested stop for Greenbone task %s", task_id)
        except Exception:
            log.warning("Unable to stop Greenbone task %s", task_id, exc_info=True)


def _resolve_scan_config_name(explicit: str | None = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    try:
        from app.config import get_settings

        name = (getattr(get_settings(), "gvm_scan_config", None) or DEFAULT_SCAN_CONFIG).strip()
        return name or DEFAULT_SCAN_CONFIG
    except Exception:
        return DEFAULT_SCAN_CONFIG


def _feed_count_from_xml(response: Any) -> int | None:
    if response is None or not hasattr(response, "xpath"):
        return None
    values: list[int] = []
    for xpath in (
        ".//nvt_count/filtered/text()",
        ".//nvt_count/total/text()",
        ".//nvt_count/text()",
        ".//config/nvt_count/text()",
    ):
        try:
            for raw in response.xpath(xpath):
                try:
                    values.append(int(str(raw).strip()))
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
    return max(values) if values else None


def _gmp_feed_quality(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
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
        nvts = gmp.get_nvts(filter_string="rows=1 first=1")
        nvt_count = _feed_count_from_xml(nvts)
        if nvt_count is None and hasattr(nvts, "xpath") and nvts.xpath(".//nvt"):
            nvt_count = -1
    except Exception:
        log.debug("Unable to read Greenbone NVT inventory", exc_info=True)

    config_nvt_count: int | None = None
    getter = getattr(gmp, "get_scan_config", None)
    if config_id and callable(getter):
        try:
            config_nvt_count = _feed_count_from_xml(getter(config_id))
        except Exception:
            log.debug("Unable to read Greenbone scan-config NVT count", exc_info=True)

    return {
        "syncing": syncing,
        "versions": versions,
        "nvt_count": nvt_count,
        "config_nvt_count": config_nvt_count,
    }


def _required_min_nvt_count() -> int:
    try:
        from app.config import get_settings
        return max(1, int(getattr(get_settings(), "gvm_min_nvt_count", 10000) or 10000))
    except Exception:
        return 10000


def _assert_gmp_feed_quality(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    health = _gmp_feed_quality(gmp, config_id)
    if health["syncing"]:
        raise GreenboneFeedNotReadyError(
            "Greenbone feed is still synchronizing; refusing to start a partial-quality scan"
        )
    minimum = _required_min_nvt_count()
    for label in ("nvt_count", "config_nvt_count"):
        count = health.get(label)
        if isinstance(count, int) and count >= 0 and count < minimum:
            raise GreenboneFeedNotReadyError(
                f"Greenbone {label}={count} is below required minimum {minimum}; feed/config import is incomplete"
            )
    return health


def gmp_scan_readiness(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    scan_config_name: str = DEFAULT_SCAN_CONFIG,
    verify: bool = False,
    socket_path: str | None = None,
) -> dict[str, Any]:
    """Return readiness without throwing merely because feed objects are late.

    Connection/authentication errors still raise. A reachable gvmd with zero
    configs (or without the requested config) returns ``status=initializing``.
    """
    host, port = _parse_host_port(host, port)
    config_name = _resolve_scan_config_name(scan_config_name)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        inventory = _scan_config_inventory(gmp)
        available_names = [cfg["name"] for cfg in inventory if cfg["name"]]

        try:
            config_id = _find_scan_config_id(gmp, config_name)
        except GreenboneFeedNotReadyError as exc:
            return {
                "status": "initializing",
                "ready": False,
                "gmp_connected": True,
                "scan_config": config_name,
                "scan_config_id": None,
                "config_available": False,
                "available_scan_configs": exc.available_configs or available_names,
                "message": str(exc),
                "transport": "unix" if socket_path else "tls",
                "socket_path": socket_path,
                "host": None if socket_path else host,
                "port": None if socket_path else port,
            }

        try:
            feed_quality = _assert_gmp_feed_quality(gmp, config_id)
        except GreenboneFeedNotReadyError as exc:
            return {
                "status": "initializing",
                "ready": False,
                "gmp_connected": True,
                "scan_config": config_name,
                "scan_config_id": config_id,
                "config_available": True,
                "available_scan_configs": available_names,
                "message": str(exc),
                "transport": "unix" if socket_path else "tls",
                "socket_path": socket_path,
                "host": None if socket_path else host,
                "port": None if socket_path else port,
            }
        scanner_id = _find_openvas_scanner_id(gmp)
        port_sel = _resolve_port_selection(gmp)
        prefs = _task_performance_preferences()
        return {
            "status": "ok",
            "ready": True,
            "gmp_connected": True,
            "scan_config": config_name,
            "scan_config_id": config_id,
            "config_available": True,
            "available_scan_configs": available_names,
            "scanner_id": scanner_id,
            "performance": prefs,
            "feed_quality": feed_quality,
            "transport": "unix" if socket_path else "tls",
            "socket_path": socket_path,
            "host": None if socket_path else host,
            "port": None if socket_path else port,
            **port_sel,
        }


def _wait_for_scan_config(gmp: Any, config_name: str) -> str:
    """Wait until feed scan configs are visible. timeout 0 = wait indefinitely."""
    try:
        from app.config import get_settings

        settings = get_settings()
        timeout = max(0, int(getattr(settings, "gvm_feed_ready_timeout_sec", 0) or 0))
        interval = max(2, int(getattr(settings, "gvm_feed_ready_poll_interval_sec", 15) or 15))
    except Exception:
        timeout, interval = 0, 15

    deadline = (time.monotonic() + timeout) if timeout > 0 else None
    last_error: GreenboneFeedNotReadyError | None = None

    while True:
        try:
            return _find_scan_config_id(gmp, config_name)
        except GreenboneFeedNotReadyError as exc:
            last_error = exc
            if deadline is not None and time.monotonic() >= deadline:
                raise
            log.warning(
                "Greenbone feed not ready for scan config %r; retrying in %ss. %s",
                config_name,
                interval,
                exc,
            )
            time.sleep(interval)

    # Kept for type checkers; the loop either returns or raises.
    if last_error:
        raise last_error
    raise GreenboneFeedNotReadyError(f"Greenbone scan config '{config_name}' is unavailable")


def gmp_create_and_start_scan(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    name: str,
    targets: str,
    scan_config_name: str = DEFAULT_SCAN_CONFIG,
    verify: bool = False,
    socket_path: str | None = None,
    port_range: str | None = None,
) -> str:
    host, port = _parse_host_port(host, port)
    target_hosts = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_hosts:
        raise ValueError("At least one scan target is required")

    config_name = _resolve_scan_config_name(scan_config_name)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        # Resolve reusable feed objects before creating the target. This avoids
        # leaving an orphan target if scan configuration data is not ready yet.
        config_id = _wait_for_scan_config(gmp, config_name)
        _assert_gmp_feed_quality(gmp, config_id)
        scanner_id = _find_openvas_scanner_id(gmp)
        override_range = (port_range or "").strip()
        if override_range:
            port_sel = {"port_selection": "port_range", "port_range": override_range}
        else:
            port_sel = _resolve_port_selection(gmp)
        prefs = _task_performance_preferences()

        target_kwargs: dict[str, Any] = {
            "name": f"platform-{name[:40]}",
            "hosts": target_hosts,
        }
        if port_sel.get("port_list_id"):
            target_kwargs["port_list_id"] = port_sel["port_list_id"]
            log.info("Creating Greenbone target with port_list_id=%s", port_sel["port_list_id"])
        else:
            target_kwargs["port_range"] = port_sel.get("port_range") or FAST_TARGET_PORT_RANGE
            try:
                from app.services.control_plane_scan import (
                    control_plane_ports_for_hosts,
                    exclude_tcp_ports_from_range,
                )

                skip = control_plane_ports_for_hosts(target_hosts)
                if skip:
                    target_kwargs["port_range"] = exclude_tcp_ports_from_range(
                        str(target_kwargs["port_range"]), skip
                    )
                    log.info(
                        "OpenVAS port_range excludes Aetheris control-plane ports %s",
                        sorted(skip),
                    )
            except Exception:
                log.debug("Control-plane port exclusion skipped", exc_info=True)
            log.info(
                "Creating Greenbone target with port_range=%s (profile performance)",
                target_kwargs["port_range"][:80],
            )

        target_resp = gmp.create_target(**target_kwargs)
        target_id = target_resp.get("id")
        if not target_id:
            raise RuntimeError(f"GMP create_target failed: {target_resp}")

        task_kwargs: dict[str, Any] = {
            "name": name[:128],
            "config_id": config_id,
            "target_id": target_id,
            "scanner_id": scanner_id,
            "preferences": prefs,
        }
        try:
            task_resp = gmp.create_task(**task_kwargs)
        except Exception as pref_exc:
            # Retry only with a compact set of current, quality-critical scanner
            # preferences.  Never silently create a bare task: a scan can still
            # reach 100% while using a shallower/default scanner profile.
            minimal_prefs = {
                "max_checks": prefs["max_checks"],
                "max_hosts": prefs["max_hosts"],
                "optimize_test": prefs["optimize_test"],
                "safe_checks": prefs["safe_checks"],
            }
            log.warning(
                "create_task full preferences failed (%s); retrying quality-critical preferences",
                pref_exc,
            )
            try:
                task_resp = gmp.create_task(
                    name=name[:128],
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id,
                    preferences=minimal_prefs,
                )
            except Exception as minimal_exc:
                try:
                    from app.config import get_settings
                    allow_bare = bool(getattr(get_settings(), "gvm_allow_bare_task_fallback", False))
                except Exception:
                    allow_bare = False
                if not allow_bare:
                    try:
                        gmp.delete_target(target_id)
                    except Exception:
                        log.debug("Could not remove orphan Greenbone target %s", target_id, exc_info=True)
                    raise RuntimeError(
                        "Greenbone rejected required task quality preferences; refusing a bare/degraded scan. "
                        "Set GVM_ALLOW_BARE_TASK_FALLBACK=true only for diagnostic compatibility."
                    ) from minimal_exc
                log.error(
                    "DEGRADED SCAN: Greenbone rejected task preferences (%s); bare fallback explicitly enabled",
                    minimal_exc,
                )
                task_resp = gmp.create_task(
                    name=name[:128],
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id,
                )
        task_id = task_resp.get("id")
        if not task_id:
            raise RuntimeError(f"GMP create_task failed: {task_resp}")
        log.info(
            "Started Greenbone task %s config=%s max_checks=%s max_hosts=%s",
            task_id,
            config_name,
            prefs.get("max_checks"),
            prefs.get("max_hosts"),
        )
        gmp.start_task(task_id)
        return str(task_id)


def _task_status(gmp: Any, task_id: str) -> tuple[str, int, Any | None]:
    response = gmp.get_task(task_id)
    task = _first_entity(response, "task")
    if task is None:
        raise RuntimeError(f"GMP get_task returned no task for {task_id}")
    status = (task.findtext("status") or "Unknown").strip().lower()
    try:
        progress = int(float(task.findtext("progress") or "0"))
    except (TypeError, ValueError):
        progress = 0
    return status, progress, task


def gmp_poll_task(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    task_id: str,
    verify: bool = False,
    socket_path: str | None = None,
) -> dict[str, Any]:
    host, port = _parse_host_port(host, port)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        status, progress, _ = _task_status(gmp, task_id)
        return {"status": status, "progress": progress, "task_id": task_id}


def _report_filter_string() -> str:
    try:
        from app.config import get_settings

        raw = int(getattr(get_settings(), "gvm_report_min_qod", 0) or 0)
    except Exception:
        raw = 0
    return f"rows=-1 min_qod={max(0, min(100, raw))}"


def _results_to_vulns(gmp: Any, task_id: str) -> list[dict[str, Any]]:
    _, _, task = _task_status(gmp, task_id)
    report_id = None
    if task is not None:
        # In-progress / just-stopped tasks expose results on current_report;
        # finished tasks move them to last_report.
        for xpath in ("current_report/report", "last_report/report"):
            report_elem = task.find(xpath)
            if report_elem is not None and report_elem.get("id"):
                report_id = report_elem.get("id")
                break
    if not report_id:
        return []

    # Retrieve the concrete report instead of relying on a get_results filter
    # for report_id (report_id is not a dedicated get_results argument in
    # current python-gvm). A full report contains the scan result elements.
    report = gmp.get_report(
        report_id=report_id,
        filter_string=_report_filter_string(),
        ignore_pagination=True,
        details=True,
    )
    result_nodes = list(report.xpath(".//results/result"))
    vulns: list[dict[str, Any]] = []
    for res in result_nodes:
        nvt = res.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid") or ""
        name = nvt.findtext("name") or res.findtext("name") or ""
        family = nvt.findtext("family") or ""
        cvss_text = nvt.findtext("cvss_base") or res.findtext("severity") or "0"
        try:
            cvss = float(cvss_text)
        except (TypeError, ValueError):
            cvss = 0.0
        cve = None
        for ref in nvt.xpath("refs/ref"):
            if (ref.get("type") or "").lower() == "cve":
                cve = ref.get("id")
                break
        port_raw = res.findtext("port") or ""
        port = None
        protocol = None
        if "/" in port_raw:
            port_part, protocol = port_raw.split("/", 1)
            try:
                port = int(port_part)
            except ValueError:
                port = None
        threat = res.findtext("threat") or nvt.findtext("severity") or ""
        qod_raw = res.findtext("qod/value") or res.findtext("qod") or ""
        try:
            qod = float(qod_raw) if str(qod_raw).strip() else None
        except (TypeError, ValueError):
            qod = None
        qod_type = (res.findtext("qod/type") or "").strip() or None
        tags = nvt.findtext("tags") or ""
        tag_values: dict[str, str] = {}
        for part in tags.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value and key not in tag_values:
                tag_values[key] = value
        solution = tag_values.get("solution") or ""
        host = res.findtext("host") or None
        description = res.findtext("description") or tag_values.get("insight") or tag_values.get("summary") or ""
        vulns.append(
            {
                "plugin_id": oid,
                "nvt_oid": oid,
                "plugin_family": family,
                "cve": cve,
                "score": cvss,
                "cvss": cvss,
                "severity": _severity_from_threat(threat, cvss, name),
                "qod": qod,
                "qod_type": qod_type,
                "plugin_name": name,
                "description": description,
                "synopsis": tag_values.get("summary") or name,
                "solution": solution,
                "port": port,
                "protocol": protocol,
                "host": host,
            }
        )

    inner_reports = list(report.xpath(".//report")) if hasattr(report, "xpath") else []
    inner = inner_reports[-1] if inner_reports else report
    declared = -1
    try:
        raw_declared = inner.findtext("result_count/full") or inner.findtext("result_count")
        if raw_declared is not None and str(raw_declared).strip():
            declared = int(str(raw_declared).strip())
    except (TypeError, ValueError, AttributeError):
        declared = -1
    # Only fail when the report was truncated (fewer result nodes than declared).
    # Skipping result rows without an <nvt> is normal and must not wipe findings.
    if declared > 0 and len(result_nodes) < declared:
        raise RuntimeError(
            f"Greenbone report truncated: declared={declared} nodes={len(result_nodes)} parsed={len(vulns)}"
        )
    return vulns


def gmp_scan_details(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    task_id: str,
    verify: bool = False,
    socket_path: str | None = None,
) -> dict[str, Any]:
    host, port = _parse_host_port(host, port)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        status, progress, _ = _task_status(gmp, task_id)
        gmp_status = "running"
        if status in {"done", "finished", "succeeded"}:
            gmp_status = "completed"
        elif status in {"stopped", "interrupted", "failed", "internal error", "delete requested"}:
            # Treat as terminal; still try to pull any report rows produced so far.
            gmp_status = "stopped" if status in {"stopped", "interrupted"} else "failed"
        vulns: list[dict[str, Any]] = []
        try:
            vulns = _results_to_vulns(gmp, task_id)
        except Exception as exc:
            log.warning("Unable to read Greenbone results for task %s (%s)", task_id, status, exc_info=True)
            # Terminal tasks must not look "completed clean" when the report failed to parse.
            if gmp_status == "completed":
                raise RuntimeError(
                    f"Unable to read Greenbone results for completed task {task_id}: {exc}"
                ) from exc
            vulns = []
        return {
            "info": {"status": gmp_status, "gmp_status": status, "progress": progress},
            "vulnerabilities": vulns,
            "stub": False,
            "edition": "OpenVAS",
            "external_scan_id": task_id,
        }


def gmp_find_tasks(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    verify: bool = False,
    socket_path: str | None = None,
    name_contains: str = "",
) -> list[dict[str, Any]]:
    host, port = _parse_host_port(host, port)
    with _gmp_session(host, port, username, password, verify=verify, socket_path=socket_path) as gmp:
        filt = "rows=-1"
        token = (name_contains or "").strip()
        if token:
            filt = f'name~"{token}" rows=-1'
        resp = gmp.get_tasks(filter_string=filt)
        nodes: list[Any] = []
        try:
            nodes = list(resp.findall("task") or [])
            if not nodes and hasattr(resp, "xpath"):
                nodes = list(resp.xpath(".//task"))
        except Exception:
            nodes = []
        out: list[dict[str, Any]] = []
        for task in nodes:
            tid = task.get("id")
            if not tid:
                continue
            try:
                progress = int(float(task.findtext("progress") or "0"))
            except (TypeError, ValueError):
                progress = 0
            out.append(
                {
                    "id": str(tid),
                    "name": (task.findtext("name") or "").strip(),
                    "status": (task.findtext("status") or "").strip().lower(),
                    "progress": progress,
                }
            )
        return out


def tcp_port_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Safe non-destructive port check for pentest recon."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
