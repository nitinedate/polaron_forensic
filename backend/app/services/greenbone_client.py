"""OpenVAS / Greenbone GMP scanner adapter. Live GMP when configured."""

from __future__ import annotations

import logging
from typing import Any

from app.config import get_settings
from app.services import greenbone_gmp

log = logging.getLogger("greenbone_client")


class GreenboneClientError(Exception):
    pass


class GreenboneClient:
    """Greenbone/OpenVAS adapter matching the NessusClient scan surface.

    The local Docker deployment communicates with gvmd over the shared Unix
    domain socket.  Legacy DB scanner URLs such as ``gmp://gvmd:9390`` are
    transparently mapped to that socket when ``GVM_SOCKET_PATH`` is set.
    External Greenbone servers may still use a TCP/TLS URL.
    """

    def __init__(
        self,
        *,
        base_url: str = "",
        gmp_username: str = "",
        gmp_password: str = "",
        verify_tls: bool | None = None,
    ):
        settings = get_settings()
        configured_url = (base_url or settings.gvm_url or "").strip()
        socket_path = greenbone_gmp.parse_socket_path(configured_url)

        configured_socket = (getattr(settings, "gvm_socket_path", "") or "").strip()
        # Backward compatibility for the scanner record shown in the UI:
        # gmp://gvmd:9390 used to be the local endpoint, but the official
        # Greenbone container stack exposes gvmd via /run/gvmd/gvmd.sock.
        if not socket_path and configured_socket and greenbone_gmp.is_local_gvmd_tcp_url(configured_url):
            socket_path = configured_socket

        self.socket_path = socket_path or None
        self.base_url = configured_url or (
            f"unix://{self.socket_path}" if self.socket_path else f"tls://{settings.gvm_host}:{settings.gvm_port}"
        )
        self.gmp_username = gmp_username or settings.gvm_username or "admin"
        self.gmp_password = gmp_password or settings.gvm_password or settings.gvm_admin_password or "admin"
        self.verify_tls = settings.gvm_verify_tls if verify_tls is None else verify_tls

        self._host = settings.gvm_host or "gvmd"
        self._port = int(settings.gvm_port or 9390)
        if configured_url and not self.socket_path:
            self._host, self._port = greenbone_gmp._parse_host_port(configured_url, self._port)

    @property
    def configured(self) -> bool:
        settings = get_settings()
        endpoint_ok = bool(self.socket_path or self._host)
        creds_ok = bool(self.gmp_username and self.gmp_password and greenbone_gmp.gmp_available())
        local = bool(self.socket_path or greenbone_gmp.is_local_gvmd_tcp_url(self.base_url))
        if local:
            return bool(settings.gvm_live_enabled and endpoint_ok and creds_ok)
        return bool(endpoint_ok and creds_ok)

    def _connection_kwargs(self) -> dict[str, Any]:
        return {
            "host": self._host,
            "port": self._port,
            "username": self.gmp_username,
            "password": self.gmp_password,
            "verify": self.verify_tls,
            "socket_path": self.socket_path,
        }

    def server_status(self) -> dict[str, Any]:
        settings = get_settings()
        local = bool(self.socket_path or greenbone_gmp.is_local_gvmd_tcp_url(self.base_url))
        if local and not settings.gvm_live_enabled:
            return {
                "status": "disabled",
                "message": "GVM_LIVE_ENABLED is false",
                "edition": "OpenVAS",
            }
        if not greenbone_gmp.gmp_available():
            return {
                "status": "error",
                "message": "python-gvm is not installed in this service",
                "edition": "OpenVAS",
            }
        if not self.gmp_username or not self.gmp_password:
            return {
                "status": "unconfigured",
                "message": "GVM credentials not set (GVM_USERNAME / GVM_PASSWORD)",
                "edition": "OpenVAS",
            }
        try:
            ping = greenbone_gmp.gmp_ping(**self._connection_kwargs())
            return {"status": "ok", "edition": "OpenVAS", **ping}
        except Exception as exc:
            log.warning("GMP ping failed: %s", exc)
            return {
                "status": "error",
                "edition": "OpenVAS",
                "error": str(exc),
                "endpoint": f"unix://{self.socket_path}" if self.socket_path else f"tls://{self._host}:{self._port}",
            }

    def scan_readiness(self) -> dict[str, Any]:
        """Validate scan config, scanner and mandatory target port selection."""
        if not self.configured:
            return {
                "status": "disabled",
                "message": "Greenbone is disabled or not configured",
                "edition": "OpenVAS",
            }
        try:
            readiness = greenbone_gmp.gmp_scan_readiness(**self._connection_kwargs())
            return {"edition": "OpenVAS", **readiness}
        except Exception as exc:
            log.warning("GMP readiness check failed: %s", exc)
            return {
                "status": "error",
                "ready": False,
                "gmp_connected": False,
                "edition": "OpenVAS",
                "error": str(exc),
                "endpoint": f"unix://{self.socket_path}" if self.socket_path else f"tls://{self._host}:{self._port}",
            }

    def create_scan(
        self,
        *,
        name: str,
        targets: str,
        template_uuid: str | None = None,
        port_range: str | None = None,
    ) -> dict[str, Any]:
        if not self.configured:
            return {
                "scan": {"id": None},
                "stub": True,
                "edition": "OpenVAS",
                "message": "Greenbone is disabled or not configured",
            }
        try:
            task_id = greenbone_gmp.gmp_create_and_start_scan(
                **self._connection_kwargs(),
                name=name,
                targets=targets,
                port_range=port_range,
            )
            return {"scan": {"id": task_id}, "stub": False, "edition": "OpenVAS"}
        except Exception as exc:
            raise GreenboneClientError(str(exc)) from exc

    def find_tasks(self, *, name_contains: str = "") -> list[dict[str, Any]]:
        if not self.configured:
            return []
        try:
            return greenbone_gmp.gmp_find_tasks(**self._connection_kwargs(), name_contains=name_contains)
        except Exception as exc:
            log.warning("Greenbone find_tasks failed: %s", exc)
            return []

    def launch_scan(self, scan_id: int | str) -> dict[str, Any]:
        if not self.configured:
            return {"scan_uuid": f"stub-gvm-{scan_id}", "stub": True}
        # The GMP task is started in create_scan().
        return {"scan_uuid": str(scan_id), "stub": False}

    def stop_scan(self, scan_id: int | str) -> dict[str, Any]:
        if not self.configured:
            return {"stub": True, "scan_id": str(scan_id)}
        try:
            greenbone_gmp.gmp_stop_task(**self._connection_kwargs(), task_id=str(scan_id))
            return {"stopped": True, "scan_id": str(scan_id)}
        except Exception as exc:
            raise GreenboneClientError(str(exc)) from exc

    def scan_details(self, scan_id: int | str) -> dict[str, Any]:
        if not self.configured:
            from app.services.scanner_stub import stub_scan_vulnerabilities

            return {
                "info": {"status": "completed"},
                "vulnerabilities": stub_scan_vulnerabilities(),
                "stub": True,
                "edition": "OpenVAS",
            }
        try:
            return greenbone_gmp.gmp_scan_details(
                **self._connection_kwargs(),
                task_id=str(scan_id),
            )
        except Exception as exc:
            raise GreenboneClientError(str(exc)) from exc

    def list_agents(self) -> dict[str, Any]:
        return {"agents": [], "stub": not self.configured, "edition": "OpenVAS"}
