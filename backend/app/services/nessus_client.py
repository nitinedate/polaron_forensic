"""Nessus/Tenable HTTP client — detection engine adapter only (no forensic coupling)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

log = logging.getLogger("nessus_client")


class NessusClientError(Exception):
    pass


class NessusClient:
    def __init__(
        self,
        *,
        base_url: str,
        access_key: str = "",
        secret_key: str = "",
        verify_ssl: bool | None = None,
        timeout: float | None = None,
    ):
        settings = get_settings()
        self.base_url = (base_url or settings.nessus_default_url or "").rstrip("/")
        self.access_key = access_key or settings.nessus_access_key
        self.secret_key = secret_key or settings.nessus_secret_key
        self.verify_ssl = settings.nessus_verify_ssl if verify_ssl is None else verify_ssl
        raw = timeout if timeout is not None else settings.nessus_api_timeout_sec
        try:
            parsed = float(raw)
        except (TypeError, ValueError):
            parsed = 0.0
        self.timeout = None if parsed <= 0 else parsed

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.access_key and self.secret_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers=self._headers(),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

    def server_status(self) -> dict[str, Any]:
        if not self.configured:
            return {"status": "unconfigured", "message": "Nessus API keys or URL not set"}
        try:
            with self._client() as client:
                r = client.get("/server/status")
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            log.warning("Nessus status failed: %s", exc)
            raise NessusClientError(str(exc)) from exc

    def create_scan(self, *, name: str, targets: str, template_uuid: str | None = None, port_range: str | None = None) -> dict[str, Any]:
        """Create a scan via Nessus API when configured; otherwise return a stub external id."""
        if not self.configured:
            return {
                "scan": {"id": None},
                "stub": True,
                "message": "Nessus not configured — platform records scan job only",
            }
        payload: dict[str, Any] = {
            "uuid": template_uuid or "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be82",
            "settings": {"name": name, "text_targets": targets, "enabled": False},
        }
        try:
            with self._client() as client:
                r = client.post("/scans", json=payload)
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            raise NessusClientError(str(exc)) from exc

    def launch_scan(self, scan_id: int | str) -> dict[str, Any]:
        if not self.configured:
            return {"scan_uuid": f"stub-{scan_id}", "stub": True}
        try:
            with self._client() as client:
                r = client.post(f"/scans/{scan_id}/launch")
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            raise NessusClientError(str(exc)) from exc

    def scan_details(self, scan_id: int | str) -> dict[str, Any]:
        if not self.configured:
            from app.services.scanner_stub import stub_scan_vulnerabilities

            return {"info": {"status": "completed"}, "vulnerabilities": stub_scan_vulnerabilities(), "stub": True}
        try:
            with self._client() as client:
                r = client.get(f"/scans/{scan_id}")
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            raise NessusClientError(str(exc)) from exc

    def list_agents(self) -> dict[str, Any]:
        """List Nessus agents when edition supports it (Manager / Tenable)."""
        if not self.configured:
            return {"agents": [], "stub": True}
        try:
            with self._client() as client:
                r = client.get("/agents")
                if r.status_code == 404:
                    return {"agents": [], "unsupported": True}
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            raise NessusClientError(str(exc)) from exc
