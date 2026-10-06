from __future__ import annotations

# AETHERIS_V124_LAPTOP_DURABLE_RECOVERY
# Durable edge-agent authentication fallback for Aetheris v1.2.4.
# - normal AGENT_TOKEN remains first choice;
# - central 24-hour previous-token grace is therefore used automatically;
# - only a real HTTP 401 causes one retry with AGENT_RECOVERY_TOKEN;
# - recovery secret values are never logged.
import logging as _aetheris_v124_logging
import os as _aetheris_v124_os
from pathlib import Path as _AetherisV124Path
import httpx as _aetheris_v124_httpx
import uuid as _aetheris_uuid

_aetheris_v124_log = _aetheris_v124_logging.getLogger("scanner_agent.auth_recovery")
_AETHERIS_V124_RECOVERY_FILE = _AetherisV124Path("/app/.agent-recovery-token")
_AETHERIS_V124_ACTIVE_FILE = _AetherisV124Path(_aetheris_v124_os.getenv("AGENT_TOKEN_FILE") or "/run/aetheris-agent/agent-token")
_AETHERIS_AGENT_INSTANCE_FILE = _AetherisV124Path(
    _aetheris_v124_os.getenv("AGENT_INSTANCE_FILE") or "/run/aetheris-agent/agent-instance-id"
)


def _aetheris_agent_instance_id() -> str:
    """Return a stable non-secret ownership id for queue fencing."""
    value = (_aetheris_v124_os.getenv("AGENT_INSTANCE_ID") or "").strip()
    if value:
        return value[:128]
    try:
        if _AETHERIS_AGENT_INSTANCE_FILE.is_file():
            value = _AETHERIS_AGENT_INSTANCE_FILE.read_text(encoding="utf-8-sig").strip()
            if value:
                value = value[:128]
                _aetheris_v124_os.environ["AGENT_INSTANCE_ID"] = value
                return value
    except OSError:
        pass
    value = str(_aetheris_uuid.uuid4())
    try:
        _AETHERIS_AGENT_INSTANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _AETHERIS_AGENT_INSTANCE_FILE.write_text(value + "\n", encoding="utf-8")
        _aetheris_v124_os.chmod(str(_AETHERIS_AGENT_INSTANCE_FILE), 0o600)
    except OSError:
        pass
    _aetheris_v124_os.environ["AGENT_INSTANCE_ID"] = value
    return value


def _aetheris_v124_read_recovery_token():
    # Extra local secret only. If central still accepts it, promote to the
    # single AGENT_TOKEN file so the operator never manages two keys.
    value = (_aetheris_v124_os.getenv("AGENT_RECOVERY_TOKEN") or "").strip()
    if value:
        return value
    try:
        if _AETHERIS_V124_RECOVERY_FILE.is_file():
            return _AETHERIS_V124_RECOVERY_FILE.read_text(encoding="utf-8-sig").strip()
    except OSError:
        return ""
    return ""


def _aetheris_v124_is_agent_url(url):
    try:
        return "/api/scanner-agent/" in str(url)
    except Exception:
        return False


def _aetheris_v124_header_value(headers, name):
    if headers is None:
        return ""
    try:
        value = headers.get(name, "")
        return str(value or "")
    except Exception:
        try:
            for key, value in dict(headers).items():
                if str(key).lower() == name.lower():
                    return str(value or "")
        except Exception:
            pass
    return ""


def _aetheris_v124_retry_headers(client, request_headers, recovery_token):
    # Request-level headers override Client default headers in httpx. Preserve
    # request-specific values such as X-Tenant while changing Authorization only.
    try:
        headers = dict(request_headers or {})
    except Exception:
        headers = {}
    headers["Authorization"] = "Bearer " + recovery_token
    return headers


def _aetheris_v124_promote_for_process(client, recovery_token):
    # Promotion is process/container-local. The host .env keeps AGENT_TOKEN and
    # AGENT_RECOVERY_TOKEN separate so an operator can rotate the bearer later.
    _aetheris_v124_os.environ["AGENT_TOKEN"] = recovery_token
    try:
        client.headers["Authorization"] = "Bearer " + recovery_token
    except Exception:
        pass
    try:
        _AETHERIS_V124_ACTIVE_FILE.write_text(recovery_token, encoding="utf-8")
        _aetheris_v124_os.chmod(str(_AETHERIS_V124_ACTIVE_FILE), 0o600)
    except Exception:
        pass


def _aetheris_v124_should_retry(response, url, current_authorization, recovery_token):
    if getattr(response, "status_code", 0) != 401:
        return False
    if not _aetheris_v124_is_agent_url(url):
        return False
    if not recovery_token:
        return False
    return current_authorization.strip() != ("Bearer " + recovery_token)


if not getattr(_aetheris_v124_httpx.Client.request, "_aetheris_v124_durable_recovery", False):
    _aetheris_v124_original_client_request = _aetheris_v124_httpx.Client.request

    def _aetheris_v124_client_request(self, method, url, *args, **kwargs):
        recovery = _aetheris_v124_read_recovery_token()
        request_headers = kwargs.get("headers")
        # Once recovery has succeeded in this process, do not intentionally send
        # the known-stale bearer again. This still preserves central's 24-hour
        # grace on startup because recovery is not promoted until a real 401.
        if (
            recovery
            and _aetheris_v124_is_agent_url(url)
            and (_aetheris_v124_os.getenv("AGENT_TOKEN") or "").strip() == recovery
        ):
            kwargs = dict(kwargs)
            kwargs["headers"] = _aetheris_v124_retry_headers(self, request_headers, recovery)
            request_headers = kwargs.get("headers")
        response = _aetheris_v124_original_client_request(self, method, url, *args, **kwargs)
        current_auth = _aetheris_v124_header_value(request_headers, "Authorization")
        if not current_auth:
            current_auth = _aetheris_v124_header_value(getattr(self, "headers", None), "Authorization")
        if not _aetheris_v124_should_retry(response, url, current_auth, recovery):
            return response
        try:
            response.close()
        except Exception:
            pass
        retry_kwargs = dict(kwargs)
        retry_kwargs["headers"] = _aetheris_v124_retry_headers(self, request_headers, recovery)
        retry = _aetheris_v124_original_client_request(self, method, url, *args, **retry_kwargs)
        if 200 <= getattr(retry, "status_code", 0) < 300:
            _aetheris_v124_promote_for_process(self, recovery)
            _aetheris_v124_log.warning(
                "Aetheris v1.2.4 durable recovery credential accepted after bearer 401; process recovered"
            )
        return retry

    _aetheris_v124_client_request._aetheris_v124_durable_recovery = True
    _aetheris_v124_httpx.Client.request = _aetheris_v124_client_request


if hasattr(_aetheris_v124_httpx, "AsyncClient") and not getattr(
    _aetheris_v124_httpx.AsyncClient.request, "_aetheris_v124_durable_recovery", False
):
    _aetheris_v124_original_async_request = _aetheris_v124_httpx.AsyncClient.request

    async def _aetheris_v124_async_request(self, method, url, *args, **kwargs):
        recovery = _aetheris_v124_read_recovery_token()
        request_headers = kwargs.get("headers")
        if (
            recovery
            and _aetheris_v124_is_agent_url(url)
            and (_aetheris_v124_os.getenv("AGENT_TOKEN") or "").strip() == recovery
        ):
            kwargs = dict(kwargs)
            kwargs["headers"] = _aetheris_v124_retry_headers(self, request_headers, recovery)
            request_headers = kwargs.get("headers")
        response = await _aetheris_v124_original_async_request(self, method, url, *args, **kwargs)
        current_auth = _aetheris_v124_header_value(request_headers, "Authorization")
        if not current_auth:
            current_auth = _aetheris_v124_header_value(getattr(self, "headers", None), "Authorization")
        if not _aetheris_v124_should_retry(response, url, current_auth, recovery):
            return response
        try:
            await response.aclose()
        except Exception:
            pass
        retry_kwargs = dict(kwargs)
        retry_kwargs["headers"] = _aetheris_v124_retry_headers(self, request_headers, recovery)
        retry = await _aetheris_v124_original_async_request(self, method, url, *args, **retry_kwargs)
        if 200 <= getattr(retry, "status_code", 0) < 300:
            _aetheris_v124_promote_for_process(self, recovery)
            _aetheris_v124_log.warning(
                "Aetheris v1.2.4 durable recovery credential accepted after bearer 401; process recovered"
            )
        return retry

    _aetheris_v124_async_request._aetheris_v124_durable_recovery = True
    _aetheris_v124_httpx.AsyncClient.request = _aetheris_v124_async_request


if not getattr(_aetheris_v124_httpx.request, "_aetheris_v124_durable_recovery", False):
    _aetheris_v124_original_module_request = _aetheris_v124_httpx.request

    def _aetheris_v124_module_request(method, url, *args, **kwargs):
        # httpx.request commonly delegates to Client.request, which is already
        # protected above. This wrapper covers versions/uses that do not.
        recovery = _aetheris_v124_read_recovery_token()
        if (
            recovery
            and _aetheris_v124_is_agent_url(url)
            and (_aetheris_v124_os.getenv("AGENT_TOKEN") or "").strip() == recovery
        ):
            kwargs = dict(kwargs)
            kwargs["headers"] = _aetheris_v124_retry_headers(None, kwargs.get("headers"), recovery)
        response = _aetheris_v124_original_module_request(method, url, *args, **kwargs)
        current_auth = _aetheris_v124_header_value(kwargs.get("headers"), "Authorization")
        if not _aetheris_v124_should_retry(response, url, current_auth, recovery):
            return response
        try:
            response.close()
        except Exception:
            pass
        retry_kwargs = dict(kwargs)
        retry_kwargs["headers"] = _aetheris_v124_retry_headers(None, kwargs.get("headers"), recovery)
        retry = _aetheris_v124_original_module_request(method, url, *args, **retry_kwargs)
        if 200 <= getattr(retry, "status_code", 0) < 300:
            _aetheris_v124_os.environ["AGENT_TOKEN"] = recovery
            try:
                _AETHERIS_V124_ACTIVE_FILE.write_text(recovery, encoding="utf-8")
                _aetheris_v124_os.chmod(str(_AETHERIS_V124_ACTIVE_FILE), 0o600)
            except Exception:
                pass
            _aetheris_v124_log.warning(
                "Aetheris v1.2.4 durable recovery credential accepted after bearer 401; process recovered"
            )
        return retry

    _aetheris_v124_module_request._aetheris_v124_durable_recovery = True
    _aetheris_v124_httpx.request = _aetheris_v124_module_request


from typing import Any
import time

import httpx


class CentralApi:
    def __init__(
        self,
        *,
        base_url: str,
        tenant: str,
        token: str,
        verify_tls: bool = True,
        timeout: float | None = None,
    ) -> None:
        base = base_url.strip().rstrip("/")
        # CENTRAL_API_URL is normally the site root. Be tolerant of operators
        # entering a trailing /api so we do not generate /api/api/... URLs.
        if base.lower().endswith("/api"):
            base = base[:-4].rstrip("/")
        self.base = base
        self.agent_instance_id = _aetheris_agent_instance_id()
        self.headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant": tenant.strip().lower(),
            "X-Aetheris-Agent-Instance": self.agent_instance_id,
            "Content-Type": "application/json",
        }
        self._token = token
        self.verify = verify_tls
        # WAN / Nginx gateway links often need a longer read window than LAN.
        raw = timeout
        if raw is None:
            env = (_aetheris_v124_os.environ.get("CENTRAL_API_TIMEOUT_SEC") or "").strip()
            try:
                raw = float(env) if env else 0.0
            except (TypeError, ValueError):
                raw = 0.0
        try:
            parsed = float(raw)
        except (TypeError, ValueError):
            parsed = 0.0
        self.timeout = 0.0 if parsed <= 0 else parsed

    def set_token(self, token: str) -> None:
        value = (token or "").strip()
        self._token = value
        self.headers["Authorization"] = f"Bearer {value}"

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def _httpx_timeout(self, timeout: float | None = None) -> httpx.Timeout:
        total = self.timeout if timeout is None else float(timeout)
        # Connect stays bounded so a black-holed route fails fast; read/write
        # wait until the server finishes (0 / None = no deadline).
        if total is None or total <= 0:
            return httpx.Timeout(None, connect=20.0)
        connect = min(20.0, max(5.0, total / 4.0))
        return httpx.Timeout(total, connect=connect, read=total, write=total, pool=connect)

    @staticmethod
    def is_retryable(exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.TransportError, httpx.NetworkError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            return status in {408, 425, 429, 500, 502, 503, 504}
        return False

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        attempts: int = 5,
    ) -> dict[str, Any]:
        delay = 1.0
        last_exc: Exception | None = None
        http_timeout = self._httpx_timeout(timeout)
        for attempt in range(1, max(1, attempts) + 1):
            try:
                with httpx.Client(verify=self.verify, timeout=http_timeout) as client:
                    r = client.request(
                        method,
                        self._url(path),
                        headers=self.headers,
                        json=json,
                        params=params,
                    )
                    r.raise_for_status()
                    if not r.content:
                        return {}
                    return r.json()
            except Exception as exc:
                last_exc = exc
                if attempt >= attempts or not self.is_retryable(exc):
                    raise
                time.sleep(delay)
                delay = min(delay * 2.0, 15.0)
        assert last_exc is not None
        raise last_exc

    def post_logs(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/scanner-agent/logs",
            json={"entries": entries},
            attempts=2,
        )

    def heartbeat(
        self,
        *,
        version: str | None = None,
        openvas_ready: bool | None = None,
        detail: str | None = None,
    ) -> dict[str, Any]:
        # Heartbeat must not stall the dispatcher for minutes on a slow WAN hop.
        payload: dict[str, Any] = {"version": version, "openvas_ready": openvas_ready}
        if detail:
            payload["detail"] = str(detail)[:500]
        return self._request(
            "POST",
            "/api/scanner-agent/heartbeat",
            json=payload,
            attempts=3,
        )

    def next_job(self, *, active_job_ids: list[str] | None = None) -> dict[str, Any] | None:
        active = [str(x).strip() for x in (active_job_ids or []) if str(x).strip()]
        params: dict[str, Any] = {"agent_instance_id": self.agent_instance_id}
        if active:
            params["active_job_ids"] = ",".join(active[:16])
        data = self._request(
            "GET",
            "/api/scanner-agent/jobs/next",
            params=params,
            attempts=3,
        )
        return data.get("job")

    def patch_job(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"/api/scanner-agent/jobs/{job_id}",
            json=payload,
            params={"agent_instance_id": self.agent_instance_id},
            attempts=5,
        )

    def upload_results(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/scanner-agent/jobs/{job_id}/results",
            json=payload,
            params={"agent_instance_id": self.agent_instance_id},
            attempts=8,
        )
