from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

MARKER = "AETHERIS_BOOTSTRAP_RESULT="
USER_AGENT = "Aetheris-Laptop-Scanner/1.4.5-bootstrap"


def _emit(payload: dict[str, Any], code: int = 0) -> int:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii")
    print(MARKER + encoded, flush=True)
    return code


def _normalize_base(base: str) -> str:
    value = (base or "").strip().rstrip("/")
    if value.lower().endswith("/api"):
        value = value[:-4].rstrip("/")
    if not value:
        raise ValueError("CENTRAL_API_URL is empty")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"CENTRAL_API_URL is invalid: {value}")
    return value


def _health_is_ready(data: dict[str, Any] | None) -> bool:
    return isinstance(data, dict) and str(data.get("status") or "").strip().lower() == "ok"


def _unusable_health_error(base: str, data: dict[str, Any] | None, text: str) -> str:
    host = (urlparse(base).hostname or "").lower()
    hint = ""
    if host == "122.179.141.248":
        hint = " Set CENTRAL_API_URL=https://future-softtech.co.in."
    snippet = (text or "").strip().replace("\n", " ")
    if len(snippet) > 160:
        snippet = snippet[:160]
    return (
        f"{base} answered HTTP 200 but is not the Aetheris API "
        f"(health was not {{\"status\":\"ok\"}}). The access token was not sent.{hint} {snippet}"
    ).strip()


def _canonical_from_health(final_url: str) -> str:
    parsed = urlparse(final_url)
    path = parsed.path.rstrip("/")
    suffix = "/api/health"
    if path.lower().endswith(suffix):
        prefix = path[: -len(suffix)].rstrip("/")
    else:
        prefix = ""
    authority = f"{parsed.scheme}://{parsed.netloc}"
    return (authority + prefix).rstrip("/")


def _client(verify_tls: bool, follow_redirects: bool) -> httpx.Client:
    return httpx.Client(
        verify=verify_tls,
        follow_redirects=follow_redirects,
        timeout=httpx.Timeout(45.0, connect=15.0),
        headers={"User-Agent": USER_AGENT},
    )


def _headers(tenant: str, bearer: str | None = None) -> dict[str, str]:
    result = {"X-Tenant": (tenant or "").strip().lower()}
    if bearer:
        result["Authorization"] = f"Bearer {bearer}"
    return result


def _request_json(
    method: str,
    url: str,
    tenant: str,
    *,
    verify_tls: bool,
    bearer: str | None = None,
    body: dict[str, Any] | None = None,
    follow_redirects: bool = False,
) -> tuple[int, str, dict[str, Any] | None, str]:
    with _client(verify_tls, follow_redirects) as client:
        response = client.request(method, url, headers=_headers(tenant, bearer), json=body)
        text = response.text
        data: dict[str, Any] | None = None
        if text:
            try:
                parsed = response.json()
                if isinstance(parsed, dict):
                    data = parsed
            except Exception:
                data = None
        final_url = str(response.url)
        return response.status_code, text, data, final_url


def _cert_details(host: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"host": host, "port": port, "ok": False}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls:
                der = tls.getpeercert(binary_form=True)
                result["tls_version"] = tls.version()
                result["cipher"] = tls.cipher()[0] if tls.cipher() else ""
        if not der:
            result["error"] = "Server did not present a certificate"
            return result
        pem = ssl.DER_cert_to_PEM_cert(der)
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as handle:
                handle.write(pem)
                tmp = handle.name
            decoded = ssl._ssl._test_decode_cert(tmp)  # type: ignore[attr-defined]
        finally:
            if tmp:
                try:
                    Path(tmp).unlink(missing_ok=True)
                except OSError:
                    pass
        result["subject"] = _name_to_text(decoded.get("subject", ()))
        result["issuer"] = _name_to_text(decoded.get("issuer", ()))
        result["not_before"] = decoded.get("notBefore", "")
        result["not_after"] = decoded.get("notAfter", "")
        dns_names: list[str] = []
        ip_names: list[str] = []
        for kind, value in decoded.get("subjectAltName", ()):
            if kind == "DNS":
                dns_names.append(value)
            elif kind in {"IP Address", "IP"}:
                ip_names.append(value)
        result["san_dns"] = dns_names
        result["san_ip"] = ip_names
        result["ok"] = True
        return result
    except Exception as exc:
        result["error"] = _exception_text(exc)
        return result


def _name_to_text(items: Any) -> str:
    parts: list[str] = []
    try:
        for rdn in items:
            for key, value in rdn:
                parts.append(f"{key}={value}")
    except Exception:
        return str(items)
    return ", ".join(parts)


def _exception_text(exc: BaseException) -> str:
    parts: list[str] = []
    current: BaseException | None = exc
    while current is not None:
        message = str(current).strip()
        if message and message not in parts:
            parts.append(message)
        current = current.__cause__ or current.__context__
    return " -> ".join(parts) or exc.__class__.__name__


def _is_ip(host: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _http_redirect_hint(base: str, tenant: str) -> dict[str, Any] | None:
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    # If HTTPS-by-IP fails verification, query the same host over plain HTTP
    # WITHOUT following redirects. This sends no secret and can reveal the
    # canonical HTTPS hostname chosen by the reverse proxy.
    if not _is_ip(parsed.hostname):
        return None
    netloc = parsed.hostname
    if parsed.port and parsed.port != 443:
        netloc = f"{netloc}:{parsed.port}"
    url = f"http://{netloc}/api/health"
    try:
        with _client(True, False) as client:
            response = client.get(url, headers=_headers(tenant))
        location = response.headers.get("location", "")
        if 300 <= response.status_code < 400 and location:
            absolute = urljoin(url, location)
            return {"status": response.status_code, "location": absolute}
    except Exception as exc:
        return {"error": _exception_text(exc)}
    return None


def preflight(base: str, tenant: str, verify_tls: bool) -> dict[str, Any]:
    normalized = _normalize_base(base)
    health = normalized + "/api/health"
    try:
        status, text, data, final_url = _request_json(
            "GET",
            health,
            tenant,
            verify_tls=verify_tls,
            follow_redirects=True,
        )
        if status < 200 or status >= 400 or not _health_is_ready(data):
            if 200 <= status < 400:
                error = _unusable_health_error(normalized, data, text)
            else:
                error = _api_error(data, text) or f"Health check failed (HTTP {status})"
            return {
                "ok": False,
                "stage": "health",
                "status": status,
                "error": error,
                "body": text[:500],
                "effective_url": final_url,
                "health": data,
                "transport": "docker-httpx-openssl",
            }
        return {
            "ok": True,
            "stage": "health",
            "status": status,
            "canonical_url": _canonical_from_health(final_url),
            "effective_url": final_url,
            "health": data,
            "transport": "docker-httpx-openssl",
        }
    except Exception as exc:
        parsed = urlparse(normalized)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        details = _cert_details(host, port) if parsed.scheme == "https" and host else None
        hint = _http_redirect_hint(normalized, tenant)
        return {
            "ok": False,
            "stage": "tls_or_connect",
            "error": _exception_text(exc),
            "certificate": details,
            "http_redirect_hint": hint,
            "transport": "docker-httpx-openssl",
        }


def bind(
    base: str,
    tenant: str,
    client_token: str,
    scanner_name: str,
    scanner_role: str,
    scanner_id: str,
    verify_tls: bool,
) -> dict[str, Any]:
    if not client_token.strip():
        return {"ok": False, "stage": "input", "error": "Access token was empty"}
    pf = preflight(base, tenant, verify_tls)
    if not pf.get("ok"):
        return pf
    canonical = str(pf["canonical_url"]).rstrip("/")

    try:
        status, text, data, _ = _request_json(
            "POST",
            canonical + "/api/auth/token-login",
            tenant,
            verify_tls=verify_tls,
            body={"token": client_token.strip()},
            follow_redirects=False,
        )
    except Exception as exc:
        return {"ok": False, "stage": "token_login", "error": _exception_text(exc), "canonical_url": canonical}
    if status < 200 or status >= 300 or not data:
        return {
            "ok": False,
            "stage": "token_login",
            "status": status,
            "error": _api_error(data, text),
            "canonical_url": canonical,
        }
    access = _extract_access_token(data)
    if not access:
        return {
            "ok": False,
            "stage": "token_login",
            "status": status,
            "error": _token_login_failure(data, text, status),
            "canonical_url": canonical,
        }

    body: dict[str, Any] = {
        "token": client_token.strip(),
        "name": scanner_name,
        "scanner_role": scanner_role,
    }
    if scanner_id:
        body["scanner_id"] = scanner_id
    try:
        status, text, data, _ = _request_json(
            "POST",
            canonical + "/api/scanners/bind-client-token",
            tenant,
            verify_tls=verify_tls,
            bearer=access,
            body=body,
            follow_redirects=False,
        )
    except Exception as exc:
        return {"ok": False, "stage": "bind", "error": _exception_text(exc), "canonical_url": canonical}
    if status == 403:
        return {
            "ok": False,
            "stage": "bind",
            "status": status,
            "error": "Logged-in user cannot manage scanners (needs scan:policy_manage)",
            "canonical_url": canonical,
        }
    if status < 200 or status >= 300 or not data:
        return {
            "ok": False,
            "stage": "bind",
            "status": status,
            "error": _api_error(data, text),
            "canonical_url": canonical,
        }
    agent_token = str(data.get("agent_token") or client_token).strip()
    returned_id = str(data.get("id") or scanner_id).strip()

    # Confirm the bound credential before returning it to the Windows host.
    try:
        status, text, data2, _ = _request_json(
            "POST",
            canonical + "/api/scanner-agent/heartbeat",
            tenant,
            verify_tls=verify_tls,
            bearer=agent_token,
            body={},
            follow_redirects=False,
        )
    except Exception as exc:
        return {"ok": False, "stage": "heartbeat", "error": _exception_text(exc), "canonical_url": canonical}
    if status < 200 or status >= 300:
        return {
            "ok": False,
            "stage": "heartbeat",
            "status": status,
            "error": _api_error(data2, text),
            "canonical_url": canonical,
        }
    return {
        "ok": True,
        "stage": "complete",
        "canonical_url": canonical,
        "scanner_id": returned_id,
        "agent_token": agent_token,
        "status": status,
        "transport": "docker-httpx-openssl",
    }


def _extract_access_token(data: dict[str, Any]) -> str:
    direct = data.get("access_token") or data.get("accessToken")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    for key in ("data", "result", "session"):
        nested = data.get(key)
        if isinstance(nested, dict):
            found = _extract_access_token(nested)
            if found:
                return found
    return ""


def _token_login_failure(data: dict[str, Any], text: str, status: int) -> str:
    if data.get("mfa_required") or data.get("mfa_enrollment_required"):
        return (
            "The server asked for an authenticator code instead of a session. "
            "The emailed access token should sign in without one."
        )
    detail = _api_error(data, "")
    if detail and detail != "HTTP request failed":
        return detail
    fields = ", ".join(sorted(str(key) for key in data.keys()))
    body = (text or "").strip().replace("\n", " ")
    if len(body) > 180:
        body = body[:180]
    return f"Server did not return access_token (HTTP {status}; fields: {fields or 'none'}). {body}".strip()


def _api_error(data: dict[str, Any] | None, text: str) -> str:
    if data:
        candidates: list[Any] = [
            data.get("message"),
            data.get("error"),
            data.get("detail"),
        ]
        detail = data.get("detail")
        if isinstance(detail, dict):
            candidates.insert(0, detail.get("message"))
            err = detail.get("error")
            if isinstance(err, dict):
                candidates.insert(0, err.get("message"))
        for item in candidates:
            if isinstance(item, str) and item.strip():
                return item.strip()[:500]
            if isinstance(item, dict):
                msg = item.get("message")
                if isinstance(msg, str) and msg.strip():
                    return msg.strip()[:500]
    return (text or "HTTP request failed").strip()[:500]


def inspect_cert(base: str, tenant: str) -> dict[str, Any]:
    normalized = _normalize_base(base)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result: dict[str, Any] = {
        "ok": True,
        "base_url": normalized,
        "transport": "docker-python-openssl",
    }
    if parsed.scheme == "https":
        result["certificate"] = _cert_details(host, port)
    result["http_redirect_hint"] = _http_redirect_hint(normalized, tenant)
    return result


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aetheris Docker/OpenSSL control-plane bootstrap")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--base-url", required=True)
        p.add_argument("--tenant", required=True)
        p.add_argument("--verify-tls", default="true")

    p_pre = sub.add_parser("preflight")
    common(p_pre)

    p_cert = sub.add_parser("inspect-cert")
    common(p_cert)

    p_bind = sub.add_parser("bind")
    common(p_bind)
    p_bind.add_argument("--scanner-name", required=True)
    p_bind.add_argument("--scanner-role", default="portable")
    p_bind.add_argument("--scanner-id", default="")

    args = parser.parse_args(argv)
    verify = _parse_bool(args.verify_tls)
    try:
        if args.command == "preflight":
            payload = preflight(args.base_url, args.tenant, verify)
        elif args.command == "inspect-cert":
            payload = inspect_cert(args.base_url, args.tenant)
        else:
            token = sys.stdin.readline().rstrip("\r\n")
            payload = bind(
                args.base_url,
                args.tenant,
                token,
                args.scanner_name,
                args.scanner_role,
                args.scanner_id,
                verify,
            )
        return _emit(payload, 0 if payload.get("ok") else 2)
    except Exception as exc:
        return _emit({"ok": False, "stage": "bootstrap", "error": _exception_text(exc)}, 2)


if __name__ == "__main__":
    raise SystemExit(main())
