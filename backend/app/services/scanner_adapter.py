"""Scanner-agnostic adapter factory (FR-2.4, FR-1)."""

from __future__ import annotations

from typing import Any, Protocol

from app.services.greenbone_client import GreenboneClient
from app.services.nessus_client import NessusClient
from app.services.scanner_stub import stub_scan_vulnerabilities


class ScannerClient(Protocol):
    configured: bool

    def create_scan(self, *, name: str, targets: str, template_uuid: str | None = None) -> dict[str, Any]: ...
    def launch_scan(self, scan_id: int | str) -> dict[str, Any]: ...
    def scan_details(self, scan_id: int | str) -> dict[str, Any]: ...
    def server_status(self) -> dict[str, Any]: ...


def get_scanner_client(*, edition: str | None, base_url: str = "", api_key_ref: str | None = None) -> ScannerClient:
    from app.config import get_settings
    from app.services.scanner_credentials import (
        is_remote_scanner_url,
        normalize_scanner_url,
        parse_gmp_credentials,
    )

    settings = get_settings()
    ed = (edition or "openvas").strip().lower()
    if ed in {
        "openvas",
        "greenbone",
        "gvm",
        "greenbone community edition",
        "greenbone community",
        "greenbone enterprise",
    }:
        url = normalize_scanner_url(base_url) or settings.gvm_url or f"tls://{settings.gvm_host}:{settings.gvm_port}"
        user, password = parse_gmp_credentials(api_key_ref)
        return GreenboneClient(
            base_url=url,
            gmp_username=user or settings.gvm_username,
            gmp_password=password or settings.gvm_password or settings.gvm_admin_password,
            # Remote on-site laptops often use self-signed GMP certs.
            verify_tls=False if is_remote_scanner_url(url) else None,
        )
    return NessusClient(base_url=base_url or settings.nessus_default_url)


def enrich_stub_scan_details(details: dict[str, Any], *, credentialed: bool, custom_checks: list[dict] | None) -> dict[str, Any]:
    if not details.get("stub"):
        return details
    out = dict(details)
    out["vulnerabilities"] = stub_scan_vulnerabilities(credentialed=credentialed, custom_checks=custom_checks)
    return out
