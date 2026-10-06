"""Common adapter interfaces for mobile acquisition/import (Architecture §26)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class AdapterResult:
    ok: bool
    adapter_name: str
    format: str | None = None
    message: str = ""
    manifest: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ImportAdapter(Protocol):
    name: str

    def detect(self, names: list[str], paths: list[str] | None = None) -> bool: ...

    def identify(self, names: list[str], paths: list[str] | None = None) -> dict[str, Any]: ...

    def preflight(self, *, mobile_os: str | None = None) -> AdapterResult: ...

    def verify_output(self, names: list[str]) -> AdapterResult: ...

    def produce_manifest(self, names: list[str], *, mobile_os: str | None = None) -> dict[str, Any]: ...


class AcquisitionAdapter(Protocol):
    """Phase 2 live-device adapter — Phase 1 stubs raise EXTERNAL_TOOL_REQUIRED."""

    name: str

    def detect(self) -> bool: ...

    def identify(self) -> dict[str, Any]: ...

    def preflight(self) -> AdapterResult: ...

    def supported_methods(self) -> list[str]: ...

    def acquire(self) -> AdapterResult: ...
