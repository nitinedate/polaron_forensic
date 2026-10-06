"""UFED-style mobile export importer (.pas / .ufd / .ufdx)."""

from __future__ import annotations

from typing import Any

from app.services.mobile_adapters.base import AdapterResult
from app.services.mobile_segments import mobile_segment_key


class UfedImportAdapter:
    name = "import_ufed"
    _FORMATS = frozenset({"pas", "ufd", "ufdx"})

    def detect(self, names: list[str], paths: list[str] | None = None) -> bool:
        return any(self._format_of(n) in self._FORMATS for n in names or [])

    def identify(self, names: list[str], paths: list[str] | None = None) -> dict[str, Any]:
        formats = sorted({f for n in names or [] if (f := self._format_of(n)) in self._FORMATS})
        return {
            "adapter": self.name,
            "formats": formats,
            "segment_count": len(names or []),
            "source_class": "ufed_export",
        }

    def preflight(self, *, mobile_os: str | None = None) -> AdapterResult:
        return AdapterResult(
            ok=True,
            adapter_name=self.name,
            format="pas",
            message="UFED-compatible export import is available.",
            manifest={"mobile_os": mobile_os, "acquisition_mode": "import"},
        )

    def verify_output(self, names: list[str]) -> AdapterResult:
        ok = self.detect(names)
        return AdapterResult(
            ok=ok,
            adapter_name=self.name,
            message="UFED segments verified." if ok else "No UFED segments found.",
            errors=[] if ok else ["missing_ufed_segments"],
        )

    def produce_manifest(self, names: list[str], *, mobile_os: str | None = None) -> dict[str, Any]:
        return {
            **self.identify(names),
            "mobile_os": mobile_os,
            "acquisition_mode": "import",
            "immutable_original": True,
            "supported_containers": ["pas", "ufd", "ufdx", "zip"],
            "parser_platform_version": "2.0.0",
        }

    @staticmethod
    def _format_of(name: str) -> str | None:
        key = mobile_segment_key(name)
        return key[2] if key else None
