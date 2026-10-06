"""Generic ZIP / folder mobile export importer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.mobile_adapters.base import AdapterResult
from app.services.mobile_segments import mobile_segment_key


class ZipImportAdapter:
    name = "import_zip"

    def detect(self, names: list[str], paths: list[str] | None = None) -> bool:
        for name in names or []:
            key = mobile_segment_key(name)
            if key and key[2] == "zip":
                return True
            if Path(name).suffix.lower() == ".zip":
                return True
        return False

    def identify(self, names: list[str], paths: list[str] | None = None) -> dict[str, Any]:
        zips = [n for n in names or [] if Path(n).suffix.lower() == ".zip" or (mobile_segment_key(n) or (None, None, None))[2] == "zip"]
        return {
            "adapter": self.name,
            "formats": ["zip"] if zips else [],
            "segment_count": len(zips),
            "source_class": "generic_zip",
        }

    def preflight(self, *, mobile_os: str | None = None) -> AdapterResult:
        return AdapterResult(
            ok=True,
            adapter_name=self.name,
            format="zip",
            message="Generic ZIP/folder import is available.",
            manifest={"mobile_os": mobile_os, "acquisition_mode": "import"},
        )

    def verify_output(self, names: list[str]) -> AdapterResult:
        ok = self.detect(names)
        return AdapterResult(
            ok=ok,
            adapter_name=self.name,
            message="ZIP package verified." if ok else "No ZIP package found.",
            errors=[] if ok else ["missing_zip"],
        )

    def produce_manifest(self, names: list[str], *, mobile_os: str | None = None) -> dict[str, Any]:
        return {
            **self.identify(names),
            "mobile_os": mobile_os,
            "acquisition_mode": "import",
            "immutable_original": True,
        }
