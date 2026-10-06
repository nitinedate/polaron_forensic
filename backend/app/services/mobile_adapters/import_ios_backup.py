"""Apple local backup importer (manifest.plist markers) — import-only."""

from __future__ import annotations

from typing import Any

from app.services.mobile_adapters.base import AdapterResult

_IOS_MARKERS = frozenset({"manifest.plist", "info.plist", "status.plist"})


class IosBackupImportAdapter:
    name = "import_ios_backup"

    def detect(self, names: list[str], paths: list[str] | None = None) -> bool:
        lower = {n.lower() for n in names or []}
        if lower & _IOS_MARKERS:
            return True
        blob = " ".join((paths or []) + (names or [])).lower()
        return "manifest.plist" in blob or "/ios" in blob or "\\ios" in blob

    def identify(self, names: list[str], paths: list[str] | None = None) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "formats": ["ios_backup"],
            "segment_count": len(names or []),
            "source_class": "apple_backup",
            "markers": sorted(_IOS_MARKERS & {n.lower() for n in names or []}),
        }

    def preflight(self, *, mobile_os: str | None = None) -> AdapterResult:
        return AdapterResult(
            ok=True,
            adapter_name=self.name,
            format="ios_backup",
            message=("iOS backup import is available. Encrypted imported backups must be "
                     "materialized by a supported decrypt/unback workflow before artifact parsing; "
                     "the parser never treats encrypted hashed files as plaintext merely because a "
                     "password was supplied."),
            manifest={"mobile_os": mobile_os or "ios", "acquisition_mode": "import"},
        )

    def verify_output(self, names: list[str]) -> AdapterResult:
        ok = self.detect(names)
        return AdapterResult(
            ok=ok,
            adapter_name=self.name,
            message="iOS backup markers verified." if ok else "No iOS backup markers found.",
            errors=[] if ok else ["missing_ios_backup_markers"],
        )

    def produce_manifest(self, names: list[str], *, mobile_os: str | None = None) -> dict[str, Any]:
        return {
            **self.identify(names),
            "mobile_os": mobile_os or "ios",
            "acquisition_mode": "import",
            "immutable_original": True,
        }
