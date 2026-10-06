"""Android backup / OEM export importer (.ab / .adb markers) — import-only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.mobile_adapters.base import AdapterResult

_ANDROID_BACKUP_EXT = {".ab", ".adb"}


class AndroidBackupImportAdapter:
    name = "import_android_backup"

    def detect(self, names: list[str], paths: list[str] | None = None) -> bool:
        for name in names or []:
            if Path(name).suffix.lower() in _ANDROID_BACKUP_EXT:
                return True
        blob = " ".join((paths or []) + (names or [])).lower()
        return "backup.ab" in blob or "android_backup" in blob

    def identify(self, names: list[str], paths: list[str] | None = None) -> dict[str, Any]:
        matches = [n for n in names or [] if Path(n).suffix.lower() in _ANDROID_BACKUP_EXT]
        return {
            "adapter": self.name,
            "formats": ["android_backup"] if matches else [],
            "segment_count": len(matches),
            "source_class": "android_backup",
        }

    def preflight(self, *, mobile_os: str | None = None) -> AdapterResult:
        return AdapterResult(
            ok=True,
            adapter_name=self.name,
            format="android_backup",
            message="Android backup import is available.",
            manifest={"mobile_os": mobile_os or "android", "acquisition_mode": "import"},
        )

    def verify_output(self, names: list[str]) -> AdapterResult:
        ok = self.detect(names)
        return AdapterResult(
            ok=ok,
            adapter_name=self.name,
            message="Android backup verified." if ok else "No Android backup found.",
            errors=[] if ok else ["missing_android_backup"],
        )

    def produce_manifest(self, names: list[str], *, mobile_os: str | None = None) -> dict[str, Any]:
        return {
            **self.identify(names),
            "mobile_os": mobile_os or "android",
            "acquisition_mode": "import",
            "immutable_original": True,
        }
