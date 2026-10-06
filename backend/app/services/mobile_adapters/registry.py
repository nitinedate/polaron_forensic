"""Select import adapter by OS + detected formats."""

from __future__ import annotations

from typing import Any

from app.services.mobile_adapters.import_android_backup import AndroidBackupImportAdapter
from app.services.mobile_adapters.import_ios_backup import IosBackupImportAdapter
from app.services.mobile_adapters.import_ufed import UfedImportAdapter
from app.services.mobile_adapters.import_zip import ZipImportAdapter
from app.services.mobile_os import normalize_mobile_os

_IMPORT_ADAPTERS = (
    UfedImportAdapter(),
    IosBackupImportAdapter(),
    AndroidBackupImportAdapter(),
    ZipImportAdapter(),
)


class LiveAcquisitionStub:
    """Phase 2 placeholder — live acquire is not implemented."""

    name = "live_acquisition_stub"

    def detect(self) -> bool:
        return False

    def identify(self) -> dict[str, Any]:
        return {"adapter": self.name, "status": "EXTERNAL_TOOL_REQUIRED"}

    def preflight(self) -> dict[str, Any]:
        return {
            "ok": False,
            "adapter_name": self.name,
            "message": "Live acquisition requires Phase 2 ADB/iOS adapters or specialist hand-off.",
            "capability_label": "EXTERNAL_TOOL_REQUIRED",
        }

    def supported_methods(self) -> list[str]:
        return []

    def acquire(self) -> dict[str, Any]:
        raise RuntimeError("EXTERNAL_TOOL_REQUIRED: live mobile acquisition is not enabled")


def list_import_adapters() -> list[Any]:
    return list(_IMPORT_ADAPTERS)


def select_import_adapter(
    *,
    names: list[str] | None = None,
    paths: list[str] | None = None,
    mobile_os: str | None = None,
) -> Any:
    names = names or []
    paths = paths or []
    os_id = normalize_mobile_os(mobile_os)

    # Prefer OS-specific backup adapters when markers match.
    if os_id == "ios":
        ios = IosBackupImportAdapter()
        if ios.detect(names, paths):
            return ios
    if os_id == "android":
        android = AndroidBackupImportAdapter()
        if android.detect(names, paths):
            return android

    for adapter in _IMPORT_ADAPTERS:
        if adapter.detect(names, paths):
            return adapter

    # Default: UFED-style for mobile OS jobs (covers .pas/.ufd folder imports).
    return UfedImportAdapter()


def build_import_collection_summary(
    *,
    names: list[str],
    paths: list[str] | None = None,
    mobile_os: str | None = None,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    adapter = select_import_adapter(names=names, paths=paths, mobile_os=mobile_os)
    manifest = adapter.produce_manifest(names, mobile_os=mobile_os)
    return {
        "adapter": getattr(adapter, "name", "unknown"),
        "adapter_manifest": manifest,
        "capability_label": (capability or {}).get("capability_label"),
        "detected_formats": (capability or {}).get("detected_formats") or manifest.get("formats") or [],
        "segment_count": len(names or []),
        "acquisition_mode": "import",
        "provenance": "import",
        "immutable_original": True,
    }
