"""Device / OS metadata parser."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class DeviceOsParser(ArtifactParser):
    name = "device_os_parser"
    version = "1.0.0"
    domains = ("device_os",)

    _MARKERS = (
        "build.prop",
        "info.plist",
        "manifest.plist",
        "status.plist",
        "device_info",
        "android_info",
        "imei",
    )

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = Path(p).name.lower()
        return any(m in p or m == name for m in self._MARKERS)

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = {
            "path": item.path,
            "platform": context.platform,
            "size": item.size,
            "note": "Device/OS metadata source inventoried",
        }
        # Best-effort key=value from build.prop
        if item.path.lower().endswith("build.prop"):
            for root in context.root_paths:
                cand = Path(root) / item.path
                if cand.is_file():
                    try:
                        text = cand.read_text(encoding="utf-8", errors="replace")
                        props = {}
                        for line in text.splitlines():
                            if "=" in line and not line.strip().startswith("#"):
                                k, _, v = line.partition("=")
                                props[k.strip()] = v.strip()
                        data["properties"] = {
                            k: props[k]
                            for k in (
                                "ro.product.model",
                                "ro.build.version.release",
                                "ro.product.manufacturer",
                                "ro.serialno",
                            )
                            if k in props
                        }
                    except OSError:
                        pass
                    break
        yield NormalizedArtifact.create(
            artifact_type="device_info",
            source_domain="device_os",
            data=data,
            state="allocated",
            recovery_source="live_file",
            source_path=item.path,
            parser=self.name,
            parser_version=self.version,
            job_id=context.job_id,
        )
