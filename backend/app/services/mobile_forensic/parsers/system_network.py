"""System logs / network / accounts metadata parser."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class SystemNetworkParser(ArtifactParser):
    name = "system_network_parser"
    version = "1.0.0"
    domains = ("system", "network")

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return any(
            m in p
            for m in (
                "/log/",
                "/logs/",
                "wifi",
                "wpa_supplicant",
                "accounts.db",
                "sync",
                "dropbox",
                "networkstats",
                "usagestats",
                "batterystats",
            )
        ) or name in {"accounts.db", "wifi.db", "networkpolicy.xml", "wpa_supplicant.conf"}

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        p = item.path.lower()
        domain = "network" if any(x in p for x in ("wifi", "network", "wpa")) else "system"
        yield NormalizedArtifact.create(
            artifact_type="system_artifact" if domain == "system" else "network_artifact",
            source_domain=domain,
            data={
                "path": item.path,
                "name": PurePosixPath(item.path).name,
                "size": item.size,
                "mime": item.mime_hint,
            },
            state="allocated",
            recovery_source="live_file",
            source_path=item.path,
            parser=self.name,
            parser_version=self.version,
            job_id=context.job_id,
        )
