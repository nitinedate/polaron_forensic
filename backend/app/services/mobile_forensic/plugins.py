"""Plugin contracts for mobile artifact parsers and recovery analyzers."""

from __future__ import annotations

import logging
from collections import OrderedDict
from abc import ABC, abstractmethod
from typing import Any, Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact

log = logging.getLogger("mobile_forensic.plugins")


class ParseContext:
    """Read-only parse context shared across domain parsers."""

    def __init__(
        self,
        *,
        job_id: str,
        platform: str,
        source_id: str | None = None,
        whatsapp_key_hex: str | None = None,
        whatsapp_legacy_account: str | None = None,
        whatsapp_key_candidates: list | None = None,
        signal_db_key_hex: str | None = None,
        ios_backup_password: str | None = None,
        root_paths: list[str] | None = None,
        read_bytes: Any | None = None,
        db: Any | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.job_id = job_id
        self.platform = (platform or "Android").strip()
        self.source_id = source_id
        self.whatsapp_key_hex = whatsapp_key_hex
        self.whatsapp_legacy_account = whatsapp_legacy_account
        self.whatsapp_key_candidates = list(whatsapp_key_candidates or [])
        if whatsapp_key_hex:
            from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate

            self.whatsapp_key_candidates.insert(0, WhatsAppKeyCandidate(whatsapp_key_hex, "case_intake"))
        self.signal_db_key_hex = signal_db_key_hex
        self.ios_backup_password = ios_backup_password
        self.root_paths = list(root_paths or [])
        self._read_bytes = read_bytes
        self.db = db
        self.extra = dict(extra or {})
        self._byte_cache = OrderedDict()
        self._cache_bytes = 0
        self._cache_budget = 64 * 1024 * 1024

    def read_artifact_bytes(self, path: str, *, max_bytes: int = 120_000_000) -> bytes | None:
        key = (path, max_bytes)
        if key in self._byte_cache:
            self._byte_cache.move_to_end(key)
            return self._byte_cache[key]
        if callable(self._read_bytes):
            try:
                result = self._read_bytes(path, max_bytes=max_bytes)
            except TypeError:
                result = self._read_bytes(path)
            except Exception:
                return None
            # Exact read-request keys avoid treating a cached prefix as a complete
            # source. Keep SQLite companion-bearing bytes subclasses intact.
            if result is not None and len(result) <= self._cache_budget // 2:
                while self._byte_cache and self._cache_bytes + len(result) > self._cache_budget:
                    _, old = self._byte_cache.popitem(last=False)
                    self._cache_bytes -= len(old)
                self._byte_cache[key] = result
                self._cache_bytes += len(result)
            return result
        return None

    def clear_byte_cache(self):
        self._byte_cache.clear()
        self._cache_bytes = 0


class ArtifactParser(ABC):
    name: str = "base"
    version: str = "1.0.0"
    domains: tuple[str, ...] = ()

    @abstractmethod
    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        ...

    @abstractmethod
    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        ...


class RecoveryAnalyzer(ABC):
    name: str = "base_recovery"
    version: str = "1.0.0"

    @abstractmethod
    def analyze(
        self,
        items: list[InventoryItem],
        parsed: list[NormalizedArtifact],
        context: ParseContext,
    ) -> Iterator[NormalizedArtifact]:
        ...


class PluginRegistry:
    def __init__(self) -> None:
        self._parsers: list[ArtifactParser] = []
        self._recovery: list[RecoveryAnalyzer] = []

    def register_parser(self, parser: ArtifactParser) -> None:
        self._parsers.append(parser)
        log.debug("registered parser %s@%s", parser.name, parser.version)

    def register_recovery(self, analyzer: RecoveryAnalyzer) -> None:
        self._recovery.append(analyzer)

    @property
    def parsers(self) -> list[ArtifactParser]:
        return list(self._parsers)

    @property
    def recovery_analyzers(self) -> list[RecoveryAnalyzer]:
        return list(self._recovery)

    def route(self, item: InventoryItem, context: ParseContext) -> list[ArtifactParser]:
        matches=[p for p in self._parsers if p.supports(item, context)]
        native_sqlite=any(p.name not in {'generic_message_sqlite','files_media_parser','communication_evidence'} for p in matches)
        return [p for p in matches if p.name!='generic_message_sqlite' or not native_sqlite]


_REGISTRY: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PluginRegistry()
        _register_builtin_plugins(_REGISTRY)
    return _REGISTRY


def reset_plugin_registry_for_tests() -> None:
    global _REGISTRY
    _REGISTRY = None


def _register_builtin_plugins(reg: PluginRegistry) -> None:
    from app.services.mobile_forensic.parsers.app_accounts import AppAccountsParser
    from app.services.mobile_forensic.parsers.communications import CommunicationEvidenceParser,GenericMessageSqliteParser
    from app.services.mobile_forensic.parsers.browser import BrowserHistoryParser
    from app.services.mobile_forensic.parsers.calendar_notes import CalendarNotesParser
    from app.services.mobile_forensic.parsers.contacts import ContactsParser
    from app.services.mobile_forensic.parsers.device_os import DeviceOsParser
    from app.services.mobile_forensic.parsers.files_media import FilesMediaParser
    from app.services.mobile_forensic.parsers.media_store import MediaStoreParser
    from app.services.mobile_forensic.parsers.location import LocationParser
    from app.services.mobile_forensic.parsers.messaging import (
        DiscordParser,
        InstagramParser,
        LineParser,
        LinkedInParser,
        MessengerParser,
        SignalParser,
        SnapchatParser,
        TelegramParser,
        TikTokParser,
        ViberParser,
        WeChatParser,
        WhatsAppParser,
    )
    from app.services.mobile_forensic.parsers.sms_calls import SmsCallsParser
    from app.services.mobile_forensic.parsers.system_network import SystemNetworkParser
    from app.services.mobile_forensic.recovery.analyzers import (
        CacheThumbnailAnalyzer,
        OrphanMediaAnalyzer,
        SqliteHistoryAnalyzer,
        TrashPathAnalyzer,
    )

    for p in (
        DeviceOsParser(),
        ContactsParser(),
        SmsCallsParser(),
        WhatsAppParser(),
        TelegramParser(),
        SignalParser(),
        MessengerParser(),
        InstagramParser(),
        SnapchatParser(),
        DiscordParser(),
        ViberParser(),
        WeChatParser(),
        LineParser(),
        TikTokParser(),
        LinkedInParser(),
        FilesMediaParser(),
        MediaStoreParser(),
        BrowserHistoryParser(),
        LocationParser(),
        CalendarNotesParser(),
        SystemNetworkParser(),
        CommunicationEvidenceParser(),
        GenericMessageSqliteParser(),
        AppAccountsParser(),
    ):
        reg.register_parser(p)
    for a in (
        SqliteHistoryAnalyzer(),
        OrphanMediaAnalyzer(),
        TrashPathAnalyzer(),
        CacheThumbnailAnalyzer(),
    ):
        reg.register_recovery(a)
