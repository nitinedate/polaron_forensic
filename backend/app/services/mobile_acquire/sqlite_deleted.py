"""Recover deleted / residual content from *inside* acquired SQLite files.

This is NOT disk-level unallocated recovery. On stock (non-root / non-jailbreak)
handsets we cannot image free filesystem clusters over ADB/lockdown. What we
*can* do after a backup/DB is obtained is carve residual payloads from SQLite
freelist / free pages and WAL/journal remnants — often recovering deleted chat
rows that still live inside ChatStorage.sqlite, msgstore.db, or other app DBs.
"""

from __future__ import annotations

import json
import re
import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


_UTF8_RUN = re.compile(
    rb"(?:[\x20-\x7e]|[\xC2-\xF4][\x80-\xBF]+){16,4096}"
)

# Path markers → social/chat app label for deleted residuals.
_APP_MARKERS: tuple[tuple[str, str], ...] = (
    ("whatsapp", "whatsapp"),
    ("com.whatsapp", "whatsapp"),
    ("net.whatsapp", "whatsapp"),
    ("telegram", "telegram"),
    ("org.telegram", "telegram"),
    ("signal", "signal"),
    ("org.thoughtcrime", "signal"),
    ("instagram", "instagram"),
    ("com.instagram", "instagram"),
    ("facebook", "facebook"),
    ("messenger", "facebook"),
    ("com.facebook", "facebook"),
    ("linkedin", "linkedin"),
    ("com.linkedin", "linkedin"),
    ("snapchat", "snapchat"),
    ("com.snapchat", "snapchat"),
    ("tiktok", "tiktok"),
    ("discord", "discord"),
    ("com.discord", "discord"),
    ("viber", "viber"),
    ("wechat", "wechat"),
    ("com.tencent.mm", "wechat"),
    ("line/", "line"),
    ("jp.naver.line", "line"),
    ("slack", "slack"),
    ("teams", "teams"),
    ("skype", "skype"),
    ("sms.db", "sms"),
    ("mmssms", "sms"),
    ("chatstorage", "whatsapp"),
    ("msgstore", "whatsapp"),
    ("extchatdatabase", "whatsapp"),
)


def infer_social_app(path: str | Path) -> str | None:
    low = str(path).replace("\\", "/").lower()
    for marker, app in _APP_MARKERS:
        if marker in low:
            return app
    return None


def _page_size(header: bytes) -> int:
    if len(header) < 32:
        return 4096
    raw = struct.unpack(">H", header[16:18])[0]
    return 65536 if raw == 1 else (raw or 4096)


def _is_schema_or_index_junk(text: str) -> bool:
    """True for SQLite DDL / FTS schema / Core Data leftovers — never chat bodies."""
    low = (text or "").strip().lower()
    if not low:
        return True
    if any(
        tok in low
        for tok in (
            "create table",
            "create index",
            "create virtual table",
            "sqlite_autoindex",
            "sqlite_master",
            "using fts",
            "fts4(",
            "fts5(",
            "tokenize=",
            "wa_tokenizer",
            "matchinfo=",
            "itable",
            "docsdocs",
            "c0docs_content",
            "collate binary",
            "indexz_wa",
            " on zwa",
        )
    ):
        return True
    if any(
        tok in text
        for tok in (
            "WAMessageDataItem",
            "WAChatProperties",
            "WAMediaItem",
            "WAGroupMember",
            "NSKeyedArchiver",
            "NSMutable",
            "SystemMessage",
            "ContactBlocked",
            "BizChatSystem",
            "Z_PK",
            "Z_ENT",
        )
    ):
        return True
    return False


def _infer_residual_identity(text: str) -> dict[str, Any]:
    """Best-effort sender/conversation/JID from carved residual text."""
    raw = (text or "").strip()
    out: dict[str, Any] = {
        "sender": "unknown",
        "conversation": None,
        "chat_jid": None,
        "is_group": False,
    }
    if not raw or _is_schema_or_index_junk(raw):
        return out

    jid_m = re.search(
        r"(~?\d{6,20}@(?:s\.whatsapp\.net|g\.us|lid|c\.us))",
        raw,
        flags=re.IGNORECASE,
    )
    if jid_m:
        jid = jid_m.group(1)
        out["chat_jid"] = jid
        out["is_group"] = jid.lower().endswith("@g.us")
        local = jid.split("@", 1)[0].lstrip("~")
        out["sender"] = local
        out["conversation"] = local

    # ChatSearch FTS freelist often concatenates: <body>…<contact>…<chat>
    # Prefer a human-looking contact token when present near the end.
    contact_m = re.search(
        r"(?:contact|chat)[=:\s]+([A-Za-z][A-Za-z0-9 .'_-]{1,40})",
        raw,
        flags=re.IGNORECASE,
    )
    if contact_m:
        name = contact_m.group(1).strip(" ._-")
        if name and name.lower() not in {"unknown", "chat", "docs", "text", "documenttype"}:
            out["sender"] = name
            out["conversation"] = name

    phone_m = re.search(r"(?<!\d)(\+?\d{10,15})(?!\d)", raw)
    if out["sender"] == "unknown" and phone_m:
        out["sender"] = phone_m.group(1)
        out["conversation"] = phone_m.group(1)

    return out


def _carve_bytes(data: bytes, *, limit: int | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in _UTF8_RUN.finditer(data):
        try:
            text = match.group(0).decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if len(text) < 16:
            continue
        low = text.lower()
        if low.startswith("create table") or low.startswith("create virtual") or low.startswith("sqlite_"):
            continue
        if _is_schema_or_index_junk(text):
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if limit is not None and len(out) >= limit:
            break
    return out


def _looks_like_chat_residual(text: str) -> bool:
    """Heuristic: residual string resembles human chat content (not schema/JID junk)."""
    text = (text or "").strip()
    if len(text) < 8:
        return False
    low = text.lower()
    if _is_schema_or_index_junk(text):
        return False
    if re.match(r"^\$?[A-Za-z][A-Za-z0-9_]{15,}_?$", text):
        return False
    # Bare JIDs / group ids with no message body.
    if re.fullmatch(r"~?\d{8,20}@(?:s\.whatsapp\.net|g\.us|lid|c\.us)", text.strip("()[] ")) or (
        ("@s.whatsapp.net" in low or "@g.us" in low or "@lid" in low)
        and " " not in text
        and len(text) < 80
    ):
        return False
    # URL-only blobs without surrounding chat context are weak; still allow short links.
    if low.startswith("http://") or low.startswith("https://"):
        return len(text) >= 16
    # Human chat-ish: spaces + printable run, not a pure path/hash
    if " " in text and len(text) >= 12 and not text.startswith("/") and not text.startswith("{"):
        printable = sum(1 for c in text[:200] if c.isprintable() or c in "\n\r\t")
        return printable >= int(min(len(text), 200) * 0.75)
    return False


def _carve_freelist(data: bytes) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for _kind, _page, _offset, blob in _freelist_spans(data):
        for text in _carve_bytes(blob):
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


def _freelist_spans(data: bytes) -> Iterator[tuple[str, int, int, bytes]]:
    """Visit both SQLite trunk and leaf pages, preserving their byte offsets.

    Trunk pointer arrays are structural data, not residual text. Bounds and
    visited sets prevent damaged files from looping or reading active page 1.
    """
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        return
    page_size = _page_size(data)
    if not 512 <= page_size <= 65536 or page_size & (page_size - 1):
        return
    usable = page_size - data[20]
    if usable < 480:
        return
    page_count = len(data) // page_size
    trunks: dict[int, int] = {}
    leaves: dict[int, None] = {}
    page_no = struct.unpack(">I", data[32:36])[0]
    while 1 < page_no <= page_count and page_no not in trunks:
        offset = (page_no - 1) * page_size
        next_page, count = struct.unpack(">II", data[offset:offset + 8])
        if count > (usable - 8) // 4:
            break
        pointer_end = 8 + count * 4
        trunks[page_no] = pointer_end
        for pos in range(offset + 8, offset + pointer_end, 4):
            leaf = struct.unpack(">I", data[pos:pos + 4])[0]
            if 1 < leaf <= page_count:
                leaves[leaf] = None
        page_no = next_page
    for page_no, pointer_end in trunks.items():
        start = (page_no - 1) * page_size
        yield "freelist_trunk", page_no, start + pointer_end, data[start + pointer_end:start + usable]
    for page_no in leaves:
        if page_no not in trunks:
            start = (page_no - 1) * page_size
            yield "freelist_leaf", page_no, start, data[start:start + usable]


def iter_sqlite_residuals_bytes(
    data: bytes, *, companion_bytes: dict[str, bytes] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield unverified text spans; never assert a deleted row or timestamp.

    Offsets address the supplied plaintext SQLite or companion bytes. They do
    not address the compressed/encrypted source container. WAL strings may
    belong to live transactions and are therefore also only candidates.
    """
    spans = _freelist_spans(data)
    for kind, page, offset, blob in spans:
        yield from _residual_spans(blob, kind=kind, page=page, offset=offset, source="main")
    for name, blob in (companion_bytes or {}).items():
        if blob:
            kind = "wal_candidate" if "wal" in name.lower() else "journal_candidate"
            yield from _residual_spans(blob, kind=kind, page=None, offset=0, source=name)


def _residual_spans(
    blob: bytes, *, kind: str, page: int | None, offset: int, source: str,
) -> Iterator[dict[str, Any]]:
    for match in _UTF8_RUN.finditer(blob):
        try:
            raw_text = match.group(0).decode("utf-8")
        except UnicodeDecodeError:
            continue
        text = raw_text.strip()
        if not _looks_like_chat_residual(text):
            continue
        leading_bytes = len(raw_text.encode("utf-8")) - len(raw_text.lstrip().encode("utf-8"))
        yield {
            "text": text, "offset": offset + match.start() + leading_bytes,
            "byte_length": len(text.encode("utf-8")), "page_number": page,
            "source_kind": kind, "source_component": source,
        }


def recover_sqlite_residuals(
    db_path: Path,
    dest_dir: Path,
    *,
    companion_bytes: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Carve residual strings from a SQLite DB (+ optional WAL/journal bytes)."""
    db_path = Path(db_path)
    dest_dir = Path(dest_dir)
    result: dict[str, Any] = {
        "source": str(db_path),
        "ok": False,
        "live_tables": [],
        "carved_strings": 0,
        "chat_like_residuals": 0,
        "output": "",
        "errors": [],
        "sources_carved": [],
    }
    if not db_path.is_file() or db_path.stat().st_size < 100:
        result["errors"].append("DB missing or too small")
        return result

    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        data = db_path.read_bytes()
    except OSError as exc:
        result["errors"].append(str(exc))
        return result

    live_path = dest_dir / "live_schema.txt"
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = con.cursor()
        tables = [
            r[0]
            for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        result["live_tables"] = tables
        lines = [f"tables={len(tables)}"]
        for table in tables[:80]:
            try:
                n = cur.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                lines.append(f"{table}: {n} rows")
            except Exception as exc:
                lines.append(f"{table}: (count failed: {exc})")
        live_path.write_text("\n".join(lines), encoding="utf-8")
        con.close()
    except Exception as exc:
        result["errors"].append(f"live schema: {exc}")

    carved: list[str] = []
    try:
        carved = _carve_freelist(data)
        result["sources_carved"].append("main")
    except Exception as exc:
        result["errors"].append(f"carve main: {exc}")
        carved = _carve_bytes(data)
        result["sources_carved"].append("main_fallback")

    # Companion WAL / journal (and any caller-supplied companion bytes).
    companions: list[tuple[str, Path | None, bytes | None]] = []
    for suffix in ("-wal", "-journal"):
        companion = Path(str(db_path) + suffix)
        if companion.is_file() and companion.stat().st_size > 32:
            companions.append((suffix.lstrip("-"), companion, None))
    for label, blob in (companion_bytes or {}).items():
        if blob and len(blob) > 32:
            companions.append((label, None, blob))

    for label, path, blob in companions:
        try:
            raw = blob if blob is not None else path.read_bytes()  # type: ignore[union-attr]
            extra = _carve_bytes(raw)
            if extra:
                carved.extend(extra)
                result["sources_carved"].append(label)
        except Exception as exc:
            result["errors"].append(f"carve {label}: {exc}")

    # Dedupe preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for text in carved:
        if text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    carved = deduped

    out_file = dest_dir / "carved_deleted_residuals.txt"
    out_file.write_text(
        "# Residual / freelist / WAL strings carved from SQLite file\n"
        "# These are NOT guaranteed deleted messages; validate before relying.\n"
        "# Disk unallocated clusters are NOT included (stock USB limitation).\n\n"
        + "\n---\n".join(carved),
        encoding="utf-8",
        errors="replace",
    )

    social_app = infer_social_app(db_path)
    iso_re = re.compile(r"\b(20\d{2}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})?")
    structured: list[dict[str, Any]] = []
    chat_like = 0
    for i, text in enumerate(carved):
        retained_time_text = None
        m = iso_re.search(text)
        if m:
            retained_time_text = m.group(0)
        is_chat = _looks_like_chat_residual(text)
        if not is_chat:
            continue
        chat_like += 1
        identity = _infer_residual_identity(text)
        structured.append(
            {
                "record_type": "sqlite_deleted_residual",
                "is_deleted": None,
                "is_deleted_candidate": True,
                "recovery_state": "sqlite_residual_candidate",
                "social_app": social_app,
                "chat_like": True,
                "deleted_at": None,
                "retained_time_text": retained_time_text,
                "text": text,
                "text_body": text,
                "body": text,
                "sender": identity.get("sender") or "unknown",
                "conversation": identity.get("conversation"),
                "chat_jid": identity.get("chat_jid"),
                "is_group": bool(identity.get("is_group")),
                "source": str(db_path),
                "index": i,
                "confidence": "UNVERIFIED",
            }
        )
    meta_file = dest_dir / "carved_deleted_residuals.json"
    meta_file.write_text(
        json.dumps(
            {
                "source": str(db_path),
                "social_app": social_app,
                "carved_strings": len(carved),
                "chat_like_residuals": chat_like,
                "sources_carved": result["sources_carved"],
                "recovered_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                "items": structured,
                "note": (
                    "In-file SQLite freelist / WAL / residual carving. "
                    "Validate before relying; retained date text does not establish deletion time or UTC. "
                    "True filesystem unallocated recovery needs physical/full-FS access."
                ),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    result["carved_strings"] = len(carved)
    result["chat_like_residuals"] = chat_like
    result["structured_items"] = len(structured)
    result["social_app"] = social_app
    result["output"] = str(out_file)
    result["structured_output"] = str(meta_file)
    result["ok"] = True
    return result


def recover_sqlite_bytes(
    data: bytes,
    *,
    source_label: str,
    companion_bytes: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Carve residuals from in-memory SQLite bytes (job_artifacts path)."""
    import tempfile

    if not data or len(data) < 100:
        return {"ok": False, "carved_strings": 0, "items": [], "errors": ["empty"]}
    with tempfile.TemporaryDirectory(prefix="mobile_del_") as tmp:
        root = Path(tmp)
        db_path = root / "source.db"
        db_path.write_bytes(data)
        # Materialise companions next to DB so recover_sqlite_residuals can find -wal/-journal
        for label, blob in (companion_bytes or {}).items():
            if not blob:
                continue
            if label in {"wal", "-wal"}:
                (root / "source.db-wal").write_bytes(blob)
            elif label in {"journal", "-journal"}:
                (root / "source.db-journal").write_bytes(blob)
        dest = root / "out"
        # Override social app via source_label path markers
        item = recover_sqlite_residuals(db_path, dest, companion_bytes=None)
        # Re-infer app from original path label (temp path has no markers)
        app = infer_social_app(source_label) or item.get("social_app")
        items: list[dict[str, Any]] = []
        structured_path = dest / "carved_deleted_residuals.json"
        if structured_path.is_file():
            try:
                payload = json.loads(structured_path.read_text(encoding="utf-8"))
                for rec in payload.get("items") or []:
                    if isinstance(rec, dict):
                        rec = dict(rec)
                        rec["social_app"] = app or rec.get("social_app")
                        rec["source"] = source_label
                        items.append(rec)
            except Exception:
                pass
        return {
            "ok": bool(item.get("ok")),
            "source": source_label,
            "social_app": app,
            "carved_strings": int(item.get("carved_strings") or 0),
            "chat_like_residuals": int(item.get("chat_like_residuals") or 0),
            "items": items,
            "sources_carved": list(item.get("sources_carved") or []),
            "errors": list(item.get("errors") or []),
            "note": (
                "In-file SQLite freelist / WAL residual carving from imported mobile evidence."
            ),
        }


def recover_tree(readable_root: Path) -> dict[str, Any]:
    """Run residual recovery on every DB under readable_artifacts/."""
    readable_root = Path(readable_root)
    summary: dict[str, Any] = {
        "ok": False,
        "databases": [],
        "total_carved": 0,
        "total_chat_like": 0,
        "by_app": {},
        "note": (
            "In-file SQLite freelist / WAL / residual carving only. "
            "True filesystem unallocated recovery requires physical/full-filesystem "
            "access (root/jailbreak or vendor extract) — not available on stock USB."
        ),
    }
    if not readable_root.is_dir():
        return summary

    dest_root = readable_root / "deleted_recovery"
    by_app: dict[str, int] = {}
    for path in readable_root.rglob("*"):
        if not path.is_file():
            continue
        low = path.name.lower()
        if not low.endswith((".sqlite", ".sqlite3", ".db", ".sqlitedb")):
            continue
        if "deleted_recovery" in path.parts:
            continue
        # Skip companion files themselves as primary targets
        if low.endswith(("-wal", "-journal")):
            continue
        rel = path.relative_to(readable_root)
        dest = dest_root / rel.parent / path.stem
        item = recover_sqlite_residuals(path, dest)
        summary["databases"].append(item)
        summary["total_carved"] += int(item.get("carved_strings") or 0)
        summary["total_chat_like"] += int(item.get("chat_like_residuals") or 0)
        app = item.get("social_app") or "unknown"
        by_app[app] = by_app.get(app, 0) + int(item.get("chat_like_residuals") or item.get("carved_strings") or 0)

    summary["by_app"] = by_app
    summary["ok"] = bool(summary["databases"])
    summary["output_root"] = str(dest_root)
    return summary
