"""Windows Jump List parsers — AutomaticDestinations / CustomDestinations entry counts."""

from __future__ import annotations

import io
import re
import struct
from typing import Any

_LNK_MAGIC = b"L\x00\x00\x00"
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\x00\r\n]{3,200}")
_UNC_RE = re.compile(r"\\\\[^\x00\r\n]{5,200}")


def _unique_paths(data: bytes) -> set[str]:
    try:
        text = data.decode("utf-16-le", errors="ignore")
    except Exception:
        return set()
    found = set(_PATH_RE.findall(text)) | set(_UNC_RE.findall(text))
    return {p.strip().rstrip("\\") for p in found if len(p.strip()) > 5}


def _destlist_entry_count(data: bytes) -> int | None:
    """Read Automatic Destinations DestList.NumberOfEntries when OLE is available."""
    try:
        import olefile
    except Exception:
        return None
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return None
    try:
        if not ole.exists("DestList"):
            return 0
        raw = ole.openstream("DestList").read()
        if len(raw) < 8:
            return 0
        _ver, cnt = struct.unpack_from("<II", raw, 0)
        if 0 <= cnt < 100_000:
            return int(cnt)
        return 0
    except Exception:
        return None
    finally:
        try:
            ole.close()
        except Exception:
            pass


def _automatic_lnk_stream_count(data: bytes) -> int | None:
    """Count per-stream LNK objects inside an Automatic Destinations CFB."""
    try:
        import olefile
    except Exception:
        return None
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return None
    try:
        n = 0
        for entry in ole.listdir():
            name = "/".join(entry) if isinstance(entry, (list, tuple)) else str(entry)
            if name.lower() == "destlist":
                continue
            try:
                stream = ole.openstream(entry).read()
            except Exception:
                continue
            if stream.startswith(_LNK_MAGIC):
                n += 1
            elif _LNK_MAGIC in stream[:64]:
                n += stream.count(_LNK_MAGIC)
        return n
    except Exception:
        return None
    finally:
        try:
            ole.close()
        except Exception:
            pass


def parse_jump_list(data: bytes, path: str = "") -> list[dict[str, Any]]:
    """Count Jump List destinations / embedded LNK structures (Axiom-style)."""
    if not data or len(data) < 16:
        return [{"format": "jump_list", "valid": False, "path": path}]

    lower = (path or "").replace("\\", "/").lower()
    is_custom = "customdestinations" in lower
    embedded_raw = data.count(_LNK_MAGIC)
    paths = _unique_paths(data)

    if is_custom:
        # Custom Destinations = concatenated Shell Link structures
        entry_count = max(embedded_raw, 1) if embedded_raw or paths else 0
        embedded_lnk = embedded_raw
        kind = "custom"
        method = "lnk_magic"
    else:
        destlist = _destlist_entry_count(data)
        stream_lnk = _automatic_lnk_stream_count(data)
        if destlist is not None:
            entry_count = int(destlist)
            method = "destlist"
        else:
            entry_count = max(len(paths), embedded_raw)
            method = "heuristic"
        # Prefer stream LNK count for embedded; fall back to DestList / raw magic.
        # Raw CFB magic is also retained so LNK Files can include all Shell Link blobs.
        if stream_lnk is not None and stream_lnk > 0:
            embedded_lnk = max(int(stream_lnk), embedded_raw)
        elif destlist is not None:
            embedded_lnk = max(int(destlist), embedded_raw)
        else:
            embedded_lnk = embedded_raw
        kind = "automatic"

    records: list[dict[str, Any]] = [
        {
            "record_type": "jump_list_file",
            "jump_list_kind": kind,
            "entry_count": int(entry_count),
            "embedded_lnk_count": int(embedded_lnk),
            "path_count": len(paths),
            "size_bytes": len(data),
            "count_method": method,
            "source": path,
            "text": (
                f"Jump List ({kind}): {entry_count} entries, "
                f"{embedded_lnk} embedded LNK structure(s)"
            ),
        }
    ]
    for i, p in enumerate(sorted(paths)[:12]):
        records.append({
            "record_type": "jump_list_entry",
            "target_path": p,
            "source": path,
            "text": f"Jump List destination: {p}",
        })
        if i >= 11:
            break
    return records
