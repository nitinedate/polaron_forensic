"""Windows Shell Link (.lnk) parser."""

from __future__ import annotations

import struct
from typing import Any

LNK_MAGIC = b"\x4c\x00\x00\x00"  # 0x0000004C


def parse_lnk(data: bytes, path: str) -> list[dict[str, Any]]:
    if len(data) < 76 or data[:4] != LNK_MAGIC:
        return [{"lnk": True, "path": path, "valid": False, "size_bytes": len(data)}]

    records: list[dict[str, Any]] = []
    try:
        flags = struct.unpack_from("<I", data, 20)[0]
        has_link_info = bool(flags & 0x2)
        has_name = bool(flags & 0x4)
        has_working_dir = bool(flags & 0x10)
        has_args = bool(flags & 0x20)

        record: dict[str, Any] = {
            "format": "shell_link",
            "path": path,
            "size_bytes": len(data),
            "valid": True,
            "has_link_info": has_link_info,
            "has_arguments": has_args,
        }

        # Extract ASCII/Unicode strings from link data section
        text = data.decode("utf-16-le", errors="ignore")
        paths = []
        for segment in text.split("\x00"):
            seg = segment.strip()
            if len(seg) > 3 and (":" in seg or seg.startswith("\\\\") or seg.startswith("/")):
                paths.append(seg[:260])
        if paths:
            record["target_paths"] = paths[:5]
            record["target"] = paths[0]

        ascii_text = data.decode("latin-1", errors="ignore")
        for marker in (".exe", ".dll", ".bat", ".cmd", ".ps1"):
            idx = ascii_text.lower().find(marker)
            if idx > 0:
                start = max(0, idx - 80)
                snippet = ascii_text[start : idx + len(marker)]
                clean = "".join(c for c in snippet if c.isprintable())
                if len(clean) > 8:
                    record.setdefault("target_hints", []).append(clean[-120:])
                    break

        records.append(record)
    except struct.error:
        records.append({"lnk": True, "path": path, "valid": False})

    return records
