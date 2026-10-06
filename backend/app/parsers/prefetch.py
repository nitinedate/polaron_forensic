"""Windows Prefetch (.pf) parser."""

from __future__ import annotations

import struct
from typing import Any

PF_MAGIC = (b"SCCA", b"MAM\x04")


def parse_prefetch(data: bytes, path: str) -> list[dict[str, Any]]:
    if len(data) < 84:
        return []

    records: list[dict[str, Any]] = []
    sig = data[:4]
    version = None
    exec_name = ""

    if sig == b"SCCA":
        try:
            version = struct.unpack_from("<I", data, 0)[0]
            run_count = struct.unpack_from("<I", data, 12)[0]
            # Executable name at offset 16, UTF-16 null-terminated, max 60 chars
            name_bytes = data[16:16 + 120]
            exec_name = name_bytes.decode("utf-16-le", errors="ignore").split("\x00")[0].strip()
            records.append({
                "format": "prefetch_scca",
                "executable": exec_name or path.split("\\")[-1].replace(".pf", ""),
                "run_count": run_count,
                "version": version,
                "size_bytes": len(data),
                "path": path,
            })
        except struct.error:
            pass
    elif sig == b"MAM\x04":
        records.append({"format": "prefetch_compressed_mam", "path": path, "size_bytes": len(data)})
    else:
        records.append({"format": "prefetch_unknown", "path": path, "size_bytes": len(data)})

    return records or [{"prefetch": True, "path": path, "size_bytes": len(data)}]
