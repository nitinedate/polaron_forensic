"""Raw extension counts from full walk (no video path filters) + doc by_ext_key."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import PurePosixPath

from sqlalchemy import text
from app.db.session import firm_session
from app.services.virtual_disk import enumerate_all_files, open_virtual_disk

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
VIDEO = {
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg",
    ".m4v", ".3gp", ".webm", ".mts", ".vob", ".asf", ".m2ts",
    ".divx", ".f4v", ".ogv", ".rm", ".rmvb", ".3g2", ".wtv", ".dvr-ms", ".ts",
}
PIC = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".ico", ".jfif", ".raw", ".cr2", ".nef", ".dng",
    ".svg", ".emf", ".wmf", ".exif", ".jpe", ".tga", ".cur", ".ani",
    ".dib", ".pcx", ".jp2", ".jxr", ".wdp", ".dds",
}

with firm_session("firm_aetheris") as db:
    ds = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": JID}).scalar()
    d = ds if isinstance(ds, dict) else json.loads(ds or "{}")
    doc = d.get("document_disk_inventory") or {}
    print("by_ext_key", json.dumps(doc.get("by_ext_key") or {}, indent=2)[:2000])

    vd = open_virtual_disk(db, JID)
    nodes = enumerate_all_files(vd)
    raw_v = Counter()
    filt_v = 0
    pic_by = Counter()
    psd = 0
    for n in nodes:
        path = (n.get("path") or "").replace("\\", "/")
        ext = PurePosixPath(path).suffix.lower()
        if ext in VIDEO:
            raw_v[ext] += 1
        if ext in PIC:
            pic_by[ext] += 1
        if ext in {".psd", ".psb", ".pdd"}:
            psd += 1
    print("files", len(nodes), "psd", psd)
    print("raw video by ext", dict(raw_v), "total", sum(raw_v.values()))
    print("picture by ext top", pic_by.most_common(15), "total", sum(pic_by.values()))
