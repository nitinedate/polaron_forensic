"""Export BRD docx volumes + S1/S2 supplements to encyclopedia JSONL."""

from __future__ import annotations

import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
ARTIFACT_ID_RE = re.compile(
    r"^(?:WFS|WRG|WRX|WBR|WEM|WLX|WMX|WAX|WIX|WCL|WML|WNT|WEN|WIO|WVT|USR|OSD|FLD)-[A-Z0-9]+-\d{4}$",
    re.I,
)


def docx_paragraphs(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml")
    root = ET.fromstring(xml)
    paras: list[str] = []
    for p in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
        texts = [t.text for t in p.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t") if t.text]
        if texts:
            paras.append("".join(texts).strip())
    return paras


def docx_tables(path: Path) -> list[list[list[str]]]:
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml")
    root = ET.fromstring(xml)
    tables: list[list[list[str]]] = []
    for tbl in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tbl"):
        rows: list[list[str]] = []
        for tr in tbl.findall("w:tr", NS):
            cells: list[str] = []
            for tc in tr.findall("w:tc", NS):
                parts = [
                    t.text
                    for t in tc.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")
                    if t.text
                ]
                cells.append(" ".join(parts).strip())
            if any(cells):
                rows.append(cells)
        if rows:
            tables.append(rows)
    return tables


def volume_key(name: str) -> str | None:
    m = re.match(r"Vol(\d+)_(.+)\.docx", name, re.I)
    if m:
        return f"vol{m.group(1)}"
    if name.startswith("Supplement_S1"):
        return "s1"
    if name.startswith("Supplement_S2"):
        return "s2"
    return None


def parse_artifact_table(rows: list[list[str]], *, volume: str, section: str = "") -> list[dict]:
    if len(rows) < 2:
        return []
    header = [c.lower() for c in rows[0]]
    id_idx = next((i for i, h in enumerate(header) if h in ("id", "artifact id")), 0)
    name_idx = next((i for i, h in enumerate(header) if "artifact" in h and "id" not in h), 1)
    if name_idx == id_idx:
        name_idx = 1 if id_idx == 0 else 0
    out: list[dict] = []
    for row in rows[1:]:
        if id_idx >= len(row):
            continue
        aid = row[id_idx].strip()
        if not ARTIFACT_ID_RE.match(aid):
            continue
        record = {
            "artifact_id": aid.upper(),
            "artifact_name": row[name_idx].strip() if name_idx < len(row) else "",
            "volume": volume,
            "section": section,
            "category": _infer_category(aid),
            "operating_system": _infer_os(volume, aid),
            "default_paths": row[2].strip() if len(row) > 2 else "",
            "file_extensions": row[4].strip() if len(row) > 4 else "",
            "evidence_value": row[-2].strip() if len(row) > 5 else "",
            "raw_row": row,
        }
        record["search_text"] = " | ".join(
            x for x in [record["artifact_name"], record["default_paths"], record["evidence_value"], aid] if x
        )
        out.append(record)
    return out


def parse_field_table(rows: list[list[str]], *, supplement: str) -> list[dict]:
    if len(rows) < 2:
        return []
    header = [c.lower() for c in rows[0]]
    field_idx = next((i for i, h in enumerate(header) if "field" in h), 0)
    out: list[dict] = []
    for row in rows[1:]:
        if field_idx >= len(row) or not row[field_idx].strip():
            continue
        field = row[field_idx].strip()
        record = {
            "chunk_type": "field_row",
            "supplement": supplement,
            "field_name": field,
            "where_found": row[1].strip() if len(row) > 1 else "",
            "source_artifact": row[2].strip() if len(row) > 2 else "",
            "notes": row[3].strip() if len(row) > 3 else "",
            "artifact_id": f"FLD-{supplement.upper()}-{re.sub(r'[^A-Z0-9]+', '_', field.upper())[:40]}",
            "search_text": f"{field} | {row[1] if len(row)>1 else ''} | {row[2] if len(row)>2 else ''}",
        }
        out.append(record)
    return out


def _infer_category(aid: str) -> str:
    prefix = aid.split("-")[0].upper()
    return {
        "WFS": "File System",
        "WRG": "Registry",
        "WRX": "Execution",
        "WBR": "Browser",
        "WEM": "Email",
        "WLX": "Linux",
        "WMX": "macOS",
        "WAX": "Android",
        "WIX": "iOS",
        "USR": "User Account",
        "OSD": "OS Details",
    }.get(prefix, "Forensic")


def _infer_os(volume: str, aid: str) -> str:
    if volume.startswith("vol"):
        n = volume[3:]
        return {
            "1": "Windows",
            "2": "Windows",
            "3": "Windows",
            "4": "Cross-platform",
            "5": "Cross-platform",
            "6": "Linux",
            "7": "macOS",
            "8": "Android",
            "9": "iOS",
            "10": "Cloud",
            "11": "Memory",
            "12": "Malware/IR",
            "13": "Network",
            "14": "Enterprise",
            "15": "IoT/Vehicle",
        }.get(n, "Multi")
    return "Multi"


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    brd_dir = repo / "data" / "brd"
    out_path = repo / "data" / "encyclopedia" / "artifacts.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, dict] = {}
    field_rows: list[dict] = []
    sections: list[dict] = []

    for docx in sorted(brd_dir.glob("*.docx")):
        vol = volume_key(docx.name)
        if not vol or vol.startswith("vol16") or vol.startswith("vol17"):
            continue
        if int(vol[3:]) > 15 if vol.startswith("vol") and vol[3:].isdigit() else False:
            if vol not in ("s1", "s2"):
                continue
        tables = docx_tables(docx)
        paras = docx_paragraphs(docx)
        section_title = ""
        for p in paras[:30]:
            if len(p) > 5 and p[0].isdigit() and "." in p[:4]:
                section_title = p
                break
        if section_title:
            sections.append({"volume": vol, "title": section_title, "source_file": docx.name})
        for tbl in tables:
            if vol in ("s1", "s2"):
                field_rows.extend(parse_field_table(tbl, supplement=vol))
            else:
                for rec in parse_artifact_table(tbl, volume=vol, section=section_title):
                    artifacts[rec["artifact_id"]] = rec

    with out_path.open("w", encoding="utf-8") as f:
        for rec in artifacts.values():
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        for rec in field_rows:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Wrote {len(artifacts)} artifacts + {len(field_rows)} field rows -> {out_path}")


if __name__ == "__main__":
    main()
