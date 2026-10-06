"""Parse native Cellebrite UFED descriptors (.ufd / .ufdx / .pas).

AXIOM / Physical Analyzer open these formats as:

* ``.ufd`` — INI unit descriptor: ``FileDump=<zip>``, ``ZIPLogicalPath=Dump``
* ``.ufdx`` — XML evidence collection pointing at ``.ufd`` / ``.pas`` paths
* ``.pas`` — PA BinaryFormatter case object (not a ZIP; payload is the FileDump zip)
* ``.zip`` — filesystem dump (usually rooted at ``Dump/``)

Inventory and extract must follow ``.ufd`` → FileDump zip, not treat ``.pas`` as ZIP.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("mobile_forensic.cellebrite_ufed")

_SECTION_RE = re.compile(r"^\[(?P<section>[^\]]+)\]\s*$")
_KV_RE = re.compile(r"^(?P<key>[^=]+?)\s*=\s*(?P<value>.*)$")


def _clean_reference(value: str | None) -> str:
    """Normalize Cellebrite path values without trusting host-absolute paths."""
    return str(value or "").strip().strip('"').strip("'").strip()


def _reference_basename(value: str | None) -> str:
    # Path(...).name on Linux does not split Windows backslashes.
    normalized = _clean_reference(value).replace("\\", "/")
    return normalized.rsplit("/", 1)[-1] if normalized else ""


@dataclass
class CellebriteUfdDescriptor:
    path: Path
    device_info: dict[str, str] = field(default_factory=dict)
    file_dump: str | None = None
    key_store: str | None = None
    zip_logical_path: str = "Dump"
    dump_type: str | None = None
    extraction_status: str | None = None
    raw_sections: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def dump_zip_name(self) -> str | None:
        return self.file_dump or self.key_store


def parse_ufd_text(text: str, *, path: Path | None = None) -> CellebriteUfdDescriptor:
    """Parse Cellebrite ``.ufd`` INI contents."""
    desc = CellebriteUfdDescriptor(path=path or Path("."))
    section = ""
    current: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        m = _SECTION_RE.match(line)
        if m:
            if section:
                desc.raw_sections[section] = current
            section = m.group("section").strip()
            current = {}
            continue
        km = _KV_RE.match(line)
        if not km:
            continue
        key = km.group("key").strip()
        value = _clean_reference(km.group("value"))
        current[key] = value
        sec_l = section.lower()
        if sec_l == "deviceinfo":
            desc.device_info[key] = value
        elif sec_l == "dumps":
            if key.lower() == "filedump":
                desc.file_dump = value
            elif key.lower() == "keystore":
                desc.key_store = value
        elif sec_l == "filedump":
            if key.lower() == "ziplogicalpath":
                desc.zip_logical_path = value.strip().strip("/\\") or "Dump"
            elif key.lower() == "type":
                desc.dump_type = value
        elif sec_l == "extractionstatus" and key.lower() == "extractionstatus":
            desc.extraction_status = value
    if section:
        desc.raw_sections[section] = current
    return desc


def parse_ufd_file(path: Path) -> CellebriteUfdDescriptor | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.debug("ufd read failed %s: %s", path, exc)
        return None
    if "[DeviceInfo]" not in text and "[Dumps]" not in text and "[FileDump]" not in text:
        return None
    return parse_ufd_text(text, path=path)


def resolve_ufd_dump_zip(ufd_path: Path) -> tuple[Path, str] | None:
    """Return (zip_path, logical_root_prefix) for a Cellebrite .ufd, if present.

    Cellebrite descriptors may preserve the examiner workstation's absolute Windows
    path.  For a portable evidence set we never follow that host path; we resolve the
    referenced basename/relative path only inside the descriptor directory.
    """
    desc = parse_ufd_file(ufd_path)
    if not desc or not desc.dump_zip_name:
        return None
    parent = ufd_path.parent.resolve()
    raw = _clean_reference(desc.dump_zip_name)
    rel_text = raw.replace("\\", "/")
    candidates: list[Path] = []
    # Keep a genuinely relative subpath, but never follow a foreign absolute path.
    posixish = Path(rel_text)
    if not posixish.is_absolute() and not re.match(r"^[A-Za-z]:/", rel_text):
        candidates.append((parent / posixish).resolve())
    base = _reference_basename(raw)
    if base:
        candidates.append((parent / base).resolve())
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            # A referenced file must stay inside the evidence descriptor folder.
            resolved.relative_to(parent)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            prefix = (desc.zip_logical_path or "Dump").replace("\\", "/").strip("/")
            return resolved, prefix
    return None


def parse_ufdx_extraction_paths(path: Path) -> list[str]:
    """Return referenced Extraction Path= values from Cellebrite .ufdx XML."""
    out: list[str] = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as exc:
        log.debug("ufdx parse failed %s: %s", path, exc)
        return out
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag != "Extraction":
            continue
        p = (el.attrib.get("Path") or "").strip()
        if p:
            out.append(p)
    return out


def resolve_ufdx_referenced_paths(ufdx_path: Path) -> list[Path]:
    """Resolve .ufdx Extraction Path= entries to portable companion files.

    Absolute paths embedded by another examiner workstation are treated as metadata
    only; the resolver looks for the referenced basename beside the .ufdx.  This both
    improves portability and prevents an imported descriptor from reading arbitrary
    host files outside the evidence folder.
    """
    refs = parse_ufdx_extraction_paths(ufdx_path)
    parent = ufdx_path.parent.resolve()
    resolved: list[Path] = []
    seen: set[str] = set()
    for raw in refs:
        clean = _clean_reference(raw)
        rel_text = clean.replace("\\", "/")
        candidates: list[Path] = []
        p = Path(rel_text)
        if not p.is_absolute() and not re.match(r"^[A-Za-z]:/", rel_text):
            candidates.append((parent / p).resolve())
        base = _reference_basename(clean)
        if base:
            candidates.append((parent / base).resolve())
        for cand in candidates:
            try:
                real = cand.resolve()
                real.relative_to(parent)
                key = str(real)
            except (OSError, ValueError):
                continue
            if key in seen or not real.is_file():
                continue
            seen.add(key)
            resolved.append(real)
            break
    return resolved


def collect_mobile_payload_paths(root: Path) -> dict[str, Any]:
    """Discover .pas/.ufd/.ufdx/.zip payload graph under an evidence folder."""
    root = Path(root)
    ufds: list[Path] = []
    ufdxs: list[Path] = []
    passes: list[Path] = []
    zips: list[Path] = []
    dump_zips: list[Path] = []
    ufdx_refs: list[Path] = []
    device_info: dict[str, str] = {}

    if not root.is_dir():
        return {
            "ufds": ufds,
            "ufdxs": ufdxs,
            "pas": passes,
            "zips": zips,
            "dump_zips": dump_zips,
            "ufdx_refs": ufdx_refs,
            "device_info": device_info,
        }

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        if suf == ".ufd":
            ufds.append(p)
            desc = parse_ufd_file(p)
            if desc and desc.device_info and not device_info:
                device_info = dict(desc.device_info)
            resolved = resolve_ufd_dump_zip(p)
            if resolved:
                dump_zips.append(resolved[0])
        elif suf == ".ufdx":
            ufdxs.append(p)
            refs = resolve_ufdx_referenced_paths(p)
            ufdx_refs.extend(refs)
            # Follow the descriptor graph even when the referenced .ufd/.zip was not
            # independently registered in evidence_files.
            for ref in refs:
                rsuf = ref.suffix.lower()
                if rsuf == ".ufd":
                    if ref not in ufds:
                        ufds.append(ref)
                    desc = parse_ufd_file(ref)
                    if desc and desc.device_info and not device_info:
                        device_info = dict(desc.device_info)
                    linked = resolve_ufd_dump_zip(ref)
                    if linked:
                        dump_zips.append(linked[0])
                elif rsuf == ".zip":
                    dump_zips.append(ref)
                elif rsuf == ".pas" and ref not in passes:
                    passes.append(ref)
        elif suf == ".pas":
            passes.append(p)
        elif suf == ".zip":
            zips.append(p)

    # Deduplicate dump zips
    seen_z: set[str] = set()
    uniq_dumps: list[Path] = []
    for z in dump_zips:
        try:
            key = str(z.resolve())
        except OSError:
            key = str(z)
        if key in seen_z:
            continue
        seen_z.add(key)
        uniq_dumps.append(z)

    return {
        "ufds": ufds,
        "ufdxs": ufdxs,
        "pas": passes,
        "zips": zips,
        "dump_zips": uniq_dumps,
        "ufdx_refs": ufdx_refs,
        "device_info": device_info,
        "formats": sorted(
            {
                *(["ufd"] if ufds else []),
                *(["ufdx"] if ufdxs else []),
                *(["pas"] if passes else []),
                *(["zip"] if zips or uniq_dumps else []),
            }
        ),
    }


def is_native_cellebrite_pas(path: Path) -> bool:
    """True when .pas is PA BinaryFormatter (not an Aetheris ZIP package)."""
    try:
        if not path.is_file() or path.suffix.lower() != ".pas":
            return False
        head = path.read_bytes()[:64]
    except OSError:
        return False
    # Observed magic: 00 01 00 00 00 FF FF FF FF … plus UTF-8 "Logic" / version.
    if head.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"):
        return True
    if b"Logic" in head or b"PA.Data" in head:
        return True
    return False
