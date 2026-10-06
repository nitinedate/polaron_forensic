"""Extract artifact/objective content from sample forensic PDF reports."""
from __future__ import annotations

import re
from pathlib import Path

from pypdf import PdfReader

PATHS = [
    Path(r"d:\all\Fotrensics_Data\DISK1\HDD\Report\Ex-5 Histotechlab1 Report.pdf"),
    Path(r"d:\all\Fotrensics_Data\DISK2\RRP E Mr.Seger Forensic Report.pdf"),
]
OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "axiom"


def main() -> None:
    for p in PATHS:
        print("\n" + "=" * 80)
        print("FILE:", p.name)
        reader = PdfReader(str(p))
        print("pages:", len(reader.pages))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        out = OUT_DIR / (p.stem.replace(" ", "_") + "_extract.txt")
        out.write_text(text, encoding="utf-8")
        print("chars:", len(text), "saved:", out)
        for pat in [
            r"B\.\s*ARTIFACTS",
            r"OBJECTIVE",
            r"PROCEDURE",
            r"Connected Devices",
            r"Application Usage",
            r"Operating System",
            r"Communication",
            r"Documents",
            r"Media",
            r"Browser",
            r"Execution",
            r"O\d{3}",
            r"P\d{3}",
        ]:
            m = re.findall(pat, text, re.I)
            if m:
                print(f"  {pat}: {len(m)} hits, sample: {m[:5]}")


if __name__ == "__main__":
    main()
