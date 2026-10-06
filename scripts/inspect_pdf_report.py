"""Inspect Magnet forensic PDF structure."""
import pdfplumber
from pathlib import Path

pdf_path = Path(r"d:\all\Fotrensics_Data\DISK2\RRP E Mr.Seger Forensic Report.pdf")
with pdfplumber.open(pdf_path) as pdf:
    print("pages", len(pdf.pages))
    for i, page in enumerate(pdf.pages):
        text = page.extract_text() or ""
        low = text.lower()
        if any(k in low for k in ("artifact", "feature usage", "b. artifacts", "connected devices", "documents")):
            print(f"\n--- PAGE {i+1} ---")
            print(text[:3000])
            tables = page.extract_tables()
            print(f"tables: {len(tables)}")
            for ti, table in enumerate(tables[:3]):
                print(f" table {ti} rows={len(table)}")
                for row in table[:8]:
                    print("  ", row)
