import pdfplumber
from pathlib import Path

pdf_path = Path(r"d:\all\Fotrensics_Data\DISK1\HDD\Report\Ex-5 Histotechlab1 Report.pdf")
out = Path(r"e:\rag_new2\scripts\_pdf_artifacts_pages.txt")
lines = []
with pdfplumber.open(str(pdf_path)) as pdf:
    # Artifacts section ~ pages 9-12 (1-based) => indices 8-11
    for i in range(5, min(15, len(pdf.pages))):
        text = pdf.pages[i].extract_text() or ""
        lines.append(f"\n========== PAGE {i+1} ==========\n")
        lines.append(text)
        # Also try tables
        tables = pdf.pages[i].extract_tables() or []
        if tables:
            lines.append(f"\n--- TABLES on page {i+1}: {len(tables)} ---\n")
            for ti, t in enumerate(tables):
                lines.append(f"[table {ti}]")
                for row in t[:40]:
                    lines.append(" | ".join(str(c or "") for c in row))
out.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {out} chars={out.stat().st_size}")
