"""Compare Axiom PDF report counts vs exported artifacts XLSX."""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

PDF = Path(r"d:\all\Fotrensics_Data\DISK1\HDD\Report\Ex-5 Histotechlab1 Report.pdf")
XLSX = Path(r"c:\Users\ndate\Downloads\artifacts_d963d7b1.xlsx")
OUT = Path(r"e:\rag_new2\scripts\_axiom_count_diff.txt")


def norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^\w\s/\-\(\)\.\$]+", "", s)
    return s.strip()


def extract_pdf_counts(pdf_path: Path) -> dict[str, int]:
    try:
        import pdfplumber
    except ImportError:
        import subprocess

        subprocess.check_call([sys.executable, "-m", "pip", "install", "pdfplumber", "-q"])
        import pdfplumber

    counts: dict[str, int] = {}
    # Patterns seen in Magnet AXIOM PDFs: "Artifact Name ..... 123" or "Name 123"
    line_re = re.compile(
        r"^(?P<name>.+?)\s+[\.·…]{2,}\s*(?P<n>[\d,]+)\s*$|"
        r"^(?P<name2>.+?)\s{2,}(?P<n2>[\d,]+)\s*$|"
        r"^(?P<name3>.+?)\s+(?P<n3>[\d,]+)\s*$"
    )
    # Also TOC-like: Artifact (123)
    paren_re = re.compile(r"^(?P<name>.+?)\s*\((?P<n>[\d,]+)\)\s*$")

    with pdfplumber.open(str(pdf_path)) as pdf:
        print(f"PDF pages: {len(pdf.pages)}", flush=True)
        for i, page in enumerate(pdf.pages):
            text = page.extract_text() or ""
            for raw in text.splitlines():
                line = raw.strip()
                if not line or len(line) < 3:
                    continue
                m = paren_re.match(line)
                if m:
                    name = m.group("name").strip()
                    n = int(m.group("n").replace(",", ""))
                    key = norm(name)
                    # Prefer larger if duplicate labels
                    counts[key] = max(counts.get(key, 0), n)
                    continue
                m = line_re.match(line)
                if not m:
                    continue
                name = (m.group("name") or m.group("name2") or m.group("name3") or "").strip()
                n_s = m.group("n") or m.group("n2") or m.group("n3")
                if not name or not n_s:
                    continue
                # Filter noise
                if name.lower() in {"page", "total", "contents", "index"}:
                    continue
                if len(name) > 120:
                    continue
                try:
                    n = int(n_s.replace(",", ""))
                except ValueError:
                    continue
                if n < 0 or n > 50_000_000:
                    continue
                key = norm(name)
                counts[key] = max(counts.get(key, 0), n)
            if i < 3:
                print(f"--- page {i+1} sample ---", flush=True)
                print("\n".join((text or "").splitlines()[:40]), flush=True)
    return counts


def extract_xlsx_counts(xlsx_path: Path) -> dict[str, dict]:
    import openpyxl

    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    print("sheets:", wb.sheetnames, flush=True)
    out: dict[str, dict] = {}
    for sheet in wb.sheetnames:
        ws = wb[sheet]
        rows = ws.iter_rows(values_only=True)
        try:
            header = next(rows)
        except StopIteration:
            continue
        headers = [str(h or "").strip().lower() for h in header]
        print(f"sheet={sheet} headers={headers[:12]}", flush=True)
        # Find name/count columns
        name_idx = None
        count_idx = None
        status_idx = None
        id_idx = None
        for i, h in enumerate(headers):
            if name_idx is None and any(x in h for x in ("artifact", "name", "title", "category")):
                if "count" in h:
                    continue
                name_idx = i
            if count_idx is None and any(x in h for x in ("count", "records", "total", "occurrences")):
                count_idx = i
            if status_idx is None and "status" in h:
                status_idx = i
            if id_idx is None and h in ("artifact_id", "id", "key"):
                id_idx = i
        if name_idx is None:
            # fallback first col
            name_idx = 0
        if count_idx is None:
            # try second numeric-ish
            for i, h in enumerate(headers):
                if i != name_idx and ("#" in h or "qty" in h or h.endswith("n")):
                    count_idx = i
                    break
        for row in rows:
            if not row or name_idx >= len(row):
                continue
            name = str(row[name_idx] or "").strip()
            if not name:
                continue
            n = 0
            if count_idx is not None and count_idx < len(row) and row[count_idx] is not None:
                try:
                    n = int(float(str(row[count_idx]).replace(",", "")))
                except ValueError:
                    n = 0
            status = str(row[status_idx] or "") if status_idx is not None and status_idx < len(row) else ""
            aid = str(row[id_idx] or "") if id_idx is not None and id_idx < len(row) else ""
            key = norm(name)
            prev = out.get(key)
            if prev is None or n >= int(prev.get("count") or 0):
                out[key] = {"name": name, "count": n, "status": status, "id": aid, "sheet": sheet}
    wb.close()
    return out


def main() -> None:
    pdf_counts = extract_pdf_counts(PDF)
    xlsx = extract_xlsx_counts(XLSX)
    print(f"PDF keys={len(pdf_counts)} XLSX keys={len(xlsx)}", flush=True)

    # Match by normalized name; also try substring containment
    matched = []
    only_pdf = []
    only_xlsx = []
    used_xlsx = set()

    for pk, pn in sorted(pdf_counts.items(), key=lambda x: x[0]):
        if pk in xlsx:
            xn = int(xlsx[pk]["count"])
            used_xlsx.add(pk)
            matched.append((xlsx[pk]["name"], pn, xn, xn - pn, xlsx[pk].get("id", "")))
            continue
        # fuzzy: exact token overlap
        best = None
        best_score = 0
        for xk, meta in xlsx.items():
            if xk in used_xlsx:
                continue
            if pk == xk or pk in xk or xk in pk:
                score = min(len(pk), len(xk))
                if score > best_score:
                    best_score = score
                    best = xk
        if best:
            xn = int(xlsx[best]["count"])
            used_xlsx.add(best)
            matched.append((xlsx[best]["name"], pn, xn, xn - pn, xlsx[best].get("id", "")))
        else:
            only_pdf.append((pk, pn))

    for xk, meta in xlsx.items():
        if xk not in used_xlsx:
            only_xlsx.append((meta["name"], int(meta["count"]), meta.get("id", "")))

    gaps = [m for m in matched if m[3] != 0]
    gaps.sort(key=lambda x: abs(x[3]), reverse=True)

    lines = []
    lines.append(f"PDF artifacts parsed: {len(pdf_counts)}")
    lines.append(f"XLSX artifacts parsed: {len(xlsx)}")
    lines.append(f"Matched: {len(matched)}  Gaps(nonzero): {len(gaps)}")
    lines.append(f"Only in PDF: {len(only_pdf)}  Only in XLSX: {len(only_xlsx)}")
    lines.append("")
    lines.append("=== TOP GAPS (XLSX - PDF) ===")
    for name, pdf_n, x_n, delta, aid in gaps[:80]:
        lines.append(f"{delta:+8d}  PDF={pdf_n:>10,}  XLSX={x_n:>10,}  {aid:12}  {name}")
    lines.append("")
    lines.append("=== ONLY IN PDF (sample 40) ===")
    for name, n in only_pdf[:40]:
        lines.append(f"{n:>10,}  {name}")
    lines.append("")
    lines.append("=== ONLY IN XLSX with count>0 (sample 40) ===")
    for name, n, aid in sorted(only_xlsx, key=lambda x: -x[1])[:40]:
        if n <= 0:
            continue
        lines.append(f"{n:>10,}  {aid:12}  {name}")

    text = "\n".join(lines)
    OUT.write_text(text, encoding="utf-8")
    print(text)
    print(f"\nWrote {OUT}")


if __name__ == "__main__":
    main()
