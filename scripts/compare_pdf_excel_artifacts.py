"""Compare Magnet report PDF artifact counts vs exported Excel."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import openpyxl
import pdfplumber


def load_excel(path: Path) -> dict[str, int]:
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb["Artifacts"] if "Artifacts" in wb.sheetnames else wb.active
    out: dict[str, int] = {}
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    if rows and len(rows[0]) >= 3 and rows[0][0] and rows[0][1] is not None:
        # Legacy: Artifact | Count
        for row in rows:
            if not row or not row[0]:
                continue
            if row[1] is not None and not str(row[1]).strip().isdigit() and row[1] != "":
                continue
            name = str(row[0]).strip()
            if not name:
                continue
            out[name.lower()] = int(row[1] or 0)
        return out
    # Current: Group | Artifact | Count | In scope
    for row in rows:
        if not row or len(row) < 3:
            continue
        artifact = row[1]
        if artifact is None or str(artifact).strip() == "":
            continue
        name = str(artifact).strip()
        out[name.lower()] = int(row[2] or 0)
    return out


def _parse_indian_number(raw: str) -> int:
    """Parse counts like 2,01,447 or 37,277."""
    cleaned = re.sub(r"[^\d]", "", raw)
    return int(cleaned) if cleaned else 0


def parse_pdf_artifacts(path: Path) -> dict[str, int]:
    text_parts: list[str] = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text_parts.append(page.extract_text() or "")
    full = "\n".join(text_parts)

    parsed: dict[str, int] = {}
    current_name: str | None = None
    in_section = False
    skip_titles = re.compile(
        r"^(Connected Devices|Application Usages|Communication|Documents|Email|Encryption|Media|Operating System|Web Related)",
        re.I,
    )
    for line in full.splitlines():
        l = line.strip()
        if not l or l.startswith("Page ") or l.startswith("Description:"):
            continue
        if re.search(r"\.{5,}", l):
            continue
        if re.match(r"^B\.?\s*ARTIFACTS", l, re.I):
            in_section = True
            current_name = None
            continue
        if not in_section:
            continue
        if re.match(r"^C\.?\s*OBJECTIVE", l, re.I):
            break
        m_count = re.match(r"^Count:\s*([\d,]+)", l, re.I)
        if m_count and current_name:
            parsed[current_name.lower()] = _parse_indian_number(m_count.group(1))
            current_name = None
            continue
        if re.match(r"^Count:\s*Reviewed", l, re.I):
            current_name = None
            continue
        m_item = re.match(r"^\d+\.\s+(.+)$", l)
        if m_item:
            name = m_item.group(1).strip().rstrip(":")
            if skip_titles.search(name):
                current_name = None
            else:
                current_name = name
    return parsed


def normalize_key(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def main() -> int:
    pdf_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"d:\all\Fotrensics_Data\DISK2\RRP E Mr.Seger Forensic Report.pdf")
    xlsx_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(r"c:\Users\ndate\Downloads\artifacts_4316aaf4.xlsx")
    report_only = "--report-only" in sys.argv

    excel = load_excel(xlsx_path)
    pdf = parse_pdf_artifacts(pdf_path)

    if report_only:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
            from app.services.report_catalog_sync import REPORT_ARTIFACTS
        except ImportError:
            REPORT_ARTIFACTS = []
        report_norms = {normalize_key(a["name"]) for a in REPORT_ARTIFACTS}
        excel = {k: v for k, v in excel.items() if normalize_key(k) in report_norms or k in report_norms}
        print("(Filtered Excel to report-template Section B artifacts only)")
        print()

    print(f"Excel artifacts: {len(excel)}")
    print(f"PDF artifacts parsed: {len(pdf)}")
    print()

    # Fuzzy match by normalized title
    pdf_by_norm = {normalize_key(k): (k, v) for k, v in pdf.items()}
    excel_by_norm = {normalize_key(k): (k, v) for k, v in excel.items()}

    matched = 0
    missing_in_excel = []
    large_diff = []
    small_diff = []
    excel_only = []

    for norm, (pdf_name, pdf_count) in sorted(pdf_by_norm.items()):
        if norm in excel_by_norm:
            ex_name, ex_count = excel_by_norm[norm]
            matched += 1
            diff = ex_count - pdf_count
            pct = abs(diff) / max(pdf_count, 1)
            entry = (pdf_name, pdf_count, ex_count, diff)
            if ex_count == 0 and pdf_count > 0:
                missing_in_excel.append(entry)
            elif abs(diff) > 0 and (pct >= 0.2 or abs(diff) >= 10):
                large_diff.append(entry)
            elif diff != 0:
                small_diff.append(entry)
        else:
            missing_in_excel.append((pdf_name, pdf_count, None, None))

    for norm, (ex_name, ex_count) in excel_by_norm.items():
        if norm not in pdf_by_norm and ex_count > 0:
            excel_only.append((ex_name, ex_count))

    print(f"=== MISSING or ZERO in Excel (PDF > 0): {len(missing_in_excel)} ===")
    for item in sorted(missing_in_excel, key=lambda x: -(x[1] or 0))[:40]:
        pdf_name, pdf_count, ex_count, diff = item
        print(f"  PDF {pdf_count:>6} | Excel {str(ex_count):>6} | {pdf_name}")

    print(f"\n=== LARGE differences (>=20% or >=10): {len(large_diff)} ===")
    for pdf_name, pdf_count, ex_count, diff in sorted(large_diff, key=lambda x: -abs(x[3]))[:40]:
        print(f"  PDF {pdf_count:>6} | Excel {ex_count:>6} | diff {diff:+6} | {pdf_name}")

    print(f"\n=== Small differences: {len(small_diff)} ===")
    for pdf_name, pdf_count, ex_count, diff in sorted(small_diff, key=lambda x: -abs(x[3]))[:20]:
        print(f"  PDF {pdf_count:>6} | Excel {ex_count:>6} | diff {diff:+6} | {pdf_name}")

    print(f"\n=== Excel-only with count > 0: {len(excel_only)} ===")
    for name, cnt in sorted(excel_only, key=lambda x: -x[1])[:20]:
        print(f"  Excel {cnt:>6} | {name}")

    excel_zero = sum(1 for v in excel.values() if v == 0)
    excel_nonzero = sum(1 for v in excel.values() if v > 0)
    print(f"\nExcel summary: {excel_nonzero} with count>0, {excel_zero} with count=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
