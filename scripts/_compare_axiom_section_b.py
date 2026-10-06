"""Compare Axiom PDF section B artifact counts vs XLSX export."""
from __future__ import annotations

import re
from pathlib import Path

import openpyxl

XLSX = Path(r"c:\Users\ndate\Downloads\artifacts_d963d7b1.xlsx")
OUT = Path(r"e:\rag_new2\scripts\_axiom_section_b_diff.txt")

# Parsed from Ex-5 Histotechlab1 Report.pdf pages 9-12 (B. ARTIFACTS)
PDF_COUNTS = {
    "USB Devices": 39,
    "Your Phone Device": 2,
    "Remote Desktop Protocol (RDP)": 6,
    "Feature Usage": 42,
    "Installed Microsoft Programs": 31,
    "Installed Programs (Non-Microsoft)": 167,
    "Windows Defender Logs": 3,
    "Web Chat URLs": 10,
    "Social Media URLs": 50,
    "Malware/Phishing URLs": 0,
    "CSV Documents": 5,
    "Microsoft PowerPoint Documents": 21,
    "Microsoft Excel Documents": 150,
    "PDF Documents": 400,
    "RTF Documents": 5847,
    "Text Documents": 2473,
    "Microsoft Word Documents": 305,
    "Email Attachments": 312,
    "EML(X) Files": 18,
    "Windows Mail": 0,
    "Outlook Emails": 216,
    "Outlook Tasks": 0,
    "Outlook Contacts": 0,
    "Outlook Appointments": 0,
    "Encrypted Files": 56,
    "Windows Stored Credentials": 0,
    "Audio": 594,
    "Picture": 70580,
    "Video": 330,
    "Photoshop Files": 50,
    "Logfile Analysis": 12463,
    "Jump List": 721,
    "LNK Files": 1443,
    # Web Related Files: qualitative only in PDF
}

# Aliases: PDF title -> possible XLSX artifact names
ALIASES = {
    "USB Devices": ["USB Devices", "USB Device", "USBStor", "USB Devices Connected"],
    "Your Phone Device": ["Your Phone Device", "Your Phone"],
    "Remote Desktop Protocol (RDP)": ["Remote Desktop Protocol (RDP)", "RDP", "Remote Desktop"],
    "Feature Usage": ["Feature Usage", "Windows Feature Usage"],
    "Installed Microsoft Programs": ["Installed Microsoft Programs", "Installed Microsoft Programs / Apps"],
    "Installed Programs (Non-Microsoft)": [
        "Installed Programs (Non-Microsoft)",
        "Installed Programs",
        "Installed Programs / Apps",
    ],
    "Windows Defender Logs": ["Windows Defender Logs", "Windows Defender"],
    "Web Chat URLs": ["Web Chat URLs"],
    "Social Media URLs": ["Social Media URLs"],
    "Malware/Phishing URLs": ["Malware/Phishing URLs", "Malware / Phishing URLs"],
    "CSV Documents": ["CSV Documents", "CSV"],
    "Microsoft PowerPoint Documents": ["Microsoft PowerPoint Documents", "PowerPoint Documents"],
    "Microsoft Excel Documents": ["Microsoft Excel Documents", "Excel Documents"],
    "PDF Documents": ["PDF Documents"],
    "RTF Documents": ["RTF Documents"],
    "Text Documents": ["Text Documents", "TXT Documents"],
    "Microsoft Word Documents": ["Microsoft Word Documents", "Word Documents"],
    "Email Attachments": ["Email Attachments"],
    "EML(X) Files": ["EML(X) Files", "EML Files", "EMLX Files"],
    "Windows Mail": ["Windows Mail"],
    "Outlook Emails": ["Outlook Emails", "Outlook Mail"],
    "Outlook Tasks": ["Outlook Tasks"],
    "Outlook Contacts": ["Outlook Contacts"],
    "Outlook Appointments": ["Outlook Appointments", "Outlook Calendar"],
    "Encrypted Files": ["Encrypted Files"],
    "Windows Stored Credentials": ["Windows Stored Credentials", "Stored Credentials"],
    "Audio": ["Audio", "Audio Files"],
    "Picture": ["Picture", "Pictures", "Image", "Images"],
    "Video": ["Video", "Videos", "Video Files"],
    "Photoshop Files": ["Photoshop Files", "PSD Files"],
    "Logfile Analysis": ["Logfile Analysis", "Log Files", "Logfile"],
    "Jump List": ["Jump List", "Jump Lists", "JumpLists"],
    "LNK Files": ["LNK Files", "LNK File", "Shortcut Files"],
}


def norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def load_xlsx() -> dict[str, int]:
    wb = openpyxl.load_workbook(XLSX, read_only=True, data_only=True)
    ws = wb["Artifacts"]
    rows = ws.iter_rows(values_only=True)
    next(rows)  # header
    out: dict[str, int] = {}
    for group, artifact, count, in_scope in rows:
        name = str(artifact or "").strip()
        if not name:
            continue
        try:
            n = int(count or 0)
        except Exception:
            n = 0
        out[name] = n
        out[norm(name)] = n
    wb.close()
    return out


def find_xlsx(xlsx: dict[str, int], pdf_name: str) -> tuple[str | None, int | None]:
    for alias in ALIASES.get(pdf_name, [pdf_name]):
        if alias in xlsx:
            return alias, xlsx[alias]
        if norm(alias) in xlsx:
            return alias, xlsx[norm(alias)]
    # fuzzy contains
    target = norm(pdf_name)
    best = None
    for name, n in xlsx.items():
        if " " not in name and len(name) < 3:
            continue
        nn = norm(name)
        if target == nn or target in nn or nn in target:
            if best is None or abs(len(nn) - len(target)) < abs(len(norm(best[0])) - len(target)):
                best = (name, n)
    return best if best else (None, None)


def main() -> None:
    xlsx = load_xlsx()
    lines = []
    lines.append("Axiom PDF B.ARTIFACTS vs artifacts_d963d7b1.xlsx")
    lines.append("=" * 72)
    gaps = []
    matched = 0
    for pdf_name, pdf_n in PDF_COUNTS.items():
        xname, xn = find_xlsx(xlsx, pdf_name)
        if xname is None:
            lines.append(f"MISSING IN XLSX  PDF={pdf_n:>8,}  {pdf_name}")
            gaps.append((pdf_name, pdf_n, None, None, "missing"))
            continue
        matched += 1
        delta = int(xn) - int(pdf_n)
        mark = "OK" if delta == 0 else "GAP"
        lines.append(
            f"{mark:3} delta={delta:+8d}  PDF={pdf_n:>8,}  XLSX={int(xn):>8,}  PDF[{pdf_name}] <-> XLSX[{xname}]"
        )
        if delta != 0:
            gaps.append((pdf_name, pdf_n, xname, int(xn), delta))

    lines.append("")
    lines.append(f"Matched {matched}/{len(PDF_COUNTS)}; nonzero gaps={sum(1 for g in gaps if g[4] not in (0, 'missing'))}")
    lines.append("")
    lines.append("PRIORITY GAPS (sorted by |delta|):")
    numeric = [g for g in gaps if isinstance(g[4], int)]
    numeric.sort(key=lambda g: abs(g[4]), reverse=True)
    for pdf_name, pdf_n, xname, xn, delta in numeric:
        lines.append(f"  {delta:+8d}  PDF={pdf_n:>8,}  XLSX={xn:>8,}  {pdf_name}")

    text = "\n".join(lines)
    OUT.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
