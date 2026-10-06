"""Compare artifacts_734dcf91.xlsx vs AXIOM PDF Section B reference counts."""
from __future__ import annotations

import re
from pathlib import Path

import openpyxl

XLSX = Path(r"c:\Users\ndate\Downloads\artifacts_734dcf91.xlsx")

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
}

ALIASES = {
    "USB Devices": ["USB Devices"],
    "Your Phone Device": ["Your Phone Device", "Your Phone Devices"],
    "Remote Desktop Protocol (RDP)": ["Remote Desktop Protocol (RDP)"],
    "Feature Usage": ["Feature Usage"],
    "Installed Microsoft Programs": ["Installed Microsoft Programs"],
    "Installed Programs (Non-Microsoft)": ["Installed Programs (Non-Microsoft)"],
    "Windows Defender Logs": ["Windows Defender Logs"],
    "Web Chat URLs": ["Web Chat URLs"],
    "Social Media URLs": ["Social Media URLs"],
    "Malware/Phishing URLs": ["Malware/Phishing URLs", "Malware / Phishing URLs"],
    "CSV Documents": ["CSV Documents"],
    "Microsoft PowerPoint Documents": ["Microsoft PowerPoint Documents"],
    "Microsoft Excel Documents": ["Microsoft Excel Documents"],
    "PDF Documents": ["PDF Documents"],
    "RTF Documents": ["RTF Documents"],
    "Text Documents": ["Text Documents"],
    "Microsoft Word Documents": ["Microsoft Word Documents"],
    "Email Attachments": ["Email Attachments"],
    "EML(X) Files": ["EML(X) Files"],
    "Windows Mail": ["Windows Mail"],
    "Outlook Emails": ["Outlook Emails"],
    "Outlook Tasks": ["Outlook Tasks"],
    "Outlook Contacts": ["Outlook Contacts"],
    "Outlook Appointments": ["Outlook Appointments"],
    "Encrypted Files": ["Encrypted Files"],
    "Windows Stored Credentials": ["Windows Stored Credentials"],
    "Audio": ["Audio"],
    "Picture": ["Picture", "Pictures"],
    "Video": ["Video", "Videos"],
    "Photoshop Files": ["Photoshop Files"],
    "Logfile Analysis": ["Logfile Analysis", "$LogFile Analysis"],
    "Jump List": ["Jump List", "Jump Lists"],
    "LNK Files": ["LNK Files"],
}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def load_xlsx() -> dict[str, int]:
    wb = openpyxl.load_workbook(XLSX, read_only=True, data_only=True)
    ws = wb["Artifacts"]
    rows = ws.iter_rows(values_only=True)
    next(rows)
    out: dict[str, int] = {}
    for _group, artifact, count, _scope in rows:
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


def main() -> None:
    xlsx = load_xlsx()
    print(f"{'Artifact':<42} {'PDF':>8} {'APP':>8} {'DELTA':>8} STATUS")
    print("-" * 80)
    gaps = []
    for pdf_name, pdf_n in PDF_COUNTS.items():
        app_n = None
        for alias in ALIASES.get(pdf_name, [pdf_name]):
            if alias in xlsx:
                app_n = xlsx[alias]
                break
            if norm(alias) in xlsx:
                app_n = xlsx[norm(alias)]
                break
        if app_n is None:
            status = "MISSING"
            delta = None
        else:
            delta = app_n - pdf_n
            if delta == 0:
                status = "MATCH"
            elif abs(delta) <= max(3, int(pdf_n * 0.05)) if pdf_n else abs(delta) <= 3:
                status = "NEAR"
            else:
                status = "GAP"
        print(
            f"{pdf_name:<42} {pdf_n:>8} {app_n if app_n is not None else '-':>8} "
            f"{delta if delta is not None else '-':>8} {status}"
        )
        if status == "GAP":
            gaps.append((pdf_name, pdf_n, app_n, delta))
    print("\nGAPS:")
    for name, pdf_n, app_n, delta in gaps:
        print(f"  {name}: PDF={pdf_n} APP={app_n} DELTA={delta:+d}")


if __name__ == "__main__":
    main()
