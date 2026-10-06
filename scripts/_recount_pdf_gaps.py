"""Re-count Section B artifacts with current collectors vs AXIOM PDF targets."""

from __future__ import annotations

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact
from app.services.encryption_inventory import clear_encryption_count_cache
from app.services.inventory_path_cache import clear_path_cache

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"

PDF = {
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
    "Web Related Files": None,
}

CATS = {
    "USB Devices": "Connected Devices",
    "Your Phone Device": "Connected Devices",
    "Remote Desktop Protocol (RDP)": "Connected Devices",
    "Feature Usage": "Application Usages",
    "Installed Microsoft Programs": "Application Usages",
    "Installed Programs (Non-Microsoft)": "Application Usages",
    "Windows Defender Logs": "Application Usages",
    "Web Chat URLs": "Communication",
    "Social Media URLs": "Communication",
    "Malware/Phishing URLs": "Communication",
    "CSV Documents": "Documents",
    "Microsoft PowerPoint Documents": "Documents",
    "Microsoft Excel Documents": "Documents",
    "PDF Documents": "Documents",
    "RTF Documents": "Documents",
    "Text Documents": "Documents",
    "Microsoft Word Documents": "Documents",
    "Email Attachments": "Email & Calendar",
    "EML(X) Files": "Email & Calendar",
    "Windows Mail": "Email & Calendar",
    "Outlook Emails": "Email & Calendar",
    "Outlook Tasks": "Email & Calendar",
    "Outlook Contacts": "Email & Calendar",
    "Outlook Appointments": "Email & Calendar",
    "Encrypted Files": "Encryption & Credentials",
    "Windows Stored Credentials": "Encryption & Credentials",
    "Audio": "Media",
    "Picture": "Media",
    "Video": "Media",
    "Photoshop Files": "Media",
    "Logfile Analysis": "Operating System",
    "Jump List": "Operating System",
    "LNK Files": "Operating System",
    "Web Related Files": "Web Related",
}


def main() -> None:
    clear_path_cache(JOB)
    clear_encryption_count_cache(JOB)
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    print(f"{'Artifact':<40} {'PDF':>8} {'NEW':>8} {'DELTA':>8}")
    print("-" * 70)
    gaps: list[tuple[int, str, int, int, int]] = []
    for name, expected in PDF.items():
        try:
            count = count_axiom_catalog_artifact(
                db, JOB, artifact_name=name, category=CATS[name]
            )
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            print(f"{name:<40} ERROR {exc}")
            continue
        if expected is None:
            print(f"{name:<40} {'n/a':>8} {count:>8} {'Review':>8}")
            continue
        delta = count - expected
        mark = "OK" if delta == 0 else "GAP"
        print(f"{name:<40} {expected:>8} {count:>8} {delta:>+8}  {mark}")
        if delta:
            gaps.append((abs(delta), name, expected, count, delta))
    print("\nTop gaps:")
    for _a, name, expected, count, delta in sorted(gaps, reverse=True)[:15]:
        print(f"  {delta:+8}  PDF={expected} NEW={count}  {name}")
    db.close()


if __name__ == "__main__":
    main()
