from sqlalchemy import text

from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"


def main() -> None:
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    rows = fetchall(
        db,
        """SELECT file_path, size_bytes FROM job_artifacts
           WHERE job_id=:j AND (file_path ILIKE '%.pst' OR file_path ILIKE '%.ost')""",
        {"j": JOB},
    )
    print("pst rows", len(rows), rows)
    contents = _read_job_files(db, JOB, rows, max_bytes=5_000_000)
    for path, data in contents.items():
        print(
            path,
            "len",
            len(data),
            "IPM.Note",
            data.count(b"IPM.Note"),
            "IPM.",
            data.count(b"IPM."),
            "From:",
            data.count(b"From:"),
        )
        # UTF-16LE "IPM.Note"
        ipm16 = "IPM.Note".encode("utf-16le")
        print("  IPM.Note utf16", data.count(ipm16))
        # sample unicode strings
        import re

        for pat in (rb"(?:Subject|From|To)[:\x00]{1,4}([\x20-\x7e]{3,80})",):
            hits = re.findall(pat, data)
            print("  ascii hits", [h[:50] for h in hits[:6]])
        # utf16 subjects
        subs = re.findall(
            "S\x00u\x00b\x00j\x00e\x00c\x00t\x00.{0,8}((?:[\x20-\x7e]\x00){3,60})".encode(),
            data,
        )
        decoded = []
        for s in subs[:6]:
            try:
                decoded.append(s.decode("utf-16le"))
            except Exception:
                pass
        print("  utf16 subject-ish", decoded)
    db.close()


if __name__ == "__main__":
    main()
