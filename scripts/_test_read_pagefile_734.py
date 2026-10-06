"""Verify VD can read pagefile/hiberfil and count JPEG magics."""
from app.db.session import firm_session
from app.services.virtual_disk import open_virtual_disk, read_full_file_from_disk

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
JPEG = bytes([0xFF, 0xD8, 0xFF])

with firm_session("firm_aetheris") as db:
    vd = open_virtual_disk(db, JID)
    for path in ("pagefile.sys", "hiberfil.sys", "swapfile.sys"):
        try:
            data = read_full_file_from_disk(vd, path, max_bytes=64 * 1024 * 1024)
            print(path, "ok", len(data), "jpeg", data.count(JPEG), "pdf", data.count(b"%PDF-"), "rtf", data.count(b"{\\rtf"), "8BPS", data.count(b"8BPS"), "ipm", data.count(b"IPM.Note"))
        except Exception as exc:
            print(path, "FAIL", type(exc).__name__, exc)
