"""Test sampled pagefile/hiberfil reads for magic density."""
from app.db.session import firm_session
from app.services.virtual_disk import open_virtual_disk
from app.services.signature_carve_inventory import _read_vd_file_sampled, scan_buffer_for_signatures

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
JPEG = bytes([0xFF, 0xD8, 0xFF])

with firm_session("firm_aetheris") as db:
    vd = open_virtual_disk(db, JID)
    for path in ("pagefile.sys", "hiberfil.sys"):
        data = _read_vd_file_sampled(vd, path, budget=256 * 1024 * 1024)
        hits = scan_buffer_for_signatures(data, source_path=path)
        from collections import Counter
        kinds = Counter(h["kind"] for h in hits)
        print(
            path,
            "bytes",
            len(data),
            "jpeg_magic",
            data.count(JPEG),
            "pdf",
            data.count(b"%PDF-"),
            "rtf",
            data.count(b"{\\rtf"),
            "8BPS",
            data.count(b"8BPS"),
            "ipm",
            data.count(b"IPM.Note"),
            "sig_hits",
            len(hits),
            "kinds",
            dict(kinds),
        )
