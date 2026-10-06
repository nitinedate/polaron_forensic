from collections import Counter
from app.db.session import firm_session
from app.services.signature_carve_inventory import _scan_vd_pagefile_hiberfil, _aggregate

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
with firm_session("firm_aetheris") as db:
    hits, urls, n, ipm = _scan_vd_pagefile_hiberfil(db, JID)
    kinds = Counter(h["kind"] for h in hits)
    print("scanned", n, "hits", len(hits), "urls", len(urls), "ipm", ipm)
    print("kinds", dict(kinds))
    inv = _aggregate(hits, urls, ipm_note_hits=ipm)
    print("axiom", inv.get("axiom_counts"))
    print("sources", sorted({h["source_path"] for h in hits})[:10])
