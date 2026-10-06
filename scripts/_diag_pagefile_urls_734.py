from collections import Counter
from app.db.session import firm_session
from app.services.virtual_disk import open_virtual_disk
from app.services.signature_carve_inventory import _read_vd_file_sampled, extract_urls_from_raw_bytes
from app.services.url_category_counts import classify_url_category

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
with firm_session("firm_aetheris") as db:
    vd = open_virtual_disk(db, JID)
    data = _read_vd_file_sampled(vd, "pagefile.sys", budget=512 * 1024 * 1024)
    urls = extract_urls_from_raw_bytes(data, source_path="pagefile.sys")
    cats = Counter()
    social = []
    for r in urls:
        cat = classify_url_category(r["url"])
        cats[cat or "other"] += 1
        if cat == "social media urls" and len(social) < 30:
            social.append(r["url"])
    print("urls", len(urls), "cats", dict(cats))
    print("social", social[:20])
    hosts = Counter()
    for r in urls:
        u = r["url"].lower()
        if "://" in u:
            hosts[u.split("://", 1)[1].split("/", 1)[0]] += 1
    print("top", hosts.most_common(25))
