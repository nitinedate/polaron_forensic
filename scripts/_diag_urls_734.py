"""Classify carved + browser URLs for job 734."""
from collections import Counter
from app.db.session import firm_session
from app.services.browser_url_inventory import collect_job_browser_url_records, clear_browser_url_cache
from app.services.url_category_counts import classify_url_category
from app.services.signature_carve_inventory import carved_url_records

JID = "734dcf91-453f-4461-aeef-0ea1fefa0613"
clear_browser_url_cache(JID)

with firm_session("firm_aetheris") as db:
    carved = carved_url_records(db, JID)
    records = collect_job_browser_url_records(db, JID)
    print("carved", len(carved), "merged", len(records))
    cats = Counter()
    social = []
    chat = []
    for r in records:
        cat = classify_url_category(r.get("url") or "")
        cats[cat or "other"] += max(int(r.get("visit_count") or 1), 1)
        if cat == "social media urls" and len(social) < 20:
            social.append(r.get("url"))
        if cat == "web chat urls" and len(chat) < 20:
            chat.append(r.get("url"))
    print("cats", dict(cats))
    print("social samples", social)
    print("chat samples", chat)
    # hosts from carved
    hosts = Counter()
    for r in carved[:5000]:
        u = (r.get("url") or "").lower()
        if "://" in u:
            host = u.split("://", 1)[1].split("/", 1)[0]
            hosts[host] += 1
    print("top carved hosts", hosts.most_common(30))
