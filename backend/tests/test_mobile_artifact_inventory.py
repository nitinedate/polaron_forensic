"""Unit tests for mobile artifact family classification."""

from app.services.mobile_artifact_inventory import MOBILE_FAMILIES, _family_matches


def test_pictures_match_by_extension():
    fam = next(f for f in MOBILE_FAMILIES if f.key == "pictures")
    assert _family_matches(fam, {"file_path": "mtp/Internal Storage/IMG_1.HEIC", "file_name": "IMG_1.HEIC", "extension": ".heic"})


def test_whatsapp_messages_prefer_db_markers():
    fam = next(f for f in MOBILE_FAMILIES if f.key == "whatsapp_messages")
    assert _family_matches(fam, {"file_path": "/data/data/com.whatsapp/databases/msgstore.db", "file_name": "msgstore.db", "extension": ".db"})


def test_linkedin_path_marker():
    fam = next(f for f in MOBILE_FAMILIES if f.key == "linkedin")
    assert _family_matches(fam, {"file_path": "apps/com.linkedin.android/cache/x", "file_name": "x", "extension": ""})


def test_documents_pdf():
    fam = next(f for f in MOBILE_FAMILIES if f.key == "documents")
    assert _family_matches(fam, {"file_path": "Download/report.pdf", "file_name": "report.pdf", "extension": ".pdf"})
