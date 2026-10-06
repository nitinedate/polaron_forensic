from app.services.axiom_query_manifest import _canon, parse_reference_counts


def test_parse_reference_counts_json_list():
    pairs = parse_reference_counts([{"artifact": "PDF Documents", "count": "1,234"}, {"name": "Audio", "hits": 5}])
    assert pairs == [("PDF Documents", 1234), ("Audio", 5)]


def test_parse_reference_counts_mapping():
    assert parse_reference_counts({"Picture": 70580}) == [("Picture", 70580)]


def test_parse_reference_counts_pasted_section_b():
    text = "Artifact,Count\nUSB Devices,39\nSocial Media URLs\t50\nEML(X) Files  18\nLogfile Analysis: 12,463\n"
    pairs = dict(parse_reference_counts(text))
    assert pairs["USB Devices"] == 39
    assert pairs["Social Media URLs"] == 50
    assert pairs["EML(X) Files"] == 18
    assert pairs["Logfile Analysis"] == 12463


def test_canon_aliases():
    assert _canon("Pictures (70,580)") == "picture"
    assert _canon("Remote Desktop Protocol") == "remote desktop protocol (rdp)"
    assert _canon("EML files") == "eml(x) files"
