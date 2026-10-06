from app.services.vuln_network_tokens import parse_cidr, target_in_cidr, targets_outside_cidr, NetworkTokenError


def test_parse_cidr_normalizes():
    assert parse_cidr("203.0.113.10/24") == "203.0.113.0/24"


def test_parse_cidr_rejects_junk():
    try:
        parse_cidr("not-a-net")
    except NetworkTokenError as exc:
        assert exc.code == "invalid_cidr"
    else:
        raise AssertionError("expected invalid_cidr")


def test_target_in_cidr():
    assert target_in_cidr("203.0.113.44", "203.0.113.0/24")
    assert target_in_cidr("203.0.113.0/28", "203.0.113.0/24")
    assert not target_in_cidr("198.51.100.1", "203.0.113.0/24")
    assert not target_in_cidr("office.example", "203.0.113.0/24")


def test_targets_outside_cidr():
    assert targets_outside_cidr(["203.0.113.1", "8.8.8.8"], "203.0.113.0/24") == ["8.8.8.8"]
