from app.services.port_range import exclude_tcp_ports_from_range


def test_strips_singleton_8080_from_fast_range():
    src = "T:80,443,8080,8443"
    assert exclude_tcp_ports_from_range(src, {8080}) == "T:80,443,8443"


def test_splits_full_tcp_range_around_8080():
    out = exclude_tcp_ports_from_range("T:1-65535", {8080})
    assert "8080" not in out.split(",")
    assert "T:1-8079,8081-65535" == out


def test_empty_exclude_is_noop():
    src = "T:80,8080"
    assert exclude_tcp_ports_from_range(src, set()) == src
