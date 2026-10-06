from agent.lan_fingerprint import is_docker_nat_fingerprint, lan_changed, should_watch_lan


def test_lan_changed_detects_gateway_move():
    origin = {"gateway": "192.168.1.1", "subnet": "192.168.1.0/24"}
    moved = {"gateway": "10.10.80.1", "subnet": "10.10.80.0/24"}
    assert lan_changed(origin, moved) is True
    assert lan_changed(origin, origin) is False


def test_same_slash24_still_changes_when_gateway_moves():
    origin = {"gateway": "10.10.80.1", "subnet": "10.10.80.0/24"}
    other_site = {"gateway": "10.10.80.254", "subnet": "10.10.80.0/24"}
    assert lan_changed(origin, other_site) is True


def test_docker_nat_fingerprints_do_not_false_abort():
    docker = {"gateway": "172.18.0.1", "subnet": "172.18.0.0/16"}
    assert is_docker_nat_fingerprint(docker) is True
    assert lan_changed(docker, {"gateway": "172.18.0.1", "subnet": "172.18.0.0/16"}) is False


def test_missing_fingerprint_is_not_a_change():
    assert lan_changed({}, {"gateway": "192.168.1.1"}) is False
    assert lan_changed({"gateway": "192.168.1.1"}, {}) is False


def test_only_portable_watches_lan():
    assert should_watch_lan("portable") is True
    assert should_watch_lan("persistent_edge") is False
    assert should_watch_lan("remote_vpn") is False
    assert should_watch_lan(None) is False
