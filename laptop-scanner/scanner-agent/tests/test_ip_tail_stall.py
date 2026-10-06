from agent.main import ip_tail_should_harvest


def test_frozen_94_percent_is_harvested() -> None:
    assert ip_tail_should_harvest(94, 90, stall_sec=90, stall_pct=90) is True


def test_climbing_scan_is_not_harvested() -> None:
    assert ip_tail_should_harvest(94, 20, stall_sec=90, stall_pct=90) is False
    assert ip_tail_should_harvest(50, 600, stall_sec=90, stall_pct=90) is False


def test_stall_can_be_disabled() -> None:
    assert ip_tail_should_harvest(98, 600, stall_sec=0, stall_pct=90) is False


def test_empty_tail_is_not_sealed() -> None:
    from agent.main import seal_tail_harvest

    details = {"vulnerabilities": [], "evidence": {"report_id": None, "hosts_assessed": 0}}
    assert seal_tail_harvest(details, "192.168.0.163", reason="stalled") is False
    assert details.get("status") != "completed"


def test_report_host_is_sealed_for_upload() -> None:
    from agent.main import seal_tail_harvest

    details = {
        "vulnerabilities": [{"host": "192.168.0.163", "plugin_id": "1.3.6.1.4.1.25623.1.0.1"}],
        "evidence": {
            "report_id": "b5ebead4-ebd5-4b91-b972-a3698b34549e",
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "task_status": "stop requested",
        },
    }
    assert seal_tail_harvest(details, "192.168.0.163", reason="stalled 30s at 94%") is True
    evidence = details["evidence"]
    assert evidence["hosts_assessed"] == 1
    assert "192.168.0.163" in evidence["assessed_hosts"]
    assert evidence["task_status"] == "done"
    assert evidence["report_result_count"] == 1
    assert evidence["assessment_complete"] is True
    assert details["status"] == "completed"
