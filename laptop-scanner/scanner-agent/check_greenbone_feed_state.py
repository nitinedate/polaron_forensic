import json

from agent.gmp_local import LocalOpenVAS, _find_scanner_id, _ospd_feed_state, _session


o = LocalOpenVAS()
try:
    with _session(
        socket_path=o.socket_path,
        host=o.host,
        port=o.port,
        username=o.username,
        password=o.password,
    ) as gmp:
        scanner_id = _find_scanner_id(gmp)
        state = _ospd_feed_state(gmp)
    payload = {"scanner_id": scanner_id, **state}
    print(json.dumps(payload, sort_keys=True))
    raise SystemExit(0 if state.get("ready") else 10)
except SystemExit:
    raise
except Exception as exc:
    print(json.dumps({"ready": False, "reason": "probe_failed", "detail": str(exc)}))
    raise SystemExit(2)
