from agent.gmp_local import LocalOpenVAS, _find_config_id, _find_scanner_id, _session

o = LocalOpenVAS()
try:
    with _session(socket_path=o.socket_path, host=o.host, port=o.port, username=o.username, password=o.password) as gmp:
        scanner_id = _find_scanner_id(gmp)
        config_id = _find_config_id(gmp, o.scan_config_name)
    print(f"READY scanner={scanner_id} config={config_id} name={o.scan_config_name}")
except Exception as exc:
    print(f"NOT_READY {exc}")
    raise SystemExit(2)
