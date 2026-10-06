from __future__ import annotations

import logging

from app.access_log import SkipScanner404Filter, keep_access_log


def test_keep_real_api_404s():
    assert keep_access_log("/api/scanners", 404) is True
    assert keep_access_log("/health", 404) is True
    assert keep_access_log("/docs", 404) is True


def test_drop_scanner_cgi_404s():
    assert keep_access_log("/crm/", 404) is False
    assert keep_access_log("/vtigercrm/", 404) is False
    assert keep_access_log("/web/app_dev.php/_profiler/", 404) is False
    assert keep_access_log("/zport/acl_users/", 404) is False
    assert keep_access_log("/WsusAdmin/", 404) is False


def test_keep_non_404():
    assert keep_access_log("/crm/", 200) is True
    assert keep_access_log("/api/health", 200) is True


def test_filter_parses_uvicorn_message():
    filt = SkipScanner404Filter()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='172.18.0.1:56862 - "GET /crm/ HTTP/1.1" 404 Not Found',
        args=(),
        exc_info=None,
    )
    assert filt.filter(record) is False

    record2 = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg='172.18.0.1:1 - "GET /api/health HTTP/1.1" 404 Not Found',
        args=(),
        exc_info=None,
    )
    assert filt.filter(record2) is True
