from datetime import date

import pytest
from fastapi import HTTPException

from app.routers.cases import _gap_day_label, gap_merge_date_window


def test_gap_merge_window_defaults_to_yesterday_through_today():
    today = date(2026, 9, 9)
    start, end = gap_merge_date_window(None, today=today)
    assert start == date(2026, 9, 8)
    assert end == today


def test_gap_merge_window_allows_older_from_date():
    today = date(2026, 9, 9)
    start, end = gap_merge_date_window("2026-09-06", today=today)
    assert start == date(2026, 9, 6)
    assert end == today


def test_gap_merge_window_clamps_from_after_today():
    today = date(2026, 9, 9)
    start, end = gap_merge_date_window("2026-09-12", today=today)
    assert start == today
    assert end == today


def test_gap_merge_window_rejects_invalid_date():
    with pytest.raises(HTTPException) as exc:
        gap_merge_date_window("09-09-2026", today=date(2026, 9, 9))
    assert exc.value.status_code == 400


def test_gap_day_label_bands():
    today = date(2026, 9, 9)
    assert _gap_day_label(today, today) == "today"
    assert _gap_day_label(date(2026, 9, 8), today) == "yesterday"
    assert _gap_day_label(date(2026, 9, 6), today) == "06 Sep 2026"
