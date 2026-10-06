from app.services.download_agent import (
    DOWNLOAD_PARALLELISM,
    download_block_reason,
    download_counts,
    download_progress_pct,
    download_running_detail,
)


def test_download_parallelism_is_five():
    assert DOWNLOAD_PARALLELISM == 5


def test_download_counts_and_pct():
    ds = {"upload_received_files": 2, "upload_expected_files": 5}
    assert download_counts(ds) == (2, 5)
    assert download_progress_pct(2, 5) == 40
    assert 1 <= download_progress_pct(0, 5) <= 5 or download_progress_pct(0, 5) == 1


def test_download_block_reason_names_agent_and_slots():
    reason = download_block_reason(
        {"upload_received_files": 1, "upload_expected_files": 5}
    )
    assert "Download Agent" in reason
    assert "1/5" in reason
    assert "parallelism=5" in reason


def test_download_running_detail_blocks_others():
    detail = download_running_detail(
        {"upload_received_files": 3, "upload_expected_files": 9}
    )
    assert "3/9" in detail
    assert "blocked" in detail.lower()
