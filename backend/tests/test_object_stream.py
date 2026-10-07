"""Truncated object downloads retry the broken slice and stay resumable."""
import http.client
import io

import pytest

from app.services import storage, tar_cache
from app.services.storage import TransientStreamError, _RangedS3Stream, is_transient_stream_error


class _Resp:
    def __init__(self, data: bytes):
        self._data = data
        self.closed = False

    def read(self):
        return self._data

    def close(self):
        self.closed = True

    def release_conn(self):
        return None


class _Client:
    def __init__(self, payload: bytes, *, fail_first: int):
        self.payload = payload
        self.fail_first = fail_first
        self.calls = 0

    def get_object(self, bucket, key, offset=0, length=0):
        self.calls += 1
        if self.calls <= self.fail_first:
            raise http.client.IncompleteRead(b"", length or 1)
        return _Resp(self.payload[offset : offset + length])


def test_incomplete_read_is_transient():
    exc = http.client.IncompleteRead(b"abc", 50)
    assert is_transient_stream_error(exc)
    assert is_transient_stream_error(
        RuntimeError("Connection broken: IncompleteRead(10 bytes read, 20 more expected)")
    )
    assert not is_transient_stream_error(ValueError("damaged source database"))


def test_ranged_read_retries_one_slice_and_continues(monkeypatch):
    monkeypatch.setattr(storage, "_RANGE_BYTES", 4)
    monkeypatch.setattr(storage.time, "sleep", lambda _seconds: None)
    payload = b"abcdefghij"
    client = _Client(payload, fail_first=1)
    stream = _RangedS3Stream(client, "bucket", "part.tar.zst", len(payload))
    assert stream.read() == payload
    assert client.calls == 4  # first 4-byte slice retried once, then two more slices
    assert stream.read() == b""


def test_broken_shard_stream_does_not_skip_the_rest(monkeypatch):
    class _Broken(io.BytesIO):
        def read(self, size=-1):
            raise http.client.IncompleteRead(b"", 100)

    monkeypatch.setattr(tar_cache, "open_object_stream", lambda _uri: _Broken())
    with pytest.raises(TransientStreamError, match="Extract shard stream interrupted"):
        list(tar_cache.iter_files_from_part("s3://bucket/part.tar.zst", {"Users/a/file.txt"}))
