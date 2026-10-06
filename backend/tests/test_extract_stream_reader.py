import hashlib

from app.services.extracted_disk import _IterFileReader


def test_iter_file_reader_streams_and_hashes_without_full_materialization():
    chunks = [b"abc", b"defgh", b"ijk"]
    reader = _IterFileReader(iter(chunks), hash_enabled=True)
    assert reader.read(4) == b"abcd"
    assert reader.read(3) == b"efg"
    assert reader.read(99) == b"hijk"
    assert reader.bytes_read == 11
    assert reader.hexdigest() == hashlib.sha256(b"abcdefghijk").hexdigest()
