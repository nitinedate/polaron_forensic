"""MinIO / local object storage for extracted disk artifacts."""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path

from app.config import get_settings

log = logging.getLogger("storage")
_client = None
_client_failed = False


def _local_root() -> Path:
    root = Path(get_settings().data_root) / "objects"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _minio_client():
    global _client, _client_failed
    if _client_failed:
        return None
    if _client is not None:
        return _client
    settings = get_settings()
    try:
        import urllib3
        from minio import Minio
        from urllib3.exceptions import NameResolutionError, NewConnectionError

        # Shard uploads open more sockets than urllib3's default pool of 10.
        http_client = urllib3.PoolManager(num_pools=16, maxsize=64, retries=urllib3.Retry(total=3, backoff_factor=0.2))
        client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
            http_client=http_client,
        )
        if not client.bucket_exists(settings.minio_bucket):
            client.make_bucket(settings.minio_bucket)
        _client = client
        return _client
    except (NameResolutionError, NewConnectionError, OSError) as exc:
        log.warning("MinIO unavailable (%s); using local filesystem", exc)
        _client_failed = True
        return None
    except Exception as exc:
        log.warning("MinIO unavailable (%s); using local filesystem", exc)
        return None


def put_bytes(key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    settings = get_settings()
    client = _minio_client()
    uri = f"s3://{settings.minio_bucket}/{key}"
    if client:
        client.put_object(settings.minio_bucket, key, io.BytesIO(data), len(data), content_type=content_type)
        return uri
    path = _local_root() / key.replace("/", os.sep)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return f"file://{path.resolve()}"


def put_file(key: str, file_path: Path, content_type: str = "application/octet-stream") -> str:
    settings = get_settings()
    client = _minio_client()
    uri = f"s3://{settings.minio_bucket}/{key}"
    size = file_path.stat().st_size
    if client:
        with file_path.open("rb") as fh:
            client.put_object(settings.minio_bucket, key, fh, size, content_type=content_type)
        return uri
    dest = _local_root() / key.replace("/", os.sep)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(file_path.read_bytes())
    return f"file://{dest.resolve()}"


def get_bytes(storage_uri: str, *, max_bytes: int | None = None) -> bytes | None:
    if not storage_uri:
        return None
    if storage_uri.startswith("file://"):
        path = Path(storage_uri[7:])
        if not path.is_file():
            return None
        if max_bytes is None:
            return path.read_bytes()
        with path.open("rb") as fh:
            return fh.read(max_bytes)
    if storage_uri.startswith("s3://"):
        parts = storage_uri[5:].split("/", 1)
        bucket, key = parts[0], parts[1] if len(parts) > 1 else ""
        client = _minio_client()
        if not client:
            path = _local_root() / key.replace("/", os.sep)
            if not path.is_file():
                return None
            if max_bytes is None:
                return path.read_bytes()
            with path.open("rb") as fh:
                return fh.read(max_bytes)
        resp = client.get_object(bucket, key)
        try:
            if max_bytes is None:
                return resp.read()
            return resp.read(max_bytes)
        finally:
            resp.close()
            resp.release_conn()
    return None


class _ObjectStream:
    """Readable stream over a MinIO/local object — caller must close()."""

    def __init__(self, fh, *, closer=None):
        self._fh = fh
        self._closer = closer

    def read(self, size: int = -1):
        return self._fh.read(size)

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
        if self._closer:
            try:
                self._closer()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def open_object_stream(storage_uri: str) -> _ObjectStream | None:
    """Open a streaming read for an object without buffering the whole blob in RAM.

    Critical for multi-GB ``.tar.zst`` extract shards — ``get_bytes`` would OOM workers.
    """
    if not storage_uri:
        return None
    if storage_uri.startswith("file://"):
        path = Path(storage_uri[7:])
        if not path.is_file():
            return None
        return _ObjectStream(path.open("rb"))
    if storage_uri.startswith("s3://"):
        parts = storage_uri[5:].split("/", 1)
        bucket, key = parts[0], parts[1] if len(parts) > 1 else ""
        client = _minio_client()
        if not client:
            path = _local_root() / key.replace("/", os.sep)
            if not path.is_file():
                return None
            return _ObjectStream(path.open("rb"))
        resp = client.get_object(bucket, key)

        def _closer() -> None:
            try:
                resp.close()
            finally:
                try:
                    resp.release_conn()
                except Exception:
                    pass

        return _ObjectStream(resp, closer=_closer)
    return None


def delete_prefix(prefix: str) -> int:
    count = 0
    settings = get_settings()
    client = _minio_client()
    if client:
        try:
            from minio.deleteobjects import DeleteObject
        except Exception:
            DeleteObject = None  # type: ignore[misc, assignment]
        names: list[str] = []
        for obj in client.list_objects(settings.minio_bucket, prefix=prefix, recursive=True):
            names.append(obj.object_name)
            if DeleteObject is None:
                client.remove_object(settings.minio_bucket, obj.object_name)
                count += 1
                names.clear()
                continue
            if len(names) >= 1000:
                list(client.remove_objects(
                    settings.minio_bucket,
                    [DeleteObject(name) for name in names],
                ))
                count += len(names)
                names.clear()
        if names and DeleteObject is not None:
            list(client.remove_objects(
                settings.minio_bucket,
                [DeleteObject(name) for name in names],
            ))
            count += len(names)
        return count
    root = _local_root() / prefix.replace("/", os.sep)
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file():
                p.unlink()
                count += 1
    return count
