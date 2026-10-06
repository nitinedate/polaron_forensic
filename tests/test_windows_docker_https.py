"""Certificate and hostname verification for the Windows deployment helpers."""

from __future__ import annotations

import datetime as dt
import importlib.util
import ipaddress
from pathlib import Path
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_https", ROOT / "script_docker/public_https.py"
)
https = importlib.util.module_from_spec(spec)
spec.loader.exec_module(https)


def make_certificates(
    path: Path, identity="8.8.8.8", expired=False, self_signed=False, san=True
):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Offline deployment test CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=3))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
    issuer = name if self_signed else ca_name
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=-1 if expired else 6))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    if san:
        try:
            value = x509.IPAddress(ipaddress.ip_address(identity))
        except ValueError:
            value = x509.DNSName(identity)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([value]), critical=False
        )
    cert = builder.sign(leaf_key if self_signed else ca_key, hashes.SHA256())
    path.mkdir(parents=True, exist_ok=True)
    (path / "fullchain.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + ca.public_bytes(serialization.Encoding.PEM)
    )
    (path / "privkey.pem").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return path


def lineage(tmp_path, identity="8.8.8.8", **kwargs):
    name = (
        "aetheris-ip-8.8.8.8"
        if identity == "8.8.8.8"
        else "aetheris-domain-example.org"
    )
    certs = make_certificates(tmp_path / "live" / name, identity, **kwargs)
    (tmp_path / "renewal").mkdir(exist_ok=True)
    (tmp_path / "renewal" / f"{name}.conf").write_text(
        f"version = 5.8.0\n[renewalparams]\nserver = {https.ACME_SERVER}\nauthenticator = webroot\n"
    )
    return name, certs


@pytest.mark.parametrize("identity", ["8.8.8.8", "example.org"])
def test_matching_san_key_and_managed_lineage_accepted(tmp_path, identity):
    name, _ = lineage(tmp_path, identity)
    assert https.inspect_certificate(tmp_path, name, identity)["valid"] is True


def test_ip_san_is_not_a_dns_name(tmp_path):
    name, _ = lineage(tmp_path, "example.org")
    assert (
        https.inspect_certificate(tmp_path, name, "8.8.8.8")["reason"] == "san_mismatch"
    )


def test_wrong_identity_rejected(tmp_path):
    name, _ = lineage(tmp_path)
    assert (
        https.inspect_certificate(tmp_path, name, "8.8.4.4")["reason"] == "san_mismatch"
    )


def test_expired_certificate_is_managed_but_invalid(tmp_path):
    name, _ = lineage(tmp_path, expired=True)
    result = https.inspect_certificate(tmp_path, name, "8.8.8.8")
    assert result["managed"] and not result["valid"]


def test_self_signed_certificate_is_not_trusted_intake(tmp_path):
    name, _ = lineage(tmp_path, self_signed=True)
    assert (
        https.inspect_certificate(tmp_path, name, "8.8.8.8")["reason"] == "self_signed"
    )


def test_key_mismatch_rejected(tmp_path):
    name, certs = lineage(tmp_path)
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (certs / "privkey.pem").write_bytes(
        replacement.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    assert (
        https.inspect_certificate(tmp_path, name, "8.8.8.8")["reason"] == "key_mismatch"
    )


def test_staging_lineage_rejected(tmp_path):
    name, _ = lineage(tmp_path)
    p = tmp_path / "renewal" / f"{name}.conf"
    p.write_text(
        p.read_text().replace(
            https.ACME_SERVER, "https://acme-staging-v02.api.letsencrypt.org/directory"
        )
    )
    assert (
        https.inspect_certificate(tmp_path, name, "8.8.8.8")["reason"]
        == "not_production_acme"
    )


def test_existing_pem_without_acme_metadata_is_not_reused(tmp_path):
    make_certificates(tmp_path / "live" / "aetheris-ip-8.8.8.8")
    assert not https.inspect_certificate(tmp_path, "aetheris-ip-8.8.8.8", "8.8.8.8")[
        "managed"
    ]


@pytest.mark.parametrize("name", ["../other", "a;touch", "a/b", ""])
def test_certificate_path_traversal_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        https.inspect_certificate(tmp_path, name, "8.8.8.8")


def start_tls(path, response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(path / "fullchain.pem"), str(path / "privkey.pem"))
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = server.getsockname()[1]

    def serve():
        try:
            with server.accept()[0] as raw:
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(4096)
                    tls.sendall(response)
        except (OSError, ssl.SSLError):
            pass
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


@pytest.mark.parametrize("identity", ["8.8.8.8", "example.org"])
def test_probe_verifies_public_identity_over_local_connection(tmp_path, identity):
    path = make_certificates(tmp_path, identity)
    port, thread = start_tls(path)
    try:
        result = https.probe_https(identity, "127.0.0.1", port, str(path / "ca.pem"))
        assert result["trusted"] and result["http_status"] == 200
    finally:
        thread.join(5)


def test_probe_rejects_name_mismatch(tmp_path):
    path = make_certificates(tmp_path)
    port, thread = start_tls(path)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            https.probe_https("8.8.4.4", "127.0.0.1", port, str(path / "ca.pem"))
    finally:
        thread.join(5)


def test_probe_rejects_untrusted_certificate(tmp_path):
    path = make_certificates(tmp_path)
    port, thread = start_tls(path)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            https.probe_https("8.8.8.8", "127.0.0.1", port)
    finally:
        thread.join(5)


def test_probe_checks_http_status_after_tls(tmp_path):
    path = make_certificates(tmp_path)
    port, thread = start_tls(
        path, b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"
    )
    try:
        with pytest.raises(ValueError):
            https.probe_https("8.8.8.8", "127.0.0.1", port, str(path / "ca.pem"))
    finally:
        thread.join(5)


@pytest.mark.parametrize("path", ["health", "/health\r\nHost: injected"])
def test_probe_rejects_invalid_request_paths(path):
    with pytest.raises(ValueError):
        https.probe_https("8.8.8.8", "127.0.0.1", path=path)


def test_probe_can_verify_proxied_health_path(tmp_path):
    certs = make_certificates(tmp_path)
    port, thread = start_tls(certs)
    try:
        assert (
            https.probe_https(
                "8.8.8.8", "127.0.0.1", port, str(certs / "ca.pem"), path="/health"
            )["http_status"]
            == 200
        )
    finally:
        thread.join(5)
