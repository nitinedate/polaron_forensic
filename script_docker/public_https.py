"""Small certificate checks run inside the pinned Certbot container.

No Python installation or Windows TLS/Schannel configuration is required on
the deployment host. This helper never outputs private keys or certificates.
"""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ACME_SERVER = "https://acme-v02.api.letsencrypt.org/directory"


def inspect_certificate(directory: Path, name: str, identity: str) -> dict:
    """Require an ACME-managed lineage, matching SAN/key, and a valid lifetime."""
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in name):
        raise ValueError("Invalid certificate name")
    live = directory / "live" / name
    renewal = directory / "renewal" / f"{name}.conf"
    if not (live / "fullchain.pem").is_file() or not renewal.is_file():
        return {"managed": False, "valid": False, "reason": "missing_acme_lineage"}
    parser = configparser.ConfigParser()
    # Certbot renewal files have unsectioned defaults before [renewalparams].
    parser.read_string("[DEFAULT]\n" + renewal.read_text())
    if parser.get("renewalparams", "server", fallback="") != ACME_SERVER:
        return {"managed": False, "valid": False, "reason": "not_production_acme"}
    cert = x509.load_pem_x509_certificate((live / "fullchain.pem").read_bytes())
    key = serialization.load_pem_private_key((live / "privkey.pem").read_bytes(), None)

    def public(obj):
        return obj.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    if public(cert) != public(key):
        return {"managed": True, "valid": False, "reason": "key_mismatch"}
    if cert.issuer == cert.subject:
        return {"managed": False, "valid": False, "reason": "self_signed"}
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        address = ipaddress.ip_address(identity)
    except ValueError:
        matches = identity.lower() in [
            x.lower() for x in sans.get_values_for_type(x509.DNSName)
        ]
    else:
        matches = address in sans.get_values_for_type(x509.IPAddress)
    now = dt.datetime.now(dt.timezone.utc)
    if not matches:
        return {"managed": True, "valid": False, "reason": "san_mismatch"}
    valid = cert.not_valid_before_utc <= now < cert.not_valid_after_utc
    return {
        "managed": True,
        "valid": valid,
        "reason": "ok" if valid else "expired_or_not_yet_valid",
        "expires_utc": cert.not_valid_after_utc.isoformat(),
    }


def probe_https(
    identity: str,
    connect_to: str,
    port: int = 443,
    cafile: str | None = None,
    path: str = "/",
) -> dict:
    """Connect locally while verifying the public IP/domain against trusted roots."""
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("Invalid probe path")
    context = ssl.create_default_context(cafile=cafile)
    with socket.create_connection((connect_to, port), timeout=20) as raw:
        with context.wrap_socket(raw, server_hostname=identity) as tls:
            tls.settimeout(20)
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {identity}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            response = b""
            while b"\r\n" not in response and len(response) < 8192:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                response += chunk
            status = response.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                raise ValueError("The verified HTTPS gateway did not return HTTP 200")
            return {
                "trusted": True,
                "identity": identity,
                "http_status": 200,
                "tls": tls.version(),
            }


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--directory", type=Path, default=Path("/etc/letsencrypt"))
    inspect.add_argument("--name", required=True)
    inspect.add_argument("--identity", required=True)
    probe = commands.add_parser("probe")
    probe.add_argument("--identity", required=True)
    probe.add_argument("--connect-to", default="host.docker.internal")
    probe.add_argument("--port", type=int, default=443)
    probe.add_argument("--path", default="/")
    challenge = commands.add_parser("challenge")
    challenge.add_argument("--directory", type=Path, default=Path("/var/www/certbot"))
    challenge.add_argument("--token", required=True)
    challenge.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect_certificate(args.directory, args.name, args.identity)
        elif args.command == "probe":
            result = probe_https(
                args.identity, args.connect_to, args.port, path=args.path
            )
        else:
            if not re.fullmatch(r"[a-f0-9]{32}", args.token):
                raise ValueError("Invalid challenge token")
            path = args.directory / ".well-known" / "acme-challenge" / args.token
            if args.remove:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(args.token)
            result = {"challenge_ready": not args.remove}
        print(json.dumps(result))
        return 0
    except (
        OSError,
        ValueError,
        ssl.SSLError,
        x509.ExtensionNotFound,
        configparser.Error,
    ) as exc:
        if args.command == "inspect":
            print(
                json.dumps(
                    {"managed": False, "valid": False, "reason": type(exc).__name__}
                )
            )
            return 0
        print(json.dumps({"trusted": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
