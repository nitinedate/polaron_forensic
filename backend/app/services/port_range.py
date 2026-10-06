"""Greenbone port_range helpers."""

from __future__ import annotations


def exclude_tcp_ports_from_range(port_range: str, exclude: set[int]) -> str:
    """Remove TCP ports from a Greenbone port_range string (singles and ranges)."""
    drop = {int(p) for p in exclude if 1 <= int(p) <= 65535}
    raw = (port_range or "").strip()
    if not drop or not raw:
        return port_range

    prefix = ""
    body = raw
    if body[:2].upper() in {"T:", "U:"}:
        prefix = body[:2]
        body = body[2:]

    out: list[str] = []
    for token in body.split(","):
        token = token.strip()
        if not token:
            continue
        proto = ""
        piece = token
        if piece[:2].upper() in {"T:", "U:"}:
            proto = piece[:2]
            piece = piece[2:]
        if "-" in piece:
            left, right = piece.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                out.append(token)
                continue
            if lo > hi:
                lo, hi = hi, lo
            cursor = lo
            while cursor <= hi:
                while cursor <= hi and cursor in drop:
                    cursor += 1
                if cursor > hi:
                    break
                start = cursor
                while cursor <= hi and cursor not in drop:
                    cursor += 1
                end = cursor - 1
                span = str(start) if start == end else f"{start}-{end}"
                out.append(f"{proto}{span}" if proto else span)
        else:
            try:
                port = int(piece)
            except ValueError:
                out.append(token)
                continue
            if port not in drop:
                out.append(token)

    if not out:
        return port_range
    joined = ",".join(out)
    if prefix and not joined.upper().startswith(("T:", "U:")):
        joined = prefix + joined
    return joined
