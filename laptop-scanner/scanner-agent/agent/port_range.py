"""Greenbone port_range helpers."""

from __future__ import annotations


def _parse_protocol_tokens(port_range: str) -> list[tuple[str, str]]:
    """Parse GMP ``T:...`` / ``U:...`` groups while preserving protocol state."""
    raw = (port_range or "").strip()
    if not raw:
        return []
    current = "T"
    out: list[tuple[str, str]] = []
    for token in raw.split(","):
        piece = token.strip()
        if not piece:
            continue
        if len(piece) >= 2 and piece[1] == ":" and piece[0].upper() in {"T", "U"}:
            current = piece[0].upper()
            piece = piece[2:].strip()
        if piece:
            out.append((current, piece))
    return out


def _serialize_protocol_tokens(tokens: list[tuple[str, str]]) -> str:
    # GMP 22.x port_range syntax requires every comma-separated item to be
    # explicitly prefixed with T: or U:.
    return ",".join(
        f"{(proto.upper() if proto.upper() in {'T', 'U'} else 'T')}:{piece}"
        for proto, piece in tokens
    )


def _exclude_piece(piece: str, drop: set[int]) -> list[str]:
    if "-" in piece:
        left, right = piece.split("-", 1)
        try:
            lo, hi = int(left), int(right)
        except ValueError:
            return [piece]
        if lo > hi:
            lo, hi = hi, lo
        out: list[str] = []
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
            out.append(str(start) if start == end else f"{start}-{end}")
        return out
    try:
        port = int(piece)
    except ValueError:
        return [piece]
    return [] if port in drop else [piece]


def exclude_tcp_ports_from_range(port_range: str, exclude: set[int]) -> str:
    """Remove only TCP ports from a mixed Greenbone TCP/UDP port range."""
    drop = {int(p) for p in exclude if 1 <= int(p) <= 65535}
    raw = (port_range or "").strip()
    if not drop or not raw:
        return port_range

    parsed = _parse_protocol_tokens(raw)
    if not parsed:
        return port_range
    filtered: list[tuple[str, str]] = []
    for proto, piece in parsed:
        if proto == "U":
            filtered.append((proto, piece))
            continue
        for remaining in _exclude_piece(piece, drop):
            filtered.append((proto, remaining))

    return _serialize_protocol_tokens(filtered) if filtered else port_range
