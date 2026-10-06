#!/usr/bin/env python3
"""Read-only sequential source benchmark for forensic disk SLO preflight."""
from __future__ import annotations

import argparse
import hashlib
import os
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="E01/raw/segment file to read sequentially (never modified)")
    ap.add_argument("--sample-gb", type=float, default=5.0)
    ap.add_argument("--block-mib", type=int, default=8)
    ap.add_argument("--sha256", action="store_true", help="also hash sampled bytes")
    args = ap.parse_args()

    path = Path(args.path)
    if not path.is_file():
        raise SystemExit(f"Not a file: {path}")
    limit = min(path.stat().st_size, int(args.sample_gb * 1024**3))
    block = max(args.block_mib, 1) * 1024**2
    done = 0
    h = hashlib.sha256() if args.sha256 else None
    start = time.perf_counter()
    with path.open("rb", buffering=0) as fh:
        while done < limit:
            data = fh.read(min(block, limit - done))
            if not data:
                break
            done += len(data)
            if h:
                h.update(data)
    elapsed = max(time.perf_counter() - start, 1e-9)
    mib_s = done / 1024**2 / elapsed
    print(f"path={path}")
    print(f"sample_gib={done / 1024**3:.2f}")
    print(f"elapsed_sec={elapsed:.2f}")
    print(f"sequential_mib_s={mib_s:.2f}")
    print(f"50GB_30min_raw_floor={'PASS' if mib_s >= 28 else 'FAIL'} (needs ~28 MB/s + overhead margin)")
    print(f"500GB_3h_raw_floor={'PASS' if mib_s >= 47 else 'FAIL'} (needs ~46 MB/s + overhead margin)")
    if h:
        print(f"sample_sha256={h.hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
