#!/usr/bin/env python3
"""Build a known-good hash index from an NSRL RDS export (or any hash list).

    # NSRL RDS 2.x CSV
    python scripts/build_known_good_index.py /rds/NSRLFile.txt \
        --out /evidence/reference/nsrl_sha1.hgi --algorithm sha1

    # NSRL RDS 3.x SQLite
    python scripts/build_known_good_index.py /rds/rds_modern.db \
        --out /evidence/reference/nsrl_sha256.hgi --algorithm sha256

    # Several sources at once (RDS plus the lab's own vendor baseline)
    python scripts/build_known_good_index.py /rds/NSRLFile.txt /lab/baseline.txt \
        --out /evidence/reference/known_good.hgi

Then point the extraction pipeline at it:

    export FORENSIC_KNOWN_GOOD_INDEX=/evidence/reference/nsrl_sha1.hgi

Build once per RDS release. The index is read-only at query time and safe to
share across workers and containers.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.extract_known_good import (  # noqa: E402
    DIGEST_LENGTHS,
    KnownGoodError,
    KnownGoodIndex,
    build_index,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a memory-mapped known-good hash index.")
    parser.add_argument("sources", nargs="+",
                        help="RDS file(s), SQLite database(s), hash list(s) or directory.")
    parser.add_argument("--out", required=True, help="Destination .hgi index path.")
    parser.add_argument("--algorithm", default="sha1", choices=sorted(DIGEST_LENGTHS),
                        help="Digest column to extract (default: sha1).")
    parser.add_argument("--verify", action="store_true",
                        help="Re-open the index and spot-check membership after building.")
    args = parser.parse_args()

    started = time.time()
    last = [started]

    def on_progress(read: int, unique: int) -> None:
        now = time.time()
        rate = read / max(now - started, 0.001)
        print(f"  read {read:,} digests · {unique:,} unique · {rate:,.0f}/s", flush=True)
        last[0] = now

    print(f"Building {args.algorithm} index from {len(args.sources)} source(s)…")
    try:
        stats = build_index(
            args.sources, args.out, algorithm=args.algorithm, on_progress=on_progress)
    except KnownGoodError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    elapsed = time.time() - started
    duplicates = stats.read - stats.unique
    print()
    print(f"algorithm      : {stats.algorithm}")
    print(f"digests read   : {stats.read:,}")
    print(f"unique digests : {stats.unique:,} ({duplicates:,} duplicates collapsed)")
    print(f"index          : {stats.output}")
    print(f"index size     : {stats.bytes_written / (1024 ** 2):,.1f} MiB")
    print(f"build time     : {elapsed:,.1f}s")

    if args.verify:
        print("\nverifying…")
        with KnownGoodIndex(args.out) as index:
            if len(index) != stats.unique:
                print(f"  FAIL: index reports {len(index)} digests, expected {stats.unique}",
                      file=sys.stderr)
                return 1
            # A digest that is present must be found; a well-known absent one must not be.
            absent = "f" * (index.digest_len * 2)
            if index.contains(absent):
                print("  FAIL: an all-f digest was reported present", file=sys.stderr)
                return 1
            print(f"  OK: {len(index):,} digests, membership test behaves correctly")

    print("\nNext step:")
    print(f"  export FORENSIC_KNOWN_GOOD_INDEX={stats.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
