from __future__ import annotations
import argparse
from pathlib import Path
from app.db.session import SessionLocal, apply_firm_search_path
from app.services.artifact_export import build_catalog_export_for_job


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--job', required=True)
    ap.add_argument('--schema', default='firm_aetheris')
    ap.add_argument('--out', default='/app/data/artifacts_authoritative_v1_6.xlsx')
    args=ap.parse_args()
    with SessionLocal() as db:
        apply_firm_search_path(db,args.schema)
        data=build_catalog_export_for_job(db,args.job,job_label=args.job,authoritative_refresh=False)
        Path(args.out).parent.mkdir(parents=True,exist_ok=True)
        Path(args.out).write_bytes(data)
        print(f'Wrote {args.out} ({len(data)} bytes)')
    return 0
if __name__=='__main__':
    raise SystemExit(main())
