#!/usr/bin/env python3
"""Create vars/search/<id>-<site>-<customer>.yml for one customer job."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.search_job import search_filename


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="Customer or ticket ID")
    parser.add_argument("--site", required=True, help="Data centre / site")
    parser.add_argument("--customer", required=True, help="Customer name")
    parser.add_argument("--cidr", action="append", dest="cidrs", required=True, help="Search CIDR (repeatable)")
    parser.add_argument("--dir", type=Path, default=Path(__file__).resolve().parent.parent / "vars" / "search")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if yaml is None:
        raise SystemExit("PyYAML is required")

    filename = search_filename(args.id, args.site, args.customer)
    path = args.dir / filename
    args.dir.mkdir(parents=True, exist_ok=True)
    if path.exists() and not args.force:
        raise SystemExit(f"{path} already exists (use --force to overwrite)")

    payload = {
        "search_targets": args.cidrs,
        "customer": args.customer,
        "id": args.id,
        "site": args.site,
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    stem = path.stem
    print(path)
    print(f"Run with: -e search_job={stem}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
