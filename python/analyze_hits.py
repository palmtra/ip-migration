#!/usr/bin/env python3
"""Match collected device artifacts against subnet/host search targets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.engine import find_hits
from ip_discovery.job import load_job
from ip_discovery.load import load_all_records
from ip_discovery.report import write_reports


def _load_search(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yml", ".yaml"}:
        if yaml is None:
            raise SystemExit("PyYAML is required to read search YAML")
        data = yaml.safe_load(text) or {}
        return [str(item) for item in data.get("search_targets") or []]
    import json

    data = json.loads(text)
    return [str(item) for item in data.get("search_targets") or []]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--search", type=Path)
    parser.add_argument("--job", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    job = load_job(args.job) if args.job else None
    if job:
        targets = job.search_targets
    elif args.search:
        targets = _load_search(args.search)
    else:
        raise SystemExit("Provide --job or --search")
    if not targets:
        raise SystemExit("No search targets found")

    records = load_all_records(args.artifacts)
    hits = find_hits(records, targets)
    paths = write_reports(hits, targets, args.out, job=job)
    print(f"records={len(records)} hits={len(hits)}")
    for kind, path in paths.items():
        print(f"{kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
