#!/usr/bin/env python3
"""Match collected device artifacts against subnet/host search targets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.engine import find_hits
from ip_discovery.load import load_all_records
from ip_discovery.report import write_target_reports


def _load_search(path: Path) -> tuple[list[str], dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yml", ".yaml"}:
        if yaml is None:
            raise SystemExit("PyYAML is required to read search YAML")
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    targets = [str(item) for item in (data.get("search_targets") or [])]
    if not targets and data.get("subnet"):
        targets = [str(data["subnet"])]
    labels = {
        "customer": str(data.get("customer") or ""),
        "id": str(data.get("id") or ""),
        "site": str(data.get("site") or ""),
    }
    return targets, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--search", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    targets, labels = _load_search(args.search)
    if not targets:
        raise SystemExit("No search_targets found in search file")

    records = load_all_records(args.artifacts)
    hits = find_hits(records, targets)
    by_target = write_target_reports(hits, targets, args.out, labels=labels)
    print(f"records={len(records)} hits={len(hits)}")
    for target, paths in by_target.items():
        print(f"{target}:")
        for kind, path in paths.items():
            print(f"  {kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
