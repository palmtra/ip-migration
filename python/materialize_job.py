#!/usr/bin/env python3
"""Write Ansible vars JSON from a customer job file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.job import load_job


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    job = load_job(args.job)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(job.ansible_vars(), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(job.ansible_vars()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
