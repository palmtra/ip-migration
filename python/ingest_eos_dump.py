#!/usr/bin/env python3
"""Turn EOS running-config + CLI dump files into collection artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.eos_dump import write_eos_dump_artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dumps", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for dump in args.dumps:
        device_dir = write_eos_dump_artifact(dump, args.out)
        print(device_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
