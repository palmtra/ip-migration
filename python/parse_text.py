#!/usr/bin/env python3
"""Parse VRF or vsys names from CLI/API text (used by Ansible collection)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.discover import parse_vrf_names, parse_vsys_names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["vrfs", "vsys"])
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
    names = parse_vrf_names(text) if args.kind == "vrfs" else parse_vsys_names(text)
    json.dump(names, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
