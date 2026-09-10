#!/usr/bin/env python3
"""Parse VRF, vsys, or Panorama serials from CLI/API text (used by Ansible collection)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_discovery.discover import parse_panorama_devices, parse_vrf_names, parse_vsys_names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["vrfs", "vsys", "serials"])
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
    if args.kind == "vrfs":
        payload = parse_vrf_names(text)
    elif args.kind == "vsys":
        payload = parse_vsys_names(text)
    else:
        payload = parse_panorama_devices(text)
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
