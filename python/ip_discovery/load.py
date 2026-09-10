from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ip_discovery.adapters.arista import records_from_arista
from ip_discovery.adapters.cisco import records_from_cisco
from ip_discovery.adapters.palo import records_from_palo
from ip_discovery.models import Record


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_device_records(device_dir: Path) -> list[Record]:
    meta = read_json(device_dir / "meta.json") or {}
    device = meta.get("device") or device_dir.name
    platform = str(meta.get("platform") or meta.get("vendor") or "")
    vendor = str(meta.get("vendor") or "").lower()

    if vendor == "paloalto" or "palo" in platform.lower():
        return records_from_palo(device_dir, device, platform or "paloalto.panos")
    if vendor == "arista" or "eos" in platform.lower():
        return records_from_arista(device_dir, device, platform or "arista.eos.eos")
    return records_from_cisco(device_dir, device, platform or "cisco")


def load_all_records(artifacts_dir: Path) -> list[Record]:
    records: list[Record] = []
    if not artifacts_dir.exists():
        return records
    for child in sorted(artifacts_dir.iterdir()):
        if child.is_dir() and (child / "meta.json").exists():
            records.extend(load_device_records(child))
    return records
