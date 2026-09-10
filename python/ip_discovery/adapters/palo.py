from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ip_discovery.models import Record
from ip_discovery.tokens import extract_tokens_from_text


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _gathered(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("gathered"), list):
            return [item for item in payload["gathered"] if isinstance(item, dict)]
        if "name" in payload or "value" in payload:
            return [payload]
    return []


def _op_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        stdout = payload.get("stdout") or payload.get("msg") or payload.get("xml") or ""
        if isinstance(stdout, list):
            return "\n".join(str(item) for item in stdout)
        return str(stdout)
    return str(payload)


def _as_values(*items: Any) -> tuple[str, ...]:
    values: list[str] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, (list, tuple)):
            values.extend(str(part) for part in item if part is not None)
        else:
            values.append(str(item))
    return tuple(value for value in values if value and str(value).lower() != "any")


def records_from_palo(device_dir: Path, device: str, platform: str) -> list[Record]:
    records: list[Record] = []

    for item in _gathered(_read_json(device_dir / "addresses.json")):
        name = str(item.get("name") or item.get("object_name") or "")
        value = item.get("value") or item.get("address") or item.get("ip_netmask")
        if not name:
            continue
        values = _as_values(value)
        records.append(
            Record(
                device=device,
                platform=platform,
                category="address_object",
                name=name,
                field="value",
                values=values,
                context={"type": item.get("address_type") or item.get("type")},
            )
        )

    for item in _gathered(_read_json(device_dir / "address_groups.json")):
        name = str(item.get("name") or "")
        members = item.get("static_value") or item.get("members") or item.get("static_members") or []
        records.append(
            Record(
                device=device,
                platform=platform,
                category="address_group",
                name=name,
                field="members",
                values=(),
                refs=tuple(str(member) for member in members),
                context={"description": item.get("description")},
            )
        )

    for item in _gathered(_read_json(device_dir / "security_rules.json")):
        name = str(item.get("name") or "")
        refs = _as_values(item.get("source_ip"), item.get("destination_ip"), item.get("source"), item.get("destination"))
        records.append(
            Record(
                device=device,
                platform=platform,
                category="security_rule",
                name=name,
                field="src/dst",
                values=(),
                refs=refs,
                context={
                    "from": item.get("from_zone") or item.get("from_zones"),
                    "to": item.get("to_zone") or item.get("to_zones"),
                    "action": item.get("action"),
                },
            )
        )

    for item in _gathered(_read_json(device_dir / "nat_rules.json")):
        name = str(item.get("name") or "")
        refs = _as_values(
            item.get("source_addresses"),
            item.get("destination_addresses"),
            item.get("source_translation_static_translated_address"),
            item.get("source_translation_translated_addresses"),
            item.get("destination_translated_address"),
            item.get("destination_dynamic_translated_address"),
        )
        records.append(
            Record(
                device=device,
                platform=platform,
                category="nat_rule",
                name=name,
                field="original/translated",
                values=(),
                refs=refs,
                context={
                    "nat_type": item.get("nat_type"),
                    "to_interface": item.get("to_interface"),
                },
            )
        )

    for item in _gathered(_read_json(device_dir / "ike_gateways.json")):
        name = str(item.get("name") or "")
        values = _as_values(
            item.get("peer_ip_value"),
            item.get("local_ip_address"),
            item.get("peer_ip"),
            item.get("interface_ip"),
        )
        records.append(
            Record(
                device=device,
                platform=platform,
                category="ike_gateway",
                name=name,
                field="local/peer",
                values=values,
                context={"peer_id": item.get("peer_id_value")},
            )
        )

    for item in _gathered(_read_json(device_dir / "ipsec_tunnels.json")):
        name = str(item.get("name") or "")
        values = _as_values(item.get("ak_local_ip") or item.get("local_ip"), item.get("ak_peer_ip") or item.get("peer_ip"))
        records.append(
            Record(
                device=device,
                platform=platform,
                category="ipsec_tunnel",
                name=name,
                field="endpoints",
                values=values,
                context={"ike_gtw_name": item.get("ak_ike_gateway") or item.get("ike_gtw_name")},
            )
        )

    for item in _gathered(_read_json(device_dir / "ipsec_proxyids.json")):
        name = str(item.get("name") or item.get("proxy_id") or "")
        values = _as_values(item.get("local"), item.get("remote"), item.get("local_ip"), item.get("remote_ip"))
        records.append(
            Record(
                device=device,
                platform=platform,
                category="ipsec_proxyid",
                name=name,
                field="local/remote",
                values=values,
                context={"tunnel": item.get("tunnel_name") or item.get("ipsec_tunnel")},
            )
        )

    running = _op_text(_read_json(device_dir / "running_config.json"))
    gp_idx = running.lower().find("global-protect")
    gp_text = running[gp_idx : gp_idx + 40000] if gp_idx >= 0 else ""
    gp_text += "\n" + _op_text(_read_json(device_dir / "op_gp_users.json"))
    for token in extract_tokens_from_text(gp_text):
        records.append(
            Record(
                device=device,
                platform=platform,
                category="globalprotect",
                name=token.raw,
                field="config/runtime",
                values=(token.raw,),
            )
        )

    for category, filename, field_name in (
        ("interface", "op_interfaces.json", "interface"),
        ("route", "op_routes.json", "route"),
        ("arp", "op_arp.json", "arp"),
    ):
        text = _op_text(_read_json(device_dir / filename))
        for token in extract_tokens_from_text(text):
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category=category,
                    name=token.raw,
                    field=field_name,
                    values=(token.raw,),
                )
            )
    return records
