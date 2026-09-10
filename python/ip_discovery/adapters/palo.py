from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ip_discovery.models import Record
from ip_discovery.routes import parse_palo_routes
from ip_discovery.tokens import extract_tokens_from_text, parse_token

PALO_ARP_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<mac>(?:[0-9a-fA-F]{2}[:.-]){5}[0-9a-fA-F]{2})\s+(?P<iface>\S+)"
)
_SCOPE_KEYS = (
    "shared",
    "location",
    "device_group",
    "template",
    "template_stack",
    "rulebase",
    "vsys",
    "serial",
    "hostname",
    "firewall",
)


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
        if "name" in payload or "value" in payload or "if_name" in payload:
            return [payload]
    return []


def _op_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list):
        return "\n".join(_op_text(item) for item in payload)
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return "\n".join(_op_text(item) for item in payload["results"])
        stdout = payload.get("stdout") or payload.get("msg") or payload.get("xml") or payload.get("stdout_xml") or ""
        if isinstance(stdout, list):
            return "\n".join(str(item) for item in stdout)
        return str(stdout) if stdout else ""
    return str(payload)


def _iter_op_results(payload: Any) -> list[tuple[dict[str, Any], str]]:
    if payload is None:
        return []
    if isinstance(payload, dict) and isinstance(payload.get("results"), list) and payload["results"]:
        sections: list[tuple[dict[str, Any], str]] = []
        for item in payload["results"]:
            if not isinstance(item, dict):
                sections.append(({}, _op_text(item)))
                continue
            meta = {
                key: item[key]
                for key in _SCOPE_KEYS
                if item.get(key) not in (None, "", [], {})
            }
            sections.append((meta, _op_text(item)))
        return sections
    return [({}, _op_text(payload))]


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


def _clean(context: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in context.items() if value not in (None, "", [], {})}


def _scope_context(item: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    location = item.get("location")
    shared = item.get("shared")
    if shared is None and location is not None:
        shared = location == "shared"
    context: dict[str, Any] = {}
    if shared is not None:
        context["shared"] = bool(shared)
    for key in _SCOPE_KEYS:
        if key == "shared":
            continue
        value = item.get(key)
        if value not in (None, "", [], {}):
            context[key] = value
    if extra:
        context.update(extra)
    return _clean(context)


def records_from_palo(device_dir: Path, device: str, platform: str) -> list[Record]:
    records: list[Record] = []

    for item in _gathered(_read_json(device_dir / "addresses.json")):
        name = str(item.get("name") or item.get("object_name") or "")
        value = item.get("value") or item.get("address") or item.get("ip_netmask")
        if not name:
            continue
        records.append(
            Record(
                device=device,
                platform=platform,
                category="address_object",
                name=name,
                field="value",
                values=_as_values(value),
                context=_scope_context(item, {"type": item.get("address_type") or item.get("type")}),
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
                context=_scope_context(item, {"description": item.get("description")}),
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
                context=_scope_context(
                    item,
                    {
                        "from": item.get("from_zone") or item.get("from_zones"),
                        "to": item.get("to_zone") or item.get("to_zones"),
                        "action": item.get("action"),
                    },
                ),
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
                context=_scope_context(
                    item,
                    {
                        "nat_type": item.get("nat_type"),
                        "to_interface": item.get("to_interface"),
                    },
                ),
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
                context=_scope_context(item, {"peer_id": item.get("peer_id_value")}),
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
                context=_scope_context(item, {"ike_gtw_name": item.get("ak_ike_gateway") or item.get("ike_gtw_name")}),
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
                context=_scope_context(item, {"tunnel": item.get("tunnel_name") or item.get("ipsec_tunnel")}),
            )
        )

    for item in _gathered(_read_json(device_dir / "virtual_routers.json")):
        name = str(item.get("name") or "")
        values = _as_values(item.get("interface") or item.get("interfaces"))
        if name:
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="virtual_router",
                    name=name,
                    field="name",
                    values=(),
                    refs=tuple(str(part) for part in values),
                    context=_scope_context(item, {"interfaces": item.get("interface") or item.get("interfaces")}),
                )
            )

    for item in _gathered(_read_json(device_dir / "static_routes.json")):
        name = str(item.get("name") or item.get("destination") or "")
        values = _as_values(
            item.get("destination"),
            item.get("nexthop"),
            item.get("nexthop_ip"),
            item.get("interface"),
        )
        records.append(
            Record(
                device=device,
                platform=platform,
                category="route",
                name=name,
                field="static",
                values=values,
                context=_scope_context(
                    item,
                    {
                        "vr": item.get("vr_name") or item.get("virtual_router"),
                        "nexthop_type": item.get("nexthop_type"),
                    },
                ),
            )
        )

    for item in _gathered(_read_json(device_dir / "interfaces.json")):
        name = str(item.get("name") or item.get("if_name") or "")
        values = _as_values(item.get("ip") or item.get("ip_address") or item.get("ipv4"))
        if not name or not values:
            continue
        records.append(
            Record(
                device=device,
                platform=platform,
                category="interface",
                name=name,
                field="address",
                values=values,
                context=_scope_context(
                    item,
                    {
                        "comment": item.get("comment") or item.get("description"),
                        "zone": item.get("zone_name") or item.get("zone"),
                        "vr": item.get("vr_name"),
                    },
                ),
            )
        )

    running = _op_text(_read_json(device_dir / "running_config.json"))
    gp_idx = running.lower().find("global-protect")
    gp_text = running[gp_idx : gp_idx + 40000] if gp_idx >= 0 else ""
    gp_meta: dict[str, Any] = {}
    for meta, text in _iter_op_results(_read_json(device_dir / "op_gp_users.json")):
        gp_text += "\n" + text
        gp_meta.update(meta)
    for token in extract_tokens_from_text(gp_text):
        records.append(
            Record(
                device=device,
                platform=platform,
                category="globalprotect",
                name=token.raw,
                field="config/runtime",
                values=(token.raw,),
                context=_scope_context(gp_meta),
            )
        )

    for meta, iface_text in _iter_op_results(_read_json(device_dir / "op_interfaces.json")):
        for token in extract_tokens_from_text(iface_text):
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="interface",
                    name=token.raw,
                    field="interface",
                    values=(token.raw,),
                    context=_scope_context(meta),
                )
            )

    for meta, arp_text in _iter_op_results(_read_json(device_dir / "op_arp.json")):
        arp_matches = list(PALO_ARP_RE.finditer(arp_text))
        if arp_matches:
            for match in arp_matches:
                ip_addr = match.group("ip")
                if not parse_token(ip_addr):
                    continue
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="arp",
                        name=f"{match.group('iface')}:{ip_addr}",
                        field="address",
                        values=(ip_addr,),
                        context=_scope_context(
                            meta,
                            {"mac": match.group("mac"), "interface": match.group("iface")},
                        ),
                    )
                )
        else:
            for token in extract_tokens_from_text(arp_text):
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="arp",
                        name=token.raw,
                        field="arp",
                        values=(token.raw,),
                        context=_scope_context(meta),
                    )
                )

    for filename in ("op_routes.json", "op_fib.json", "op_route_destination.json"):
        payload = _read_json(device_dir / filename)
        for meta, text in _iter_op_results(payload):
            parsed = parse_palo_routes(text)
            if parsed:
                for route in parsed:
                    values = route.match_values()
                    if not values:
                        continue
                    records.append(
                        Record(
                            device=device,
                            platform=platform,
                            category="route",
                            name=route.prefix,
                            field="prefix/nexthop",
                            values=values,
                            context=_scope_context(
                                meta,
                                {
                                    "protocol": route.protocol,
                                    "next_hop": route.next_hop,
                                    "interface": route.interface,
                                    "vrf": route.vrf,
                                    "flags": route.flags,
                                    "metric": route.metric,
                                    "source": filename,
                                },
                            ),
                        )
                    )
                continue
            for token in extract_tokens_from_text(text):
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="route",
                        name=token.raw,
                        field="route",
                        values=(token.raw,),
                        context=_scope_context(meta, {"source": filename}),
                    )
                )

    for meta, bgp_text in _iter_op_results(_read_json(device_dir / "op_bgp_peers.json")):
        for token in extract_tokens_from_text(bgp_text):
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="bgp_neighbor",
                    name=token.raw,
                    field="peer",
                    values=(token.raw,),
                    context=_scope_context(meta),
                )
            )
    return records
