from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ip_discovery.models import Record
from ip_discovery.tokens import parse_token


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _command_payloads(show_commands: dict[str, Any]) -> list[tuple[str, Any]]:
    invocation = (show_commands.get("invocation") or {}).get("module_args") or {}
    commands = invocation.get("commands") or show_commands.get("commands") or []
    stdout = show_commands.get("stdout") or []
    payloads: list[tuple[str, Any]] = []
    for index, output in enumerate(stdout):
        command = commands[index] if index < len(commands) else f"command_{index}"
        parsed: Any = output
        if isinstance(output, str):
            try:
                parsed = json.loads(output)
            except json.JSONDecodeError:
                parsed = output
        payloads.append((str(command), parsed))
    return payloads


def _payloads_for(show_commands: dict[str, Any], needle: str) -> list[Any]:
    found: list[Any] = []
    for command, payload in _command_payloads(show_commands):
        if needle in command.lower():
            found.append(payload)
    return found


def _payload_for(show_commands: dict[str, Any], needle: str) -> Any:
    payloads = _payloads_for(show_commands, needle)
    return payloads[0] if payloads else None


def records_from_arista(device_dir: Path, device: str, platform: str) -> list[Record]:
    records: list[Record] = []
    show_commands = _read_json(device_dir / "show_commands.json") or {}

    arp = _payload_for(show_commands, "show ip arp")
    neighbors = []
    if isinstance(arp, dict):
        neighbors = arp.get("ipV4Neighbors") or arp.get("ipv4Neighbors") or []
    for neighbor in neighbors:
        address = neighbor.get("address") or neighbor.get("ipAddress")
        if not parse_token(str(address or "")):
            continue
        iface = neighbor.get("interface") or neighbor.get("port") or "unknown"
        records.append(
            Record(
                device=device,
                platform=platform,
                category="arp",
                name=f"{iface}:{address}",
                field="address",
                values=(str(address),),
                context={
                    "mac": neighbor.get("hwAddress") or neighbor.get("macAddress"),
                    "interface": iface,
                },
            )
        )

    interfaces = _payload_for(show_commands, "show ip interface brief")
    iface_map = {}
    if isinstance(interfaces, dict):
        iface_map = interfaces.get("interfaces") or interfaces.get("ipInterfaces") or {}
    if isinstance(iface_map, dict):
        for name, data in iface_map.items():
            values = []
            if isinstance(data, dict):
                interface_addr = data.get("interfaceAddress") or data.get("ipv4Addr")
                if isinstance(interface_addr, dict):
                    addr = interface_addr.get("ipAddr") or interface_addr
                    if isinstance(addr, dict) and addr.get("address"):
                        prefix = addr.get("maskLen") or addr.get("masklen")
                        values.append(f"{addr['address']}/{prefix}" if prefix else addr["address"])
                address = data.get("address") or data.get("ipAddress")
                if address:
                    values.append(str(address))
            parsed = [value for value in values if parse_token(value)]
            if parsed:
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="interface",
                        name=name,
                        field="address",
                        values=tuple(parsed),
                    )
                )

    route_payloads = _payloads_for(show_commands, "show ip route")
    for routes in route_payloads:
        vrfs = []
        if isinstance(routes, dict):
            vrfs = [routes]
            if "vrfs" in routes and isinstance(routes["vrfs"], dict):
                vrfs = [
                    {**value, "vrfName": name} if isinstance(value, dict) else value
                    for name, value in routes["vrfs"].items()
                ]
        for vrf in vrfs:
            routes_map = vrf.get("routes") if isinstance(vrf, dict) else None
            if not isinstance(routes_map, dict):
                continue
            for prefix, data in routes_map.items():
                if not parse_token(prefix) and not str(prefix).endswith("/0"):
                    continue
                vias = (data or {}).get("vias") if isinstance(data, dict) else []
                next_hops = []
                if isinstance(vias, list):
                    for via in vias:
                        if not isinstance(via, dict):
                            continue
                        hop = via.get("nexthopAddr") or via.get("nexthop") or via.get("intAddr")
                        if hop:
                            next_hops.append(str(hop))
                values = []
                if parse_token(prefix):
                    values.append(prefix)
                values.extend(hop for hop in next_hops if parse_token(hop))
                if not values:
                    continue
                vrf_name = vrf.get("vrfName") if isinstance(vrf, dict) else None
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="route",
                        name=prefix,
                        field="prefix/nexthop",
                        values=tuple(values),
                        context={
                            "routeType": (data or {}).get("routeType") if isinstance(data, dict) else None,
                            "next_hops": next_hops,
                            "vrf": vrf_name,
                        },
                    )
                )

    acls = _payload_for(show_commands, "show ip access-lists")
    acl_map = acls.get("aclList") if isinstance(acls, dict) else None
    if isinstance(acl_map, list):
        for acl in acl_map:
            name = acl.get("name") or "unnamed"
            for sequence in acl.get("sequence") or acl.get("entries") or []:
                values = []
                for key in ("sourcePrefix", "destinationPrefix", "srcAddress", "dstAddress"):
                    if sequence.get(key):
                        values.append(str(sequence[key]))
                parsed = [value for value in values if parse_token(value)]
                if parsed:
                    records.append(
                        Record(
                            device=device,
                            platform=platform,
                            category="acl",
                            name=str(name),
                            field="ace",
                            values=tuple(parsed),
                            context={"sequence": sequence.get("sequenceNumber")},
                        )
                    )
    return records
