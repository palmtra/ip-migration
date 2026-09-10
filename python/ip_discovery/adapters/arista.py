from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ip_discovery.bgp import parse_running_config_bgp
from ip_discovery.models import Record
from ip_discovery.tokens import parse_token

IFACE_HEADER = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
IP_VIRTUAL = re.compile(r"^ip address virtual\s+(\S+)", re.IGNORECASE)
IP_ADDR = re.compile(r"^ip address\s+(\S+)", re.IGNORECASE)
IP_VR = re.compile(r"^ip virtual-router address\s+(\S+)", re.IGNORECASE)
IFACE_VRF = re.compile(r"^vrf\s+(?:forwarding\s+)?(\S+)", re.IGNORECASE)
IFACE_DESC = re.compile(r"^description\s+(.+)$", re.IGNORECASE)
VR_MAC = re.compile(r"^ip virtual-router mac-address\s+(\S+)", re.IGNORECASE)


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


def parse_eos_running_interfaces(text: str) -> list[dict[str, Any]]:
    """Parse SVI/physical IPs and VARP virtual IPs from EOS running-config."""
    items: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def close() -> None:
        nonlocal current
        if current and (current["addresses"] or current["virtual"]):
            items.append(current)
        current = None

    for raw in (text or "").splitlines():
        if raw.strip().startswith("!"):
            continue
        stripped = raw.strip()
        if not stripped:
            continue
        header = IFACE_HEADER.match(stripped)
        indented = bool(raw[:1].isspace())
        if header and not indented:
            close()
            current = {
                "name": header.group(1),
                "addresses": [],
                "virtual": [],
                "vrf": None,
                "description": None,
            }
            continue
        if current is not None and not indented:
            close()
        if current is None:
            continue
        virtual = IP_VIRTUAL.match(stripped)
        if virtual:
            current["virtual"].append(virtual.group(1))
            continue
        varp = IP_VR.match(stripped)
        if varp:
            current["virtual"].append(varp.group(1))
            continue
        addr = IP_ADDR.match(stripped)
        if addr:
            current["addresses"].append(addr.group(1))
            continue
        vrf = IFACE_VRF.match(stripped)
        if vrf:
            current["vrf"] = vrf.group(1)
            continue
        desc = IFACE_DESC.match(stripped)
        if desc:
            current["description"] = desc.group(1).strip()
    close()
    return items


def parse_eos_virtual_router_mac(text: str) -> str | None:
    for raw in (text or "").splitlines():
        match = VR_MAC.match(raw.strip())
        if match:
            return match.group(1)
    return None


def _varp_entries(payload: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return entries

    def add(iface: str | None, address: Any, extra: dict[str, Any] | None = None) -> None:
        if not address or not parse_token(str(address)):
            return
        item = {"interface": iface or "varp", "address": str(address)}
        if extra:
            item.update({key: value for key, value in extra.items() if value not in (None, "")})
        entries.append(item)

    routers = payload.get("virtualRouters") or payload.get("ipVirtualRouters") or payload.get("virtualRouter")
    if isinstance(routers, dict):
        for name, data in routers.items():
            if isinstance(data, dict):
                add(
                    data.get("interface") or data.get("ifName") or name,
                    data.get("address") or data.get("ipAddress") or data.get("virtualRouterIp") or data.get("virtualIp"),
                    {"mac": data.get("macAddress") or data.get("virtualMac")},
                )
            elif parse_token(str(data)):
                add(name, data, None)
    elif isinstance(routers, list):
        for data in routers:
            if not isinstance(data, dict):
                continue
            add(
                data.get("interface") or data.get("ifName") or data.get("name"),
                data.get("address") or data.get("ipAddress") or data.get("virtualRouterIp") or data.get("virtualIp"),
                {"mac": data.get("macAddress") or data.get("virtualMac")},
            )

    virtual_macs = payload.get("virtualMacs")
    if isinstance(virtual_macs, dict):
        for mac, data in virtual_macs.items():
            if not isinstance(data, dict):
                continue
            interfaces = data.get("interfaces") or data.get("ipInterfaces") or {}
            if isinstance(interfaces, dict):
                for name, iface in interfaces.items():
                    if isinstance(iface, dict):
                        add(name, iface.get("ipAddress") or iface.get("address") or iface.get("virtualIp"), {"mac": mac})
                    elif parse_token(str(iface)):
                        add(name, iface, {"mac": mac})
    return entries


def _mlag_context(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    config = payload.get("config") if isinstance(payload.get("config"), dict) else payload
    detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else {}
    merged = {**config, **detail, **payload}
    context = {
        "domain": merged.get("domainId") or merged.get("domain-id") or merged.get("domain"),
        "peer_address": merged.get("peerAddress") or merged.get("peerIp") or merged.get("peer-address"),
        "local_interface": merged.get("localInterface") or merged.get("local-interface"),
        "peer_link": merged.get("peerLink") or merged.get("peer-link"),
        "state": merged.get("state") or merged.get("mlagState"),
    }
    return {key: value for key, value in context.items() if value not in (None, "")}


def records_from_arista(device_dir: Path, device: str, platform: str) -> list[Record]:
    records: list[Record] = []
    show_commands = _read_json(device_dir / "show_commands.json") or {}

    arp_payloads = _payloads_for(show_commands, "show ip arp")
    for arp in arp_payloads:
        neighbor_rows = []
        if isinstance(arp, dict):
            neighbor_rows.extend(arp.get("ipV4Neighbors") or arp.get("ipv4Neighbors") or [])
            vrfs = arp.get("vrfs") if isinstance(arp.get("vrfs"), dict) else {}
            for vrf_name, vrf_data in vrfs.items():
                if not isinstance(vrf_data, dict):
                    continue
                for neighbor in vrf_data.get("ipV4Neighbors") or vrf_data.get("ipv4Neighbors") or []:
                    if isinstance(neighbor, dict):
                        neighbor_rows.append({**neighbor, "vrf": vrf_name})
        for neighbor in neighbor_rows:
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
                        "vrf": neighbor.get("vrf"),
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
    varp_payload = _payload_for(show_commands, "show ip virtual-router")
    for item in _varp_entries(varp_payload):
        records.append(
            Record(
                device=device,
                platform=platform,
                category="interface",
                name=str(item["interface"]),
                field="varp",
                values=(item["address"],),
                context={"virtual": True, "mac": item.get("mac"), "role": "varp"},
            )
        )

    mlag_payload = _payload_for(show_commands, "show mlag")
    mlag_ctx = _mlag_context(mlag_payload)
    peer = mlag_ctx.get("peer_address")
    if peer and parse_token(str(peer)):
        records.append(
            Record(
                device=device,
                platform=platform,
                category="mlag",
                name=str(mlag_ctx.get("domain") or "mlag"),
                field="peer-address",
                values=(str(peer),),
                context=mlag_ctx,
            )
        )

    running = _payload_for(show_commands, "show running-config")
    running_text = running if isinstance(running, str) else json.dumps(running or "")
    vr_mac = parse_eos_virtual_router_mac(running_text)
    for iface in parse_eos_running_interfaces(running_text):
        physical = [value for value in iface["addresses"] if parse_token(value)]
        if physical:
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="interface",
                    name=iface["name"],
                    field="address",
                    values=tuple(physical),
                    context={
                        "vrf": iface.get("vrf"),
                        "description": iface.get("description"),
                        "source": "running-config",
                    },
                )
            )
        virtual = [value for value in iface["virtual"] if parse_token(value)]
        if virtual:
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="interface",
                    name=iface["name"],
                    field="varp",
                    values=tuple(virtual),
                    context={
                        "vrf": iface.get("vrf"),
                        "description": iface.get("description"),
                        "virtual": True,
                        "role": "varp",
                        "mac": vr_mac,
                    },
                )
            )
    advertisements, neighbors = parse_running_config_bgp(running_text)
    for item in advertisements:
        records.append(
            Record(
                device=device,
                platform=platform,
                category="bgp_advertisement",
                name=f"{item.vrf}:{item.prefix}",
                field="network",
                values=(item.prefix,),
                context={"asn": item.asn, "vrf": item.vrf},
            )
        )
    for item in neighbors:
        records.append(
            Record(
                device=device,
                platform=platform,
                category="bgp_neighbor",
                name=f"{item.vrf}:{item.peer}",
                field="peer",
                values=(item.peer,),
                context={"asn": item.asn, "vrf": item.vrf, "remote_as": item.remote_as},
            )
        )
    return records
