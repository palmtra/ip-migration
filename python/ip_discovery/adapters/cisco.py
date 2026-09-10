from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ip_discovery.models import Record
from ip_discovery.routes import parse_ios_routes
from ip_discovery.tokens import parse_token

ARP_RE = re.compile(
    r"Internet\s+(\S+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)",
    re.IGNORECASE,
)
IFACE_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
    re.MULTILINE,
)
ACL_HOST_RE = re.compile(r"host\s+(\S+)", re.IGNORECASE)
ACL_NET_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
)


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _command_outputs(show_commands: dict[str, Any]) -> list[tuple[str, str]]:
    if not show_commands:
        return []
    invocation = (show_commands.get("invocation") or {}).get("module_args") or {}
    commands = invocation.get("commands") or show_commands.get("commands") or []
    stdout = show_commands.get("stdout") or []
    pairs: list[tuple[str, str]] = []
    for index, output in enumerate(stdout):
        command = commands[index] if index < len(commands) else f"command_{index}"
        pairs.append((str(command), output if isinstance(output, str) else json.dumps(output)))
    return pairs


def _load_show_files(device_dir: Path) -> dict[str, Any]:
    merged_commands: list[str] = []
    merged_stdout: list[str] = []
    for name in ("show_commands.json", "show_vrf_commands.json"):
        payload = _read_json(device_dir / name) or {}
        for command, output in _command_outputs(payload):
            merged_commands.append(command)
            merged_stdout.append(output)
    return {
        "commands": merged_commands,
        "stdout": merged_stdout,
        "invocation": {"module_args": {"commands": merged_commands}},
    }


def _output_for(show_commands: dict[str, Any], needle: str) -> str:
    chunks = [
        output
        for command, output in _command_outputs(show_commands)
        if needle in command.lower()
    ]
    return "\n".join(chunks)


def records_from_cisco(device_dir: Path, device: str, platform: str) -> list[Record]:
    records: list[Record] = []
    show_commands = _load_show_files(device_dir)
    facts = _read_json(device_dir / "facts.json") or {}

    ipv4 = (facts.get("ansible_net_interfaces") or facts.get("net_interfaces") or {})
    if isinstance(ipv4, dict):
        for name, data in ipv4.items():
            if not isinstance(data, dict):
                continue
            values = []
            for key in ("ipv4", "ipv6"):
                entries = data.get(key) or []
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    address = entry.get("address")
                    prefix = entry.get("subnet") or entry.get("prefix") or entry.get("masklen")
                    if address and prefix:
                        values.append(f"{address}/{prefix}" if "/" not in str(address) else str(address))
                    elif address:
                        values.append(str(address))
            if values:
                records.append(
                    Record(
                        device=device,
                        platform=platform,
                        category="interface",
                        name=name,
                        field="address",
                        values=tuple(values),
                        context={"status": data.get("operstatus") or data.get("state")},
                    )
                )

    arp_text = _output_for(show_commands, "arp")
    for match in ARP_RE.finditer(arp_text):
        ip_addr, mac, iface = match.groups()
        if parse_token(ip_addr):
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="arp",
                    name=f"{iface}:{ip_addr}",
                    field="address",
                    values=(ip_addr,),
                    context={"mac": mac, "interface": iface},
                )
            )

    iface_text = _output_for(show_commands, "ip interface brief")
    for match in IFACE_RE.finditer(iface_text):
        name, address, status, proto = match.groups()
        if parse_token(address):
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="interface",
                    name=name,
                    field="address",
                    values=(address,),
                    context={"status": status, "protocol": proto},
                )
            )

    for command, output in _command_outputs(show_commands):
        lowered = command.lower()
        if "ip route" not in lowered:
            continue
        vrf = None
        if "vrf " in lowered:
            vrf = command.split("vrf", 1)[1].strip().split()[0]
        for route in parse_ios_routes(output, default_vrf=vrf):
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
                    context={
                        "protocol": route.protocol,
                        "next_hop": route.next_hop,
                        "interface": route.interface,
                        "vrf": route.vrf,
                        "flags": route.flags,
                        "command": command,
                    },
                )
            )

    acl_text = _output_for(show_commands, "access-list")
    current_acl = "unnamed"
    for line in acl_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("standard") or stripped.lower().startswith("extended") or stripped.lower().startswith("ip access-list"):
            current_acl = stripped
            continue
        values = [match.group(1) for match in ACL_HOST_RE.finditer(stripped)]
        for match in ACL_NET_RE.finditer(stripped):
            values.append(f"{match.group(1)} {match.group(2)}")
        parsed = [value for value in values if parse_token(value)]
        if parsed:
            records.append(
                Record(
                    device=device,
                    platform=platform,
                    category="acl",
                    name=current_acl,
                    field="ace",
                    values=tuple(parsed),
                    context={"line": stripped},
                )
            )
    return _dedupe(records)


def _dedupe(records: Iterable[Record]) -> list[Record]:
    seen: set[tuple] = set()
    unique: list[Record] = []
    for record in records:
        key = (record.category, record.name, record.field, record.values)
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique
