from __future__ import annotations

import re
from dataclasses import dataclass

ROUTE_CODES = {
    "C": "connected",
    "L": "local",
    "S": "static",
    "B": "bgp",
    "O": "ospf",
    "D": "eigrp",
    "R": "rip",
    "K": "kernel",
    "i": "isis",
    "*": "candidate_default",
}

SUBNETTED_RE = re.compile(
    r"(?P<prefix>\d+\.\d+\.\d+\.\d+)/(?P<len>\d+)\s+is (?:variably )?subnetted",
    re.IGNORECASE,
)
IOS_ROUTE_RE = re.compile(
    r"^(?P<codes>[A-Za-z*]{1,4})\s+"
    r"(?P<network>\d+\.\d+\.\d+\.\d+)(?:/(?P<len>\d+))?"
    r"(?P<rest>.*)$"
)
VIA_RE = re.compile(
    r"via\s+(?P<via>\S+?)(?:,|$)",
    re.IGNORECASE,
)
CONN_RE = re.compile(
    r"directly connected,\s+(?P<iface>\S+)",
    re.IGNORECASE,
)
VRF_RE = re.compile(
    r"(?:Routing Table|VRF):\s*(?P<vrf>\S+)",
    re.IGNORECASE,
)
PALO_VR_RE = re.compile(r"virtual router[:\s]+(?P<vr>\S+)", re.IGNORECASE)
PALO_ROUTE_RE = re.compile(
    r"^(?P<dest>\d+\.\d+\.\d+\.\d+/\d+)\s+"
    r"(?P<nexthop>\S+)\s+"
    r"(?P<metric>\d+)\s+"
    r"(?P<flags>.+?)\s+"
    r"(?P<iface>\S+)\s*$"
)


@dataclass(frozen=True)
class ParsedRoute:
    prefix: str
    protocol: str
    next_hop: str | None
    interface: str | None
    vrf: str | None
    flags: str | None = None
    metric: str | None = None

    def match_values(self) -> tuple[str, ...]:
        values: list[str] = []
        if self.prefix and not self.prefix.endswith("/0"):
            values.append(self.prefix)
        if self.next_hop and self.next_hop not in {"0.0.0.0", "::", "*"}:
            values.append(self.next_hop)
        return tuple(values)


def parse_ios_routes(text: str, default_vrf: str | None = None) -> list[ParsedRoute]:
    routes: list[ParsedRoute] = []
    current_mask: str | None = None
    current_vrf = default_vrf
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        vrf_match = VRF_RE.search(line)
        if vrf_match:
            current_vrf = vrf_match.group("vrf")
            continue
        subnetted = SUBNETTED_RE.search(line)
        if subnetted:
            current_mask = subnetted.group("len")
            continue
        stripped = line.lstrip()
        match = IOS_ROUTE_RE.match(stripped)
        if not match:
            continue
        if "subnetted" in match.group("rest").lower():
            continue
        network = match.group("network")
        length = match.group("len") or current_mask
        prefix = f"{network}/{length}" if length else network
        rest = match.group("rest") or ""
        via = VIA_RE.search(rest)
        connected = CONN_RE.search(rest)
        codes = match.group("codes")
        protocol = "unknown"
        for char in codes:
            if char in ROUTE_CODES and char != "*":
                protocol = ROUTE_CODES[char]
                break
        if connected:
            protocol = "connected"
        routes.append(
            ParsedRoute(
                prefix=prefix,
                protocol=protocol,
                next_hop=via.group("via").rstrip(",") if via else None,
                interface=connected.group("iface") if connected else None,
                vrf=current_vrf,
                flags=codes,
            )
        )
    return routes


def parse_palo_routes(text: str) -> list[ParsedRoute]:
    routes: list[ParsedRoute] = []
    current_vr: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        vr_match = PALO_VR_RE.search(line)
        if vr_match:
            current_vr = vr_match.group("vr").rstrip(":")
            continue
        match = PALO_ROUTE_RE.match(line)
        if not match:
            continue
        flags = match.group("flags")
        protocol = "unknown"
        if "C" in flags.split():
            protocol = "connected"
        elif "S" in flags.split():
            protocol = "static"
        elif "B" in flags.split():
            protocol = "bgp"
        elif "O" in flags.split():
            protocol = "ospf"
        next_hop = match.group("nexthop")
        routes.append(
            ParsedRoute(
                prefix=match.group("dest"),
                protocol=protocol,
                next_hop=None if next_hop in {"0.0.0.0", "0.0.0.0/0"} else next_hop,
                interface=match.group("iface"),
                vrf=current_vr,
                flags=flags,
                metric=match.group("metric"),
            )
        )
    return routes
