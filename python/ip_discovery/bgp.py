from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ip_discovery.tokens import parse_token

ROUTER_BGP = re.compile(r"^router bgp\s+(?P<asn>\d+)", re.IGNORECASE)
VRF_ENTER = re.compile(r"^vrf\s+(?P<vrf>\S+)", re.IGNORECASE)
ADDRESS_FAMILY_VRF = re.compile(
    r"^address-family\s+ipv4(?:\s+vrf\s+(?P<vrf>\S+))?",
    re.IGNORECASE,
)
NETWORK_MASK = re.compile(
    r"^network\s+(?P<addr>\d+\.\d+\.\d+\.\d+)(?:\s+mask\s+(?P<mask>\d+\.\d+\.\d+\.\d+))?",
    re.IGNORECASE,
)
NETWORK_CIDR = re.compile(
    r"^network\s+(?P<cidr>\d+\.\d+\.\d+\.\d+/\d+)",
    re.IGNORECASE,
)
NEIGHBOR = re.compile(
    r"^neighbor\s+(?P<ip>\S+)\s+remote-as\s+(?P<asn>\d+)",
    re.IGNORECASE,
)
EXIT = re.compile(r"^exit(?:-af)?$", re.IGNORECASE)


@dataclass(frozen=True)
class BgpAdvertisement:
    asn: str
    vrf: str
    prefix: str


@dataclass(frozen=True)
class BgpNeighbor:
    asn: str
    vrf: str
    peer: str
    remote_as: str


def _mask_to_prefix(addr: str, mask: str | None) -> str | None:
    if not mask:
        token = parse_token(addr)
        return token.raw if token else None
    try:
        net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
        return str(net)
    except ValueError:
        return None


def parse_running_config_bgp(text: str) -> tuple[list[BgpAdvertisement], list[BgpNeighbor]]:
    advertisements: list[BgpAdvertisement] = []
    neighbors: list[BgpNeighbor] = []
    asn = ""
    vrf = "default"
    in_bgp = False
    for raw in (text or "").splitlines():
        line = raw.split("!")[0].strip()
        if not line:
            continue
        bgp_match = ROUTER_BGP.match(line)
        if bgp_match:
            in_bgp = True
            asn = bgp_match.group("asn")
            vrf = "default"
            continue
        if not in_bgp:
            continue
        if line.startswith("router ") and not line.lower().startswith("router bgp"):
            in_bgp = False
            continue
        if EXIT.match(line) and vrf != "default":
            vrf = "default"
            continue
        vrf_match = VRF_ENTER.match(line) or ADDRESS_FAMILY_VRF.match(line)
        if vrf_match and vrf_match.groupdict().get("vrf"):
            vrf = vrf_match.group("vrf")
            continue
        cidr_match = NETWORK_CIDR.match(line)
        if cidr_match:
            prefix = cidr_match.group("cidr")
            advertisements.append(BgpAdvertisement(asn=asn, vrf=vrf, prefix=prefix))
            continue
        net_match = NETWORK_MASK.match(line)
        if net_match:
            prefix = _mask_to_prefix(net_match.group("addr"), net_match.group("mask"))
            if prefix:
                advertisements.append(BgpAdvertisement(asn=asn, vrf=vrf, prefix=prefix))
            continue
        neighbor_match = NEIGHBOR.match(line)
        if neighbor_match and parse_token(neighbor_match.group("ip")):
            neighbors.append(
                BgpNeighbor(
                    asn=asn,
                    vrf=vrf,
                    peer=neighbor_match.group("ip"),
                    remote_as=neighbor_match.group("asn"),
                )
            )
    return advertisements, neighbors
