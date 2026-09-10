from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable

SKIP_VALUES = {
    "",
    "any",
    "none",
    "unassigned",
    "n/a",
    "na",
    "unknown",
    "0.0.0.0",
    "::",
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
RANGE_RE = re.compile(
    r"^(?P<a>(?:\d{1,3}\.){3}\d{1,3})\s*-\s*(?P<b>(?:\d{1,3}\.){3}\d{1,3})$"
)
WILDCARD_RE = re.compile(
    r"^(?P<addr>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<wild>(?:\d{1,3}\.){3}\d{1,3})$"
)


@dataclass(frozen=True)
class AddressToken:
    raw: str
    kind: str  # net | range | fqdn | other
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    start: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    end: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None


def _host_network(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}")


def wildcard_to_prefix(addr: str, wildcard: str) -> ipaddress.IPv4Network | None:
    try:
        addr_int = int(ipaddress.IPv4Address(addr))
        wild_int = int(ipaddress.IPv4Address(wildcard))
    except ipaddress.AddressValueError:
        return None
    mask_int = (0xFFFFFFFF ^ wild_int) & 0xFFFFFFFF
    prefix = bin(mask_int).count("1")
    expected = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    if mask_int != expected:
        return None
    network_int = addr_int & mask_int
    try:
        return ipaddress.IPv4Network((network_int, prefix))
    except ValueError:
        return None


def parse_token(raw: str) -> AddressToken | None:
    value = (raw or "").strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered in SKIP_VALUES:
        return None
    if lowered.endswith("/0"):
        return None

    range_match = RANGE_RE.match(value)
    if range_match:
        start = ipaddress.ip_address(range_match.group("a"))
        end = ipaddress.ip_address(range_match.group("b"))
        if int(end) < int(start):
            start, end = end, start
        return AddressToken(raw=value, kind="range", start=start, end=end)

    wildcard_match = WILDCARD_RE.match(value)
    if wildcard_match:
        network = wildcard_to_prefix(
            wildcard_match.group("addr"), wildcard_match.group("wild")
        )
        if network is not None:
            return AddressToken(raw=value, kind="net", network=network)
        return AddressToken(raw=value, kind="other")

    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            return AddressToken(raw=value, kind="net", network=network)
        addr = ipaddress.ip_address(value)
        return AddressToken(raw=value, kind="net", network=_host_network(addr))
    except ValueError:
        return AddressToken(raw=value, kind="fqdn")


def extract_tokens_from_text(text: str) -> list[AddressToken]:
    found: list[AddressToken] = []
    seen: set[str] = set()
    for match in IPV4_RE.finditer(text or ""):
        token = parse_token(match.group(0))
        if token is None or token.raw in seen:
            continue
        seen.add(token.raw)
        found.append(token)
    return found


def token_overlaps(left: AddressToken, right: AddressToken) -> str | None:
    if left.kind == "fqdn" or right.kind == "fqdn" or left.kind == "other" or right.kind == "other":
        if left.raw.lower() == right.raw.lower():
            return "exact"
        return None

    if left.kind == "net" and right.kind == "net" and left.network and right.network:
        if left.network.version != right.network.version:
            return None
        if left.network == right.network:
            return "exact"
        if left.network.subnet_of(right.network) or right.network.subnet_of(left.network):
            return "contained"
        if left.network.overlaps(right.network):
            return "overlap"
        return None

    left_net = left.network
    right_net = right.network
    if left.kind == "range" and left.start and left.end:
        left_span = (int(left.start), int(left.end), left.start.version)
    elif left_net is not None:
        left_span = (
            int(left_net.network_address),
            int(left_net.broadcast_address),
            left_net.version,
        )
    else:
        return None

    if right.kind == "range" and right.start and right.end:
        right_span = (int(right.start), int(right.end), right.start.version)
    elif right_net is not None:
        right_span = (
            int(right_net.network_address),
            int(right_net.broadcast_address),
            right_net.version,
        )
    else:
        return None

    if left_span[2] != right_span[2]:
        return None
    if left_span[0] <= right_span[1] and right_span[0] <= left_span[1]:
        if left_span == right_span:
            return "exact"
        return "overlap"
    return None


def match_values(values: Iterable[str], targets: Iterable[AddressToken]) -> list[tuple[str, str, str]]:
    """Return (value, search_term, match_kind) for overlapping pairs."""
    hits: list[tuple[str, str, str]] = []
    parsed_values = [token for raw in values if (token := parse_token(raw))]
    for value_token in parsed_values:
        for target in targets:
            kind = token_overlaps(value_token, target)
            if kind:
                hits.append((value_token.raw, target.raw, kind))
    return hits
