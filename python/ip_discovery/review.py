from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from ip_discovery.models import Hit

VLAN_RE = re.compile(r"(?:vlan|vl)(\d+)", re.IGNORECASE)
SUBIF_RE = re.compile(r"\.(\d+)$")


def _is_firewall(platform: str) -> bool:
    return "palo" in (platform or "").lower()


def _vlan_from_name(name: str) -> int | None:
    match = VLAN_RE.search(name or "")
    if match:
        return int(match.group(1))
    sub = SUBIF_RE.search(name or "")
    if sub:
        return int(sub.group(1))
    return None


_SCOPE_ROW_KEYS = (
    "shared",
    "location",
    "device_group",
    "template",
    "template_stack",
    "rulebase",
    "serial",
    "hostname",
    "firewall",
)


def _compact_hit(hit: Hit) -> dict[str, Any]:
    ctx = hit.context or {}
    row = {
        "device": hit.device,
        "name": hit.name,
        "matched_value": hit.matched_value,
        "field": hit.field,
    }
    if "shared" in ctx and ctx["shared"] is not None:
        row["shared"] = bool(ctx["shared"])
    for key in _SCOPE_ROW_KEYS:
        if key == "shared":
            continue
        value = ctx.get(key)
        if value not in (None, "", [], {}):
            row[key] = value
    if hit.resolution_path:
        row["via"] = list(hit.resolution_path)
    useful = {
        key: value
        for key, value in ctx.items()
        if key not in _SCOPE_ROW_KEYS and value not in (None, "", [], {})
    }
    if useful:
        row["context"] = useful
    return row


def build_review(
    hits: list[Hit],
    search_targets: list[str],
    records: list[Record] | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    labels = labels or {}
    firewall_hits = [hit for hit in hits if _is_firewall(hit.platform)]
    switch_hits = [hit for hit in hits if not _is_firewall(hit.platform)]

    review: dict[str, Any] = {
        "customer": labels.get("customer") or None,
        "id": labels.get("id") or None,
        "site": labels.get("site") or None,
        "subnet": search_targets[0] if len(search_targets) == 1 else None,
        "search_targets": search_targets,
        "vlans": _vlans(hits),
        "interfaces": _interfaces(hits),
        "others": [
            {"firewall": _firewall_others(firewall_hits)},
            {"switch": _switch_others(switch_hits)},
        ],
    }
    return review


def _vlans(hits: list[Hit]) -> list[dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    for hit in hits:
        vlan_id = _vlan_from_name(hit.name) or _vlan_from_name(str((hit.context or {}).get("interface") or ""))
        if vlan_id is None:
            continue
        entry = found.setdefault(vlan_id, {"id": vlan_id, "devices": []})
        if hit.device not in entry["devices"]:
            entry["devices"].append(hit.device)
    return [found[key] for key in sorted(found)]


def _interfaces(hits: list[Hit]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for hit in hits:
        if hit.category != "interface":
            continue
        key = (hit.device, hit.name, hit.matched_value)
        if key in seen:
            continue
        seen.add(key)
        body = {
            key: value
            for key, value in {
                "name": hit.name,
                "address": hit.matched_value,
                "device": hit.device,
                "desc": (hit.context or {}).get("description") or (hit.context or {}).get("desc"),
                "vrf": (hit.context or {}).get("vrf"),
                "virtual": (hit.context or {}).get("virtual"),
                "role": (hit.context or {}).get("role"),
                "vsys": (hit.context or {}).get("vsys"),
                "shared": (hit.context or {}).get("shared"),
                "location": (hit.context or {}).get("location"),
                "device_group": (hit.context or {}).get("device_group"),
                "template": (hit.context or {}).get("template") or (hit.context or {}).get("template_stack"),
            }.items()
            if value not in (None, "", [], {})
        }
        role = "firewall" if _is_firewall(hit.platform) else "switch"
        rows.append({role: body})
    return rows


def _firewall_others(hits: list[Hit]) -> dict[str, Any]:
    buckets = {
        "object": "address_object",
        "object_groups": "address_group",
        "nat": "nat_rule",
        "gp_portal": "globalprotect",
        "gp_gateway": "globalprotect",
        "ipsec_tunnels": ("ipsec_tunnel", "ipsec_proxyid", "ike_gateway"),
        "security_policies": "security_rule",
        "routes": "route",
        "arp": "arp",
        "bgp": "bgp_neighbor",
    }
    others: dict[str, Any] = {}
    for label, category in buckets.items():
        categories = category if isinstance(category, tuple) else (category,)
        items = [_compact_hit(hit) for hit in hits if hit.category in categories]
        others[label] = items or None
    return others


def _switch_others(hits: list[Hit]) -> list[dict[str, Any]]:
    by_device: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        by_device[hit.device].append(hit)
    switches: list[dict[str, Any]] = []
    for device in sorted(by_device):
        device_hits = by_device[device]
        bgp_by_vrf: dict[tuple[str, str], list[str]] = defaultdict(list)
        for hit in device_hits:
            if hit.category != "bgp_advertisement":
                continue
            asn = str((hit.context or {}).get("asn") or "")
            vrf = str((hit.context or {}).get("vrf") or "default")
            prefix = hit.matched_value
            if prefix not in bgp_by_vrf[(asn, vrf)]:
                bgp_by_vrf[(asn, vrf)].append(prefix)
        bgp_blocks = [
            {"asn": int(asn) if str(asn).isdigit() else asn, "vrf": vrf, "advertisements": prefixes}
            for (asn, vrf), prefixes in sorted(bgp_by_vrf.items())
        ]
        switches.append(
            {
                "name": device,
                "bgp": bgp_blocks or None,
                "arp": [_compact_hit(hit) for hit in device_hits if hit.category == "arp"] or None,
                "mlag": [_compact_hit(hit) for hit in device_hits if hit.category == "mlag"] or None,
                "routes": [_compact_hit(hit) for hit in device_hits if hit.category == "route"] or None,
                "interfaces": [_compact_hit(hit) for hit in device_hits if hit.category == "interface"] or None,
            }
        )
    return switches
