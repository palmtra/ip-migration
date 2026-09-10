from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ip_discovery.models import Hit
from ip_discovery.review import build_review


def write_reports(
    hits: list[Hit],
    search_targets: list[str],
    out_dir: Path,
    labels: dict[str, str] | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    review = build_review(hits, search_targets, labels=labels)
    payload: dict[str, Any] = {
        "search_targets": search_targets,
        "hit_count": len(hits),
        "hits": [hit.as_dict() for hit in hits],
        "review": review,
        "routing": _routing_rows(hits),
    }

    json_path = out_dir / "discovery.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    csv_path = out_dir / "discovery.csv"
    fieldnames = [
        "device",
        "platform",
        "category",
        "name",
        "field",
        "matched_value",
        "search_term",
        "match_kind",
        "resolution_path",
        "shared",
        "location",
        "device_group",
        "template",
        "context",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for hit in hits:
            row = hit.as_dict()
            row["resolution_path"] = " > ".join(hit.resolution_path)
            row["shared"] = hit.context.get("shared")
            row["location"] = hit.context.get("location")
            row["device_group"] = hit.context.get("device_group")
            row["template"] = hit.context.get("template") or hit.context.get("template_stack")
            row["context"] = json.dumps(hit.context, sort_keys=True)
            writer.writerow(row)

    md_path = out_dir / "discovery.md"
    md_path.write_text(_markdown(hits, search_targets, labels=labels), encoding="utf-8")

    paths = {"json": json_path, "csv": csv_path, "markdown": md_path}
    try:
        import yaml
    except ImportError:  # pragma: no cover
        yaml = None
    if yaml is not None:
        yaml_path = out_dir / "migration-review.yml"
        yaml_path.write_text(yaml.safe_dump(review, sort_keys=False, allow_unicode=True), encoding="utf-8")
        paths["review"] = yaml_path
    return paths


def _routing_rows(hits: list[Hit]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for hit in hits:
        if hit.category != "route":
            continue
        rows.append(
            {
                "device": hit.device,
                "prefix": hit.name,
                "matched_value": hit.matched_value,
                "protocol": hit.context.get("protocol") or hit.context.get("routeType"),
                "next_hop": hit.context.get("next_hop") or hit.context.get("next_hops"),
                "interface": hit.context.get("interface"),
                "vrf": hit.context.get("vrf") or hit.context.get("vr"),
            }
        )
    return rows


def _markdown(hits: list[Hit], search_targets: list[str], labels: dict[str, str] | None = None) -> str:
    labels = labels or {}
    by_device: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        by_device[hit.device].append(hit)
    category_counts = Counter(hit.category for hit in hits)
    lines = ["# IP migration discovery report", ""]
    if labels.get("customer"):
        lines.append(f"**Customer:** {labels['customer']}")
    if labels.get("site"):
        lines.append(f"**Site:** {labels['site']}")
    if labels.get("customer") or labels.get("site"):
        lines.append("")
    lines.extend(["## Search targets", ""])
    lines.extend(f"- `{target}`" for target in search_targets)
    lines.extend(["", f"**Total hits:** {len(hits)}", "", "## Hits by category", ""])
    if category_counts:
        lines.append("| Category | Count |")
        lines.append("| --- | ---: |")
        for category, count in category_counts.most_common():
            lines.append(f"| {category} | {count} |")
        lines.append("")

    arp_hits = [hit for hit in hits if hit.category == "arp"]
    if arp_hits:
        lines.extend(["## ARP in search CIDR", ""])
        lines.append("| Device | IP | MAC | Interface | Serial |")
        lines.append("| --- | --- | --- | --- | --- |")
        for hit in arp_hits:
            lines.append(
                f"| {hit.device} | `{hit.matched_value}` | {hit.context.get('mac') or ''} | {hit.context.get('interface') or hit.name} | {hit.context.get('serial') or ''} |"
            )
        lines.append("")

    route_hits = [hit for hit in hits if hit.category == "route"]
    if route_hits:
        lines.extend(["## Routing", ""])
        lines.append("| Device | Prefix | Protocol | Next hop | VRF | Matched |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for hit in route_hits:
            hops = hit.context.get("next_hop") or hit.context.get("next_hops") or ""
            if isinstance(hops, list):
                hops = ",".join(str(item) for item in hops)
            lines.append(
                f"| {hit.device} | `{hit.name}` | {hit.context.get('protocol') or hit.context.get('routeType') or ''} | {hops} | {hit.context.get('vrf') or hit.context.get('vr') or ''} | `{hit.matched_value}` |"
            )
        lines.append("")

    bgp_hits = [hit for hit in hits if hit.category == "bgp_advertisement"]
    if bgp_hits:
        lines.extend(["## BGP advertisements", ""])
        lines.append("| Device | VRF | ASN | Prefix |")
        lines.append("| --- | --- | --- | --- |")
        for hit in bgp_hits:
            lines.append(
                f"| {hit.device} | {hit.context.get('vrf') or ''} | {hit.context.get('asn') or ''} | `{hit.matched_value}` |"
            )
        lines.append("")

    for device in sorted(by_device):
        lines.extend([f"## {device}", ""])
        lines.append("| Category | Name | Shared | Location | Field | Matched | Search | Kind | Via |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for hit in by_device[device]:
            via = " > ".join(hit.resolution_path) if hit.resolution_path else ""
            shared = hit.context.get("shared")
            shared_s = "" if shared is None else str(bool(shared)).lower()
            location = hit.context.get("location") or hit.context.get("device_group") or hit.context.get("template") or ""
            lines.append(
                f"| {hit.category} | {hit.name} | {shared_s} | {location} | {hit.field} | `{hit.matched_value}` | `{hit.search_term}` | {hit.match_kind} | {via} |"
            )
        lines.append("")
    if not hits:
        lines.extend(["No matching host or subnet usage was found.", ""])
    return "\n".join(lines)
