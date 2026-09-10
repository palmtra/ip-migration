from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ip_discovery.job import Job
from ip_discovery.models import Hit

FIREWALL_BUCKETS = {
    "address_object": "object",
    "address_group": "object_groups",
    "nat_rule": "nat",
    "globalprotect": "gp_gateway",
    "ipsec_tunnel": "ipsec_tunnels",
    "ipsec_proxyid": "ipsec_tunnels",
    "ike_gateway": "ipsec_tunnels",
    "security_rule": "security_policies",
    "route": "routes",
    "arp": "arp",
    "interface": "interfaces",
    "bgp_neighbor": "bgp",
}

AGGPE_BUCKETS = {
    "route": "routes",
    "arp": "arp",
    "interface": "interfaces",
    "bgp_neighbor": "bgp",
    "acl": "acls",
}


def write_reports(
    hits: list[Hit],
    search_targets: list[str],
    out_dir: Path,
    job: Job | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "search_targets": search_targets,
        "hit_count": len(hits),
        "hits": [hit.as_dict() for hit in hits],
    }
    if job:
        payload["job"] = job.ansible_vars()
        payload["routing"] = _routing_rows(hits)
        payload["filled_template"] = fill_job_template(job, hits)

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
        "context",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for hit in hits:
            row = hit.as_dict()
            row["resolution_path"] = " > ".join(hit.resolution_path)
            row["context"] = json.dumps(hit.context, sort_keys=True)
            writer.writerow(row)

    md_path = out_dir / "discovery.md"
    md_path.write_text(_markdown(hits, search_targets, job=job), encoding="utf-8")
    paths = {"json": json_path, "csv": csv_path, "markdown": md_path}
    if job:
        yaml_path = out_dir / "job-filled.yml"
        try:
            import yaml
        except ImportError:  # pragma: no cover
            yaml = None
        if yaml is not None:
            yaml_path.write_text(
                yaml.safe_dump(payload["filled_template"], sort_keys=False),
                encoding="utf-8",
            )
            paths["job_filled"] = yaml_path
    return paths


def fill_job_template(job: Job, hits: list[Hit]) -> dict[str, Any]:
    others: dict[str, dict[str, list[dict[str, Any]]]] = {
        "firewall": {key: [] for key in FIREWALL_BUCKETS.values()},
        "aggpe": {key: [] for key in AGGPE_BUCKETS.values()},
    }
    for hit in hits:
        role = "firewall" if "palo" in hit.platform.lower() else "aggpe"
        buckets = FIREWALL_BUCKETS if role == "firewall" else AGGPE_BUCKETS
        bucket = buckets.get(hit.category)
        if not bucket:
            continue
        others[role][bucket].append(
            {
                "device": hit.device,
                "name": hit.name,
                "matched_value": hit.matched_value,
                "field": hit.field,
                "via": list(hit.resolution_path),
                "context": hit.context,
            }
        )
    filled = {
        "customer": job.customer,
        "id": job.customer_id,
        "site": job.site,
        "subnet": job.subnets[0] if job.subnets else None,
        "vlans": job.vlans,
        "interfaces": job.raw.get("interfaces"),
        "others": [{role: buckets} for role, buckets in others.items()],
        "routing": _routing_rows(hits),
    }
    return filled


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


def _markdown(hits: list[Hit], search_targets: list[str], job: Job | None = None) -> str:
    by_device: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        by_device[hit.device].append(hit)
    category_counts = Counter(hit.category for hit in hits)
    lines = [
        "# IP migration discovery report",
        "",
    ]
    if job:
        lines.extend(
            [
                f"**Customer:** {job.customer} (`{job.customer_id}`)",
                f"**Site:** {job.site}",
                "",
            ]
        )
    lines.extend(["## Search targets", ""])
    lines.extend(f"- `{target}`" for target in search_targets)
    lines.extend(
        [
            "",
            f"**Total hits:** {len(hits)}",
            "",
            "## Hits by category",
            "",
        ]
    )
    if category_counts:
        lines.append("| Category | Count |")
        lines.append("| --- | ---: |")
        for category, count in category_counts.most_common():
            lines.append(f"| {category} | {count} |")
        lines.append("")

    route_hits = [hit for hit in hits if hit.category == "route"]
    if route_hits:
        lines.extend(["## Routing", ""])
        lines.append("| Device | Prefix | Protocol | Next hop | VRF | Matched |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for hit in route_hits:
            lines.append(
                "| {device} | `{prefix}` | {proto} | {nh} | {vrf} | `{matched}` |".format(
                    device=hit.device,
                    prefix=hit.name,
                    proto=hit.context.get("protocol") or hit.context.get("routeType") or "",
                    nh=hit.context.get("next_hop")
                    or (
                        ",".join(hit.context.get("next_hops") or [])
                        if isinstance(hit.context.get("next_hops"), list)
                        else hit.context.get("next_hops") or ""
                    ),
                    vrf=hit.context.get("vrf") or hit.context.get("vr") or "",
                    matched=hit.matched_value,
                )
            )
        lines.append("")

    for device in sorted(by_device):
        lines.extend([f"## {device}", ""])
        lines.append("| Category | Name | Field | Matched | Search | Kind | Via |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for hit in by_device[device]:
            via = " > ".join(hit.resolution_path) if hit.resolution_path else ""
            lines.append(
                f"| {hit.category} | {hit.name} | {hit.field} | `{hit.matched_value}` | `{hit.search_term}` | {hit.match_kind} | {via} |"
            )
        lines.append("")
    if not hits:
        lines.extend(["No matching host or subnet usage was found.", ""])
    return "\n".join(lines)
