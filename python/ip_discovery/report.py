from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from ip_discovery.models import Hit


def write_reports(hits: list[Hit], search_targets: list[str], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "search_targets": search_targets,
        "hit_count": len(hits),
        "hits": [hit.as_dict() for hit in hits],
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
    md_path.write_text(_markdown(hits, search_targets), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "markdown": md_path}


def _markdown(hits: list[Hit], search_targets: list[str]) -> str:
    by_device: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        by_device[hit.device].append(hit)
    category_counts = Counter(hit.category for hit in hits)
    lines = [
        "# IP migration discovery report",
        "",
        "## Search targets",
        "",
    ]
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
