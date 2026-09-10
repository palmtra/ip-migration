from __future__ import annotations

from ip_discovery.expand import build_object_maps, expand_record_values
from ip_discovery.models import Hit, Record
from ip_discovery.tokens import AddressToken, match_values, parse_token


def parse_search_targets(raw_targets: list[str]) -> list[AddressToken]:
    targets: list[AddressToken] = []
    for raw in raw_targets:
        token = parse_token(str(raw))
        if token is None or token.kind in {"fqdn", "other"}:
            continue
        targets.append(token)
    return targets


def find_hits(records: list[Record], search_targets: list[str]) -> list[Hit]:
    targets = parse_search_targets(search_targets)
    addresses, groups = build_object_maps(records)
    hits: list[Hit] = []
    seen: set[tuple] = set()

    for record in records:
        expanded = expand_record_values(record, addresses, groups)
        if not expanded and record.values:
            expanded = [(value, ()) for value in record.values]
        for value, path in expanded:
            for matched_value, search_term, match_kind in match_values([value], targets):
                key = (
                    record.device,
                    record.category,
                    record.name,
                    record.field,
                    matched_value,
                    search_term,
                    path,
                )
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    Hit(
                        device=record.device,
                        platform=record.platform,
                        category=record.category,
                        name=record.name,
                        field=record.field,
                        matched_value=matched_value,
                        search_term=search_term,
                        match_kind=match_kind,
                        resolution_path=path,
                        context=record.context,
                    )
                )
    return sorted(hits, key=lambda hit: (hit.device, hit.category, hit.name, hit.matched_value))
