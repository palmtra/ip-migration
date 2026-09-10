from __future__ import annotations

from ip_discovery.models import Record
from ip_discovery.tokens import parse_token


def build_object_maps(records: list[Record]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (address_values_by_name, group_members_by_name) scoped as device::name."""
    addresses: dict[str, list[str]] = {}
    groups: dict[str, list[str]] = {}
    for record in records:
        key = f"{record.device}::{record.name}"
        if record.category == "address_object":
            addresses[key] = list(record.values)
        elif record.category == "address_group":
            groups[key] = list(record.refs or record.values)
    return addresses, groups


def resolve_ref(device: str, name: str, addresses: dict[str, list[str]], groups: dict[str, list[str]], seen: set[str] | None = None) -> list[tuple[str, tuple[str, ...]]]:
    """Resolve an object or group name to (ip_value, path) pairs."""
    seen = seen or set()
    key = f"{device}::{name}"
    if key in seen:
        return []
    seen.add(key)

    if key in addresses:
        return [(value, (name,)) for value in addresses[key] if parse_token(value)]

    if key in groups:
        resolved: list[tuple[str, tuple[str, ...]]] = []
        for member in groups[key]:
            if parse_token(member) and parse_token(member).kind in {"net", "range"}:
                resolved.append((member, (name, member)))
                continue
            for value, path in resolve_ref(device, member, addresses, groups, seen):
                resolved.append((value, (name,) + path))
        return resolved

    token = parse_token(name)
    if token and token.kind in {"net", "range"}:
        return [(name, (name,))]
    return []


def expand_record_values(record: Record, addresses: dict[str, list[str]], groups: dict[str, list[str]]) -> list[tuple[str, tuple[str, ...]]]:
    expanded: list[tuple[str, tuple[str, ...]]] = []
    seen_values: set[tuple[str, tuple[str, ...]]] = set()

    def add(value: str, path: tuple[str, ...]) -> None:
        item = (value, path)
        if item not in seen_values:
            seen_values.add(item)
            expanded.append(item)

    for value in record.values:
        token = parse_token(value)
        if token and token.kind in {"net", "range"}:
            add(value, ())
        elif value:
            for resolved_value, path in resolve_ref(record.device, value, addresses, groups):
                add(resolved_value, path)

    for ref in record.refs:
        for resolved_value, path in resolve_ref(record.device, ref, addresses, groups):
            add(resolved_value, path)

    return expanded
