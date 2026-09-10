from __future__ import annotations

from ip_discovery.models import Record
from ip_discovery.tokens import parse_token


def record_scope(record: Record) -> str:
    """Stable scope key for Panorama shared vs device-group vs template objects."""
    ctx = record.context or {}
    if ctx.get("shared") is True or ctx.get("location") == "shared":
        return "shared"
    if ctx.get("device_group"):
        return f"device_group:{ctx['device_group']}"
    if ctx.get("template_stack"):
        return f"template_stack:{ctx['template_stack']}"
    if ctx.get("template"):
        return f"template:{ctx['template']}"
    if ctx.get("vsys"):
        return f"vsys:{ctx['vsys']}"
    location = ctx.get("location")
    if location:
        return str(location)
    return ""


def _object_key(device: str, scope: str, name: str) -> str:
    if scope:
        return f"{device}::{scope}::{name}"
    return f"{device}::{name}"


def build_object_maps(records: list[Record]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (address_values_by_name, group_members_by_name) scoped as device[::scope]::name."""
    addresses: dict[str, list[str]] = {}
    groups: dict[str, list[str]] = {}
    for record in records:
        key = _object_key(record.device, record_scope(record), record.name)
        if record.category == "address_object":
            addresses[key] = list(record.values)
        elif record.category == "address_group":
            groups[key] = list(record.refs or record.values)
    return addresses, groups


def resolve_ref(
    device: str,
    name: str,
    addresses: dict[str, list[str]],
    groups: dict[str, list[str]],
    seen: set[str] | None = None,
    scope: str = "",
) -> list[tuple[str, tuple[str, ...]]]:
    """Resolve an object or group name to (ip_value, path) pairs.

    Device-group objects override shared objects of the same name. Shared is
    the fallback when the name is not defined in the caller's scope.
    """
    seen = seen or set()
    candidates = []
    if scope:
        candidates.append(_object_key(device, scope, name))
        if scope != "shared":
            candidates.append(_object_key(device, "shared", name))
    candidates.append(_object_key(device, "", name))

    for key in candidates:
        if key in seen:
            continue
        if key in addresses:
            seen.add(key)
            return [(value, (name,)) for value in addresses[key] if parse_token(value)]
        if key in groups:
            seen.add(key)
            resolved: list[tuple[str, tuple[str, ...]]] = []
            for member in groups[key]:
                if parse_token(member) and parse_token(member).kind in {"net", "range"}:
                    resolved.append((member, (name, member)))
                    continue
                for value, path in resolve_ref(device, member, addresses, groups, seen, scope=scope):
                    resolved.append((value, (name,) + path))
            return resolved

    token = parse_token(name)
    if token and token.kind in {"net", "range"}:
        return [(name, (name,))]
    return []


def expand_record_values(record: Record, addresses: dict[str, list[str]], groups: dict[str, list[str]]) -> list[tuple[str, tuple[str, ...]]]:
    expanded: list[tuple[str, tuple[str, ...]]] = []
    seen_values: set[tuple[str, tuple[str, ...]]] = set()
    scope = record_scope(record)

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
            for resolved_value, path in resolve_ref(record.device, value, addresses, groups, scope=scope):
                add(resolved_value, path)

    for ref in record.refs:
        for resolved_value, path in resolve_ref(record.device, ref, addresses, groups, scope=scope):
            add(resolved_value, path)

    return expanded
