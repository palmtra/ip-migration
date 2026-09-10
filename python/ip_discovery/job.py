from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _addr(data: dict[str, Any]) -> str | None:
    raw = data.get("address") or data.get("adress")
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _flatten_role_maps(items: Any) -> dict[str, list[dict[str, Any]]]:
    """Turn [{firewall: {...}}, {aggpe: {...}}] into {firewall: [...], aggpe: [...]}."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in _as_list(items):
        if not isinstance(item, dict):
            continue
        if "address" in item or "adress" in item or "vsys" in item or "vrf" in item:
            role = str(item.get("role") or item.get("device_role") or "device")
            grouped.setdefault(role, []).append(item)
            continue
        for role, body in item.items():
            if isinstance(body, dict):
                grouped.setdefault(str(role), []).append(body)
            elif isinstance(body, list):
                grouped.setdefault(str(role), []).extend(
                    part for part in body if isinstance(part, dict)
                )
    return grouped


@dataclass
class Job:
    slug: str
    customer: str
    customer_id: str
    site: str
    subnets: list[str]
    extra_search: list[str]
    vlans: list[dict[str, Any]]
    interfaces: dict[str, list[dict[str, Any]]]
    targets: dict[str, list[dict[str, Any]]]
    others: dict[str, dict[str, Any]]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def vrfs(self) -> list[str]:
        found: list[str] = []
        for rows in self.interfaces.values():
            for row in rows:
                vrf = row.get("vrf")
                if vrf and str(vrf) not in found:
                    found.append(str(vrf))
        for rows in self.targets.values():
            for row in rows:
                vrf = row.get("vrf")
                if vrf and str(vrf) not in found:
                    found.append(str(vrf))
        return found

    @property
    def vsys_list(self) -> list[str]:
        found: list[str] = []
        for role in ("firewall", "firewalls"):
            for row in self.interfaces.get(role, []) + self.targets.get(role, []):
                vsys = row.get("vsys")
                if vsys and str(vsys) not in found:
                    found.append(str(vsys))
        return found

    @property
    def vlan_ids(self) -> list[int]:
        ids: list[int] = []
        for vlan in self.vlans:
            try:
                vlan_id = int(vlan.get("id"))
            except (TypeError, ValueError):
                continue
            if vlan_id not in ids:
                ids.append(vlan_id)
        return ids

    @property
    def search_targets(self) -> list[str]:
        targets: list[str] = []
        for item in [*self.subnets, *self.extra_search]:
            if item and str(item) not in targets:
                targets.append(str(item))
        for rows in self.interfaces.values():
            for row in rows:
                address = _addr(row)
                if address and address not in targets:
                    targets.append(address)
        return targets

    def ansible_vars(self) -> dict[str, Any]:
        return {
            "job_slug": self.slug,
            "job_customer": self.customer,
            "job_customer_id": self.customer_id,
            "job_site": self.site,
            "job_subnets": self.subnets,
            "job_vrfs": self.vrfs,
            "job_vsys": self.vsys_list,
            "job_vlans": self.vlan_ids,
            "search_targets": self.search_targets,
        }


def load_job(path: Path) -> Job:
    if yaml is None:
        raise RuntimeError("PyYAML is required to read job files")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Job file {path} must be a mapping")

    customer = raw.get("customer")
    customer_name = ""
    customer_id = str(raw.get("id") or "")
    if isinstance(customer, dict):
        customer_name = str(customer.get("name") or "")
        customer_id = str(customer.get("id") or customer_id)
    elif customer is not None:
        customer_name = str(customer)

    subnets = [str(item) for item in _as_list(raw.get("subnets") or raw.get("subnet")) if item]
    extra = [str(item) for item in _as_list(raw.get("extra_search")) if item]
    vlans = [item for item in _as_list(raw.get("vlans")) if isinstance(item, dict)]
    interfaces = _flatten_role_maps(raw.get("interfaces"))
    targets = raw.get("targets") if isinstance(raw.get("targets"), dict) else {}
    normalized_targets: dict[str, list[dict[str, Any]]] = {}
    for role, rows in targets.items():
        normalized_targets[str(role)] = [row for row in _as_list(rows) if isinstance(row, dict)]

    others_grouped: dict[str, dict[str, Any]] = {}
    for role, rows in _flatten_role_maps(raw.get("others")).items():
        merged: dict[str, Any] = {}
        for row in rows:
            merged.update(row)
        others_grouped[role] = merged

    slug = str(raw.get("slug") or path.stem)
    site = raw.get("site")
    site_name = str(site.get("name") if isinstance(site, dict) else site or "")

    return Job(
        slug=slug,
        customer=customer_name,
        customer_id=customer_id,
        site=site_name,
        subnets=subnets,
        extra_search=extra,
        vlans=vlans,
        interfaces=interfaces,
        targets=normalized_targets,
        others=others_grouped,
        raw=raw,
    )
