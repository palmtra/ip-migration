from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Record:
    """A normalized configuration or operational item that may contain IPs."""

    device: str
    platform: str
    category: str
    name: str
    field: str
    values: tuple[str, ...]
    context: dict[str, Any] = field(default_factory=dict)
    refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hit:
    device: str
    platform: str
    category: str
    name: str
    field: str
    matched_value: str
    search_term: str
    match_kind: str
    resolution_path: tuple[str, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "platform": self.platform,
            "category": self.category,
            "name": self.name,
            "field": self.field,
            "matched_value": self.matched_value,
            "search_term": self.search_term,
            "match_kind": self.match_kind,
            "resolution_path": list(self.resolution_path),
            "context": self.context,
        }
