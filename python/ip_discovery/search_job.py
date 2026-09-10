from __future__ import annotations

import re

_SPACE = re.compile(r"\s+")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_DASHES = re.compile(r"-{2,}")


def slug_part(value: str) -> str:
    text = _SPACE.sub("-", (value or "").strip())
    text = _UNSAFE.sub("-", text)
    text = _DASHES.sub("-", text)
    return text.strip("-.")


def search_job_name(customer_id: str, site: str, customer: str) -> str:
    """Stem for vars/search/<id>-<site>-<customer>.yml."""
    parts = [slug_part(customer_id), slug_part(site), slug_part(customer)]
    if not all(parts):
        raise ValueError("customer id, site, and customer name are all required")
    return "-".join(parts)


def search_filename(customer_id: str, site: str, customer: str) -> str:
    return f"{search_job_name(customer_id, site, customer)}.yml"
