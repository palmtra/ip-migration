from __future__ import annotations

from ip_discovery.engine import find_hits
from ip_discovery.models import Record
from ip_discovery.tokens import parse_token, token_overlaps, wildcard_to_prefix


def test_host_in_cidr():
    host = parse_token("10.50.12.10")
    cidr = parse_token("10.50.12.0/24")
    assert token_overlaps(host, cidr) == "contained"


def test_overlapping_prefixes():
    left = parse_token("10.50.12.0/24")
    right = parse_token("10.50.0.0/16")
    assert token_overlaps(left, right) == "contained"


def test_range_overlap():
    window = parse_token("10.50.12.10-10.50.12.20")
    host = parse_token("10.50.12.15")
    assert token_overlaps(window, host) == "overlap"


def test_skip_any():
    assert parse_token("any") is None
    assert parse_token("0.0.0.0/0") is None


def test_wildcard_prefix():
    network = wildcard_to_prefix("10.50.12.0", "0.0.0.255")
    assert str(network) == "10.50.12.0/24"


def test_group_expansion_hits_rule():
    records = [
        Record(
            device="fw-palo-01",
            platform="paloalto.panos",
            category="address_object",
            name="H-WEB-01",
            field="value",
            values=("10.50.12.10/32",),
        ),
        Record(
            device="fw-palo-01",
            platform="paloalto.panos",
            category="address_group",
            name="GRP-WEB",
            field="members",
            values=(),
            refs=("H-WEB-01",),
        ),
        Record(
            device="fw-palo-01",
            platform="paloalto.panos",
            category="security_rule",
            name="allow-web",
            field="src/dst",
            values=(),
            refs=("GRP-WEB", "any"),
        ),
        Record(
            device="sw-cisco-01",
            platform="cisco.ios.ios",
            category="arp",
            name="Vlan12:10.50.12.10",
            field="address",
            values=("10.50.12.10",),
            context={"mac": "0050.56ab.1234", "interface": "Vlan12"},
        ),
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    categories = {hit.category for hit in hits}
    assert categories == {"address_object", "address_group", "security_rule", "arp"}
    rule = next(hit for hit in hits if hit.category == "security_rule")
    assert "GRP-WEB" in rule.resolution_path
    assert "H-WEB-01" in rule.resolution_path


def test_device_group_object_overrides_shared():
    records = [
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="address_object",
            name="H-WEB-01",
            field="value",
            values=("10.9.9.9/32",),
            context={"location": "shared", "shared": True},
        ),
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="address_object",
            name="H-WEB-01",
            field="value",
            values=("10.50.12.10/32",),
            context={"location": "device_group", "device_group": "DG-SITE-A", "shared": False},
        ),
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="security_rule",
            name="allow-web",
            field="src/dst",
            values=(),
            refs=("H-WEB-01",),
            context={"location": "device_group", "device_group": "DG-SITE-A", "shared": False},
        ),
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="security_rule",
            name="shared-deny",
            field="src/dst",
            values=(),
            refs=("H-WEB-01",),
            context={"location": "shared", "shared": True},
        ),
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    dg_rule = next(hit for hit in hits if hit.name == "allow-web")
    assert dg_rule.matched_value in {"10.50.12.10", "10.50.12.10/32"}
    assert not any(hit.name == "shared-deny" for hit in hits)
    shared_obj = [hit for hit in hits if hit.category == "address_object" and hit.context.get("shared") is True]
    assert not shared_obj
    dg_obj = next(hit for hit in hits if hit.category == "address_object" and hit.context.get("shared") is False)
    assert dg_obj.context.get("device_group") == "DG-SITE-A"
