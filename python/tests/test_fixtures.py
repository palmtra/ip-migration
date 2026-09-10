from pathlib import Path

from ip_discovery.engine import find_hits
from ip_discovery.load import load_all_records

FIXTURES = Path(__file__).parent / "fixtures" / "artifacts"


def test_fixture_artifacts_find_block_usage():
    records = load_all_records(FIXTURES)
    hits = find_hits(records, ["10.50.12.0/24"])
    devices = {hit.device for hit in hits}
    assert devices == {"sw-cisco-01", "fw-palo-01"}
    categories = {hit.category for hit in hits}
    assert "arp" in categories
    assert "interface" in categories
    assert "acl" in categories
    assert "address_object" in categories
    assert "nat_rule" in categories
    assert "ike_gateway" in categories
    assert "route" in categories
    assert "bgp_advertisement" in categories
    assert any(
        hit.category == "route" and hit.matched_value in {"10.50.12.1", "10.50.12.10", "10.50.12.0/24", "10.50.12.2"}
        for hit in hits
    )
    assert not any(hit.matched_value.startswith("10.9.9.") for hit in hits)


def test_single_host_hits_arp_and_object():
    records = load_all_records(FIXTURES)
    hits = find_hits(records, ["10.50.12.10"])
    assert any(hit.category == "arp" and hit.device == "sw-cisco-01" for hit in hits)
    assert any(hit.name == "H-WEB-01" for hit in hits)
    assert any(hit.name == "allow-web" for hit in hits)
    assert any(hit.category == "address_object" and hit.context.get("shared") is True for hit in hits)
    assert any(
        hit.category == "address_object"
        and hit.context.get("shared") is False
        and hit.context.get("device_group") == "DG-SITE-A"
        for hit in hits
    )
