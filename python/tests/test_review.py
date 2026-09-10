from ip_discovery.engine import find_hits
from ip_discovery.models import Record
from ip_discovery.review import build_review


def test_review_includes_switch_bgp_and_arp():
    records = [
        Record(
            device="pe-eos-01",
            platform="arista.eos.eos",
            category="bgp_advertisement",
            name="tenant-a:10.50.12.0/24",
            field="network",
            values=("10.50.12.0/24",),
            context={"asn": "65000", "vrf": "tenant-a"},
        ),
        Record(
            device="pe-eos-01",
            platform="arista.eos.eos",
            category="arp",
            name="Vlan12:10.50.12.10",
            field="address",
            values=("10.50.12.10",),
            context={"mac": "0000.5e00.5301", "interface": "Vlan12"},
        ),
        Record(
            device="fw-panos-01",
            platform="paloalto.panos",
            category="interface",
            name="ethernet1/1",
            field="address",
            values=("10.50.12.2/24",),
            context={"vsys": "vsys1"},
        ),
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    review = build_review(hits, ["10.50.12.0/24"])
    switch = review["others"][1]["switch"][0]
    assert switch["name"] == "pe-eos-01"
    assert switch["bgp"][0]["asn"] == 65000
    assert switch["bgp"][0]["vrf"] == "tenant-a"
    assert "10.50.12.0/24" in switch["bgp"][0]["advertisements"]
    assert switch["arp"]
    assert any("firewall" in item for item in review["interfaces"])


def test_review_marks_shared_versus_device_group():
    records = [
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="address_object",
            name="H-SHARED",
            field="value",
            values=("10.50.12.10/32",),
            context={"location": "shared", "shared": True},
        ),
        Record(
            device="panorama-01",
            platform="paloalto.panos",
            category="address_object",
            name="H-DG",
            field="value",
            values=("10.50.12.11/32",),
            context={"location": "device_group", "device_group": "DG-SITE-A", "shared": False},
        ),
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    review = build_review(hits, ["10.50.12.0/24"])
    objects = review["others"][0]["firewall"]["object"]
    shared = next(item for item in objects if item["name"] == "H-SHARED")
    dg = next(item for item in objects if item["name"] == "H-DG")
    assert shared["shared"] is True
    assert shared["location"] == "shared"
    assert dg["shared"] is False
    assert dg["device_group"] == "DG-SITE-A"
