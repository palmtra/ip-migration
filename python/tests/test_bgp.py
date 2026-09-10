from ip_discovery.bgp import parse_running_config_bgp
from ip_discovery.engine import find_hits
from ip_discovery.models import Record


def test_parse_vrf_network_statements():
    config = """
router bgp 65000
   vrf tenant-a
      neighbor 10.50.12.2 remote-as 65001
      network 10.50.12.0/24
      network 10.50.12.0 mask 255.255.255.252
"""
    advertisements, neighbors = parse_running_config_bgp(config)
    prefixes = {item.prefix for item in advertisements}
    assert "10.50.12.0/24" in prefixes
    assert "10.50.12.0/30" in prefixes
    assert all(item.asn == "65000" and item.vrf == "tenant-a" for item in advertisements)
    assert neighbors[0].peer == "10.50.12.2"
    assert neighbors[0].remote_as == "65001"


def test_bgp_advertisement_hit():
    records = [
        Record(
            device="pe-eos-01",
            platform="arista.eos.eos",
            category="bgp_advertisement",
            name="tenant-a:10.50.12.0/24",
            field="network",
            values=("10.50.12.0/24",),
            context={"asn": "65000", "vrf": "tenant-a"},
        )
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    assert len(hits) == 1
    assert hits[0].category == "bgp_advertisement"
