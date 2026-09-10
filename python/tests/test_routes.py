from ip_discovery.engine import find_hits
from ip_discovery.models import Record
from ip_discovery.routes import parse_ios_routes, parse_palo_routes


def test_ios_connected_and_nexthop_in_block():
    text = """
      10.50.12.0/24 is subnetted, 1 subnets
C        10.50.12.0 is directly connected, Vlan12
S*    0.0.0.0/0 [1/0] via 10.50.12.2
B        10.20.0.0/16 [20/0] via 10.50.12.10
"""
    routes = parse_ios_routes(text, default_vrf="tenant-a")
    by_prefix = {route.prefix: route for route in routes}
    assert by_prefix["10.50.12.0/24"].protocol == "connected"
    assert by_prefix["0.0.0.0/0"].next_hop == "10.50.12.2"
    assert by_prefix["10.20.0.0/16"].next_hop == "10.50.12.10"
    assert by_prefix["10.20.0.0/16"].vrf == "tenant-a"


def test_palo_static_default_via_handoff():
    text = """
virtual router vsys1
0.0.0.0/0           10.50.12.2      10     A S    ethernet1/1
10.50.12.0/24       10.50.12.2      0      A C    ethernet1/1
"""
    routes = parse_palo_routes(text)
    default = next(route for route in routes if route.prefix == "0.0.0.0/0")
    assert default.protocol == "static"
    assert default.next_hop == "10.50.12.2"
    connected = next(route for route in routes if route.prefix == "10.50.12.0/24")
    assert connected.protocol == "connected"


def test_route_nexthop_is_a_hit():
    records = [
        Record(
            device="pe-eos-01",
            platform="arista.eos.eos",
            category="route",
            name="0.0.0.0/0",
            field="prefix/nexthop",
            values=("10.50.12.2",),
            context={"protocol": "static", "next_hop": "10.50.12.2", "vrf": "tenant-a"},
        )
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    assert len(hits) == 1
    assert hits[0].matched_value == "10.50.12.2"
    assert hits[0].context["vrf"] == "tenant-a"
