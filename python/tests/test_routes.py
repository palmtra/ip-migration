from ip_discovery.engine import find_hits
from ip_discovery.models import Record
from ip_discovery.routes import parse_ios_routes, parse_palo_routes


def test_ios_connected_and_nexthop_in_block():
    text = """
      63.99.122.176/29 is subnetted, 1 subnets
C        63.99.122.176 is directly connected, Vlan3051
S*    0.0.0.0/0 [1/0] via 63.99.122.179
B        10.20.0.0/16 [20/0] via 63.99.122.177
"""
    routes = parse_ios_routes(text, default_vrf="v0000001a")
    by_prefix = {route.prefix: route for route in routes}
    assert by_prefix["63.99.122.176/29"].protocol == "connected"
    assert by_prefix["0.0.0.0/0"].next_hop == "63.99.122.179"
    assert by_prefix["10.20.0.0/16"].next_hop == "63.99.122.177"
    assert by_prefix["10.20.0.0/16"].vrf == "v0000001a"


def test_palo_static_default_via_handoff():
    text = """
virtual router vsys1
0.0.0.0/0           63.99.122.177   10     A S    ethernet1/1
63.99.122.176/29    63.99.122.179   0      A C    ethernet1/1
"""
    routes = parse_palo_routes(text)
    default = next(route for route in routes if route.prefix == "0.0.0.0/0")
    assert default.protocol == "static"
    assert default.next_hop == "63.99.122.177"
    connected = next(route for route in routes if route.prefix == "63.99.122.176/29")
    assert connected.protocol == "connected"


def test_route_nexthop_is_a_hit():
    records = [
        Record(
            device="pe-oma-01",
            platform="arista.eos.eos",
            category="route",
            name="0.0.0.0/0",
            field="prefix/nexthop",
            values=("63.99.122.179",),
            context={"protocol": "static", "next_hop": "63.99.122.179", "vrf": "v0000001a"},
        )
    ]
    hits = find_hits(records, ["63.99.122.176/29"])
    assert len(hits) == 1
    assert hits[0].matched_value == "63.99.122.179"
    assert hits[0].context["vrf"] == "v0000001a"
