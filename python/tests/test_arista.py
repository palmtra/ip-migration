from ip_discovery.adapters.arista import parse_eos_running_interfaces, records_from_arista
from ip_discovery.engine import find_hits
from ip_discovery.models import Record
from ip_discovery.review import build_review


def test_parse_eos_varp_from_running_config():
    config = """
hostname DC1-LEAF01
ip virtual-router mac-address 001c.7300.0099
interface Vlan110
   description servers
   vrf TenantA
   ip address 10.50.12.2/24
   ip virtual-router address 10.50.12.1
interface Ethernet1
   no switchport
   ip address 192.0.2.1/31
"""
    items = {item["name"]: item for item in parse_eos_running_interfaces(config)}
    assert items["Vlan110"]["addresses"] == ["10.50.12.2/24"]
    assert items["Vlan110"]["virtual"] == ["10.50.12.1"]
    assert items["Vlan110"]["vrf"] == "TenantA"
    assert items["Ethernet1"]["addresses"] == ["192.0.2.1/31"]


def test_mlag_varp_pair_hits_shared_gateway_and_unique_svi():
    records = [
        Record(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="interface",
            name="Vlan110",
            field="address",
            values=("10.50.12.2/24",),
        ),
        Record(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="interface",
            name="Vlan110",
            field="varp",
            values=("10.50.12.1",),
            context={"virtual": True, "role": "varp"},
        ),
        Record(
            device="DC1-LEAF02",
            platform="arista.eos.eos",
            category="interface",
            name="Vlan110",
            field="address",
            values=("10.50.12.3/24",),
        ),
        Record(
            device="DC1-LEAF02",
            platform="arista.eos.eos",
            category="interface",
            name="Vlan110",
            field="varp",
            values=("10.50.12.1",),
            context={"virtual": True, "role": "varp"},
        ),
        Record(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="bgp_advertisement",
            name="TenantA:10.50.12.0/24",
            field="network",
            values=("10.50.12.0/24",),
            context={"asn": "65101", "vrf": "TenantA"},
        ),
        Record(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="arp",
            name="Vlan110:10.50.12.10",
            field="address",
            values=("10.50.12.10",),
            context={"mac": "0000.5e00.5301", "interface": "Vlan110"},
        ),
    ]
    hits = find_hits(records, ["10.50.12.0/24"])
    review = build_review(hits, ["10.50.12.0/24"])
    iface_rows = review["interfaces"]
    assert any(item["switch"]["address"] == "10.50.12.2/24" and item["switch"]["device"] == "DC1-LEAF01" for item in iface_rows)
    assert any(item["switch"]["address"] == "10.50.12.3/24" and item["switch"]["device"] == "DC1-LEAF02" for item in iface_rows)
    assert any(item["switch"]["address"] == "10.50.12.1" and item["switch"].get("virtual") is True for item in iface_rows)
    leaf = next(item for item in review["others"][1]["switch"] if item["name"] == "DC1-LEAF01")
    assert "10.50.12.0/24" in leaf["bgp"][0]["advertisements"]
    assert leaf["arp"]


def test_varp_json_and_mlag_from_show_commands(tmp_path):
    device_dir = tmp_path / "DC1-LEAF01"
    device_dir.mkdir()
    (device_dir / "meta.json").write_text(
        '{"device":"DC1-LEAF01","platform":"arista.eos.eos","vendor":"arista"}',
        encoding="utf-8",
    )
    show = {
        "commands": [
            "show ip virtual-router | json",
            "show mlag | json",
            "show running-config",
        ],
        "stdout": [
            {
                "virtualRouters": {
                    "Vlan110": {
                        "interface": "Vlan110",
                        "address": "10.50.12.1",
                        "macAddress": "00:1c:73:00:00:99",
                    }
                }
            },
            {"domainId": "DC1", "peerAddress": "10.255.1.2", "localInterface": "Vlan4094"},
            "interface Vlan110\n   ip address 10.50.12.2/24\n   ip virtual-router address 10.50.12.1\n",
        ],
        "invocation": {
            "module_args": {
                "commands": [
                    "show ip virtual-router | json",
                    "show mlag | json",
                    "show running-config",
                ]
            }
        },
    }
    import json

    (device_dir / "show_commands.json").write_text(json.dumps(show), encoding="utf-8")
    records = records_from_arista(device_dir, "DC1-LEAF01", "arista.eos.eos")
    assert any(record.field == "varp" and "10.50.12.1" in record.values for record in records)
    assert any(record.category == "mlag" and "10.255.1.2" in record.values for record in records)
    assert any(record.field == "address" and "10.50.12.2/24" in record.values for record in records)


def test_eos_cli_dump_finds_varp_arp_bgp_and_prefix_list(tmp_path):
    from ip_discovery.eos_dump import write_eos_dump_artifact
    from ip_discovery.load import load_device_records

    dump = tmp_path / "DC1-LEAF01.txt"
    dump.write_text(
        """
hostname DC1-LEAF01
vrf instance PROD_BLUE
ip virtual-router mac-address 001c.7300.0064
interface Vlan100
   vrf PROD_BLUE
   ip address 192.0.2.66/28
   ip virtual-router address 192.0.2.65
ip prefix-list PL-PROD-BLUE-EXPORT seq 10 permit 192.0.2.64/28
router bgp 65100
   vrf PROD_BLUE
      network 192.0.2.64/28
end
DC1-LEAF01#show mlag
domain-id                          : MLAG-RACK-07
peer-address                       : 169.254.0.2
DC1-LEAF01#show ip arp vrf PROD_BLUE
Address         Age (sec)  Hardware Addr   Interface
192.0.2.70      0:00:18    0050.56aa.1001  Vlan100, Port-Channel10
DC1-LEAF01#show ip route vrf PROD_BLUE 192.0.2.64/28
VRF: PROD_BLUE
 C        192.0.2.64/28 is directly connected, Vlan100
DC1-LEAF01#show ip bgp neighbors 203.0.113.1 vrf PROD_BLUE advertised-routes
 *>     192.0.2.64/28          203.0.113.2           0       100     0       i
""",
        encoding="utf-8",
    )
    device_dir = write_eos_dump_artifact(dump, tmp_path / "artifacts")
    records = load_device_records(device_dir)
    hits = find_hits(records, ["192.0.2.64/28"])
    categories = {hit.category for hit in hits}
    assert "interface" in categories
    assert "arp" in categories
    assert "route" in categories
    assert "bgp_advertisement" in categories
    assert "prefix_list" in categories
    assert any(hit.field == "varp" and hit.matched_value == "192.0.2.65" for hit in hits)
    assert any(hit.device == "DC1-LEAF01" and hit.matched_value == "192.0.2.66/28" for hit in hits)
    assert not any(hit.category == "mlag" for hit in hits)

