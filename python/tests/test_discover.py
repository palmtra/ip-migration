from ip_discovery.discover import parse_panorama_devices, parse_vrf_names, parse_vsys_names


def test_parse_ios_vrf_brief():
    text = """
Name                             Default RD            Protocols         Interfaces
Mgmt-vrf                         <not set>             ipv4,ipv6         Gi1
tenant-a                         65000:1               ipv4              Vl12
tenant-b                         192.0.2.1:10          ipv4              Vl13
"""
    assert parse_vrf_names(text) == ["Mgmt-vrf", "tenant-a", "tenant-b"]


def test_parse_vsys_xml_and_fallback():
    xml = """
<vsys>
  <entry name="vsys1">
    <zone>
      <entry name="trust"/>
    </zone>
  </entry>
  <entry name="tenant-fw">
    <import/>
  </entry>
</vsys>
"""
    names = parse_vsys_names(xml)
    assert "vsys1" in names
    assert "tenant-fw" in names
    assert "trust" not in names
    assert parse_vsys_names("") == ["vsys1"]


def test_parse_panorama_devices_xml():
    xml = """
<response>
  <result>
    <devices>
      <entry name="012345678901">
        <serial>012345678901</serial>
        <connected>yes</connected>
        <hostname>fw-site-a</hostname>
        <vsys>
          <entry name="vsys1">
            <display-name>vsys1</display-name>
          </entry>
        </vsys>
      </entry>
      <entry name="012345678902">
        <serial>012345678902</serial>
        <connected>no</connected>
        <hostname>fw-offline</hostname>
      </entry>
    </devices>
  </result>
</response>
"""
    devices = parse_panorama_devices(xml)
    serials = {item["serial"] for item in devices}
    assert "012345678901" in serials
    assert "012345678902" not in serials
    live = next(item for item in devices if item["serial"] == "012345678901")
    assert live["hostname"] == "fw-site-a"
