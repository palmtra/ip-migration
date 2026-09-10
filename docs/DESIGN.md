# IP subnet migration discovery

Discovery is a **read-only** pass: Ansible logs into each device, dumps usage
artifacts, then a Python analyzer finds every place a search host or CIDR
appears. Engineers use the report to plan the IP swap. Change/swap playbooks
are out of scope until discovery is trustworthy.

## Why Ansible

Ansible is the right collector for this team and these platforms:

- Inventory is already a list of management IPs.
- First-class collections exist for Cisco IOS/NX-OS, Arista EOS, and PAN-OS.
- Username/password for switches maps to `network_cli`. Palo service account
  maps to the PAN-OS XML API (`provider` username/password or API key).
- Collection is embarrassingly parallel (`forks`) and stays read-only if we
  never call commit or configuration `state: present`.

Ansible is a weak matcher. Nested Palo address groups, CIDR overlap, wildcard
ACEs, and a cross-device report are painful in Jinja. That work lives in
`python/ip_discovery`.

Do not replace this with a Palo GUI export plus switch `show run` greps. That
misses ARP, FIB, NAT translated addresses, IKE peers, and nested groups.

## Alternatives considered

| Option | When it is better | Why not first |
| --- | --- | --- |
| Nornir + Scrapli/pan-os-python | You want one Python codebase and custom parsers | More plumbing; this repo is already an Ansible workspace |
| PAN-OS SDK only | Firewall-only scope | Does not cover Cisco/Arista ARP and ACLs |
| Batfish | Offline ACL/reachability proofs | No live ARP, no GP runtime, no IKE SA |
| pyATS/Genie | Deep Cisco parsing | Weak Palo coverage |
| IPAM/NetBox only | Source of truth already complete | It will not see undocumented ARP, NAT, or VPN peers |

Nornir remains the fallback if Ansible collection modules prove too coarse for
GlobalProtect or Panorama templates. The analyzer interface does not care how
artifacts were produced.

## Pipeline

1. Engineer lists device IPs in inventory and CIDRs/hosts in `vars/search.yml`.
2. `playbooks/collect.yml` connects to every in-scope device and writes
   `artifacts/<hostname>/`.
3. `python/analyze_hits.py` normalizes artifacts, expands object groups, and
   matches search targets.
4. Report lands in `reports/` as Markdown (engineer), CSV (spreadsheet), and
   JSON (later swap automation).

Re-run analysis without touching devices via `playbooks/report.yml`.

## What is collected

### Cisco IOS / IOS-XE and NX-OS

Auth: `ansible_user` / `ansible_password` over SSH (`network_cli`). Enable
secret is optional (`ansible_become`).

| Source | Why it matters for a swap |
| --- | --- |
| Interface IPv4/IPv6 | SVIs and routed ports in the old block |
| ARP / ND | Silent hosts that never appear in config |
| Routes | Connected, static, and learned prefixes |
| ACLs | Host and network ACEs using the old block |
| Running-config | Fallback evidence for anything parsers miss |

### Arista EOS

Same categories as Cisco. Commands use `| json` so parsing stays structured.

### Palo Alto PAN-OS

Auth: service account via XML API. Prefer a dedicated local or Panorama admin
with **XML API + Operational Requests**, no commit rights. Username/password
is enough; modules generate a session key. A long-lived API key
(`PALO_API_KEY`) is optional.

| Source | Module / command | Swap relevance |
| --- | --- | --- |
| Interfaces | `show interface all` | L3 IPs, HA, tunnels, loopbacks |
| Routes | `show routing route` | VR statics and FIB |
| ARP | `show arp all` | Hosts behind the firewall |
| Address objects | `panos_address_object` `state=gathered` | Direct IP/CIDR/range/wildcard |
| Address groups | `panos_address_group` | Nested members used by policy |
| Security rules | `panos_security_rule` | ACL equivalent |
| NAT rules | `panos_nat_rule2` | Original and translated addresses |
| IKE gateways | `panos_ike_gateway` | Local/peer IPs |
| IPSec tunnels + proxy IDs | `panos_ipsec_tunnel`, `panos_ipsec_ipv4_proxyid` | Interesting traffic selectors |
| GlobalProtect | running-config slice + `show global-protect-gateway current-user` | Portal/gateway IPs and pools |

`any` is intentionally not a hit. Matching `any` would flag every rule.

## Match rules

A search target may be a host (`10.50.12.10`) or a prefix (`10.50.12.0/24`).

A collected value hits when it is:

- exact equal
- contained in the other (host in CIDR, or more-specific prefix)
- overlapping CIDR or IP range
- a Cisco/Palo wildcard that converts to a contiguous prefix

Address groups are expanded recursively. A security/NAT rule that references
`GRP-WEB` is reported with a resolution path such as
`GRP-WEB > H-WEB-01`.

FQDN objects are recorded as unresolved; they need DNS or a later pass.

## Inventory and credentials

Copy `inventories/sample/` and replace the RFC 5737 placeholders.

```bash
export NETWORK_USERNAME='netops'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='svc-ip-migration'
export PALO_PASSWORD='...'
# optional
export PALO_API_KEY='...'
```

Do not store passwords in git. Ansible Vault can replace the env lookups later.

Cisco/Arista and Palo **must** use different accounts. The Palo service account
should not have SSH to switches, and switch TACACS users should not have
firewall commit rights.

## Report

Each hit includes device, category, object name, matched value, search term,
match kind, and group resolution path. That is the working list for swapping
IPs: change the object once, then confirm every rule/NAT/VPN that referenced
it.

## Open decisions

These change collectors, not the overall shape:

1. **Panorama vs local.** If policy lives on Panorama, inventory Panorama (and
   device groups / templates) as well as the firewalls. Firewalls still supply
   ARP, FIB, and interface state.
2. **Multi-vsys.** Default is `vsys1`. Set `palo_vsys` per host or loop later.
3. **Catalyst vs Nexus mix.** Already modeled via `ansible_network_os`.
4. **Management-plane IPs.** NTP, syslog, SNMP, RADIUS, DNS, User-ID agents are
   easy to miss. Add as a second collector after the policy/ARP pass.
5. **IPv6.** Parsers accept it; Cisco/Arista collect ND and IPv6 routes.

## Implementation order

1. This skeleton + analyzer tests (done).
2. Lab run against one IOS, one EOS, one PAN-OS box; fix parsers from real
   artifacts.
3. Panorama / vsys if the lab proves they are in path.
4. GP xpath parse instead of IP scrape from config text.
5. Swap playbooks that consume `reports/discovery.json`.
