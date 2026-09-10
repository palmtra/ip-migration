# IP subnet migration discovery

Discovery is **read-only**. Inputs are:

1. An Ansible inventory of devices (management IP, platform, OS).
2. One or more search CIDRs (`vars/search.yml` or a local copy).
3. Credentials via environment variables.

Everything else is pulled from the devices: VRFs, vsys, interface IPs, ARP,
routes (prefix and next hop), BGP network statements, ACLs, and Palo objects /
NAT / security / GlobalProtect / IPSec. The engineer report is the starting
point for an IP swap review. Swap playbooks are out of scope until discovery
is trusted.

## Why Ansible

Ansible is the collector: inventory, credentials, and first-class collections
for Cisco IOS/NX-OS, Arista EOS, and PAN-OS. Matching nested Palo groups,
CIDR overlap, and a cross-device report is done in `python/ip_discovery`.

## Pipeline

1. Engineer lists devices in inventory and CIDRs in the search file.
2. `playbooks/collect.yml` connects read-only and writes `artifacts/<hostname>/`.
   IOS VRF names and PAN-OS vsys names are discovered on the device, then
   route/ARP/object collection is run for each.
3. `python/analyze_hits.py` matches the search CIDRs, including ARP entries
   and route next hops.
4. `reports/migration-review.yml` plus Markdown/CSV/JSON.

## What is collected

### Cisco IOS / IOS-XE and NX-OS, Arista EOS

Auth: username/password over SSH (`network_cli`).

| Source | Why it matters |
| --- | --- |
| Interfaces | SVIs and routed ports in the old block |
| ARP / ND (all VRFs) | Silent hosts that never appear in config |
| Routes / VRF / BGP | Connected, static, BGP, next hops in the block |
| BGP `network` statements | Advertisements to update during the swap |
| ACLs | Host and network ACEs using the old block |
| Running-config | Fallback and BGP parse |

IOS VRF list is parsed from `show vrf brief` / `show ip vrf`, then
`show ip route vrf <name>` and `show ip arp vrf <name>` run for each VRF.
NX-OS and EOS use `vrf all`.

### Palo Alto PAN-OS

Auth: service account on the XML API. XML API + operational requests, no
commit rights.

Vsys names are discovered (`show vsys` + running config), then objects,
groups, security rules, and NAT are gathered for **each** vsys.

| Source | Swap relevance |
| --- | --- |
| Interfaces | L3 IPs, tunnels, loopbacks |
| Routes / FIB / statics / VR | Next hops and prefixes in the old block |
| ARP | Hosts behind the firewall |
| Address objects / groups | Direct IP/CIDR/range plus nested members |
| Security rules | ACL equivalent |
| NAT | Original and translated addresses |
| IKE / IPSec / proxy IDs | Peers and selectors |
| GlobalProtect | Portal/gateway IPs and pools |

`any` is not a hit.

## Match rules

A search target is a host or prefix. A collected value hits when it is exact,
contained, overlapping, or a contiguous wildcard.

A **route** also hits when its **next hop** is in the search block, even if
the prefix is `0.0.0.0/0`.

ARP entries are matched the same way: any learned host whose IP is in the
CIDR is reported with MAC and interface.

Address groups are expanded recursively.

## Inventory and credentials

```bash
export NETWORK_USERNAME='netops'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='svc-ip-migration'
export PALO_PASSWORD='...'
```

Put real management IPs in `inventories/production/` (gitignored). Do not
commit customer CIDRs, hostnames, or credentials. The sample inventory uses
RFC 5737 documentation addresses only.

Cisco/Arista and Palo must use different accounts.

## Report

`reports/migration-review.yml` is the engineer template: interfaces, VLANs,
firewall objects/NAT/policy/VPN, switch BGP advertisements, ARP, and routes.
Markdown adds ARP and routing tables for review.
