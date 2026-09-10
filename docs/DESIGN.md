# IP subnet migration discovery

Operators: [USERGUIDE.md](USERGUIDE.md) is the how-to (customer, ID, site,
CIDR, inventory, Panorama group and template). This document is the design.

Discovery is **read-only**. Inputs are:

1. An Ansible inventory of devices (management IP, platform, OS).
2. One or more search CIDRs in `vars/search/<id>-<site>-<customer>.yml`.
3. Credentials via environment variables.

Everything else is pulled from the devices: VRFs, interface IPs, ARP,
routes (prefix and next hop), BGP network statements, ACLs, and Panorama
objects / NAT / security / GlobalProtect / IPSec. The engineer report is
the starting point for an IP swap review. Swap playbooks are out of scope
until discovery is trusted.

## Why Ansible

Ansible is the collector: inventory, credentials, and first-class collections
for Cisco IOS/NX-OS, Arista EOS, and PAN-OS. Matching nested Palo groups,
CIDR overlap, and a cross-device report is done in `python/ip_discovery`.

## Pipeline

1. Engineer lists devices in inventory (OS groups, per-site children, Panorama
   address) and CIDRs plus Panorama device groups/templates in one file per
   customer (`vars/search/<id>-<site>-<customer>.yml`, selected with
   `-e search_job=`). Connection settings stay in group_vars.
2. `playbooks/collect.yml` connects read-only and writes `artifacts/<hostname>/`.
   IOS VRF names are discovered on the device. Panorama objects are gathered
   from **shared**, each listed **device group**, and each listed **template**.
3. `python/analyze_hits.py` matches the search CIDRs, including ARP entries
   and route next hops, and records whether a Palo object is shared.
4. `reports/<cidr>/migration-review.yml` plus Markdown/CSV/JSON in the same
   folder. The CIDR folder replaces `.` with `-` and `/` with `_`
   (`10.200.100.10/30` → `reports/10-200-100-10_30/`).

## What is collected

### Cisco IOS / IOS-XE and NX-OS, Arista EOS

Auth: username/password over SSH (`network_cli`).

| Source | Why it matters |
| --- | --- |
| Interfaces | SVIs, VARP virtual IPs, routed ports |
| ARP / ND (all VRFs) | Silent hosts that never appear in config |
| Routes / VRF / BGP | Connected, static, BGP, next hops in the block |
| BGP `network` statements | Advertisements to update during the swap |
| Prefix-lists | Export filters that still permit the old block |
| ACLs | Host and network ACEs using the old block |
| MLAG | Peer-address only if it sits in the search CIDR |

IOS VRF list is parsed from `show vrf brief` / `show ip vrf`, then
`show ip route vrf <name>` and `show ip arp vrf <name>` run for each VRF.
NX-OS and EOS use `vrf all`.

### Palo Alto via Panorama

Auth: service account on the Panorama XML API. XML API + operational
requests, no commit rights. Discovery talks to **Panorama**, not to
firewalls directly.

Customer search file (`vars/search/<id>-<site>-<customer>.yml`):

| Variable | Purpose |
| --- | --- |
| `palo_device_groups` | Device groups whose objects, groups, security, and NAT to gather |
| `palo_templates` | Templates for interfaces, VR, statics, IKE, IPSec |
| `palo_template_stacks` | Optional stacks (same network objects) |
| `palo_serials` | Optional firewall serials for ARP/FIB/live routes via Panorama targeting |

If `palo_serials` is empty, serials are taken from `show devices all`.

Each gathered object is tagged with:

- `shared: true` when it lives in Panorama **Shared**
- `shared: false` plus `device_group`, `template`, or `template_stack`

Device-group objects override shared objects of the same name when expanding
groups and policies. Pre-rulebase and post-rulebase are both collected.

| Source | Swap relevance |
| --- | --- |
| Template interfaces | L3 IPs, tunnels, loopbacks |
| Template routes / VR / statics | Next hops and prefixes in the old block |
| ARP via Panorama serial targeting | Hosts behind the firewall |
| Shared + DG address objects / groups | Direct IP/CIDR/range plus nested members |
| Shared + DG security rules | ACL equivalent (pre and post) |
| Shared + DG NAT | Original and translated addresses |
| Template IKE / IPSec / proxy IDs | Peers and selectors |
| GlobalProtect | Portal/gateway IPs and pools |

`any` is not a hit.

Standalone firewall collection (`palo_is_panorama: false`) remains as a
fallback and still walks vsys.

## Match rules

A search target is a host or prefix. A collected value hits when it is exact,
contained, overlapping, or a contiguous wildcard.

A **route** also hits when its **next hop** is in the search block, even if
the prefix is `0.0.0.0/0`.

ARP entries are matched the same way: any learned host whose IP is in the
CIDR is reported with MAC and interface.

Address groups are expanded recursively. A name defined in a device group
wins over the same name in Shared.

## Inventory and credentials

```bash
export NETWORK_USERNAME='netops'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='svc-ip-migration'
export PALO_PASSWORD='...'
```

Put real management IPs in `inventories/production/` (gitignored). Do not
commit customer CIDRs, hostnames, or credentials. The sample inventory uses
RFC 5737 documentation addresses and placeholder device-group / template
names only.

Cisco/Arista and Palo must use different accounts.

## Report

Each search CIDR gets its own folder:

`reports/10-200-100-10_30/migration-review.yml` (`.` → `-`, `/` → `_`).

That YAML is the engineer template: interfaces, VLANs, firewall
objects/NAT/policy/VPN, switch BGP advertisements, ARP, and routes.
Each Palo hit includes `shared` and `location` / `device_group` / `template`.
Markdown adds ARP and routing tables for review.
