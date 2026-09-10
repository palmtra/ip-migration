# User guide: run IP migration discovery

This is the operator walkthrough. You already know the **customer**, **ticket/ID**, **data centre**, **IP block**, the **switches/PEs to log into** (with OS), and the **Panorama device group plus template**. Discovery is read-only: it logs in, finds every use of that block, and writes a review. It does not change config.

Match rules and collector internals are in [DESIGN.md](DESIGN.md).

## 1. What you need (minimum)

| You have | Where it goes |
| --- | --- |
| Customer name | `vars/search.local.yml` → `customer` |
| Customer / ticket ID | `vars/search.local.yml` → `id` |
| Data centre name | `vars/search.local.yml` → `site` |
| IP block(s) to find | `vars/search.local.yml` → `search_targets` |
| Each target device hostname + management IP + OS | `inventories/production/hosts.yml` |
| Panorama management IP | same inventory, `paloalto` group |
| Panorama **device group(s)** | `palo_device_groups` on the Panorama host |
| Panorama **template(s)** | `palo_templates` (and stacks if you use them) |

OS values the inventory understands:

| Device OS | Inventory group | Host variable |
| --- | --- | --- |
| Cisco IOS / IOS-XE | `cisco` | `ansible_network_os: cisco.ios.ios` (group default) |
| Cisco NX-OS | `cisco` | `ansible_network_os: cisco.nxos.nxos` |
| Arista EOS | `arista` | `ansible_network_os: arista.eos.eos` |
| Palo Alto (Panorama-managed) | `paloalto` | `palo_is_panorama: true` — do **not** SSH the firewalls |

Only list devices that should be searched. Discovery does not crawl the rest of the estate.

## 2. Critical extras (easy to miss)

These are required in practice even if they were not on the intake form:

1. **Management IPs** for every switch/PE and for **Panorama** (not the dataplane). The control node must reach SSH `22` on Cisco/Arista and HTTPS `443` on Panorama.
2. **Two accounts**, not one:
   - `NETWORK_USERNAME` / `NETWORK_PASSWORD` — SSH to Cisco and Arista (`network_cli`).
   - `PALO_USERNAME` / `PALO_PASSWORD` (or `PALO_API_KEY`) — Panorama XML API. Use a service account with **no commit** rights.
3. **Every device group that can hold the objects**, including child groups. A parent group does not pull child-group objects.
4. **Templates for network/VPN** (interfaces, VARP-equivalent is on switches; on Palo: VR, statics, IKE, IPSec). Policy lives in device groups; interfaces/IKE live in templates. If you use **template stacks**, set `palo_template_stacks` as well.
5. **Python 3 venv + Ansible collections** on the machine that runs the playbook (see setup below).
6. **Do not commit** production inventory, CIDRs, or passwords. `inventories/production/` and `vars/search.local.yml` are gitignored.

Optional, but fill them if you have them:

| Extra | Why |
| --- | --- |
| `palo_serials` | Firewall serials so Panorama can pull live ARP/FIB. If empty, discovery uses `show devices all`. |
| `palo_template_stacks` | Stack-level network objects. |
| Enable / become password | Only if IOS/EOS login lands in exec and needs `enable`. Default is `ansible_become: false`. |
| Several CIDRs | Each block gets its own report folder. |

## 3. One-time setup on the control node

```bash
cd /path/to/ip-migration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

Copy the sample files once (production copies stay local):

```bash
mkdir -p inventories/production/group_vars
cp inventories/sample/hosts.yml inventories/production/hosts.yml
cp inventories/sample/group_vars/*.yml inventories/production/group_vars/
cp vars/search.yml vars/search.local.yml
```

## 4. Worked example

Intake:

- Customer: `Example Retail`
- ID: `INC-1042`
- Data centre: `DC1`
- IP block: `10.200.100.0/24`
- Devices: two EOS MLAG leaves, one IOS access switch, one NX-OS core, Panorama
- Panorama device group: `DG-DC1-PROD`
- Panorama template: `TPL-DC1-NETWORK`

### 4.1 Search file — `vars/search.local.yml`

```yaml
search_targets:
  - 10.200.100.0/24
customer: Example Retail
id: INC-1042
site: DC1
```

Add more CIDRs under `search_targets` if this ticket covers more than one block. Each CIDR is reported separately.

A host such as `10.200.100.10` or a `/30` is valid. `any` and `0.0.0.0/0` are ignored.

### 4.2 Inventory — `inventories/production/hosts.yml`

Use real management IPs. Hostnames can be the device hostname or any inventory name you will recognise in the report.

```yaml
all:
  children:
    switches:
      children:
        cisco:
          hosts:
            dc1-acc-01:
              ansible_host: 10.0.0.11
              ansible_network_os: cisco.ios.ios
            dc1-core-01:
              ansible_host: 10.0.0.12
              ansible_network_os: cisco.nxos.nxos
        arista:
          hosts:
            DC1-LEAF01:
              ansible_host: 10.0.0.21
              ansible_network_os: arista.eos.eos
            DC1-LEAF02:
              ansible_host: 10.0.0.22
              ansible_network_os: arista.eos.eos
    firewalls:
      children:
        paloalto:
          hosts:
            panorama-01:
              ansible_host: 10.0.0.30
              palo_is_panorama: true
              palo_device_groups:
                - DG-DC1-PROD
              palo_templates:
                - TPL-DC1-NETWORK
              palo_template_stacks: []
              palo_serials: []
```

Leave out groups you do not have. A switch-only job can omit `firewalls`. A firewall-only job can omit `switches`.

NX-OS **must** set `ansible_network_os: cisco.nxos.nxos`. IOS can omit it because the `cisco` group defaults to IOS.

### 4.3 Credentials (environment, not files)

```bash
export NETWORK_USERNAME='netops'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='svc-ip-migration'
export PALO_PASSWORD='...'
# optional instead of username/password on Panorama:
# export PALO_API_KEY='...'
```

## 5. Run discovery

From the repo root, with the venv active:

```bash
ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_file="$PWD/vars/search.local.yml"
```

That logs into every host in the inventory, then writes reports.

Limit to this customer's devices if the inventory file also holds other sites:

```bash
ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_file="$PWD/vars/search.local.yml" \
  -l 'DC1-LEAF01,DC1-LEAF02,dc1-acc-01,dc1-core-01,panorama-01'
```

Collection is read-only: no PAN-OS commit, no `state: present`.

## 6. Where the output goes

For `10.200.100.0/24` the folder name replaces `.` with `-` and `/` with `_`:

```text
reports/10-200-100-0_24/
  migration-review.yml   ← start here
  discovery.md
  discovery.csv
  discovery.json
```

`10.200.100.10/30` would be `reports/10-200-100-10_30/`.

Raw per-device CLI/API dumps stay in `artifacts/<hostname>/` (gitignored). Re-run analysis without logging in again:

```bash
ansible-playbook playbooks/report.yml \
  -i inventories/production/hosts.yml \
  -e search_file="$PWD/vars/search.local.yml"
```

## 7. How to read `migration-review.yml`

Header should show the labels you entered (`customer`, `id`, `site`) and the CIDR.

Typical switch/MLAG findings:

- VLAN and SVI addresses (unique per leaf)
- VARP virtual IP (`virtual: true`, same on both MLAG peers)
- ARP of hosts in the block
- Connected/static/BGP routes, including **next hops** in the block
- BGP `network` / advertised prefixes
- Prefix-lists that permit the block

Typical Panorama findings:

- Address objects and groups, with `shared: true` or `device_group: DG-DC1-PROD`
- NAT and security rules (pre- and post-rulebase)
- Template interfaces, IKE, IPSec (`shared: false`, `template: TPL-DC1-NETWORK`)

Transit links, MLAG keepalives, and loopbacks **outside** the search CIDR are omitted on purpose.

## 8. If something is missing

| Symptom | Check |
| --- | --- |
| Playbook cannot SSH | Management IP, VRF of mgmt, username/password, SSH from the control node |
| NX-OS collected as IOS | Host has `ansible_network_os: cisco.nxos.nxos` |
| No Palo objects | Panorama IP, API account, `palo_device_groups` names exactly as on Panorama |
| No Palo interfaces / IKE | `palo_templates` or `palo_template_stacks` |
| Shared vs DG looks wrong | You listed each device group; child groups are not inherited automatically |
| No ARP on firewalls | Panorama can reach managed devices; set `palo_serials` if auto-discovery is empty |
| Empty report | CIDR does not appear on the listed devices, or `search_targets` was left as the sample `192.0.2.0/24` |
| Enable password required | Set become on that host/group (default is off) |

## 9. What this does *not* do

- It does not log into Palo Alto firewalls directly; only Panorama.
- It does not push, commit, or swap IPs.
- It does not invent devices you did not put in inventory.
- VRF and vsys names are discovered on the boxes; you do not pre-list them.
