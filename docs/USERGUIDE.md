# User guide: run IP migration discovery

This is the operator walkthrough. You already know the **customer**, **ticket/ID**, **data centre**, **IP block**, the **switches/PEs to log into** (with OS), and the **Panorama device group plus template**. Discovery is read-only: it logs in, finds every use of that block, and writes a review. It does not change config.

Match rules and collector internals are in [DESIGN.md](DESIGN.md).

## 1. What you need (minimum)

| You have | Where it goes |
| --- | --- |
| Customer name, ID, site, IP block, Panorama device groups/templates | One file: `vars/search/<id>-<site>-<customer>.yml` |
| Each switch/PE hostname + management IP + data centre | `inventories/production/hosts.yml` under `network_devices` |
| Panorama management address | same inventory, `panorama` group (hostname + IP only) |
| SSH / API connection, `ansible_network_os` | `inventories/production/group_vars/` |

OS values the inventory understands:

| Device OS | Inventory group | Connection vars |
| --- | --- | --- |
| Cisco IOS / IOS-XE | `ios_devices` | `group_vars/ios_devices.yml` |
| Cisco NX-OS | `nxos_devices` | `group_vars/nxos_devices.yml` |
| Arista EOS | `eos_devices` | `group_vars/eos_devices.yml` |
| Palo Alto (Panorama) | `panorama` | `group_vars/panorama.yml`: API connection only; do **not** SSH firewalls |

Inventory can hold the whole estate. Limit a run with `-l dc_dc1` (or hostnames). Skip Panorama with `-l network_devices` or `-l '!panorama'` if you do not have API access yet. Per-customer Panorama scope is selected by `search_job`, not by editing hosts.yml.

## 2. Critical extras (easy to miss)

These are required in practice even if they were not on the intake form:

1. **Management IPs** for every switch/PE and for **Panorama** (not the dataplane). The control node must reach SSH `22` on Cisco/Arista and HTTPS `443` on Panorama.
2. **Two accounts**, not one:
   - `NETWORK_USERNAME` / `NETWORK_PASSWORD`: SSH to Cisco and Arista (`network_cli`).
   - `PALO_USERNAME` / `PALO_PASSWORD` (or `PALO_API_KEY`): Panorama XML API. Use a service account with **no commit** rights.
3. **Every device group that can hold the objects**, including child groups, in the **customer search file**. A parent group does not pull child-group objects.
4. **Templates for network/VPN** in that same search file (interfaces, VR, statics, IKE, IPSec). Policy lives in device groups; interfaces/IKE live in templates. If you use **template stacks**, set `palo_template_stacks` as well.
5. **Python 3 venv + Ansible collections** on the machine that runs the playbook (see setup below).
6. **Do not commit** production inventory, CIDRs, or passwords. `inventories/production/` and `vars/search/*.yml` (except `_example.yml`) are gitignored.

Optional, but fill them if you have them:

| Extra | Why |
| --- | --- |
| `palo_serials` in the customer search file | Firewall serials so Panorama can pull live ARP/FIB. If empty, discovery uses `show devices all`. |
| `palo_template_stacks` in the customer search file | Stack-level network objects. |
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
```

Create one search file per customer (name is `<id>-<site>-<customer>.yml`):

```bash
python3 python/new_search.py \
  --id INC-1042 \
  --site DC1 \
  --customer "Example Retail" \
  --cidr 10.200.100.0/24 \
  --device-group DG-DC1-PROD \
  --template TPL-DC1-NETWORK
# writes vars/search/INC-1042-DC1-Example-Retail.yml
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

### 4.1 Search file: `vars/search/INC-1042-DC1-Example-Retail.yml`

One YAML file per customer. Filename is `<id>-<site>-<customer>` with spaces turned into hyphens.

```yaml
search_targets:
  - 10.200.100.0/24
customer: Example Retail
id: INC-1042
site: DC1
palo_device_groups:
  - DG-DC1-PROD
palo_templates:
  - TPL-DC1-NETWORK
palo_template_stacks: []
palo_serials: []
```

Add more CIDRs under `search_targets` if this ticket covers more than one block. Each CIDR is reported separately. Other customers get their own files in `vars/search/`; you pick the file when you run. Device groups and templates stay in this file so inventory stays shared.

A host such as `10.200.100.10` or a `/30` is valid. `any` and `0.0.0.0/0` are ignored.

### 4.2 Inventory: `inventories/production/hosts.yml`

Use real management IPs. Hosts.yml is the estate: OS groups, per-site children, and controllers with hostname + IP only. Connection settings stay in `group_vars/`. Do not put device groups or templates on Panorama.

```yaml
all:
  children:
    network_devices:
      children:
        eos_devices:
          children:
            eos_dc1:
              hosts:
                dc1-leaf-01:
                  ansible_host: 192.0.2.21
                  data_center: dc1
                dc1-aggpe-mls01:
                  ansible_host: 192.0.2.22
                  data_center: dc1
        ios_devices:
          children:
            ios_dc1:
              hosts:
                dc1-acc-01:
                  ansible_host: 192.0.2.11
                  data_center: dc1
        nxos_devices:
          children:
            nxos_dc1:
              hosts:
                dc1-core-01:
                  ansible_host: 192.0.2.12
                  data_center: dc1
    dc_dc1:
      children:
        eos_dc1: null
        ios_dc1: null
        nxos_dc1: null
    panorama:
      hosts:
        panorama-01:
          ansible_host: 192.0.2.30
```

`dc_dc1` is an alias so you can `-l dc_dc1`. Leave out OS groups you do not have.

NX-OS hosts must live under `nxos_devices` (that group sets `cisco.nxos.nxos`). IOS lives under `ios_devices`.

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
  -e search_job=INC-1042-DC1-Example-Retail
```

`search_job` is the filename in `vars/search/` without `.yml`. Collection logs into `network_devices` and `panorama`.

Limit to one data centre if the inventory holds the whole estate:

```bash
ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_job=INC-1042-DC1-Example-Retail \
  -l 'dc_dc1,panorama'
```

Skip Panorama when you do not have API access yet, or this customer has no device groups yet. Leave `panorama` out of the limit:

```bash
ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_job=INC-1042-DC1-Example-Retail \
  -l network_devices
```

or exclude the group:

```bash
ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_job=INC-1042-DC1-Example-Retail \
  -l '!panorama'
```

Ansible prints `skipping: no hosts matched` for the Panorama play. That is not a failure. You can omit `PALO_USERNAME` / `PALO_PASSWORD` on that run.

Leave `palo_device_groups` and `palo_templates` empty in the customer file until you have them. If the Panorama play still runs with those lists empty, the playbook asserts and fails.

When access is ready, add the groups and templates, then re-run with `-l panorama` (or include `panorama` in the limit). Existing switch artifacts are reused; `playbooks/report.yml` rebuilds the review after a full collect.

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
  -e search_job=INC-1042-DC1-Example-Retail
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
| NX-OS collected as IOS | Host is under `nxos_devices`, not `ios_devices` |
| No Palo objects | Panorama IP, API account, `palo_device_groups` in the **customer search file** match Panorama |
| No Palo interfaces / IKE | `palo_templates` or `palo_template_stacks` in that same search file |
| Shared vs DG looks wrong | You listed each device group; child groups are not inherited automatically |
| No ARP on firewalls | Panorama can reach managed devices; set `palo_serials` if auto-discovery is empty |
| Empty report | CIDR does not appear on the listed devices, or you pointed `search_job` at the wrong customer file |
| Search file not found | Filename is `vars/search/<id>-<site>-<customer>.yml` and `-e search_job=` matches the stem |
| Panorama play fails / no API access yet | Omit `panorama` from `-l`, or use `-l '!panorama'`. `skipping: no hosts matched` is OK |
| Assert on `palo_device_groups` | The Panorama play ran with empty groups in the customer file; skip `panorama` until you have them |
| EOS/NX-OS `command timeout triggered` | Large RIB/BGP/running-config on PEs. Commands are batched; default wait is 600s. Raise `eos_command_timeout` or `nxos_command_timeout` in group_vars if it still times out. Re-run the failed hosts with `-l`. |
| Enable password required | Set become on that host/group (default is off) |

## 9. What this does *not* do

- It does not log into Palo Alto firewalls directly; only Panorama.
- It does not push, commit, or swap IPs.
- It does not invent devices you did not put in inventory.
- VRF and vsys names are discovered on the boxes; you do not pre-list them.
