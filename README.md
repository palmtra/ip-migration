# IP migration discovery

Read-only discovery. You provide **device inventory**, **search CIDRs**, and
**credentials**. Ansible logs into each switch over SSH and into **Panorama**
over the XML API. The analyzer writes an engineer review of every place those
CIDRs appear: interfaces, ARP, routes (including next hops), BGP
advertisements, ACLs, and Palo objects / NAT / security / VPN.

**Operators:** start with [docs/USERGUIDE.md](docs/USERGUIDE.md) (customer, ID,
site, CIDR, inventory, Panorama group/template). Match rules are in
[docs/DESIGN.md](docs/DESIGN.md).

## Usable now

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r collections/requirements.yml -p collections

# 1. Inventory: copy the sample and put real management IPs locally (gitignored)
mkdir -p inventories/production/group_vars
cp inventories/sample/hosts.yml inventories/production/hosts.yml
cp inventories/sample/group_vars/*.yml inventories/production/group_vars/
# edit inventories/production/hosts.yml
# For Panorama: ansible_host is Panorama, plus palo_device_groups and palo_templates

# 2. CIDR to find
cp vars/search.yml vars/search.local.yml
# edit search_targets in vars/search.local.yml

export NETWORK_USERNAME='...'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='...'
export PALO_PASSWORD='...'

ansible-playbook playbooks/discover.yml \
  -i inventories/production/hosts.yml \
  -e search_file="$PWD/vars/search.local.yml"
```

Reports (under `reports/<cidr>/`, with `.` → `-` and `/` → `_`):

- `reports/10-200-100-10_30/migration-review.yml` — engineer template
- `discovery.md` — readable review including ARP and routing tables
- `discovery.csv` / `discovery.json` — full hit list for that CIDR

Re-run analysis without logging into devices:

```bash
ansible-playbook playbooks/report.yml \
  -i inventories/production/hosts.yml \
  -e search_file="$PWD/vars/search.local.yml"
```

Self-check without devices:

```bash
pytest
python3 python/analyze_hits.py \
  --artifacts python/tests/fixtures/artifacts \
  --search python/tests/fixtures/search.yml \
  --out /tmp/ip-discovery-report
# writes /tmp/ip-discovery-report/10-50-12-0_24/migration-review.yml
```

Collection is read-only: no PAN-OS commit, no `state: present`, no config writes.
