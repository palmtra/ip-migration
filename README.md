# IP migration discovery

Read-only discovery for an IP subnet migration across Cisco/Arista switches and
Palo Alto firewalls. Ansible collects device usage; Python matches hosts and
CIDRs (including ARP and nested object groups) and writes an engineer report.

See [docs/DESIGN.md](docs/DESIGN.md) for architecture, match rules, and why
this is not a pure-Ansible or Nornir-first design.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r collections/requirements.yml -p collections

export NETWORK_USERNAME='netops'
export NETWORK_PASSWORD='...'
export PALO_USERNAME='svc-ip-migration'
export PALO_PASSWORD='...'

# Edit inventories/sample/hosts.yml and vars/search.yml first.
ansible-playbook playbooks/discover.yml
```

Reports: `reports/discovery.md`, `reports/discovery.csv`, `reports/discovery.json`.

Analyze existing artifacts again without logging into devices:

```bash
ansible-playbook playbooks/report.yml
```

Run the matcher against checked-in fixtures:

```bash
pytest
python3 python/analyze_hits.py \
  --artifacts python/tests/fixtures/artifacts \
  --search vars/search.yml \
  --out reports
```

## Layout

| Path | Role |
| --- | --- |
| `inventories/sample/hosts.yml` | Device management IPs by platform |
| `vars/search.yml` | CIDRs and hosts to find |
| `playbooks/collect.yml` | Read-only collection |
| `playbooks/report.yml` | Analyze only |
| `playbooks/discover.yml` | Collect + analyze |
| `roles/collect_*` | Per-platform commands and API gathers |
| `python/ip_discovery/` | Normalize, expand groups, match, report |
| `artifacts/` | Per-device dumps (gitignored) |
| `reports/` | Engineer output (gitignored) |

Collection is read-only: no PAN-OS commit, no `state: present`, no switch
config writes.
