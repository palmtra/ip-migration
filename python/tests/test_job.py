from pathlib import Path

from ip_discovery.job import load_job


def test_tyson_job_search_and_routing_scope():
    job = load_job(Path("jobs/tyson-foods.yml"))
    assert job.customer == "tyson foods"
    assert job.customer_id == "909"
    assert job.site == "omaha"
    assert "63.99.122.176/29" in job.search_targets
    assert "63.99.122.179/29" in job.search_targets
    assert "63.99.122.177/29" in job.search_targets
    assert job.vrfs == ["v0000001a"]
    assert job.vsys_list == ["909-chi-tyson"]
    assert 3051 in job.vlan_ids
    vars_ = job.ansible_vars()
    assert vars_["job_vrfs"] == ["v0000001a"]
    assert vars_["job_vsys"] == ["909-chi-tyson"]


def test_typo_adress_is_accepted(tmp_path: Path):
    path = tmp_path / "job.yml"
    path.write_text(
        "customer: demo\nid: '1'\nsite: lab\nsubnet: 10.1.1.0/29\n"
        "interfaces:\n  - aggpe:\n      adress: 10.1.1.1/29\n      vrf: v1\n",
        encoding="utf-8",
    )
    job = load_job(path)
    assert "10.1.1.1/29" in job.search_targets
    assert job.vrfs == ["v1"]
