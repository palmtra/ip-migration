import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from ip_discovery.search_job import search_filename, search_job_name


def test_search_job_filename():
    assert search_job_name("INC-1042", "DC1", "Example Retail") == "INC-1042-DC1-Example-Retail"
    assert search_filename("INC-1042", "DC1", "Example Retail") == "INC-1042-DC1-Example-Retail.yml"
    assert search_job_name("acme/west", "NYC 01", "Acme, Inc.") == "acme-west-NYC-01-Acme-Inc"


def test_search_job_requires_all_parts():
    with pytest.raises(ValueError):
        search_job_name("INC-1042", "DC1", "")


def test_new_search_writes_customer_file(tmp_path: Path):
    script = Path(__file__).resolve().parents[1] / "new_search.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--id",
            "INC-1042",
            "--site",
            "DC1",
            "--customer",
            "Example Retail",
            "--cidr",
            "10.200.100.0/24",
            "--dir",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    path = tmp_path / "INC-1042-DC1-Example-Retail.yml"
    assert path.exists()
    assert "search_job=INC-1042-DC1-Example-Retail" in result.stdout
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["search_targets"] == ["10.200.100.0/24"]
    assert data["customer"] == "Example Retail"
    assert data["id"] == "INC-1042"
    assert data["site"] == "DC1"
    assert data["palo_device_groups"] == []
    assert data["palo_templates"] == []
    assert data["palo_template_stacks"] == []
    assert data["palo_serials"] == []


def test_new_search_writes_panorama_scope(tmp_path: Path):
    script = Path(__file__).resolve().parents[1] / "new_search.py"
    subprocess.run(
        [
            sys.executable,
            str(script),
            "--id",
            "INC-1042",
            "--site",
            "DC1",
            "--customer",
            "Example Retail",
            "--cidr",
            "10.200.100.0/24",
            "--device-group",
            "DG-DC1-PROD",
            "--template",
            "TPL-DC1-NETWORK",
            "--dir",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    data = yaml.safe_load((tmp_path / "INC-1042-DC1-Example-Retail.yml").read_text(encoding="utf-8"))
    assert data["palo_device_groups"] == ["DG-DC1-PROD"]
    assert data["palo_templates"] == ["TPL-DC1-NETWORK"]
