from pathlib import Path

from ip_discovery.engine import find_hits
from ip_discovery.models import Hit
from ip_discovery.report import report_dir_name, write_target_reports


def test_report_dir_name_replaces_dots_and_slash():
    assert report_dir_name("10.200.100.10/30") == "10-200-100-10_30"
    assert report_dir_name("192.0.2.64/28") == "192-0-2-64_28"
    assert report_dir_name("10.50.12.10") == "10-50-12-10"


def test_write_target_reports_one_folder_per_cidr(tmp_path: Path):
    hits = [
        Hit(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="interface",
            name="Vlan100",
            field="address",
            matched_value="192.0.2.66/28",
            search_term="192.0.2.64/28",
            match_kind="contained",
        ),
        Hit(
            device="DC1-LEAF01",
            platform="arista.eos.eos",
            category="interface",
            name="Ethernet49",
            field="address",
            matched_value="203.0.113.2/30",
            search_term="203.0.113.0/30",
            match_kind="contained",
        ),
    ]
    written = write_target_reports(hits, ["192.0.2.64/28", "203.0.113.0/30"], tmp_path)
    review = tmp_path / "192-0-2-64_28" / "migration-review.yml"
    other = tmp_path / "203-0-113-0_30" / "migration-review.yml"
    assert review.exists()
    assert other.exists()
    assert "192.0.2.66/28" in review.read_text(encoding="utf-8")
    assert "203.0.113.2/30" not in review.read_text(encoding="utf-8")
    assert written["192.0.2.64/28"]["review"] == review
