from ex_migration_provisioner.cabling_report import build_facilities_report, render_csv, render_markdown


def _transaction():
    return {
        "transaction_id": "tx123",
        "migration_id": "sw1203",
        "activated": [
            {
                "old_interface": "ge-0/0/12",
                "new_interface": "ge-0/0/12",
                "description": "Printer-101",
                "data_vlan_id": 200,
                "data_vlan_name": "v200",
                "expected_macs": ["02:00:00:00:00:01"],
                "observed_support": {"02:00:00:00:00:01": ["ge-0/0/12"]},
            },
            {
                "old_interface": "ge-5/0/7",
                "new_interface": "ge-1/0/44",
                "description": "Camera-527",
                "data_vlan_id": 100,
                "data_vlan_name": "v100",
                "expected_macs": ["02:00:00:00:00:02"],
                "observed_support": {"02:00:00:00:00:02": ["ge-1/0/44"]},
            },
        ],
        "holds": [{"old_interface": "ge-2/0/8", "reason": "NO_APPROVED_MAC_OBSERVED_POST_MOVE"}],
        "commit": {
            "status": "COMMITTED_AND_CONFIRMED",
            "confirmed": True,
            "confirmed_at": "2026-09-09T12:00:00Z",
        },
        "validation": {"result": "PASS"},
    }


def test_report_only_lists_physical_interface_changes():
    report = build_facilities_report(_transaction(), "d" * 64)
    assert report["statistics"]["activated_endpoint_intents"] == 2
    assert report["statistics"]["same_position_no_relabel"] == 1
    assert report["statistics"]["relabel_required"] == 1
    assert report["statistics"]["operator_holds"] == 1
    assert len(report["rows"]) == 1
    row = report["rows"][0]
    assert row["old_interface"] == "ge-5/0/7"
    assert row["new_interface"] == "ge-1/0/44"
    assert row["relabel_required"] is True
    assert row["reason"] == "PHYSICAL_INTERFACE_CHANGED"


def test_report_formats_include_only_relabel_rows():
    report = build_facilities_report(_transaction(), "d" * 64)
    markdown = render_markdown(report)
    csv_text = render_csv(report)
    assert "ge-5/0/7" in markdown
    assert "ge-1/0/44" in markdown
    assert "ge-0/0/12" not in markdown
    assert "ge-5/0/7" in csv_text
    assert "ge-0/0/12" not in csv_text
    assert "Camera-527" in csv_text
