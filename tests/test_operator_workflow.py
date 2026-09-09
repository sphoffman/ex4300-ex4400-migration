import json

from ex_migration_operator import core


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_source_address_reused_from_existing_discovery(tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    _write_json(
        root / "old-switch" / "collections" / "001" / "snapshot.json",
        {
            "snapshot_id": "s1",
            "migration_id": "sw1203",
            "management": {"connection_address": "10.255.3.18"},
        },
    )
    assert core.source_address_from_evidence(root) == "10.255.3.18"


def test_workflow_status_starts_with_discovery(tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    value = core.workflow_status(root)
    assert value["collections"] == 0
    assert value["next_action"] == "discover"


def test_analysis_coverage_detects_newer_discovery_collection(tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    _write_json(
        root / "old-switch" / "collections" / "001" / "snapshot.json",
        {"snapshot_id": "s1", "management": {}},
    )
    analysis = {
        "composite_evidence": {
            "collections": [{"snapshot_id": "s1", "collection_digest": "a" * 64}]
        }
    }
    assert core.analysis_covers_all_collections(root, analysis) is True
    _write_json(
        root / "old-switch" / "collections" / "002" / "snapshot.json",
        {"snapshot_id": "s2", "management": {}},
    )
    assert core.analysis_covers_all_collections(root, analysis) is False


def test_historical_mac_lookup_distinguishes_port_vlan_from_observed_vlan(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    analysis_path = root / "analyses" / "a1" / "analysis.json"
    _write_json(analysis_path, {"placeholder": True})
    selected_plan = {
        "plan": {"plan_id": "p1", "migration_id": "sw1203"},
        "plan_digest": "d" * 64,
    }
    analysis = {
        "analysis_id": "a1",
        "template_variables": {
            "migration_id": "sw1203",
            "configured_vlans": [
                {"name": "v100", "vlan_id": 100},
                {"name": "voip", "vlan_id": 1111},
            ],
        },
        "ports": [
            {
                "interface": "ge-0/0/5",
                "description": "OFFICE-123",
                "configured_data_vlan_id": 100,
                "unique_macs": [],
                "historical_observations": [],
            }
        ],
        "historical_evidence": {
            "catalog": [
                {
                    "mac": "00:11:22:33:44:55",
                    "vlan_id": 1111,
                    "interface": "ge-0/0/5",
                    "snapshot_ids": ["s1", "s2"],
                }
            ]
        },
    }
    monkeypatch.setattr(
        core.provisioner_base,
        "choose_approved_plan",
        lambda _root: selected_plan,
    )
    monkeypatch.setattr(
        core,
        "analysis_for_approved_plan",
        lambda _root, _plan: (analysis, analysis_path, "a" * 64),
    )

    value = core.historical_mac_lookup(root, "0011.2233.4455")
    assert value["mac"] == "00:11:22:33:44:55"
    assert value["port_consistency"] == "CONSISTENT"
    assert value["matches"][0]["interface"] == "ge-0/0/5"
    assert value["matches"][0]["configured_data_vlan_id"] == 100
    assert value["matches"][0]["configured_data_vlan_name"] == "v100"
    assert value["matches"][0]["observed_vlan_id"] == 1111
    assert value["matches"][0]["observed_vlan_name"] == "voip"


def test_historical_mac_lookup_flags_multiple_old_ports(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    analysis_path = root / "analyses" / "a1" / "analysis.json"
    _write_json(analysis_path, {"placeholder": True})
    selected_plan = {
        "plan": {"plan_id": "p1", "migration_id": "sw1203"},
        "plan_digest": "d" * 64,
    }
    analysis = {
        "analysis_id": "a1",
        "template_variables": {"migration_id": "sw1203", "configured_vlans": []},
        "ports": [
            {"interface": "ge-0/0/5", "configured_data_vlan_id": 100},
            {"interface": "ge-0/0/6", "configured_data_vlan_id": 100},
        ],
        "historical_evidence": {
            "catalog": [
                {"mac": "00:11:22:33:44:55", "vlan_id": 100, "interface": "ge-0/0/5"},
                {"mac": "00:11:22:33:44:55", "vlan_id": 100, "interface": "ge-0/0/6"},
            ]
        },
    }
    monkeypatch.setattr(core.provisioner_base, "choose_approved_plan", lambda _root: selected_plan)
    monkeypatch.setattr(core, "analysis_for_approved_plan", lambda _root, _plan: (analysis, analysis_path, "a" * 64))
    value = core.historical_mac_lookup(root, "00-11-22-33-44-55")
    assert value["port_consistency"] == "CONFLICTING_HISTORY"
    assert [row["interface"] for row in value["matches"]] == ["ge-0/0/5", "ge-0/0/6"]
