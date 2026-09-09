from copy import deepcopy

from ex_migration_analyzer.composite import build_composite_evidence
from ex_migration_analyzer.core import analyze
from ex_migration_analyzer.cli import _apply_composite_metadata


def _snapshot(snapshot_id, completed_at, mac, interface="ge-0/0/2", vlan_id=100):
    reconciliation = [
        {"sample_index": index, "status": "RECONCILED"}
        for index in range(3)
    ]
    sample_runs = [
        {"sample_index": index, "commands": [], "mac_table_reconciliation": reconciliation[index]}
        for index in range(3)
    ]
    return {
        "schema_version": "1.4",
        "snapshot_id": snapshot_id,
        "migration_id": "sw1203",
        "device_role": "old-switch",
        "started_at": completed_at,
        "completed_at": completed_at,
        "lifecycle": "COLLECTED",
        "device": {
            "hostname": "home1-ex4300-vc-fd-sw1203",
            "model": "EX4300",
            "junos_version": "21.4R3",
            "serial_numbers": ["ABC123"],
            "configured_hostname": "home1-ex4300-vc-fd-sw1203",
            "proposed_hostname": "home1-ex4400-vc-fd-sw1203",
            "identity_rule": "replace-ex4300-ex4400",
        },
        "management": {
            "consistency": "CONSISTENT",
            "vlan_id": 163,
            "vlan_name": "v163",
            "l3_interface": "irb.163",
            "addresses": ["10.100.163.30/24"],
            "production_ipv4": "10.100.163.30",
            "default_gateway": "10.100.163.1",
            "fxp0_addresses": [],
            "mgmt_junos_default_gateways": [],
            "snmp": {"name": None, "location": "lab", "engine_id": "10.100.163.30", "v3_configured": True},
        },
        "collection_policy": {"samples": 3, "duration_seconds": 120, "mac_table_reconciliation": reconciliation},
        "capabilities": {},
        "virtual_chassis": {"status": "collected"},
        "interfaces": [
            {
                "physical_name": "ge-0/0/2",
                "effective_mode": "access",
                "ae_parent": None,
                "description": "Desk",
                "untagged_vlan": {"name": "v100", "vlan_id": 100},
                "tagged_vlans": [],
                "interface_ranges": [],
                "oper_status": "up",
            },
            {
                "physical_name": "ge-0/0/3",
                "effective_mode": "access",
                "ae_parent": None,
                "description": "Desk 2",
                "untagged_vlan": {"name": "v100", "vlan_id": 100},
                "tagged_vlans": [],
                "interface_ranges": [],
                "oper_status": "up",
            },
        ],
        "vlans": [
            {"name": "v100", "vlan_id": 100, "configured": True, "observed_mac_count": 1, "observed": True},
            {"name": "v163", "vlan_id": 163, "configured": True, "observed_mac_count": 0, "observed": False, "irb_interface": "irb.163"},
            {"name": "voip", "vlan_id": 1111, "configured": True, "observed_mac_count": 0, "observed": False},
        ],
        "voice_policy": {"configured": True, "vlan_name": "voip", "vlan_id": 1111, "interface_selectors": [], "valid": True, "errors": []},
        "mac_observations": [
            {
                "observed_at": completed_at,
                "mac": mac,
                "physical_interface": interface,
                "reported_interface": interface + ".0",
                "interface_class": "physical_access",
                "vlan": {"name": "v%d" % vlan_id, "vlan_id": vlan_id},
            }
        ],
        "lldp_neighbors": [],
        "raw_artifacts": [],
        "warnings": [],
        "errors": [],
        "sample_runs": sample_runs,
    }


def _candidate(snapshot):
    return {
        "snapshot": snapshot,
        "envelope": {"collection_digest": snapshot["snapshot_id"] * 8},
        "blockers": [],
    }


def _policy():
    return {
        "policy_id": "lab",
        "accepted_snapshot_schemas": ["1.4"],
        "observation": {"minimum_samples": 1, "minimum_duration_seconds": 0},
        "required_capabilities": [],
        "require_virtual_chassis": False,
        "production_eligible": False,
    }


def test_composite_unions_endpoint_macs_across_collections():
    one = _candidate(_snapshot("11111111", "2026-09-08T20:00:00Z", "02:00:00:00:00:01"))
    two = _candidate(_snapshot("22222222", "2026-09-09T01:00:00Z", "02:00:00:00:00:02"))
    composite = build_composite_evidence([one, two], _policy(), "p" * 64)
    assert {row["mac"] for row in composite["snapshot"]["mac_observations"]} == {
        "02:00:00:00:00:01",
        "02:00:00:00:00:02",
    }
    assert composite["evidence"]["endpoint_statistics"]["unique_macs"] == 2
    assert composite["evidence"]["configuration_consistency"]["interfaces"] == "CONSISTENT"


def test_composite_flags_interface_change_but_uses_latest_state():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z", "02:00:00:00:00:01")
    second = _snapshot("22222222", "2026-09-09T01:00:00Z", "02:00:00:00:00:02")
    second["interfaces"][0]["description"] = "New Desk"
    composite = build_composite_evidence([_candidate(first), _candidate(second)], _policy(), "p" * 64)
    assert composite["snapshot"]["interfaces"][0]["description"] == "New Desk"
    assert composite["evidence"]["configuration_consistency"]["interfaces"] == "CHANGED"
    assert any(item["code"] == "INTERFACE_CONFIGURATION_CHANGED" for item in composite["findings"])


def test_composite_blocks_management_change():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z", "02:00:00:00:00:01")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["management"]["production_ipv4"] = "10.100.163.31"
    composite = build_composite_evidence([_candidate(first), _candidate(second)], _policy(), "p" * 64)
    assert any(item["code"] == "MANAGEMENT_CONFIGURATION_CHANGED" and item["severity"] == "BLOCKER" for item in composite["findings"])


def test_same_mac_on_different_old_ports_becomes_composite_review():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z", "02:00:00:00:00:01", "ge-0/0/2")
    second = _snapshot("22222222", "2026-09-09T01:00:00Z", "02:00:00:00:00:01", "ge-0/0/3")
    composite = build_composite_evidence([_candidate(first), _candidate(second)], _policy(), "p" * 64)
    result = analyze(
        composite["snapshot"],
        composite["envelope"],
        _policy(),
        "p" * 64,
        "approval",
        "0.8.0",
        composite["history"],
    )
    result = _apply_composite_metadata(result, composite)
    assert result["result"] == "REVIEW_REQUIRED"
    assert any(item["code"] == "MAC_MULTI_PORT" for item in result["findings"])
    assert composite["evidence"]["endpoint_statistics"]["conflicting_macs"] == 1
