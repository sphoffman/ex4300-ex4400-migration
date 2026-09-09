from pathlib import Path

from ex_migration_provisioner.port_state import (
    build_port_state_comparison,
    build_port_state_evidence,
    classify_port_state,
    current_edge_states,
)


def _interface(name):
    return {
        "name": name,
        "physical_name": name,
        "effective_mode": "access",
        "ae_parent": None,
    }


def _candidate(tmp_path):
    collection = tmp_path / "collection"
    (collection / "raw").mkdir(parents=True)
    terse0 = collection / "raw" / "terse0.txt"
    terse1 = collection / "raw" / "terse1.txt"
    text = "\n".join([
        "ge-0/0/2 up up",
        "ge-0/0/3 up up",
        "ge-0/0/4 up down",
        "ge-0/0/5 down down",
        "",
    ])
    terse0.write_text(text, encoding="utf-8")
    terse1.write_text(text, encoding="utf-8")
    snapshot = {
        "snapshot_id": "snap1",
        "started_at": "2026-09-09T10:00:00Z",
        "interfaces": [
            _interface("ge-0/0/2"),
            _interface("ge-0/0/3"),
            _interface("ge-0/0/4"),
            _interface("ge-0/0/5"),
        ],
        "sample_runs": [
            {
                "sample_index": 0,
                "observed_at": "2026-09-09T10:00:00Z",
                "commands": [{
                    "command": "show interfaces terse",
                    "status": "SUCCESS",
                    "text_artifact": "raw/terse0.txt",
                }],
            },
            {
                "sample_index": 1,
                "observed_at": "2026-09-09T10:01:00Z",
                "commands": [{
                    "command": "show interfaces terse",
                    "status": "SUCCESS",
                    "text_artifact": "raw/terse1.txt",
                }],
            },
        ],
        "mac_observations": [
            {
                "observed_at": "2026-09-09T10:00:00Z",
                "physical_interface": "ge-0/0/2",
                "mac_type": "dynamic",
            },
            {
                "observed_at": "2026-09-09T10:01:00Z",
                "physical_interface": "ge-0/0/2",
                "mac_type": "dynamic",
            },
        ],
    }
    return {
        "path": collection,
        "snapshot": snapshot,
        "envelope": {"collection_digest": "a" * 64},
    }


def _mac_detail(interface):
    return """MAC address: 02:00:00:00:00:01
Routing instance: default-switch
VLAN name: v100, VLAN ID: 100
Learning interface: %s.0
Layer 2 flags: dynamic
""" % interface


def test_classify_port_state():
    assert classify_port_state("up", "up", True) == "ACTIVE_MAC"
    assert classify_port_state("up", "up", False) == "UP_SILENT"
    assert classify_port_state("up", "down", False) == "LINK_DOWN"
    assert classify_port_state("down", "down", False) == "ADMIN_DOWN"
    assert classify_port_state(None, None, False) == "NOT_OBSERVED"


def test_reconstructs_per_sample_discovery_state(tmp_path):
    evidence = build_port_state_evidence([_candidate(tmp_path)])
    by_port = {item["interface"]: item for item in evidence["ports"]}

    assert evidence["total_sample_runs"] == 2
    assert by_port["ge-0/0/2"]["counts"]["ACTIVE_MAC"] == 2
    assert by_port["ge-0/0/2"]["stable_state"] == "ACTIVE_MAC"
    assert by_port["ge-0/0/3"]["counts"]["UP_SILENT"] == 2
    assert by_port["ge-0/0/3"]["latest_state"] == "UP_SILENT"
    assert by_port["ge-0/0/4"]["counts"]["LINK_DOWN"] == 2
    assert by_port["ge-0/0/5"]["counts"]["ADMIN_DOWN"] == 2


def test_current_state_uses_dynamic_mac_presence():
    terse = "\n".join([
        "ge-0/0/2 up up",
        "ge-0/0/3 up up",
        "ge-0/0/4 up down",
        "ge-0/0/47 up up",
        "",
    ])
    states = current_edge_states(
        terse,
        _mac_detail("ge-0/0/2"),
        "ge-0/0/47",
        uplink_interfaces=[],
        observed_at="2026-09-09T12:00:00Z",
    )
    assert states["ge-0/0/2"]["state"] == "ACTIVE_MAC"
    assert states["ge-0/0/3"]["state"] == "UP_SILENT"
    assert states["ge-0/0/4"]["state"] == "LINK_DOWN"
    assert "ge-0/0/47" not in states


def test_same_position_matching_is_advisory_and_claims_fail_closed(tmp_path):
    evidence = build_port_state_evidence([_candidate(tmp_path)])
    plan = {
        "plan_id": "plan1",
        "port_intents": [
            {"old_interface": "ge-0/0/2", "planned_action": "CORRELATE_AFTER_CABLE_MOVE", "configured_data_vlan_id": 100},
            {"old_interface": "ge-0/0/3", "planned_action": "HOLD_FOR_OPERATOR_RESOLUTION", "configured_data_vlan_id": 100},
            {"old_interface": "ge-0/0/4", "planned_action": "HOLD_FOR_OPERATOR_RESOLUTION", "configured_data_vlan_id": 200},
            {"old_interface": "ge-0/0/5", "planned_action": "HOLD_FOR_OPERATOR_RESOLUTION", "configured_data_vlan_id": 200},
        ],
    }
    terse = "\n".join([
        "ge-0/0/2 up up",
        "ge-0/0/3 up up",
        "ge-0/0/4 up down",
        "ge-0/0/5 up up",
        "",
    ])
    completed = {
        "by_old": {"ge-0/0/2": {"new_interface": "ge-0/0/5"}},
        "by_new": {"ge-0/0/5": "ge-0/0/2"},
    }
    comparison = build_port_state_comparison(
        "sw1203",
        plan,
        "b" * 64,
        evidence,
        terse,
        _mac_detail("ge-0/0/5"),
        "ge-0/0/47",
        uplink_interfaces=[],
        completed=completed,
        observed_at="2026-09-09T12:00:00Z",
    )
    rows = {item["old_interface"]: item for item in comparison["rows"]}

    assert rows["ge-0/0/2"]["mapping_source"] == "CONFIRMED_ENDPOINT_TRANSACTION"
    assert rows["ge-0/0/2"]["candidate_new_interface"] == "ge-0/0/5"
    assert rows["ge-0/0/3"]["mapping_source"] == "SAME_PHYSICAL_POSITION_ADVISORY"
    assert rows["ge-0/0/3"]["state_match"] is True
    assert rows["ge-0/0/3"]["confidence"] == "CORROBORATING_STATE_MATCH"
    assert rows["ge-0/0/3"]["authorization"] == "ADVISORY_ONLY"
    assert rows["ge-0/0/4"]["state_match"] is True
    assert rows["ge-0/0/4"]["confidence"] == "CORROBORATING_STATE_MATCH"
    assert rows["ge-0/0/5"]["candidate_new_interface"] is None
    assert rows["ge-0/0/5"]["candidate_reason"] == "SAME_POSITION_ALREADY_CLAIMED_BY_CONFIRMED_MAPPING"
