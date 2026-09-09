import pytest

from ex_migration_provisioner.access_hardening import (
    classify_final_ports,
    current_port_states,
    hardening_statements,
    validate_final_hardening,
)


def _mac(mac, interface):
    return "\n".join([
        "MAC address: %s" % mac,
        "Routing instance: default-switch",
        "VLAN name: default, VLAN ID: 3998",
        "Learning interface: %s.0" % interface,
        "Layer 2 flags: 0x1",
        "",
    ])


def _plan():
    return {
        "port_intents": [
            {
                "old_interface": "ge-0/0/2",
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
            {
                "old_interface": "ge-0/0/10",
                "planned_action": "LEAVE_TEMPLATE_DEFAULT",
            },
        ]
    }


def test_classification_keeps_completed_and_disables_proven_unused():
    states = {
        "ge-0/0/2": {
            "interface": "ge-0/0/2", "state": "LINK_DOWN",
            "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False,
        },
        "ge-0/0/10": {
            "interface": "ge-0/0/10", "state": "LINK_DOWN",
            "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False,
        },
        "ge-0/0/11": {
            "interface": "ge-0/0/11", "state": "ADMIN_DOWN",
            "admin_status": "down", "oper_status": "down", "dynamic_mac_present": False,
        },
        "ge-0/0/47": {
            "interface": "ge-0/0/47", "state": "LINK_DOWN",
            "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False,
        },
    }
    completed = {
        "ge-0/0/2": {
            "old_interface": "ge-0/0/2",
            "new_interface": "ge-0/0/2",
        }
    }
    value = classify_final_ports(_plan(), completed, states, "ge-0/0/47")
    assert value["result"] == "PASS"
    assert [row["interface"] for row in value["used"]] == ["ge-0/0/2"]
    assert [row["interface"] for row in value["unused"]] == [
        "ge-0/0/10", "ge-0/0/11", "ge-0/0/47"
    ]
    assert next(row for row in value["unused"] if row["interface"] == "ge-0/0/47")["reason"] == "RECOVERY_PORT_RETIRED_AT_CLEANUP"


def test_unmapped_active_or_silent_port_blocks_cleanup():
    states = {
        "ge-0/0/12": {
            "interface": "ge-0/0/12", "state": "ACTIVE_MAC",
            "admin_status": "up", "oper_status": "up", "dynamic_mac_present": True,
        },
        "ge-0/0/13": {
            "interface": "ge-0/0/13", "state": "UP_SILENT",
            "admin_status": "up", "oper_status": "up", "dynamic_mac_present": False,
        },
    }
    value = classify_final_ports(_plan(), {}, states, "ge-0/0/47")
    assert value["result"] == "FAIL"
    assert {row["reason"] for row in value["blockers"]} == {
        "UNMAPPED_PORT_CURRENTLY_ACTIVE",
        "UNMAPPED_PORT_UP_SILENT",
    }


def test_uncompleted_approved_endpoint_blocks_even_when_link_down():
    states = {
        "ge-0/0/2": {
            "interface": "ge-0/0/2", "state": "LINK_DOWN",
            "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False,
        },
    }
    value = classify_final_ports(_plan(), {}, states, "ge-0/0/47")
    assert value["result"] == "FAIL"
    assert value["blockers"][0]["reason"] == "APPROVED_ENDPOINT_INTENT_NOT_COMPLETED"


def test_current_port_state_detects_mac_and_silent():
    terse = "\n".join([
        "ge-0/0/2 up up",
        "ge-0/0/3 up up",
        "ge-0/0/4 up down",
    ])
    states = current_port_states(
        terse,
        _mac("02:00:00:00:00:01", "ge-0/0/2"),
        ["ge-0/0/2", "ge-0/0/3", "ge-0/0/4"],
        "2026-09-09T18:00:00Z",
    )
    assert states["ge-0/0/2"]["state"] == "ACTIVE_MAC"
    assert states["ge-0/0/3"]["state"] == "UP_SILENT"
    assert states["ge-0/0/4"]["state"] == "LINK_DOWN"


def test_hardening_replaces_all_trunk_and_narrows_voice_policy():
    statements = hardening_statements(
        ["ge-0/0/10", "ge-0/0/47"],
        ["ge-0/0/2", "ge-0/0/3"],
        ["v100", "v163", "v200", "voip"],
        "voip",
        "TEMP-RECOVERY",
    )
    assert statements[0] == "delete interfaces ae0 unit 0 family ethernet-switching vlan members all"
    assert "set interfaces ge-0/0/10 disable" in statements
    assert "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default" in statements
    assert "delete switch-options voip interface edge_ports" in statements
    assert "set switch-options voip interface ge-0/0/2 vlan voip" in statements
    assert not any("TEMP-RECOVERY" in line and "ae0" in line for line in statements)


def test_final_hardening_validation():
    config = "\n".join([
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v163",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members voip",
        "set interfaces ge-0/0/10 disable",
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default",
        "set switch-options voip interface ge-0/0/2 vlan voip",
    ])
    value = validate_final_hardening(
        config,
        {},
        ["ge-0/0/2"],
        ["ge-0/0/10"],
        ["v100", "v163", "voip"],
        "voip",
    )
    assert value["result"] == "PASS"


def test_inactive_vlan_cannot_be_in_production_trunk_list():
    with pytest.raises(Exception):
        hardening_statements(
            ["ge-0/0/10"], ["ge-0/0/2"], ["v100", "default"], "voip", "TEMP-RECOVERY"
        )
