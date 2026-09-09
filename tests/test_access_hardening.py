import pytest

from ex_migration_provisioner.access_hardening import (
    classify_final_ports,
    current_port_states,
    edge_interfaces,
    expand_edge_range,
    final_production_vlan_names,
    hardening_statements,
    stale_vlan_cleanup,
    validate_final_hardening,
    validate_pre_hardening_config,
)


def _mac(mac, interface, vlan_name="default", vlan_id=3998):
    return "\n".join([
        "MAC address: %s" % mac,
        "Routing instance: default-switch",
        "VLAN name: %s, VLAN ID: %s" % (vlan_name, vlan_id),
        "Learning interface: %s.0" % interface,
        "Layer 2 flags: 0x1",
        "",
    ])


def _plan():
    return {
        "port_intents": [
            {"old_interface": "ge-0/0/2", "planned_action": "CORRELATE_AFTER_CABLE_MOVE"},
            {"old_interface": "ge-0/0/10", "planned_action": "LEAVE_TEMPLATE_DEFAULT"},
        ]
    }


def test_edge_range_expands_junos_numeric_ranges_from_live_template_policy():
    assert expand_edge_range("ge-[0-9]/0/[2-47]", [0]) == [
        "ge-0/0/%d" % port for port in range(2, 48)
    ]
    values = expand_edge_range("ge-[0-9]/0/[0-47]", [0, 1])
    assert "ge-0/0/0" in values
    assert "ge-1/0/47" in values
    assert len(values) == 96


def test_edge_interfaces_uses_live_template_range_and_rejects_uplink_overlap():
    config = 'set interfaces interface-range edge_ports member "ge-[0-9]/0/[2-47]"\n'
    values = edge_interfaces(config, [0], ["ge-0/0/0", "ge-0/0/1"])
    assert values[0] == "ge-0/0/2"
    assert values[-1] == "ge-0/0/47"
    assert len(values) == 46

    prod = 'set interfaces interface-range edge_ports member "ge-[0-9]/0/[0-47]"\n'
    values = edge_interfaces(prod, [0], ["et-0/0/48", "et-0/0/49"])
    assert values[0] == "ge-0/0/0"
    with pytest.raises(Exception):
        edge_interfaces(prod, [0], ["ge-0/0/0"])


def test_final_production_vlans_follow_qfx_lineage_plus_management():
    configured = [
        {"name": "v100", "vlan_id": 100, "classification": "data"},
        {"name": "v163", "vlan_id": 163, "classification": "management"},
        {"name": "v200", "vlan_id": 200, "classification": "data"},
        {"name": "v300", "vlan_id": 300, "classification": "data"},
        {"name": "voip", "vlan_id": 1111, "classification": "voice"},
    ]
    assert final_production_vlan_names(configured, 163, [100, 200, 1111]) == [
        "v100", "v163", "v200", "voip"
    ]


def test_classification_keeps_completed_and_disables_proven_unused():
    states = {
        "ge-0/0/2": {"interface": "ge-0/0/2", "state": "LINK_DOWN", "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False},
        "ge-0/0/10": {"interface": "ge-0/0/10", "state": "LINK_DOWN", "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False},
        "ge-0/0/11": {"interface": "ge-0/0/11", "state": "ADMIN_DOWN", "admin_status": "down", "oper_status": "down", "dynamic_mac_present": False},
        "ge-0/0/47": {"interface": "ge-0/0/47", "state": "LINK_DOWN", "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False},
    }
    completed = {"ge-0/0/2": {"old_interface": "ge-0/0/2", "new_interface": "ge-0/0/2"}}
    value = classify_final_ports(_plan(), completed, states, "ge-0/0/47")
    assert value["result"] == "PASS"
    assert [row["interface"] for row in value["used"]] == ["ge-0/0/2"]
    assert [row["interface"] for row in value["unused"]] == ["ge-0/0/10", "ge-0/0/11", "ge-0/0/47"]
    assert next(row for row in value["unused"] if row["interface"] == "ge-0/0/47")["reason"] == "RECOVERY_PORT_PROVEN_INACTIVE_AT_CLEANUP"


def test_live_or_silent_recovery_port_blocks_cleanup():
    for state, mac, reason in (
        ("ACTIVE_MAC", True, "RECOVERY_PORT_CURRENTLY_ACTIVE"),
        ("UP_SILENT", False, "RECOVERY_PORT_UP_SILENT"),
    ):
        states = {
            "ge-0/0/47": {
                "interface": "ge-0/0/47",
                "state": state,
                "admin_status": "up",
                "oper_status": "up",
                "dynamic_mac_present": mac,
            }
        }
        value = classify_final_ports(_plan(), {}, states, "ge-0/0/47")
        assert value["result"] == "FAIL"
        assert value["blockers"][0]["reason"] == reason


def test_completed_admin_down_port_blocks_cleanup():
    states = {"ge-0/0/2": {"interface": "ge-0/0/2", "state": "ADMIN_DOWN", "admin_status": "down", "oper_status": "down", "dynamic_mac_present": False}}
    completed = {"ge-0/0/2": {"old_interface": "ge-0/0/2", "new_interface": "ge-0/0/2"}}
    value = classify_final_ports(_plan(), completed, states, "ge-0/0/47")
    assert value["result"] == "FAIL"
    assert value["blockers"][0]["reason"] == "CONFIRMED_ENDPOINT_PORT_ADMIN_DOWN"


def test_unmapped_active_or_silent_port_blocks_cleanup():
    states = {
        "ge-0/0/12": {"interface": "ge-0/0/12", "state": "ACTIVE_MAC", "admin_status": "up", "oper_status": "up", "dynamic_mac_present": True},
        "ge-0/0/13": {"interface": "ge-0/0/13", "state": "UP_SILENT", "admin_status": "up", "oper_status": "up", "dynamic_mac_present": False},
    }
    value = classify_final_ports(_plan(), {}, states, "ge-0/0/47")
    assert value["result"] == "FAIL"
    assert {row["reason"] for row in value["blockers"]} == {"UNMAPPED_PORT_CURRENTLY_ACTIVE", "UNMAPPED_PORT_UP_SILENT"}


def test_uncompleted_approved_endpoint_blocks_even_when_link_down():
    states = {"ge-0/0/2": {"interface": "ge-0/0/2", "state": "LINK_DOWN", "admin_status": "up", "oper_status": "down", "dynamic_mac_present": False}}
    value = classify_final_ports(_plan(), {}, states, "ge-0/0/47")
    assert value["result"] == "FAIL"
    assert value["blockers"][0]["reason"] == "APPROVED_ENDPOINT_INTENT_NOT_COMPLETED"


def test_current_port_state_detects_mac_and_silent():
    terse = "\n".join(["ge-0/0/2 up up", "ge-0/0/3 up up", "ge-0/0/4 up down"])
    states = current_port_states(terse, _mac("02:00:00:00:00:01", "ge-0/0/2"), ["ge-0/0/2", "ge-0/0/3", "ge-0/0/4"], "2026-09-09T18:00:00Z")
    assert states["ge-0/0/2"]["state"] == "ACTIVE_MAC"
    assert states["ge-0/0/3"]["state"] == "UP_SILENT"
    assert states["ge-0/0/4"]["state"] == "LINK_DOWN"


def _pre_config():
    return "\n".join([
        'set interfaces interface-range edge_ports member "ge-[0-9]/0/[2-47]"',
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members all",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set switch-options voip interface edge_ports vlan voip",
    ])


def test_pre_hardening_config_accepts_expected_template_state():
    classification = {"unused": [{"interface": "ge-0/0/10"}, {"interface": "ge-0/0/47"}]}
    value = validate_pre_hardening_config(_pre_config(), classification, "ge-0/0/47", "TEMP-RECOVERY", "voip")
    assert value["result"] == "PASS"
    assert value["edge_ports_expression"] == "ge-[0-9]/0/[2-47]"


def test_pre_hardening_blocks_unexpected_vlan_on_unused_port():
    config = _pre_config() + "\nset interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100\n"
    classification = {"unused": [{"interface": "ge-0/0/10"}]}
    value = validate_pre_hardening_config(config, classification, "ge-0/0/47", "TEMP-RECOVERY", "voip")
    assert value["result"] == "FAIL"
    assert value["unexpected_unused_port_memberships"][0]["unexpected"] == ["v100"]


def test_stale_vlan_cleanup_deletes_only_proven_unused_data_vlan():
    configured = [
        {"name": "v100", "vlan_id": 100, "classification": "data"},
        {"name": "v163", "vlan_id": 163, "classification": "management"},
        {"name": "v300", "vlan_id": 300, "classification": "data"},
    ]
    config = "\n".join([
        "set vlans v100 vlan-id 100",
        "set vlans v163 vlan-id 163",
        "set vlans v300 vlan-id 300",
        "set vlans v300 description legacy",
        "set vlans v300 forwarding-options dhcp-security group DHCP_TRUST interface ae0.0",
    ])
    value = stale_vlan_cleanup(config, "", configured, [100, 163])
    assert [row["name"] for row in value["delete"]] == ["v300"]

    referenced = config + "\nset interfaces ge-0/0/20 unit 0 family ethernet-switching vlan members v300\n"
    value = stale_vlan_cleanup(referenced, "", configured, [100, 163])
    assert value["delete"] == []
    assert value["preserve"][0]["reason"] == "EXTERNAL_CONFIGURATION_REFERENCE"

    dynamic = _mac("02:00:00:00:03:00", "ge-0/0/20", "v300", 300)
    value = stale_vlan_cleanup(config, dynamic, configured, [100, 163])
    assert value["delete"] == []
    assert value["preserve"][0]["reason"] == "DYNAMIC_MAC_PRESENT"


def test_hardening_replaces_all_preserves_voice_and_prunes_stale_vlan():
    config = _pre_config() + "\n" + "\n".join([
        "set vlans v300 vlan-id 300",
        "set vlans v300 description legacy",
        "set vlans v300 forwarding-options dhcp-security group DHCP_TRUST interface ae0.0",
    ])
    statements = hardening_statements(
        config,
        ["ge-0/0/10", "ge-0/0/47"],
        ["ge-0/0/2", "ge-0/0/3"],
        ["v100", "v163", "v200", "voip"],
        "voip",
        "TEMP-RECOVERY",
        stale_vlan_names=["v300"],
    )
    assert statements[0] == "delete interfaces ae0 unit 0 family ethernet-switching vlan members all"
    assert "set interfaces ge-0/0/10 disable" in statements
    assert "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default" in statements
    assert not any("switch-options voip" in statement for statement in statements)
    assert "delete vlans v300 vlan-id 300" in statements
    assert "delete vlans v300 description legacy" in statements


def test_hardening_does_not_repeat_preexisting_unused_state():
    config = _pre_config() + "\nset interfaces ge-0/0/10 disable\nset interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default\n"
    statements = hardening_statements(config, ["ge-0/0/10"], ["ge-0/0/2"], ["v100", "v163", "voip"], "voip", "TEMP-RECOVERY")
    assert "set interfaces ge-0/0/10 disable" not in statements
    assert "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default" not in statements


def test_final_hardening_validation_preserves_range_and_broad_voice_policy():
    config = "\n".join([
        'set interfaces interface-range edge_ports member "ge-[0-9]/0/[2-47]"',
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v163",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members voip",
        "set interfaces ge-0/0/10 disable",
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default",
        "set switch-options voip interface edge_ports vlan voip",
    ])
    value = validate_final_hardening(
        config,
        {},
        ["ge-0/0/2"],
        ["ge-0/0/10"],
        ["v100", "v163", "voip"],
        "voip",
        deleted_vlan_names=["v300"],
        expected_edge_expression="ge-[0-9]/0/[2-47]",
    )
    assert value["result"] == "PASS"


def test_inactive_vlan_cannot_be_in_production_trunk_list():
    with pytest.raises(Exception):
        hardening_statements(_pre_config(), ["ge-0/0/10"], ["ge-0/0/2"], ["v100", "default"], "voip", "TEMP-RECOVERY")
