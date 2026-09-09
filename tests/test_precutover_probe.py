from ex_migration_provisioner.precutover_probe import (
    discovered_candidate_macs,
    eligible_interfaces,
    live_candidate_state,
    silent_candidates,
)


def _analysis():
    return {
        "ports": [
            {
                "interface": "ge-0/0/2",
                "disposition": "DATA_ONLY",
                "configured_data_vlan_id": 100,
            },
            {
                "interface": "ge-0/0/10",
                "disposition": "CONFIGURED_NO_MAC",
                "configured_data_vlan_id": 100,
                "historical_observations": [],
            },
            {
                "interface": "ge-0/0/11",
                "disposition": "ACTIVE_UNASSIGNED_SILENT",
                "configured_data_vlan_id": None,
                "historical_observations": [],
            },
        ]
    }


def _config():
    return "\n".join([
        "set vlans v100 vlan-id 100",
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching interface-mode access",
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ge-0/0/11 unit 0 family ethernet-switching interface-mode access",
    ])


def _terse():
    return "\n".join([
        "ge-0/0/10 up up",
        "ge-0/0/11 up up",
    ])


def test_silent_candidates_are_derived_only_from_bound_analysis_dispositions():
    rows = silent_candidates(_analysis())
    assert [row["interface"] for row in rows] == ["ge-0/0/10", "ge-0/0/11"]
    assert rows[0]["configured_data_vlan_id"] == 100
    assert rows[1]["configured_data_vlan_id"] is None


def test_live_recheck_allows_only_still_silent_up_access_ports():
    rows = live_candidate_state(_config(), _terse(), "", silent_candidates(_analysis()))
    assert eligible_interfaces(rows) == ["ge-0/0/10", "ge-0/0/11"]


def test_live_recheck_skips_mac_vlan_and_link_changes():
    candidates = silent_candidates(_analysis())
    changed_config = _config().replace(
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v200",
    ) + "\nset vlans v200 vlan-id 200\n"
    changed_terse = "ge-0/0/10 up up\nge-0/0/11 up down\n"
    rows = live_candidate_state(changed_config, changed_terse, "", candidates)
    by_interface = {row["interface"]: row for row in rows}
    assert by_interface["ge-0/0/10"]["eligible"] is False
    assert by_interface["ge-0/0/10"]["skip_reason"] == "ACCESS_VLAN_CHANGED"
    assert by_interface["ge-0/0/11"]["eligible"] is False
    assert by_interface["ge-0/0/11"]["skip_reason"] == "INTERFACE_NOT_OPER_UP"


def test_live_recheck_skips_port_when_mac_has_appeared():
    mac_detail = """MAC address: 02:11:22:33:44:55
Routing instance: default-switch
VLAN name: v100, VLAN ID: 100
Learning interface: ge-0/0/10.0
Layer 2 flags: 0x1
"""
    rows = live_candidate_state(_config(), _terse(), mac_detail, silent_candidates(_analysis()))
    by_interface = {row["interface"]: row for row in rows}
    assert by_interface["ge-0/0/10"]["eligible"] is False
    assert by_interface["ge-0/0/10"]["skip_reason"] == "MAC_NOW_PRESENT"
    assert by_interface["ge-0/0/11"]["eligible"] is True


def test_discovered_candidate_macs_only_reports_dynamic_candidate_evidence():
    snapshot = {
        "mac_observations": [
            {
                "physical_interface": "ge-0/0/10",
                "mac": "02:11:22:33:44:55",
                "mac_type": "dynamic",
                "vlan": {"vlan_id": 100},
            },
            {
                "physical_interface": "ge-0/0/10",
                "mac": "02:aa:bb:cc:dd:ee",
                "mac_type": "static",
                "vlan": {"vlan_id": 100},
            },
            {
                "physical_interface": "ge-0/0/2",
                "mac": "02:00:00:00:00:02",
                "mac_type": "dynamic",
                "vlan": {"vlan_id": 100},
            },
        ]
    }
    assert discovered_candidate_macs(snapshot, ["ge-0/0/10"]) == {
        "ge-0/0/10": [{"mac": "02:11:22:33:44:55", "vlan_id": 100}]
    }
