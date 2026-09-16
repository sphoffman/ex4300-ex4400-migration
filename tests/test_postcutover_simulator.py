import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.postcutover_simulator import (
    build_simulated_postcutover_observation,
)


def _plan():
    ports = []
    for interface, mac, voice in [
        ("ge-0/0/2", "02:00:00:00:00:02", False),
        ("ge-0/0/3", "02:00:00:00:00:03", False),
        ("ge-0/0/4", "02:00:00:00:00:04", True),
        ("ge-1/0/2", "02:00:00:00:01:02", False),
        ("ge-1/0/3", "02:00:00:00:01:03", False),
        ("ge-1/0/4", "02:00:00:00:01:04", False),
    ]:
        historical = [{
            "mac": mac,
            "vlan_id": 1111 if voice else 100,
            "interface": interface,
        }]
        ports.append({
            "old_interface": interface,
            "configured_data_vlan_id": 100,
            "endpoint_macs": [mac],
            "historical_observations": historical,
            "pre_migration_state": {"latest_state": "ACTIVE_MAC"},
            "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
        })
    return {
        "plan_id": "plan-1",
        "migration_id": "sw1203",
        "template_variables": {"new_hostname": "sw1203-new"},
        "vlan_intents": [
            {"name": "v100", "vlan_id": 100},
            {"name": "voip", "vlan_id": 1111},
        ],
        "port_intents": ports,
    }


def _identity():
    return {
        "identity_id": "identity-1",
        "observed": {
            "connection": {
                "address": "10.0.0.15",
                "port": 830,
                "ssh_host_key_sha256": "SHA256:" + "A" * 43,
            },
            "device": {
                "hostname": "factory-name",
                "model": "EX4400-48F",
                "serial_number": "SERIAL0",
                "members": [
                    {
                        "member_id": 0,
                        "status": "Prsnt",
                        "serial_number": "SERIAL0",
                        "model": "EX4400-48F",
                    },
                    {
                        "member_id": 1,
                        "status": "Prsnt",
                        "serial_number": "SERIAL1",
                        "model": "EX4400-48F",
                    },
                ],
            },
        },
    }


def _package():
    return {
        "package_id": "package-1",
        "variables": {
            "voice_vlan_id": 1111,
            "voice_vlan_name": "voip",
            "prestage_access_vlan_id": 3998,
            "prestage_access_vlan_name": "PRESTAGE",
            "uplink_interfaces": ["ge-0/0/0", "ge-0/0/1"],
            "recovery_interface": "ge-1/0/47",
        },
    }


def _access():
    return {
        "environment": "lab",
        "mode": "transport-override",
        "logical_address": "10.100.163.30",
        "transport_address": "10.0.0.15",
        "port": 830,
    }


def _build(swap_pairs=2):
    return build_simulated_postcutover_observation(
        "sw1203",
        _plan(),
        "a" * 64,
        _identity(),
        "b" * 64,
        _package(),
        "c" * 64,
        _access(),
        swap_pairs=swap_pairs,
        observed_at="2026-09-16T18:00:00Z",
    )


def test_default_simulation_uses_two_swap_pairs_across_members():
    result = _build()
    scenario = result["scenario"]
    assert scenario["name"] == "NORMAL_WITH_TWO_SWAPS"
    assert scenario["statistics"] == {
        "correlatable_endpoint_intents": 6,
        "approved_endpoint_macs": 6,
        "same_position_placements": 2,
        "moved_placements": 4,
        "missing_endpoints": 0,
        "unexpected_endpoints": 0,
    }
    assert scenario["mutations"] == [
        {
            "a": {
                "old_interface": "ge-0/0/2",
                "new_interface": "ge-0/0/3",
            },
            "b": {
                "old_interface": "ge-0/0/3",
                "new_interface": "ge-0/0/2",
            },
        },
        {
            "a": {
                "old_interface": "ge-1/0/2",
                "new_interface": "ge-1/0/3",
            },
            "b": {
                "old_interface": "ge-1/0/3",
                "new_interface": "ge-1/0/2",
            },
        },
    ]


def test_simulated_observation_matches_production_shape_and_holding_vlan_model():
    result = _build()
    observation = result["observation"]
    assert observation["source"] == {"kind": "SIMULATED"}
    assert observation["device"]["hostname"] == "sw1203-new"
    assert observation["device"]["ssh_host_key_sha256"].startswith("SHA256:")
    assert observation["statistics"]["physical_interfaces_observed"] == 96
    assert observation["statistics"]["unique_dynamic_macs"] == 6

    by_mac = {
        row["mac"]: row
        for row in observation["mac_observations"]
    }
    assert by_mac["02:00:00:00:00:04"]["vlan"] == {
        "name": "voip",
        "vlan_id": 1111,
    }
    assert by_mac["02:00:00:00:00:02"]["vlan"] == {
        "name": "PRESTAGE",
        "vlan_id": 3998,
    }


def test_simulation_is_deterministic_for_fixed_inputs_and_timestamp():
    first = _build()
    second = _build()
    assert first["scenario"] == second["scenario"]
    assert first["mac_table_text"] == second["mac_table_text"]
    assert first["terse_text"] == second["terse_text"]
    assert first["observation"] == second["observation"]


def test_zero_swaps_keeps_every_endpoint_in_same_physical_position():
    result = _build(swap_pairs=0)
    assert result["scenario"]["name"] == "NORMAL_NO_SWAPS"
    assert result["scenario"]["statistics"]["moved_placements"] == 0
    assert all(
        row["old_interface"] == row["new_interface"]
        for row in result["scenario"]["placements"]
    )


def test_swap_request_fails_when_not_enough_populated_ports():
    plan = _plan()
    plan["port_intents"] = plan["port_intents"][:2]
    with pytest.raises(ProvisioningError, match="requested 2 swap pair"):
        build_simulated_postcutover_observation(
            "sw1203",
            plan,
            "a" * 64,
            _identity(),
            "b" * 64,
            _package(),
            "c" * 64,
            _access(),
            swap_pairs=2,
            observed_at="2026-09-16T18:00:00Z",
        )


def test_uplinks_and_recovery_port_are_never_destination_assignments():
    result = _build()
    destinations = {
        row["new_interface"]
        for row in result["scenario"]["placements"]
    }
    assert "ge-0/0/0" not in destinations
    assert "ge-0/0/1" not in destinations
    assert "ge-1/0/47" not in destinations
