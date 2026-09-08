import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.endpoint_stage import (
    correlate_endpoint_intent,
    resolve_postcutover_access,
    validate_postcutover_access,
)


def _plan():
    return {
        "vlan_intents": [
            {"name": "v100", "vlan_id": 100},
            {"name": "v163", "vlan_id": 163},
            {"name": "v200", "vlan_id": 200},
            {"name": "UNUSED-TEST", "vlan_id": 300},
            {"name": "voip", "vlan_id": 1111},
        ],
        "port_intents": [
            {
                "old_interface": "ge-0/0/2",
                "description": "Desk A",
                "configured_data_vlan_id": 100,
                "endpoint_macs": ["02:00:00:00:00:01", "02:00:00:00:00:02"],
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
            {
                "old_interface": "ge-0/0/3",
                "description": "Desk B",
                "configured_data_vlan_id": 200,
                "endpoint_macs": ["02:00:00:00:00:03"],
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
            {
                "old_interface": "ge-0/0/4",
                "description": "Silent",
                "configured_data_vlan_id": 100,
                "endpoint_macs": ["02:00:00:00:00:04"],
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
        ],
    }


def _mac(mac, vlan_name, vlan_id, interface):
    return "\n".join([
        "MAC address: %s" % mac,
        "Routing instance: default-switch",
        "VLAN name: %s, VLAN ID: %s" % (vlan_name, vlan_id),
        "Learning interface: %s.0" % interface,
        "Layer 2 flags: 0x1",
        "",
    ])


def test_unambiguous_endpoint_correlation_and_silent_hold():
    text = "".join([
        _mac("02:00:00:00:00:01", "v100", 100, "ge-0/0/10"),
        # Same historical endpoint can appear in another VLAN as long as it is
        # learned on the same physical port.
        _mac("02:00:00:00:00:02", "voip", 1111, "ge-0/0/10"),
        _mac("02:00:00:00:00:03", "v200", 200, "ge-0/0/11"),
    ])
    value = correlate_endpoint_intent(
        _plan(),
        text,
        recovery_interface="ge-0/0/47",
        management_vlan_id=163,
        voice_vlan_id=1111,
        temporary_recovery_vlan_id=3999,
    )
    assert [(row["old_interface"], row["new_interface"]) for row in value["activated"]] == [
        ("ge-0/0/2", "ge-0/0/10"),
        ("ge-0/0/3", "ge-0/0/11"),
    ]
    assert value["activated"][0]["statements"] == [
        'set interfaces ge-0/0/10 description "Desk A"',
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
    ]
    assert value["holds"] == [
        {
            "old_interface": "ge-0/0/4",
            "reason": "NO_APPROVED_MAC_OBSERVED_POST_MOVE",
            "expected_macs": ["02:00:00:00:00:04"],
            "observed_support": {},
        }
    ]


def test_recovery_port_is_never_auto_correlated():
    text = _mac("02:00:00:00:00:01", "v100", 100, "ge-0/0/47")
    value = correlate_endpoint_intent(
        _plan(), text, "ge-0/0/47", 163, 1111, 3999
    )
    desk_a = next(row for row in value["holds"] if row["old_interface"] == "ge-0/0/2")
    assert desk_a["reason"] == "NO_APPROVED_MAC_OBSERVED_POST_MOVE"


def test_multiple_old_intents_cannot_claim_same_new_port():
    plan = _plan()
    plan["port_intents"][1]["endpoint_macs"] = ["02:00:00:00:00:01"]
    text = _mac("02:00:00:00:00:01", "v100", 100, "ge-0/0/10")
    value = correlate_endpoint_intent(plan, text, "ge-0/0/47", 163, 1111, 3999)
    assert not value["activated"]
    reasons = {
        row["old_interface"]: row["reason"]
        for row in value["holds"]
        if row["old_interface"] in ("ge-0/0/2", "ge-0/0/3")
    }
    assert reasons == {
        "ge-0/0/2": "MULTIPLE_APPROVED_PORT_INTENTS_MAP_TO_SAME_NEW_PORT",
        "ge-0/0/3": "MULTIPLE_APPROVED_PORT_INTENTS_MAP_TO_SAME_NEW_PORT",
    }


def test_lab_transport_override_and_production_direct_management():
    lab = {
        "schema_version": "1.0",
        "environment": "lab",
        "postcutover_ex_access": {
            "mode": "transport-override",
            "transport_address": "10.255.3.18",
            "port": 830,
        },
    }
    assert resolve_postcutover_access(lab, "10.100.163.30") == {
        "environment": "lab",
        "mode": "transport-override",
        "logical_address": "10.100.163.30",
        "transport_address": "10.255.3.18",
        "port": 830,
        "allow_vjunos_switch": True,
    }

    prod = {
        "schema_version": "1.0",
        "environment": "production",
        "postcutover_ex_access": {
            "mode": "direct-management",
            "port": 830,
        },
    }
    assert resolve_postcutover_access(prod, "10.100.163.30")["transport_address"] == "10.100.163.30"


def test_transport_override_is_lab_only():
    profile = {
        "schema_version": "1.0",
        "environment": "production",
        "postcutover_ex_access": {
            "mode": "transport-override",
            "transport_address": "192.0.2.10",
            "port": 830,
        },
    }
    with pytest.raises(ProvisioningError):
        validate_postcutover_access(profile)
