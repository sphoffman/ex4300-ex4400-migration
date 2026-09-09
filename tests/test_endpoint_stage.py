import hashlib
import json

import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.endpoint_stage import (
    committed_endpoint_state,
    correlate_endpoint_intent,
    detect_silent_up_ports,
    resolve_postcutover_access,
    validate_postcutover_access,
)
from ex_migration_provisioner.endpoint_stage_cli import (
    _interface_up_from_terse,
    _interfaces_config_set,
    _planned_config_rows,
    _reconcile_completed_state,
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


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _write_endpoint_history(migration_root, transaction_id, correlation_id, plan_digest, old_interface, new_interface):
    correlation_dir = migration_root / "endpoint-correlations" / correlation_id
    correlation = {
        "migration_id": migration_root.name,
        "inputs": {"approved_plan_digest": plan_digest},
    }
    _write_json(correlation_dir / "correlation.json", correlation)
    correlation_digest = hashlib.sha256((correlation_dir / "correlation.json").read_bytes()).hexdigest()
    _write_json(correlation_dir / "integrity.json", {"correlation.json": correlation_digest})

    tx_dir = migration_root / "endpoint-transactions" / transaction_id
    tx = {
        "transaction_id": transaction_id,
        "migration_id": migration_root.name,
        "correlation_id": correlation_id,
        "activated": [{
            "old_interface": old_interface,
            "new_interface": new_interface,
            "statements": [
                "set interfaces %s unit 0 family ethernet-switching vlan members v100" % new_interface
            ],
        }],
        "commit": {"status": "COMMITTED_AND_CONFIRMED", "confirmed": True},
        "validation": {"result": "PASS"},
    }
    _write_json(tx_dir / "transaction.json", tx)
    (tx_dir / "candidate.diff").write_text("diff\n", encoding="utf-8")
    _write_json(tx_dir / "integrity.json", {
        "transaction.json": hashlib.sha256((tx_dir / "transaction.json").read_bytes()).hexdigest(),
        "candidate.diff": hashlib.sha256((tx_dir / "candidate.diff").read_bytes()).hexdigest(),
    })


def test_committed_endpoint_state_skips_transactions_from_other_plans(tmp_path):
    migration_root = tmp_path / "migrations" / "sw1203"
    current_digest = "a" * 64
    stale_digest = "b" * 64
    _write_endpoint_history(
        migration_root, "current-tx", "current-corr", current_digest,
        "ge-0/0/2", "ge-0/0/10",
    )
    _write_endpoint_history(
        migration_root, "stale-tx", "stale-corr", stale_digest,
        "ge-0/0/3", "ge-0/0/11",
    )

    state = committed_endpoint_state(migration_root, current_digest)
    assert state["transaction_ids"] == ["current-tx"]
    assert list(state["by_old"]) == ["ge-0/0/2"]
    assert state["by_new"] == {"ge-0/0/10": "ge-0/0/2"}


def test_unambiguous_endpoint_correlation_and_silent_hold():
    text = "".join([
        _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/10"),
        _mac("02:00:00:00:00:02", "voip", 1111, "ge-0/0/10"),
        _mac("02:00:00:00:00:03", "default", 3998, "ge-0/0/11"),
    ])
    value = correlate_endpoint_intent(
        _plan(),
        text,
        recovery_interface="ge-0/0/47",
        management_vlan_id=163,
        voice_vlan_id=1111,
        temporary_recovery_vlan_id=3999,
        prestage_access_vlan_id=3998,
        uplink_interfaces=["ge-0/0/0", "ge-0/0/1"],
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


def test_rerun_skips_live_completed_old_interface():
    text = "".join([
        _mac("02:00:00:00:00:01", "v100", 100, "ge-0/0/10"),
        _mac("02:00:00:00:00:03", "default", 3998, "ge-0/0/11"),
    ])
    completed = {
        "ge-0/0/2": {
            "old_interface": "ge-0/0/2",
            "new_interface": "ge-0/0/10",
            "data_vlan_id": 100,
            "data_vlan_name": "v100",
            "statements": [
                'set interfaces ge-0/0/10 description "Desk A"',
                "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
            ],
        }
    }
    value = correlate_endpoint_intent(
        _plan(), text, "ge-0/0/47", 163, 1111, 3999,
        prestage_access_vlan_id=3998,
        uplink_interfaces=["ge-0/0/0", "ge-0/0/1"],
        completed=completed,
    )
    assert [row["old_interface"] for row in value["completed"]] == ["ge-0/0/2"]
    assert [(row["old_interface"], row["new_interface"]) for row in value["activated"]] == [
        ("ge-0/0/3", "ge-0/0/11")
    ]


def test_unresolved_intent_cannot_claim_completed_new_port():
    plan = _plan()
    plan["port_intents"][1]["endpoint_macs"] = ["02:00:00:00:00:01"]
    completed = {
        "ge-0/0/2": {
            "old_interface": "ge-0/0/2",
            "new_interface": "ge-0/0/10",
            "statements": ["set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100"],
        }
    }
    text = _mac("02:00:00:00:00:01", "v100", 100, "ge-0/0/10")
    value = correlate_endpoint_intent(
        plan, text, "ge-0/0/47", 163, 1111, 3999,
        completed=completed,
    )
    desk_b = next(row for row in value["holds"] if row["old_interface"] == "ge-0/0/3")
    assert desk_b["reason"] == "NEW_PORT_ALREADY_ASSIGNED_TO_COMPLETED_INTENT"
    assert desk_b["completed_old_interface"] == "ge-0/0/2"


def test_recovery_port_is_never_auto_correlated():
    text = _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/47")
    value = correlate_endpoint_intent(
        _plan(), text, "ge-0/0/47", 163, 1111, 3999, prestage_access_vlan_id=3998
    )
    desk_a = next(row for row in value["holds"] if row["old_interface"] == "ge-0/0/2")
    assert desk_a["reason"] == "NO_APPROVED_MAC_OBSERVED_POST_MOVE"


def test_ge_zero_and_one_are_eligible_with_et_uplinks_but_not_ge_uplinks():
    text = _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/0")
    production = correlate_endpoint_intent(
        _plan(), text, "ge-0/0/47", 163, 1111, 3999,
        prestage_access_vlan_id=3998,
        uplink_interfaces=["et-0/1/0", "et-0/1/1"],
    )
    assert production["activated"][0]["new_interface"] == "ge-0/0/0"

    lab = correlate_endpoint_intent(
        _plan(), text, "ge-0/0/47", 163, 1111, 3999,
        prestage_access_vlan_id=3998,
        uplink_interfaces=["ge-0/0/0", "ge-0/0/1"],
    )
    assert not lab["activated"]


def test_multiple_old_intents_cannot_claim_same_new_port():
    plan = _plan()
    plan["port_intents"][1]["endpoint_macs"] = ["02:00:00:00:00:01"]
    text = _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/10")
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


def test_silent_up_port_detection_excludes_uplinks_recovery_and_ports_with_macs():
    terse = "\n".join([
        "ge-0/0/0               up    up",
        "ge-0/0/10              up    up",
        "ge-0/0/11              up    up",
        "ge-0/0/12              up    down",
        "ge-0/0/47              up    up",
    ])
    mac_text = _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/10")
    silent = detect_silent_up_ports(
        terse,
        mac_text,
        "ge-0/0/47",
        uplink_interfaces=["ge-0/0/0", "ge-0/0/1"],
        completed_by_new={"ge-0/0/11": "ge-0/0/4"},
    )
    assert silent == [{
        "interface": "ge-0/0/11",
        "completed_old_interface": "ge-0/0/4",
    }]


def test_historical_completion_is_reopened_when_live_config_no_longer_contains_it():
    row = {
        "old_interface": "ge-0/0/2",
        "new_interface": "ge-0/0/10",
        "transaction_id": "abc123",
        "statements": [
            'set interfaces ge-0/0/10 description "Desk A"',
            "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
        ],
    }
    historical = {
        "by_old": {"ge-0/0/2": row},
        "by_new": {"ge-0/0/10": "ge-0/0/2"},
        "transaction_ids": ["abc123"],
    }
    complete = "\n".join(row["statements"])
    live = _reconcile_completed_state(complete, historical)
    assert list(live["by_old"]) == ["ge-0/0/2"]
    assert live["stale"] == []

    stale = _reconcile_completed_state(
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members default\n",
        historical,
    )
    assert stale["by_old"] == {}
    assert stale["stale"] == [{
        "old_interface": "ge-0/0/2",
        "new_interface": "ge-0/0/10",
        "transaction_id": "abc123",
        "reason": "HISTORICAL_COMPLETION_NOT_PRESENT_IN_CURRENT_CONFIG",
    }]


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


def test_bulk_candidate_validation_requires_every_planned_statement():
    activated = [
        {
            "old_interface": "ge-0/0/2",
            "new_interface": "ge-0/0/10",
            "statements": [
                'set interfaces ge-0/0/10 description "Desk A"',
                "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
            ],
        },
        {
            "old_interface": "ge-0/0/3",
            "new_interface": "ge-0/0/11",
            "statements": [
                "set interfaces ge-0/0/11 unit 0 family ethernet-switching vlan members v200",
            ],
        },
    ]
    complete = "\n".join([
        'set interfaces ge-0/0/10 description "Desk A"',
        "set interfaces ge-0/0/10 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ge-0/0/11 unit 0 family ethernet-switching vlan members v200",
    ])
    ok, rows = _planned_config_rows(complete, activated)
    assert ok is True
    assert all(row["configuration_present"] for row in rows)

    incomplete = complete.replace(
        "set interfaces ge-0/0/11 unit 0 family ethernet-switching vlan members v200",
        "",
    )
    ok, rows = _planned_config_rows(incomplete, activated)
    assert ok is False
    missing = next(row for row in rows if row["new_interface"] == "ge-0/0/11")
    assert missing["configuration_present"] is False
    assert missing["missing_statements"] == [
        "set interfaces ge-0/0/11 unit 0 family ethernet-switching vlan members v200"
    ]


def test_bulk_interface_state_parsing():
    terse = "\n".join([
        "ge-0/0/10               up    up",
        "ge-0/0/10.0             up    up   eth-switch",
        "ge-0/0/11               up    down",
    ])
    assert _interface_up_from_terse(terse, "ge-0/0/10") is True
    assert _interface_up_from_terse(terse, "ge-0/0/11") is False


def test_interfaces_config_set_uses_candidate_default_and_committed_option():
    class Reply:
        text = "set interfaces ge-0/0/10 description Desk-A\n"

    class RPC:
        def __init__(self):
            self.calls = []

        def get_config(self, **kwargs):
            self.calls.append(kwargs)
            return Reply()

    class Dev:
        def __init__(self):
            self.rpc = RPC()

    dev = Dev()
    assert "ge-0/0/10" in _interfaces_config_set(dev, "candidate")
    assert dev.rpc.calls[-1]["options"] == {"format": "set"}
    assert "ge-0/0/10" in _interfaces_config_set(dev, "committed")
    assert dev.rpc.calls[-1]["options"] == {
        "format": "set",
        "database": "committed",
    }
