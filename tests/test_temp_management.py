import pytest

from ex_migration_provisioner import cli_base as base
from ex_migration_provisioner.temp_management_cli import (
    _candidate_statements,
    _select_temp_management_port,
)


def test_select_temp_management_port_uses_highest_proven_unused_old_port():
    plan = {
        "port_intents": [
            {"old_interface": "ge-0/0/46", "planned_action": "LEAVE_TEMPLATE_DEFAULT"},
            {"old_interface": "ge-0/0/47", "planned_action": "CORRELATE_AFTER_CABLE_MOVE"},
            {"old_interface": "ge-1/0/45", "planned_action": "LEAVE_TEMPLATE_DEFAULT"},
        ]
    }
    name, item = _select_temp_management_port(plan)
    assert name == "ge-1/0/45"
    assert item["planned_action"] == "LEAVE_TEMPLATE_DEFAULT"


def test_select_temp_management_port_fails_closed_without_unused_port():
    plan = {
        "port_intents": [
            {"old_interface": "ge-0/0/47", "planned_action": "CORRELATE_AFTER_CABLE_MOVE"},
        ]
    }
    with pytest.raises(base.ProvisioningError, match="no proven-unused"):
        _select_temp_management_port(plan)


def test_candidate_stages_vlan_old_access_port_and_explicit_ae0_member():
    config = "\n".join([
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v163",
    ])
    statements = _candidate_statements(
        config,
        "ge-0/0/47",
        {"name": "Temp-Management", "vlan_id": 3999},
    )
    assert statements == [
        "set vlans Temp-Management vlan-id 3999",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching interface-mode access",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members Temp-Management",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members Temp-Management",
    ]


def test_candidate_does_not_add_redundant_ae0_member_when_trunk_uses_all():
    config = "\n".join([
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members all",
        "set vlans Temp-Management vlan-id 3999",
    ])
    statements = _candidate_statements(
        config,
        "ge-0/0/47",
        {"name": "Temp-Management", "vlan_id": 3999},
    )
    assert statements == [
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching interface-mode access",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members Temp-Management",
    ]


def test_candidate_refuses_nonempty_reserved_port():
    config = "\n".join([
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members all",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching interface-mode access",
    ])
    with pytest.raises(base.ProvisioningError, match="not configuration-empty"):
        _candidate_statements(
            config,
            "ge-0/0/47",
            {"name": "Temp-Management", "vlan_id": 3999},
        )
