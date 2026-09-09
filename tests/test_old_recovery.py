import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.old_recovery import (
    build_recovery_transaction,
    recovery_statement,
    recovery_statements,
)


def test_recovery_statement_uses_vme_for_ex4300_vc():
    assert recovery_statement("vme", "10.0.0.15/24") == (
        "set interfaces vme unit 0 family inet address 10.0.0.15/24"
    )


def test_complete_recovery_intent_uses_mgmt_junos_only():
    statements = recovery_statements("vme", "10.0.0.15/24", "10.0.0.2")
    assert statements == [
        "set system management-instance",
        "set interfaces vme unit 0 family inet address 10.0.0.15/24",
        "set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 10.0.0.2",
    ]
    assert not any(line.startswith("set routing-options static route") for line in statements)


def test_recovery_gateway_must_be_on_bootstrap_subnet():
    with pytest.raises(ProvisioningError, match="gateway is not on"):
        recovery_statements("vme", "10.0.0.15/24", "192.0.2.1")


def test_recovery_transaction_preserves_inband_master_table_and_binds_bootstrap_identity():
    plan = {"plan_id": "plan123"}
    tx = build_recovery_transaction(
        "sw1203",
        plan,
        "1" * 64,
        "2" * 64,
        "production",
        "10.100.163.30",
        "10.100.163.30",
        "vme",
        "10.0.0.15/24",
        "10.0.0.2",
        "10.0.0.15",
        "SHA256:old",
        "[edit interfaces vme]\n+ unit 0 family inet address 10.0.0.15/24;\n",
        "2026-09-09T12:00:00Z",
        10,
        "DIRECT_RECOVERY_ADDRESS",
        bootstrap_identity_id="identity123",
        bootstrap_identity_digest="3" * 64,
        bootstrap_profile_digest="4" * 64,
    )
    assert tx["schema_version"] == "1.1"
    assert tx["recovery"]["interface"] == "vme"
    assert tx["recovery"]["routing_instance"] == "mgmt_junos"
    assert tx["recovery"]["address"] == "10.0.0.15/24"
    assert tx["recovery"]["gateway"] == "10.0.0.2"
    assert tx["source_access"]["logical_address"] == "10.100.163.30"
    assert tx["inputs"]["bootstrap_identity_id"] == "identity123"
    assert tx["safety"]["existing_inband_management_preserved"] is True
    assert tx["safety"]["master_routing_table_default_unchanged"] is True
    assert tx["safety"]["dedicated_management_instance_required"] is True
    assert tx["safety"]["bootstrap_oob_address_released_by_replacement_acknowledged"] is True
    assert tx["safety"]["secondary_recovery_connection_required"] is True
    assert tx["commit"]["status"] == "APPROVED_PENDING_COMMIT"
