import pytest

from ex_migration_provisioner import old_recovery_cli as recovery_cli
from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.old_recovery import (
    build_recovery_transaction,
    build_recovery_verification,
    recovery_statement,
    recovery_statements,
)


class FakeConfigDevice:
    def __init__(self, config_text):
        self.config_text = config_text

    def cli(self, command, warning=False):
        assert command == "show configuration | display set"
        return self.config_text


def test_recovery_statement_uses_vme_for_ex4300_vc():
    assert recovery_statement("vme", "10.255.3.18/24") == (
        "set interfaces vme unit 0 family inet address 10.255.3.18/24"
    )


def test_complete_recovery_intent_uses_mgmt_junos_only():
    statements = recovery_statements("vme", "10.255.3.18/24", "10.0.0.2")
    assert statements == [
        "set system management-instance",
        "set interfaces vme unit 0 family inet address 10.255.3.18/24",
        "set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 10.0.0.2",
    ]
    assert not any(line.startswith("set routing-options static route") for line in statements)


def test_recovery_gateway_may_be_off_subnet_when_inherited_from_approved_identity():
    statements = recovery_statements("vme", "10.255.3.18/24", "10.0.0.2")
    assert statements[-1].endswith("next-hop 10.0.0.2")


def test_recovery_gateway_cannot_equal_recovery_ip():
    with pytest.raises(ProvisioningError, match="cannot equal"):
        recovery_statements("vme", "10.255.3.18/24", "10.255.3.18")


def test_recovery_validation_requires_authoritative_vme_state():
    statements = recovery_statements("vme", "10.255.3.18/24", "10.0.0.2")
    exact = "\n".join(statements) + "\n"
    assert recovery_cli._validate_recovery_config(
        FakeConfigDevice(exact), statements, [], "vme", "10.255.3.18/24"
    ) is True

    stale = exact + "set interfaces vme description stale-recovery-config\n"
    with pytest.raises(ProvisioningError, match="not authoritative"):
        recovery_cli._validate_recovery_config(
            FakeConfigDevice(stale), statements, [], "vme", "10.255.3.18/24"
        )


def test_recovery_transaction_models_pre_cutover_physical_isolation():
    plan = {
        "plan_id": "plan123",
        "template_variables": {"old_hostname": "home1-ex4300-vc-fd-sw1203"},
    }
    tx = build_recovery_transaction(
        "sw1203",
        plan,
        "1" * 64,
        "2" * 64,
        "production",
        "10.100.163.30",
        "10.100.163.30",
        "vme",
        "10.255.3.18/24",
        "10.0.0.2",
        "SHA256:old",
        "[edit interfaces vme]\n+ unit 0 family inet address 10.255.3.18/24;\n",
        "2026-09-09T12:00:00Z",
        10,
        bootstrap_identity_id="identity123",
        bootstrap_identity_digest="3" * 64,
        bootstrap_profile_digest="4" * 64,
        master_defaults_before=[
            "set routing-options static route 0.0.0.0/0 next-hop 10.100.163.1"
        ],
    )
    assert tx["schema_version"] == "1.5"
    assert tx["recovery"]["interface"] == "vme"
    assert tx["recovery"]["routing_instance"] == "mgmt_junos"
    assert tx["recovery"]["address"] == "10.255.3.18/24"
    assert tx["recovery"]["gateway"] == "10.0.0.2"
    assert tx["recovery"]["logical_address"] == "10.255.3.18"
    assert tx["recovery"]["address_source"] == "APPROVED_REPLACEMENT_IDENTITY_OOB"
    assert tx["recovery"]["gateway_source"] == "APPROVED_REPLACEMENT_IDENTITY_MGMT_JUNOS_DEFAULT"
    assert tx["source_identity"]["configured_hostname"] == "home1-ex4300-vc-fd-sw1203"
    assert tx["inputs"]["bootstrap_identity_id"] == "identity123"
    assert tx["safety"]["replacement_may_still_own_oob_ip_before_cutover"] is True
    assert tx["safety"]["duplicate_oob_ip_requires_physical_l2_isolation_until_cable_move"] is True
    assert tx["safety"]["vme_interface_replaced_with_approved_recovery_state"] is True
    assert tx["safety"]["post_cable_recovery_verification_optional"] is True
    assert tx["validation"]["recovery_path_verified"] is False
    assert tx["commit"]["status"] == "APPROVED_PENDING_COMMIT"


def test_recovery_verification_binds_committed_transaction():
    tx = {
        "migration_id": "sw1203",
        "transaction_id": "tx123",
    }
    verification = build_recovery_verification(
        tx,
        "a" * 64,
        "home1-ex4300-vc-fd-sw1203",
        "SHA256:old",
        "b" * 64,
        "2026-09-09T13:00:00Z",
    )
    assert verification["migration_id"] == "sw1203"
    assert verification["inputs"]["recovery_transaction_id"] == "tx123"
    assert verification["inputs"]["recovery_transaction_digest"] == "a" * 64
    assert verification["result"] == "PASS"
    assert "RECOVERY_SSH_HOST_KEY_MATCH" in verification["checks"]