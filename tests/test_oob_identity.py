import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.write import (
    build_bootstrap_identity,
    parse_mgmt_junos_default_gateway,
)


def _bootstrap(environment="lab"):
    return {
        "schema_version": "1.0",
        "profile_id": "lab-in-place-v1",
        "environment": environment,
        "provisioning_mode": "in-place-lab" if environment == "lab" else "production",
        "production_eligible": environment == "production",
        "virtual_chassis": {"member_count": 1, "members": []},
    }


def _observed():
    return {
        "connection": {
            "address": "10.255.3.18",
            "port": 830,
            "ssh_host_key_sha256": "SHA256:test",
        },
        "oob_management": {
            "address": "10.255.3.18/24",
            "routing_instance": "mgmt_junos",
            "default_gateway": "10.0.0.2",
            "gateway_source": "observed-configured-mgmt_junos-default",
        },
        "device": {
            "hostname": "vQFX3",
            "model": "EX9214",
            "serial_number": "VM6A9FECABFC",
            "members": [
                {
                    "member_id": 0,
                    "status": "Prsnt",
                    "serial_number": "VM6A9FECABFC",
                    "model": "EX9214",
                }
            ],
        },
    }


def test_parse_single_mgmt_junos_default_gateway():
    text = (
        "set routing-instances mgmt_junos routing-options static route "
        "0.0.0.0/0 next-hop 10.0.0.2\n"
    )
    assert parse_mgmt_junos_default_gateway(text) == "10.0.0.2"


def test_parse_mgmt_junos_default_fails_closed_on_none_or_multiple():
    with pytest.raises(ProvisioningError):
        parse_mgmt_junos_default_gateway("")
    with pytest.raises(ProvisioningError):
        parse_mgmt_junos_default_gateway(
            "set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 10.0.0.2\n"
            "set routing-instances mgmt_junos routing-options static route default next-hop 10.0.0.3\n"
        )


def test_lab_vjunos_identity_uses_one_authoritative_oob_address():
    identity = build_bootstrap_identity(
        "sw1203",
        _bootstrap(),
        "a" * 64,
        _observed(),
        "2026-09-09T12:00:00Z",
    )
    assert identity["schema_version"] == "1.1"
    assert identity["observed"]["connection"]["address"] == "10.255.3.18"
    assert "transport_address" not in identity["observed"]["connection"]
    assert identity["observed"]["oob_management"]["address"] == "10.255.3.18/24"
    assert identity["observed"]["oob_management"]["default_gateway"] == "10.0.0.2"
    assert identity["eligibility"]["status"] == "LAB_ONLY"
