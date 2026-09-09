import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ex_migration_provisioner import cli


ROOT = Path(__file__).resolve().parents[1]


def legacy_identity(transport_address=None):
    connection = {
        "address": "10.0.0.15",
        "port": 830,
        "ssh_host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }
    if transport_address is not None:
        connection["transport_address"] = transport_address
    return {
        "schema_version": "1.0",
        "identity_id": "0123456789abcdef",
        "migration_id": "sw1203",
        "approved_at": "2026-09-08T14:00:00Z",
        "bootstrap": {
            "profile_id": "lab-in-place-v1",
            "profile_digest": "a" * 64,
            "provisioning_mode": "in-place-lab",
        },
        "observed": {
            "connection": connection,
            "device": {
                "hostname": "vjunos-switch",
                "model": "EX9214",
                "serial_number": "VM1234",
                "members": [
                    {
                        "member_id": 0,
                        "status": "Prsnt",
                        "serial_number": "VM1234",
                        "model": "EX9214",
                    }
                ],
            },
        },
        "approval": {
            "method": "interactive-operator-binding",
            "approved": True,
        },
        "eligibility": {
            "status": "LAB_ONLY",
            "production_eligible": False,
            "reason": "historical lab transport identity",
        },
    }


def new_identity(address="10.255.3.18"):
    return {
        "schema_version": "1.1",
        "identity_id": "fedcba9876543210",
        "migration_id": "sw1203",
        "approved_at": "2026-09-09T14:00:00Z",
        "bootstrap": {
            "profile_id": "lab-in-place-v1",
            "profile_digest": "a" * 64,
            "provisioning_mode": "in-place-lab",
        },
        "observed": {
            "connection": {
                "address": address,
                "port": 830,
                "ssh_host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            "oob_management": {
                "address": address + "/24",
                "routing_instance": "mgmt_junos",
                "default_gateway": "10.0.0.2",
                "gateway_source": "observed-configured-mgmt_junos-default",
            },
            "device": {
                "hostname": "vjunos-switch",
                "model": "EX9214",
                "serial_number": "VM1234",
                "members": [
                    {
                        "member_id": 0,
                        "status": "Prsnt",
                        "serial_number": "VM1234",
                        "model": "EX9214",
                    }
                ],
            },
        },
        "approval": {
            "method": "interactive-operator-binding",
            "approved": True,
        },
        "eligibility": {
            "status": "LAB_ONLY",
            "production_eligible": False,
            "reason": "lab OOB identity",
        },
    }


def _approved_plan(old_hostname="home1-ex4300-vc-fd-sw1203"):
    return {
        "plan": {
            "template_variables": {
                "old_hostname": old_hostname,
            }
        }
    }


def test_bound_transport_uses_single_oob_address_for_new_identity():
    logical, transport, port = cli._bound_transport(new_identity())
    assert logical == "10.255.3.18"
    assert transport == "10.255.3.18"
    assert port == 830


def test_bound_transport_keeps_historical_transport_compatibility():
    logical, transport, port = cli._bound_transport(legacy_identity("10.255.3.19"))
    assert logical == "10.0.0.15"
    assert transport == "10.255.3.19"
    assert port == 830


def test_identify_parser_requires_authoritative_oob_address_prefix():
    args = cli._identify_parser().parse_args([
        "sw1203",
        "--oob-address",
        "10.255.3.19/24",
    ])
    assert args.migration_id == "sw1203"
    assert args.oob_address == "10.255.3.19/24"


def test_bootstrap_identity_11_schema_accepts_single_oob_address():
    schema = json.loads(
        (ROOT / "schemas/bootstrap-identity-1.1.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(new_identity())


def test_bootstrap_identity_10_schema_keeps_historical_transport_address():
    schema = json.loads(
        (ROOT / "schemas/bootstrap-identity-1.0.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(legacy_identity("10.255.3.19"))


def test_source_switch_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: _approved_plan(),
    )
    value = new_identity()["observed"]
    value["device"]["hostname"] = "home1-ex4300-vc-fd-sw1203"
    with pytest.raises(cli.base.ProvisioningError, match="source switch hostname"):
        cli._reject_source_switch(Path("/tmp/sw1203"), value)


def test_non_source_bootstrap_hostname_is_allowed(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: _approved_plan(),
    )
    value = new_identity()["observed"]
    assert cli._reject_source_switch(Path("/tmp/sw1203"), value) is True


def test_missing_old_hostname_fails_closed(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: {"plan": {"template_variables": {}}},
    )
    with pytest.raises(cli.base.ProvisioningError, match="no source-switch hostname"):
        cli._reject_source_switch(
            Path("/tmp/sw1203"), new_identity()["observed"]
        )
