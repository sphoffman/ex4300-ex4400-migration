import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ex_migration_provisioner import cli


ROOT = Path(__file__).resolve().parents[1]


def identity(transport_address=None):
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
            "reason": "lab transport identity",
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


def test_bound_transport_defaults_to_logical_fxp0_for_hardware():
    logical, transport, port = cli._bound_transport(identity())
    assert logical == "10.0.0.15"
    assert transport == "10.0.0.15"
    assert port == 830


def test_bound_transport_uses_identity_pinned_vjunos_endpoint():
    logical, transport, port = cli._bound_transport(identity("10.255.3.19"))
    assert logical == "10.0.0.15"
    assert transport == "10.255.3.19"
    assert port == 830


def test_identify_parser_accepts_lab_transport_without_changing_bootstrap_ip():
    args = cli._identify_parser().parse_args([
        "sw1203",
        "--transport-address",
        "10.255.3.19",
    ])
    assert args.migration_id == "sw1203"
    assert args.transport_address == "10.255.3.19"


def test_bootstrap_identity_schema_allows_pinned_transport_address():
    schema = json.loads(
        (ROOT / "schemas/bootstrap-identity-1.0.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(identity("10.255.3.19"))


def test_source_switch_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: _approved_plan(),
    )
    value = identity("10.255.3.18")["observed"]
    value["device"]["hostname"] = "home1-ex4300-vc-fd-sw1203"
    with pytest.raises(cli.base.ProvisioningError, match="source switch hostname"):
        cli._reject_source_switch(Path("/tmp/sw1203"), value)


def test_non_source_bootstrap_hostname_is_allowed(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: _approved_plan(),
    )
    value = identity("10.255.3.19")["observed"]
    assert cli._reject_source_switch(Path("/tmp/sw1203"), value) is True


def test_missing_old_hostname_fails_closed(monkeypatch):
    monkeypatch.setattr(
        cli.base,
        "choose_approved_plan",
        lambda _root: {"plan": {"template_variables": {}}},
    )
    with pytest.raises(cli.base.ProvisioningError, match="no source-switch hostname"):
        cli._reject_source_switch(
            Path("/tmp/sw1203"), identity("10.255.3.19")["observed"]
        )
