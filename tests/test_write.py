import copy

import pytest

from ex_migration_provisioner.write import (
    WriteError,
    build_bootstrap_identity,
    observe_ex4400_identity,
    parse_virtual_chassis_status,
    validate_bound_identity,
    validate_running_config,
)


class FakeEX:
    def __init__(self, hostname="bootstrap-ex4400", model="EX4400-48F", serial="AB1234"):
        self.facts = {
            "hostname": hostname,
            "model": model,
            "serialnumber": serial,
        }
        self.serial = serial
        self.model = model

    def cli(self, command, warning=False):
        assert command == "show virtual-chassis status"
        return "\n".join([
            "Member ID  Status  Serial No  Model  prio  Role",
            "0 (FPC 0)  Prsnt  %s  %s  128  Master*" % (self.serial, self.model),
            "",
        ])


def bootstrap():
    return {
        "schema_version": "1.0",
        "profile_id": "lab-in-place-v1",
        "environment": "lab",
        "provisioning_mode": "in-place-lab",
        "production_eligible": False,
        "fxp0_management_ip": "10.0.0.15",
        "fxp0_prefix_length": 24,
        "fxp0_management_gateway": "10.0.0.2",
        "virtual_chassis": {"member_count": 1, "members": []},
    }


def observed(host_key="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):
    return observe_ex4400_identity(FakeEX(), "10.0.0.15", 830, host_key)


def test_virtual_chassis_parser_extracts_member_identity():
    value = parse_virtual_chassis_status(
        "0 (FPC 0) Prsnt AB1234 EX4400-48F 128 Master*\n"
        "1 (FPC 1) Prsnt CD5678 EX4400-48F 128 Backup\n"
    )
    assert value == [
        {"member_id": 0, "status": "Prsnt", "serial_number": "AB1234", "model": "EX4400-48F"},
        {"member_id": 1, "status": "Prsnt", "serial_number": "CD5678", "model": "EX4400-48F"},
    ]


def test_lab_bootstrap_identity_binds_host_key_serial_and_model():
    value = build_bootstrap_identity(
        "sw1203",
        bootstrap(),
        "a" * 64,
        observed(),
        "2026-09-08T12:00:00Z",
    )
    assert value["migration_id"] == "sw1203"
    assert value["eligibility"]["status"] == "LAB_ONLY"
    assert value["observed"]["device"]["serial_number"] == "AB1234"
    assert value["observed"]["connection"]["ssh_host_key_sha256"].startswith("SHA256:")


def test_bound_identity_rejects_host_key_change():
    identity = build_bootstrap_identity(
        "sw1203",
        bootstrap(),
        "a" * 64,
        observed(),
        "2026-09-08T12:00:00Z",
    )
    current = copy.deepcopy(observed())
    current["connection"]["ssh_host_key_sha256"] = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    with pytest.raises(WriteError):
        validate_bound_identity(current, identity, "a" * 64)


def test_bound_identity_rejects_serial_change():
    identity = build_bootstrap_identity(
        "sw1203",
        bootstrap(),
        "a" * 64,
        observed(),
        "2026-09-08T12:00:00Z",
    )
    current = copy.deepcopy(observed())
    current["device"]["members"][0]["serial_number"] = "WRONG"
    with pytest.raises(WriteError):
        validate_bound_identity(current, identity, "a" * 64)


def test_bootstrap_identity_rejects_member_count_mismatch():
    profile = bootstrap()
    profile["virtual_chassis"]["member_count"] = 2
    with pytest.raises(WriteError):
        build_bootstrap_identity(
            "sw1203",
            profile,
            "a" * 64,
            observed(),
            "2026-09-08T12:00:00Z",
        )


def test_running_config_validation_requires_every_rendered_statement():
    rendered = "\n".join([
        "# artifact comment",
        "set version 26.2R1.7",
        "set system host-name home1-ex4400-vc-fd-sw1203",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "",
    ])
    validation = validate_running_config(rendered, rendered)
    assert validation["result"] == "PASS"

    missing = rendered.replace("set version 26.2R1.7\n", "")
    with pytest.raises(WriteError):
        validate_running_config(rendered, missing)
