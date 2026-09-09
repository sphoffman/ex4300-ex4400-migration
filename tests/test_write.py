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


def observed(
    host_key="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    model="EX4400-48F",
    serial="AB1234",
    address="10.255.3.18",
):
    value = observe_ex4400_identity(
        FakeEX(model=model, serial=serial),
        address,
        830,
        host_key,
        allow_vjunos_switch=(model == "EX9214"),
    )
    value["oob_management"] = {
        "address": address + "/24",
        "routing_instance": "mgmt_junos",
        "default_gateway": "10.0.0.2",
        "gateway_source": "observed-configured-mgmt_junos-default",
    }
    return value


def test_virtual_chassis_parser_extracts_member_identity():
    value = parse_virtual_chassis_status(
        "0 (FPC 0) Prsnt AB1234 EX4400-48F 128 Master*\n"
        "1 (FPC 1) Prsnt CD5678 EX4400-48F 128 Backup\n"
    )
    assert value == [
        {"member_id": 0, "status": "Prsnt", "serial_number": "AB1234", "model": "EX4400-48F"},
        {"member_id": 1, "status": "Prsnt", "serial_number": "CD5678", "model": "EX4400-48F"},
    ]


def test_vjunos_ex9214_rejected_without_lab_allowance():
    with pytest.raises(WriteError):
        observe_ex4400_identity(
            FakeEX(model="EX9214", serial="VM1234"),
            "10.255.3.18",
            830,
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )


def test_vjunos_ex9214_allowed_with_same_oob_identity_model_in_lab():
    value = observed(model="EX9214", serial="VM1234")
    identity = build_bootstrap_identity(
        "sw1203",
        bootstrap(),
        "a" * 64,
        value,
        "2026-09-08T12:00:00Z",
    )
    assert identity["schema_version"] == "1.1"
    assert identity["observed"]["device"]["model"] == "EX9214"
    assert identity["observed"]["connection"]["address"] == "10.255.3.18"
    assert "transport_address" not in identity["observed"]["connection"]
    assert identity["observed"]["oob_management"]["address"] == "10.255.3.18/24"


def test_lab_bootstrap_identity_binds_host_key_serial_model_and_oob():
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
    assert value["observed"]["oob_management"]["default_gateway"] == "10.0.0.2"


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


def test_running_config_validation_tolerates_noncritical_junos_normalization():
    rendered = "\n".join([
        "# artifact comment",
        "set version 26.2R1.7",
        "set chassis redundancy graceful-switchover",
        "set routing-options nonstop-routing",
        "deactivate routing-options nonstop-routing",
        "set protocols layer2-control nonstop-bridging",
        "deactivate protocols layer2-control",
        "set system host-name home1-ex4400-vc-fd-sw1203",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "",
    ])
    running = "\n".join([
        "set system host-name home1-ex4400-vc-fd-sw1203",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "",
    ])
    validation = validate_running_config(rendered, running)
    assert validation["result"] == "PASS"
    assert "MIGRATION_CRITICAL_CONFIG_PRESENT" in validation["checks"]


def test_running_config_validation_still_fails_on_missing_migration_critical_state():
    rendered = "\n".join([
        "set system host-name home1-ex4400-vc-fd-sw1203",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "",
    ])
    running = "\n".join([
        "set system host-name home1-ex4400-vc-fd-sw1203",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "",
    ])
    with pytest.raises(WriteError, match="migration-critical"):
        validate_running_config(rendered, running)
