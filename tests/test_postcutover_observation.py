import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.postcutover_observation import (
    build_postcutover_observation,
    collect_live_postcutover_observation,
    load_postcutover_observation,
    write_postcutover_observation,
)


def _mac(mac, vlan_name, vlan_id, interface):
    return "\n".join([
        "MAC address: %s" % mac,
        "Routing instance: default-switch",
        "VLAN name: %s, VLAN ID: %s" % (vlan_name, vlan_id),
        "Learning interface: %s.0" % interface,
        "Layer 2 flags: 0x1",
        "",
    ])


def _bindings():
    plan = {"plan_id": "plan-1"}
    identity = {"identity_id": "identity-1"}
    package = {"package_id": "package-1"}
    access = {
        "environment": "lab",
        "mode": "transport-override",
        "logical_address": "10.100.163.30",
        "transport_address": "10.255.3.18",
        "port": 830,
    }
    current_identity = {
        "connection": {"ssh_host_key_sha256": "d" * 64},
        "device": {
            "hostname": "sw1203-new",
            "model": "EX4400-48F",
            "serial_number": "SERIAL0",
            "members": [
                {
                    "member_id": 0,
                    "status": "Prsnt",
                    "serial_number": "SERIAL0",
                    "model": "EX4400-48F",
                }
            ],
        },
    }
    return plan, identity, package, access, current_identity


def _build(source_kind="LIVE"):
    plan, identity, package, access, current_identity = _bindings()
    mac_text = "".join([
        _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/10"),
        _mac("02:00:00:00:00:02", "voip", 1111, "ge-0/0/10"),
    ])
    terse_text = "\n".join([
        "ge-0/0/0               up    up",
        "ge-0/0/10              up    up",
        "ge-0/0/11              up    down",
    ])
    value = build_postcutover_observation(
        "sw1203",
        plan,
        "a" * 64,
        identity,
        "b" * 64,
        package,
        "c" * 64,
        access,
        current_identity,
        mac_text,
        terse_text,
        source_kind=source_kind,
        started_at="2026-09-16T15:00:00Z",
        completed_at="2026-09-16T15:00:01Z",
    )
    return value, mac_text, terse_text


def test_build_and_roundtrip_postcutover_observation(tmp_path):
    value, mac_text, terse_text = _build()
    assert value["source"] == {"kind": "LIVE"}
    assert value["statistics"] == {
        "physical_interfaces_observed": 3,
        "physical_interfaces_up": 2,
        "dynamic_mac_observations": 2,
        "unique_dynamic_macs": 2,
        "dynamic_mac_interfaces": 1,
    }
    assert [row["interface"] for row in value["interfaces"]] == [
        "ge-0/0/0",
        "ge-0/0/10",
        "ge-0/0/11",
    ]
    assert [row["mac"] for row in value["mac_observations"]] == [
        "02:00:00:00:00:01",
        "02:00:00:00:00:02",
    ]

    migration_root = tmp_path / "migrations" / "sw1203"
    destination, created, action = write_postcutover_observation(
        migration_root,
        value,
        mac_text,
        terse_text,
    )
    assert action == "CREATED"
    assert created["observation_id"] == value["observation_id"]
    assert (destination / "integrity.json").is_file()

    loaded = load_postcutover_observation(
        migration_root,
        value["observation_id"],
        approved_plan_digest="a" * 64,
        identity_digest="b" * 64,
        package_digest="c" * 64,
    )
    assert loaded["observation"] == value
    assert loaded["mac_table_text"].endswith("\n")
    assert loaded["terse_text"].endswith("\n")


def test_load_rejects_tampered_raw_artifact(tmp_path):
    value, mac_text, terse_text = _build()
    migration_root = tmp_path / "migrations" / "sw1203"
    destination, _created, _action = write_postcutover_observation(
        migration_root,
        value,
        mac_text,
        terse_text,
    )
    (destination / "mac-table.txt").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ProvisioningError, match="integrity failed"):
        load_postcutover_observation(migration_root, value["observation_id"])


def test_load_rejects_wrong_binding(tmp_path):
    value, mac_text, terse_text = _build()
    migration_root = tmp_path / "migrations" / "sw1203"
    write_postcutover_observation(migration_root, value, mac_text, terse_text)
    with pytest.raises(ProvisioningError, match="different approved migration plan"):
        load_postcutover_observation(
            migration_root,
            value["observation_id"],
            approved_plan_digest="f" * 64,
        )


def test_simulated_source_preserves_same_observation_shape():
    live, _mac_text, _terse_text = _build("LIVE")
    simulated, _mac_text, _terse_text = _build("SIMULATED")
    assert simulated["source"] == {"kind": "SIMULATED"}
    assert simulated["interfaces"] == live["interfaces"]
    assert simulated["mac_observations"] == live["mac_observations"]
    assert simulated["statistics"] == live["statistics"]
    assert simulated["observation_id"] != live["observation_id"]


class _FakeDevice:
    def __init__(self, mac_text, terse_text):
        self.mac_text = mac_text
        self.terse_text = terse_text
        self.commands = []

    def cli(self, command, warning=False):
        self.commands.append((command, warning))
        if command == "show ethernet-switching table extensive":
            return self.mac_text
        if command == "show interfaces terse":
            return self.terse_text
        raise AssertionError("unexpected command %s" % command)


def test_live_collector_uses_production_commands():
    plan, identity, package, access, current_identity = _bindings()
    mac_text = _mac("02:00:00:00:00:01", "default", 3998, "ge-0/0/10")
    terse_text = "ge-0/0/10 up up\n"
    dev = _FakeDevice(mac_text, terse_text)
    value, captured_mac, captured_terse = collect_live_postcutover_observation(
        dev,
        "sw1203",
        plan,
        "a" * 64,
        identity,
        "b" * 64,
        package,
        "c" * 64,
        access,
        current_identity,
    )
    assert value["source"]["kind"] == "LIVE"
    expected_mac = mac_text if mac_text.endswith("\n") else mac_text + "\n"
    assert captured_mac == expected_mac
    assert captured_terse == terse_text
    assert dev.commands == [
        ("show ethernet-switching table extensive", False),
        ("show interfaces terse", False),
    ]
