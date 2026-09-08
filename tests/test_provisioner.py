import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes
from ex_migration_provisioner.core import ProvisioningError, assignment_for, build_package, run_qfx_preflight, validate_site_policy


ROOT = Path(__file__).resolve().parents[1]


class FakeDevice:
    def __init__(self, hostname, model, physical, ae, system_id, neighbor, up=True, lacp_up=True):
        self.facts = {"hostname": hostname, "model": model}
        self.physical = physical; self.ae = ae; self.system_id = system_id; self.neighbor = neighbor
        self.up = up; self.lacp_up = lacp_up; self.commands = []

    def cli(self, command, warning=False):
        self.commands.append(command)
        if command == "show configuration interfaces %s | display set" % self.physical:
            return "set interfaces %s ether-options 802.3ad %s\n" % (self.physical, self.ae)
        if command == "show configuration interfaces %s | display set" % self.ae:
            return "\n".join([
                "set interfaces %s aggregated-ether-options lacp active" % self.ae,
                "set interfaces %s aggregated-ether-options lacp system-id %s" % (self.ae, self.system_id),
                "set interfaces %s esi auto-derive type-1-lacp" % self.ae,
                "set interfaces %s esi all-active" % self.ae,
            ]) + "\n"
        if command == "show interfaces %s terse" % self.physical:
            return "%s %s\n" % (self.physical, "up up" if self.up else "down down")
        if command == "show lacp interfaces %s extensive" % self.ae:
            return "Aggregated interface: %s\n  %s Actor %s\n" % (self.ae, self.physical, "Collecting distributing" if self.lacp_up else "Detached")
        if command == "show lldp neighbors detail":
            return "\n".join([
                "LLDP Neighbor Information:",
                "Local Interface    : et-0/0/0",
                "Parent Interface   : -",
                "Port ID            : ge-0/0/0",
                "System name        : unrelated-switch",
                "LLDP Neighbor Information:",
                "Local Interface    : %s" % self.physical,
                "Parent Interface   : -",
                "Port ID            : ae0",
                "System name        : %s" % self.neighbor,
                "",
            ])
        raise AssertionError("unexpected command: %s" % command)


def policy():
    return {
        "schema_version": "1.0", "site_policy_id": "lab-bd-pair-v1", "environment": "lab", "production_eligible": False,
        "qfx_pair": [
            {"role": "qfx-a", "management_address": "10.255.3.14", "expected_hostname": "BD-1", "expected_model": "ptx10001-36mr"},
            {"role": "qfx-b", "management_address": "10.255.3.15", "expected_hostname": "BD-2", "expected_model": "ptx10001-36mr"},
        ],
        "stage_port_pools": {"lab-established": ["et-0/0/3", "et-0/0/4", "et-0/0/5"]}, "excluded_interfaces": [],
        "management_vlan": {"name": "MGMT", "vlan_id": 163},
        "voice_vlan": {"name": "voip", "vlan_id": 1111},
        "temporary_recovery_vlan": {"name": "TEMP-RECOVERY", "vlan_id": 3999},
        "port_to_ae": {"method": "explicit-migration-id-map", "ae_min": 0, "ae_max": 2, "assignments": [
            {"migration_id": "dh4301", "physical_interface": "et-0/0/3", "ae_interface": "ae0"},
            {"migration_id": "nh5302", "physical_interface": "et-0/0/4", "ae_interface": "ae1"},
            {"migration_id": "sw1203", "physical_interface": "et-0/0/5", "ae_interface": "ae2"},
        ]},
        "esi": {"method": "auto-derive-type-1-lacp", "all_active": True},
        "lacp_system_id": {"method": "explicit-per-ae", "values": {"ae0": "00:01:02:03:04:00", "ae1": "00:01:02:03:04:01", "ae2": "00:01:02:03:04:02"}},
        "validation": {"require_interface_symmetry": True, "require_lldp": True, "require_lacp_partner": True, "require_matching_lacp_system_id": True, "operator_supplied_ports_allowed": False},
    }


def devices_for(migration_id="sw1203", neighbor="sw1203"):
    value = policy(); assignment = assignment_for(value, migration_id); system_id = value["lacp_system_id"]["values"][assignment["ae_interface"]]
    return {
        "qfx-a": FakeDevice("BD-1", "PTX10001-36MR", assignment["physical_interface"], assignment["ae_interface"], system_id, neighbor),
        "qfx-b": FakeDevice("BD-2", "ptx10001-36mr", assignment["physical_interface"], assignment["ae_interface"], system_id, neighbor),
    }


def digest(char): return char * 64


def plan_variables():
    return {
        "migration_id": "sw1203",
        "old_hostname": "home1-ex4300-vc-fd-sw1203",
        "new_hostname": "home1-ex4400-vc-fd-sw1203",
        "management_vlan_id": 163,
        "management_vlan_name": "v163",
        "management_interface": "irb.163",
        "management_ip": "10.100.163.30",
        "management_prefix": "10.100.163.30/24",
        "management_gateway": "10.100.163.1",
        "snmp_location": "<home><1><sw1203>",
        "snmp_engine_id": "10.100.163.30",
        "configured_vlans": [
            {"name": "v100", "vlan_id": 100},
            {"name": "v163", "vlan_id": 163},
            {"name": "v200", "vlan_id": 200},
            {"name": "UNUSED-TEST", "vlan_id": 300},
            {"name": "voip", "vlan_id": 1111},
        ],
    }


def package_for(preflight, qfx_policy=None, variables=None):
    qfx_policy = qfx_policy or policy()
    plan = {"plan_id": "0123456789abcdef", "migration_id": "sw1203", "eligibility": {"production_eligible": False}, "template_variables": variables or plan_variables()}
    approval = {"plan_id": plan["plan_id"], "plan_digest": digest("a"), "production_eligible": False}
    bootstrap = {"environment": "lab", "provisioning_mode": "in-place-lab", "production_eligible": False}
    return build_package(plan, digest("a"), approval, digest("c"), digest("d"), digest("e"), digest("f"), qfx_policy, digest("1"), bootstrap, digest("2"), preflight, digest("b"), "0.8.0")


def test_qfx_preflight_passes_for_established_sw1203_mapping():
    devices = devices_for()
    value = run_qfx_preflight(policy(), "sw1203", devices, observed_at="2026-09-08T01:00:00Z")
    assert value["result"] == "PASS"
    assert value["assignment"] == {"migration_id": "sw1203", "physical_interface": "et-0/0/5", "ae_interface": "ae2"}
    assert all(value["pair_checks"].values())
    for device in devices.values():
        assert "show lldp neighbors detail" in device.commands
        assert not any(command.startswith("show lldp neighbors interface ") for command in device.commands)


def test_qfx_preflight_selects_lldp_neighbor_for_policy_interface():
    devices = devices_for(neighbor="sw1203")
    value = run_qfx_preflight(policy(), "sw1203", devices, observed_at="2026-09-08T01:00:00Z")
    assert [item["lldp_neighbor_system_name"] for item in value["devices"]] == ["sw1203", "sw1203"]


def test_qfx_preflight_fails_closed_on_asymmetric_lldp_neighbor():
    devices = devices_for(); devices["qfx-b"].neighbor = "wrong-switch"
    value = run_qfx_preflight(policy(), "sw1203", devices, observed_at="2026-09-08T01:00:00Z")
    assert value["result"] == "FAIL"
    assert value["pair_checks"]["lldp_neighbor_symmetry"] is False


def test_qfx_policy_requires_explicit_assignment_and_forbids_operator_ports():
    value = policy(); validate_site_policy(value)
    with pytest.raises(ProvisioningError): assignment_for(value, "unknown")
    broken = copy.deepcopy(value); broken["validation"]["operator_supplied_ports_allowed"] = True
    with pytest.raises(ProvisioningError): validate_site_policy(broken)


def test_package_binds_site_policy_bootstrap_preflight_and_render_variables():
    preflight = run_qfx_preflight(policy(), "sw1203", devices_for(), observed_at="2026-09-08T01:00:00Z")
    package = package_for(preflight)
    assert package["eligibility"]["status"] == "LAB_ONLY"
    assert package["inputs"]["site_policy_digest"] == digest("1")
    assert package["inputs"]["bootstrap_profile_digest"] == digest("2")
    assert package["inputs"]["qfx_preflight_digest"] == sha256_bytes(canonical_bytes(preflight))
    assert package["variables"]["qfx"]["physical_interface"] == "et-0/0/5"
    assert package["variables"]["qfx"]["ae_interface"] == "ae2"
    assert package["variables"]["voice_vlan"] == "voip"
    assert package["variables"]["voice_vlan_id"] == 1111
    assert package["variables"]["temporary_recovery_vlan_name"] == "TEMP-RECOVERY"
    classifications = {item["vlan_id"]: item["classification"] for item in package["variables"]["configured_vlans"]}
    assert classifications == {100: "data", 163: "management", 200: "data", 300: "data", 1111: "voice"}
    assert package["artifacts"] == [{"path": "qfx-preflight.json", "sha256": digest("b")}]
    assert package["safety"]["device_writes_allowed"] is False


def test_package_fails_closed_if_voice_vlan_does_not_match_policy():
    preflight = run_qfx_preflight(policy(), "sw1203", devices_for(), observed_at="2026-09-08T01:00:00Z")
    variables = plan_variables()
    variables["configured_vlans"][-1] = {"name": "wrong-voice", "vlan_id": 1111}
    with pytest.raises(ProvisioningError):
        package_for(preflight, variables=variables)


def test_preflight_package_and_site_policy_validate_against_repository_schemas():
    preflight = run_qfx_preflight(policy(), "sw1203", devices_for(), observed_at="2026-09-08T01:00:00Z")
    package = package_for(preflight)
    preflight_schema = json.loads((ROOT / "schemas/qfx-preflight-1.0.json").read_text())
    package_schema = json.loads((ROOT / "schemas/provisioning-package-1.0.json").read_text())
    policy_schema = json.loads((ROOT / "schemas/qfx-site-policy-1.0.json").read_text())
    for schema in (preflight_schema, package_schema, policy_schema): Draft202012Validator.check_schema(schema)
    Draft202012Validator(preflight_schema).validate(preflight)
    Draft202012Validator(package_schema).validate(package)
    Draft202012Validator(policy_schema).validate(policy())
