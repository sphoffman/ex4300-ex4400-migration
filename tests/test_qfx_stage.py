import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ex_migration_provisioner.qfx_stage import (
    build_qfx_vlan_plan,
    derive_required_qfx_vlans,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = "home1-ex4400-vc-fd-sw1203"


def digest(char):
    return char * 64


def policy():
    return json.loads(
        (ROOT / "tests/fixtures/qfx-site-policy.generated.json").read_text()
    )


def migration_plan():
    return {
        "plan_id": "0123456789abcdef",
        "migration_id": "sw1203",
        "template_variables": {
            "voice_vlan_name": "voip",
            "voice_vlan_id": 1111,
        },
        "vlan_intents": [
            {"name": "v100", "vlan_id": 100, "observed": True},
            {"name": "v163", "vlan_id": 163, "observed": False},
            {"name": "v200", "vlan_id": 200, "observed": True},
            {"name": "UNUSED-TEST", "vlan_id": 300, "observed": False},
            {"name": "voip", "vlan_id": 1111, "observed": True},
        ],
        "port_intents": [
            {
                "old_interface": "ge-0/0/2",
                "configured_data_vlan_id": 100,
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
            {
                "old_interface": "ge-0/0/3",
                "configured_data_vlan_id": 200,
                "planned_action": "CORRELATE_AFTER_CABLE_MOVE",
            },
            {
                "old_interface": "ge-0/0/10",
                "configured_data_vlan_id": 300,
                "planned_action": "HOLD_FOR_OPERATOR_RESOLUTION",
            },
            {
                "old_interface": "ge-0/0/11",
                "configured_data_vlan_id": None,
                "planned_action": "LEAVE_TEMPLATE_DEFAULT",
            },
        ],
    }


def attachment(plan_digest, policy_digest):
    devices = []
    for role, address, hostname, key in (
        ("qfx-a", "10.255.3.14", "BD-1", "SHA256:" + "A" * 43),
        ("qfx-b", "10.255.3.15", "BD-2", "SHA256:" + "B" * 43),
    ):
        devices.append({
            "role": role,
            "management_address": address,
            "ssh_host_key_sha256": key,
            "observed_qfx_hostname": hostname,
            "observed_qfx_model": "PTX10001-36MR",
            "expected_qfx_hostname": hostname,
            "expected_qfx_model": "ptx10001-36mr",
            "expected_ex_hostname": TARGET,
            "lldp_match_count": 1,
            "physical_interface": "et-0/0/5",
            "remote_port_id": "ge-0/0/0",
            "ae_interface": "ae2",
            "lacp_system_id": "00:01:02:03:04:02",
            "baseline_vlan_ids": [163],
            "unresolved_vlan_members": [],
            "checks": {"ok": True},
            "result": "PASS",
        })
    return {
        "schema_version": "1.0",
        "attachment_id": "c494477dac75398f",
        "migration_id": "sw1203",
        "observed_at": "2026-09-08T18:00:00Z",
        "approved_at": "2026-09-08T18:01:00Z",
        "plan": {"plan_id": "0123456789abcdef", "plan_digest": plan_digest},
        "site_policy": {
            "site_policy_id": "lab-site-inventory-test",
            "site_policy_digest": policy_digest,
        },
        "expected_ex_hostname": TARGET,
        "devices": devices,
        "pair_checks": {"ok": True},
        "result": "PASS",
    }


class FakeQFX:
    def __init__(self, hostname, host_key, missing_vlan=None):
        self.facts = {"hostname": hostname, "model": "PTX10001-36MR"}
        self.host_key = host_key
        self.missing_vlan = missing_vlan

    def cli(self, command, warning=False):
        if command == "show lldp neighbors":
            return "\n".join([
                "Local Interface    Parent Interface    Chassis Id                               Port info          System Name",
                "et-0/0/5           ae2                 2c:6b:f5:94:59:c0                        ge-0/0/0            %s" % TARGET,
                "",
            ])
        if command == "show configuration interfaces et-0/0/5 | display set":
            return "set interfaces et-0/0/5 ether-options 802.3ad ae2\n"
        if command == "show configuration interfaces ae2 | display set":
            return "\n".join([
                "set interfaces ae2 aggregated-ether-options lacp system-id 00:01:02:03:04:02",
                "set interfaces ae2 esi auto-derive type-1-lacp",
                "set interfaces ae2 esi all-active",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members v163",
                "",
            ])
        if command == "show lacp interfaces ae2 extensive":
            return "Aggregated interface: ae2\n et-0/0/5 Collecting Distributing\n"
        if command == "show configuration vlans | display set":
            return ""
        if command == 'show configuration routing-instances | display set | match " vlan-id "':
            return self._routing_instances(vlan_only=True)
        if command == "show configuration routing-instances | display set":
            return self._routing_instances(vlan_only=False)
        raise AssertionError("unexpected command: %s" % command)

    def _routing_instances(self, vlan_only):
        rows = [
            "set routing-instances MAC-VRF-1 vlans v163 vlan-id 163",
            "set routing-instances MAC-VRF-1 vlans v100 vlan-id 100",
            "set routing-instances MAC-VRF-1 vlans v200 vlan-id 200",
            "set routing-instances MAC-VRF-1 vlans voip vlan-id 1111",
        ]
        if self.missing_vlan is not None:
            rows = [row for row in rows if not row.endswith(" vlan-id %s" % self.missing_vlan)]
        if not vlan_only:
            rows.insert(0, "set routing-instances MAC-VRF-1 interface ae2.0")
        return "\n".join(rows) + "\n"


def devices():
    return {
        "qfx-a": FakeQFX("BD-1", "SHA256:" + "A" * 43),
        "qfx-b": FakeQFX("BD-2", "SHA256:" + "B" * 43),
    }


def host_keys():
    return {
        "qfx-a": "SHA256:" + "A" * 43,
        "qfx-b": "SHA256:" + "B" * 43,
    }


def test_qfx_vlan_derivation_uses_endpoint_intent_plus_this_ex_voice_not_unused_vlan():
    value = derive_required_qfx_vlans(migration_plan(), policy())
    assert value["endpoint_data_vlan_ids"] == [100, 200]
    assert value["voice_vlan_id"] == 1111
    assert value["voice_vlan_name"] == "voip"
    assert value["required_vlan_ids"] == [100, 200, 1111]
    assert value["configured_but_not_required_vlan_ids"] == [300]


def test_qfx_vlan_plan_resolves_existing_mac_vrf_vlans_and_adds_membership_only():
    plan = migration_plan()
    plan_digest = digest("a")
    policy_digest = digest("b")
    value = build_qfx_vlan_plan(
        "sw1203", plan, plan_digest, attachment(plan_digest, policy_digest), digest("c"),
        policy(), policy_digest, devices(), host_keys(), created_at="2026-09-08T19:00:00Z",
    )
    assert value["result"] == "PASS"
    assert value["derivation"]["required_vlan_ids"] == [100, 200, 1111]
    assert all(item["routing_instance"] == "MAC-VRF-1" for item in value["devices"])
    expected = [
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v200",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members voip",
    ]
    assert value["devices"][0]["statements"] == expected
    assert value["devices"][0]["statements"] == value["devices"][1]["statements"]
    assert value["safety"]["creates_vlan_definitions"] is False
    assert value["safety"]["qfx_writes_authorized"] is False

    schema = json.loads((ROOT / "schemas/qfx-vlan-plan-1.0.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)


def test_qfx_vlan_plan_never_manages_external_temp_management():
    plan = migration_plan()
    plan_digest = digest("a")
    policy_digest = digest("b")
    effective_policy = policy()
    effective_policy["_old_switch_recovery_required"] = False
    value = build_qfx_vlan_plan(
        "sw1203", plan, plan_digest, attachment(plan_digest, policy_digest), digest("c"),
        effective_policy, policy_digest, devices(), host_keys(), created_at="2026-09-08T19:00:00Z",
    )
    assert value["result"] == "PASS"
    for device in value["devices"]:
        assert all("TEMP-RECOVERY" not in statement for statement in device["statements"])
        assert all("Temp-Management" not in statement for statement in device["statements"])
        assert all("3999" not in statement for statement in device["statements"])
    schema = json.loads((ROOT / "schemas/qfx-vlan-plan-1.0.json").read_text())
    Draft202012Validator(schema).validate(value)


def test_qfx_vlan_plan_fails_if_required_vlan_is_missing_from_one_mac_vrf():
    plan = migration_plan()
    plan_digest = digest("a")
    policy_digest = digest("b")
    broken = devices()
    broken["qfx-b"] = FakeQFX("BD-2", "SHA256:" + "B" * 43, missing_vlan=200)
    value = build_qfx_vlan_plan(
        "sw1203", plan, plan_digest, attachment(plan_digest, policy_digest), digest("c"),
        policy(), policy_digest, broken, host_keys(), created_at="2026-09-08T19:00:00Z",
    )
    assert value["result"] == "FAIL"
    assert value["devices"][1]["checks"]["all_required_vlans_defined_in_owning_mac_vrf"] is False
    assert value["devices"][1]["resolution_failures"][0]["vlan_id"] == 200
