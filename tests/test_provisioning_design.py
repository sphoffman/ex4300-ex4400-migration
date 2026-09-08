import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def test_new_design_json_is_parseable():
    paths = [
        "config/site.json",
        "config/bootstrap.lab.example.json",
        "config/qfx-site-policy.lab.json",
        "schemas/ex4400-template-contract-1.0.json",
        "schemas/bootstrap-profile-1.0.json",
        "schemas/qfx-site-policy-1.0.json",
        "schemas/provisioning-package-1.0.json",
        "schemas/render-manifest-1.0.json",
        "templates/ex4400/contract-v1.json",
    ]
    for path in paths:
        assert load(path)


def test_recovery_defaults_are_explicit():
    settings = load("config/site.json")
    assert settings["temporary_recovery_vlan_name"] == "TEMP-RECOVERY"
    assert settings["temporary_recovery_vlan_id"] == 3999


def test_lab_bootstrap_is_never_production_eligible():
    profile = load("config/bootstrap.lab.example.json")
    assert profile["provisioning_mode"] == "in-place-lab"
    assert profile["production_eligible"] is False
    assert profile["fxp0_management_ip"] == "10.0.0.15"
    assert profile["fxp0_management_gateway"] == "10.0.0.2"


def test_template_excludes_bootstrap_and_device_write_material():
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text(encoding="utf-8")
    assert "fxp0_management_ip" not in template
    assert "fxp0_management_gateway" not in template
    assert "encrypted-password" not in template
    assert "vlan members all" in template
    assert "{{management_prefix}}" in template
    assert "{{management_ip}}/24" not in template


def test_contract_keeps_bootstrap_variables_outside_template():
    contract = load("templates/ex4400/contract-v1.json")
    required = set(contract["variables"]["required_scalars"])
    bootstrap = set(contract["variables"]["bootstrap_only"])
    assert "management_ip" in required
    assert "management_prefix" in required
    assert "voice_vlan" in required
    assert "fxp0_management_ip" in bootstrap
    assert not required.intersection(bootstrap)
    assert contract["safety"]["credentials_allowed"] is False


def test_lab_qfx_site_policy_validates_against_schema():
    schema = load("schemas/qfx-site-policy-1.0.json")
    policy = load("config/qfx-site-policy.lab.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)


def test_lab_qfx_site_policy_matches_established_topology():
    policy = load("config/qfx-site-policy.lab.json")
    assert policy["environment"] == "lab"
    assert policy["production_eligible"] is False

    devices = {entry["expected_hostname"]: entry for entry in policy["qfx_pair"]}
    assert devices == {
        "BD-1": {
            "role": "qfx-a",
            "management_address": "10.255.3.14",
            "expected_hostname": "BD-1",
            "expected_model": "ptx10001-36mr",
        },
        "BD-2": {
            "role": "qfx-b",
            "management_address": "10.255.3.15",
            "expected_hostname": "BD-2",
            "expected_model": "ptx10001-36mr",
        },
    }

    assignments = {
        item["migration_id"]: (item["physical_interface"], item["ae_interface"])
        for item in policy["port_to_ae"]["assignments"]
    }
    assert assignments == {
        "dh4301": ("et-0/0/3", "ae0"),
        "nh5302": ("et-0/0/4", "ae1"),
        "sw1203": ("et-0/0/5", "ae2"),
    }
    assert policy["port_to_ae"]["ae_min"] == 0
    assert policy["port_to_ae"]["ae_max"] == 2
    assert set(policy["stage_port_pools"]["lab-established"]) == {
        "et-0/0/3",
        "et-0/0/4",
        "et-0/0/5",
    }
    assert policy["excluded_interfaces"] == []
    assert policy["management_vlan"] == {"name": "MGMT", "vlan_id": 163}
    assert policy["voice_vlan"] == {"name": "voip", "vlan_id": 1111}
    assert policy["temporary_recovery_vlan"] == {"name": "TEMP-RECOVERY", "vlan_id": 3999}

    assert policy["esi"] == {
        "method": "auto-derive-type-1-lacp",
        "all_active": True,
    }
    assert policy["lacp_system_id"] == {
        "method": "explicit-per-ae",
        "values": {
            "ae0": "00:01:02:03:04:00",
            "ae1": "00:01:02:03:04:01",
            "ae2": "00:01:02:03:04:02",
        },
    }

    validation = policy["validation"]
    assert validation["require_interface_symmetry"] is True
    assert validation["require_lldp"] is True
    assert validation["require_lacp_partner"] is True
    assert validation["require_matching_lacp_system_id"] is True
    assert validation["operator_supplied_ports_allowed"] is False


def test_qfx_site_policy_lab_model_exception_does_not_relax_production():
    schema = load("schemas/qfx-site-policy-1.0.json")
    policy = load("config/qfx-site-policy.lab.json")
    production = json.loads(json.dumps(policy))
    production["environment"] = "production"
    production["production_eligible"] = True
    assert not Draft202012Validator(schema).is_valid(production)
