import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ex_migration_provisioner.prestage import validate_pre_cutover_site_policy


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def generated_policy():
    return load("tests/fixtures/qfx-site-policy.generated.json")


def test_new_design_json_is_parseable():
    paths = [
        "config/site.json",
        "config/bootstrap.lab.example.json",
        "tests/fixtures/qfx-site-policy.generated.json",
        "schemas/ex4400-template-contract-1.0.json",
        "schemas/bootstrap-profile-1.0.json",
        "schemas/qfx-site-policy-1.2.json",
        "schemas/provisioning-package-1.1.json",
        "schemas/render-manifest-1.0.json",
        "templates/ex4400/contract-v1.json",
    ]
    for path in paths:
        assert load(path)


def test_site_settings_point_to_generated_profile_and_policy():
    settings = load("config/site.json")
    assert settings["site_profile"] == "config/site-profile.json"
    assert settings["qfx_site_policy"] == "config/qfx-site-policy.active.json"
    assert settings["temporary_recovery_vlan_name"] == "Temp-Management"
    assert settings["temporary_recovery_vlan_id"] == 3999
    assert settings["default_collection_interval_seconds"] == 180


def test_lab_bootstrap_is_never_production_eligible_and_binds_uplinks():
    profile = load("config/bootstrap.lab.example.json")
    assert profile["provisioning_mode"] == "in-place-lab"
    assert profile["production_eligible"] is False
    assert profile["fxp0_management_ip"] == "10.0.0.15"
    assert profile["fxp0_management_gateway"] == "10.0.0.2"
    assert profile["uplink_interfaces"] == ["ge-0/0/0", "ge-0/0/1"]
    schema = load("schemas/bootstrap-profile-1.0.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(profile)


def test_template_keeps_edge_regex_and_uses_default_holding_vlan():
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text(encoding="utf-8")
    assert "fxp0_management_ip" not in template
    assert "fxp0_management_gateway" not in template
    assert "encrypted-password" not in template
    assert "vlan members all" in template
    assert "{{management_prefix}}" in template
    assert "{{management_ip}}/24" not in template
    assert 'set interfaces interface-range edge_ports member "ge-[0-9]/0/[2-47]"' in template
    assert "prestage_access_interfaces" not in template
    assert "for interface in uplink_interfaces" in template
    assert "gigether-options 802.3ad ae0" in template
    assert "ether-options 802.3ad ae0" in template
    assert "recovery_interface" not in template
    assert "temporary_recovery_vlan_name" not in template
    assert "set vlans default vlan-id {{prestage_access_vlan_id}}" in template
    assert "set vlans default description {{prestage_access_vlan_name}}" in template
    assert "set vlans {{prestage_access_vlan_name}} vlan-id" not in template
    assert "set protocols layer2-control nonstop-bridging" in template
    assert 'provisioning_mode == "in-place-lab"' in template
    assert "deactivate protocols layer2-control" in template


def test_contract_keeps_bootstrap_variables_outside_template():
    contract = load("templates/ex4400/contract-v1.json")
    required = set(contract["variables"]["required_scalars"])
    collections = set(contract["variables"]["required_collections"])
    bootstrap = set(contract["variables"]["bootstrap_only"])
    assert "management_ip" in required
    assert "management_prefix" in required
    assert "voice_vlan" in required
    assert "prestage_access_vlan_name" in required
    assert "prestage_access_vlan_id" in required
    assert "prestage_access_interfaces" not in collections
    assert "uplink_interfaces" in collections
    assert "recovery_interface" not in required
    assert "temporary_recovery_vlan_name" not in required
    assert "temporary_recovery_vlan_id" not in required
    assert "provisioning_mode" in required
    assert "fxp0_management_ip" in bootstrap
    assert "uplink_interfaces" in bootstrap
    assert not required.intersection(bootstrap)
    excludes = set(contract["phase_contract"]["pre_stage"]["exclude"])
    assert "TEMPORARY_MANAGEMENT_VLAN" in excludes
    assert "TEMPORARY_MANAGEMENT_PORT_OVERLAY" in excludes


def test_generated_qfx_site_policy_validates_and_has_no_site_voice_vlan():
    schema = load("schemas/qfx-site-policy-1.2.json")
    policy = generated_policy()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)
    assert validate_pre_cutover_site_policy(policy) == policy
    assert policy["schema_version"] == "1.2"
    assert policy["environment"] == "lab"
    assert policy["production_eligible"] is False
    assert "voice_vlan" not in policy
    assert "port_to_ae" not in policy
    assert "lacp_system_id" not in policy
    assert policy["ae_pool"]["migration_assignment_prebound"] is False
    assert set(policy["stage_port_pools"]["site-staged"]) == {
        "et-0/0/3",
        "et-0/0/4",
        "et-0/0/5",
    }
    assert policy["management_vlan"] == {"name": "MGMT", "vlan_id": 163}
    assert policy["temporary_recovery_vlan"] == {"name": "TEMP-RECOVERY", "vlan_id": 3999}
    assert policy["prestage_access_vlan"] == {"name": "TEMP-ACCESS", "vlan_id": 3998}
    assert policy["precutover_qfx_baseline"] == {
        "required_vlan_ids": [163, 3999],
        "lacp_mode": "active",
        "force_up": False,
    }
    assert 3998 not in policy["precutover_qfx_baseline"]["required_vlan_ids"]


def test_generated_qfx_policy_rejects_force_up_and_lab_production_eligibility():
    schema = load("schemas/qfx-site-policy-1.2.json")
    policy = generated_policy()
    force_up = copy.deepcopy(policy)
    force_up["precutover_qfx_baseline"]["force_up"] = True
    assert not Draft202012Validator(schema).is_valid(force_up)

    wrong_environment = copy.deepcopy(policy)
    wrong_environment["production_eligible"] = True
    assert not Draft202012Validator(schema).is_valid(wrong_environment)
