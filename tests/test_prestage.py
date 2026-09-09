import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ex_migration_provisioner import cli
from ex_migration_provisioner.prestage import build_pre_stage_package
from test_provisioner import bootstrap, digest, plan_variables


ROOT = Path(__file__).resolve().parents[1]


def site_policy():
    return json.loads((ROOT / "config/qfx-site-policy.lab.json").read_text())


def test_pre_stage_package_has_no_live_qfx_attachment_or_preflight():
    policy = site_policy()
    plan = {
        "plan_id": "0123456789abcdef",
        "migration_id": "sw1203",
        "eligibility": {"production_eligible": False},
        "template_variables": plan_variables(),
    }
    approval = {
        "plan_id": plan["plan_id"],
        "plan_digest": digest("a"),
        "production_eligible": False,
    }
    package = build_pre_stage_package(
        plan,
        digest("a"),
        approval,
        digest("b"),
        digest("c"),
        digest("d"),
        digest("e"),
        policy,
        digest("f"),
        bootstrap(),
        digest("1"),
        "0.9.0",
        created_at="2026-09-08T17:00:00Z",
    )

    assert package["schema_version"] == "1.1"
    assert "qfx_preflight_digest" not in package["inputs"]
    assert package["artifacts"] == []
    assert package["variables"]["qfx"] == {
        "site_policy_id": "lab-bd-pair-v2",
        "attachment_state": "UNKNOWN_UNTIL_POST_CUTOVER_DISCOVERY",
        "physical_interface": None,
        "ae_interface": None,
        "force_up": False,
    }
    assert package["variables"]["prestage_access_vlan_name"] == "TEMP-ACCESS"
    assert package["variables"]["prestage_access_vlan_id"] == 3998
    assert package["variables"]["prestage_access_interfaces"][0] == "ge-0/0/2"
    assert package["variables"]["prestage_access_interfaces"][-1] == "ge-0/0/46"
    assert "ge-0/0/47" not in package["variables"]["prestage_access_interfaces"]
    assert len(package["variables"]["prestage_access_interfaces"]) == 45
    assert package["phases"]["pre_stage"]["qfx_attachment_known"] is False
    assert package["phases"]["pre_stage"]["qfx_connections_performed"] is False
    assert package["safety"]["qfx_connections_allowed"] is False
    assert package["safety"]["qfx_attachment_prebound"] is False

    schema = json.loads((ROOT / "schemas/provisioning-package-1.1.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(package)


def test_prepare_cli_has_no_qfx_credentials_or_transport_options():
    parser = cli._prepare_parser()
    option_strings = {
        option
        for action in parser._actions
        for option in action.option_strings
    }
    assert "--username" not in option_strings
    assert "--password-env" not in option_strings
    assert "--port" not in option_strings
    assert "--no-host-key-check" not in option_strings


def test_site_policy_prohibits_force_up_prebound_attachment_and_qfx_temp_access():
    policy = site_policy()
    assert policy["precutover_qfx_baseline"]["force_up"] is False
    assert policy["precutover_qfx_baseline"]["lacp_mode"] == "active"
    assert policy["ae_pool"]["migration_assignment_prebound"] is False
    assert policy["prestage_access_vlan"] == {"name": "TEMP-ACCESS", "vlan_id": 3998}
    assert 3998 not in policy["precutover_qfx_baseline"]["required_vlan_ids"]
    assert "port_to_ae" not in policy

    schema = json.loads((ROOT / "schemas/qfx-site-policy-1.1.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)
