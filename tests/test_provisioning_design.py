import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def test_new_design_json_is_parseable():
    paths = [
        "config/site.json",
        "config/bootstrap.lab.example.json",
        "schemas/ex4400-template-contract-1.0.json",
        "schemas/bootstrap-profile-1.0.json",
        "schemas/qfx-site-policy-1.0.json",
        "schemas/provisioning-package-1.0.json",
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
    assert "{{management_ip}}/24" in template


def test_contract_keeps_bootstrap_variables_outside_template():
    contract = load("templates/ex4400/contract-v1.json")
    required = set(contract["variables"]["required_scalars"])
    bootstrap = set(contract["variables"]["bootstrap_only"])
    assert "management_ip" in required
    assert "fxp0_management_ip" in bootstrap
    assert not required.intersection(bootstrap)
    assert contract["safety"]["credentials_allowed"] is False
