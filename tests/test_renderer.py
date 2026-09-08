import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes
from ex_migration_provisioner.core import build_package, run_qfx_preflight
from ex_migration_provisioner.render import RenderError, build_render_manifest, render_pre_stage, validate_pre_stage_render
from test_provisioner import bootstrap, devices_for, digest, plan_variables, policy


ROOT = Path(__file__).resolve().parents[1]


def package_for_render():
    qfx_policy = policy()
    preflight = run_qfx_preflight(qfx_policy, "sw1203", devices_for(), observed_at="2026-09-08T01:00:00Z")
    plan = {"plan_id": "0123456789abcdef", "migration_id": "sw1203", "eligibility": {"production_eligible": False}, "template_variables": plan_variables()}
    approval = {"plan_id": plan["plan_id"], "plan_digest": digest("a"), "production_eligible": False}
    return build_package(plan, digest("a"), approval, digest("c"), digest("d"), digest("e"), digest("f"), qfx_policy, digest("1"), bootstrap(), digest("2"), preflight, digest("b"), "0.8.1")


def test_pre_stage_render_is_deterministic_and_contains_only_approved_vlan_definitions():
    package = package_for_render()
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text()
    contract = json.loads((ROOT / "templates/ex4400/contract-v1.json").read_text())
    rendered_a, validation_a = render_pre_stage(template, contract, package, "0.8.1")
    rendered_b, validation_b = render_pre_stage(template, contract, package, "0.8.1")
    assert rendered_a == rendered_b
    assert validation_a == validation_b
    assert validation_a["result"] == "PASS"
    assert "set interfaces interface-range edge_ports member \"ge-[0-9]/0/[2-47]\"" in rendered_a
    assert "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY" in rendered_a
    assert "set interfaces irb unit 163 family inet address 10.100.163.30/24" in rendered_a
    assert "set vlans v100 vlan-id 100" in rendered_a
    assert "set vlans v163 vlan-id 163" in rendered_a
    assert "set vlans v200 vlan-id 200" in rendered_a
    assert "set vlans UNUSED-TEST vlan-id 300" in rendered_a
    assert "set vlans voip vlan-id 1111" in rendered_a
    assert "set vlans TEMP-RECOVERY vlan-id 3999" in rendered_a
    assert rendered_a.count("set vlans voip vlan-id 1111") == 1
    assert rendered_a.count("set vlans v163 vlan-id 163") == 1
    assert "fxp0" not in rendered_a
    assert "encrypted-password" not in rendered_a


def test_pre_stage_static_validation_rejects_endpoint_vlan_assignment():
    package = package_for_render()
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text()
    contract = json.loads((ROOT / "templates/ex4400/contract-v1.json").read_text())
    rendered, _validation = render_pre_stage(template, contract, package, "0.8.1")
    tampered = rendered + "set interfaces ge-0/0/12 unit 0 family ethernet-switching vlan members v100\n"
    with pytest.raises(RenderError):
        validate_pre_stage_render(tampered, package)


def test_pre_stage_static_validation_rejects_wrong_recovery_port():
    package = package_for_render()
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text()
    contract = json.loads((ROOT / "templates/ex4400/contract-v1.json").read_text())
    rendered, _validation = render_pre_stage(template, contract, package, "0.8.1")
    tampered = rendered.replace(
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set interfaces ge-0/0/46 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
    )
    with pytest.raises(RenderError):
        validate_pre_stage_render(tampered, package)


def test_render_rejects_stale_renderer_version():
    package = package_for_render()
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text()
    contract = json.loads((ROOT / "templates/ex4400/contract-v1.json").read_text())
    with pytest.raises(RenderError):
        render_pre_stage(template, contract, package, "0.8.2")


def test_render_manifest_is_deterministic_and_schema_valid():
    package = package_for_render()
    template = (ROOT / "templates/ex4400/ex4400.set.j2").read_text()
    contract = json.loads((ROOT / "templates/ex4400/contract-v1.json").read_text())
    rendered, validation = render_pre_stage(template, contract, package, "0.8.1")
    package_digest = sha256_bytes(canonical_bytes(package))
    config_digest = sha256_bytes(rendered.encode("utf-8"))
    manifest_a = build_render_manifest(package, package_digest, config_digest, validation, "0.8.1")
    manifest_b = build_render_manifest(package, package_digest, config_digest, validation, "0.8.1")
    assert manifest_a == manifest_b
    assert manifest_a["safety"] == {"device_connections_allowed": False, "device_writes_allowed": False}
    schema = json.loads((ROOT / "schemas/render-manifest-1.0.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest_a)
