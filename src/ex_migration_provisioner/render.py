from __future__ import annotations

import re

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes

from .core import ProvisioningError


class RenderError(ProvisioningError):
    pass


def _require(condition, message):
    if not condition:
        raise RenderError(message)


def validate_renderable_package(package, renderer_version):
    _require(package.get("schema_version") == "1.0", "unsupported provisioning-package schema")
    _require(package.get("validation", {}).get("result") == "PASS", "provisioning package validation did not pass")
    safety = package.get("safety", {})
    _require(safety.get("rendering_allowed") is True, "provisioning package does not allow rendering")
    _require(safety.get("device_connections_allowed") is False, "render package unexpectedly allows device connections")
    _require(safety.get("device_writes_allowed") is False, "render package unexpectedly allows device writes")
    phases = package.get("phases", {})
    _require(phases.get("pre_stage", {}).get("status") == "PREFLIGHT_VALIDATED", "pre-stage is not preflight validated")
    for phase_name, phase in phases.items():
        _require(phase.get("device_writes_authorized") is False, "%s unexpectedly authorizes device writes" % phase_name)
    expected_version = package.get("inputs", {}).get("renderer_version")
    _require(expected_version == renderer_version, "package renderer version %r is stale; expected %r" % (expected_version, renderer_version))
    return package


def _validate_contract(contract):
    _require(contract.get("schema_version") == "1.0", "unsupported EX4400 template contract schema")
    _require(contract.get("render_format") == "junos-set", "EX4400 template contract must render junos-set")
    variables = contract.get("variables", {})
    _require(isinstance(variables.get("required_scalars"), list), "template contract required_scalars is invalid")
    _require(isinstance(variables.get("required_collections"), list), "template contract required_collections is invalid")
    pre_stage = contract.get("phase_contract", {}).get("pre_stage", {})
    _require("TEMPORARY_RECOVERY_PORT_OVERLAY" in pre_stage.get("include", []), "pre-stage contract must include the temporary recovery port overlay")
    _require("ENDPOINT_DESCRIPTIONS" in pre_stage.get("exclude", []), "pre-stage contract must exclude endpoint descriptions")
    _require("ENDPOINT_DATA_VLAN_ASSIGNMENTS" in pre_stage.get("exclude", []), "pre-stage contract must exclude endpoint data VLAN assignments")
    safety = contract.get("safety", {})
    _require(safety.get("old_configuration_replay_allowed") is False, "template contract cannot allow old configuration replay")
    _require(safety.get("root_configuration_retrieval_allowed") is False, "template contract cannot allow root configuration retrieval")
    _require(safety.get("credentials_allowed") is False, "template contract cannot allow credentials")
    return contract


def _validate_variables(contract, variables):
    for name in contract["variables"]["required_scalars"]:
        _require(name in variables and variables[name] not in (None, ""), "missing required render scalar %s" % name)
    for name in contract["variables"]["required_collections"]:
        _require(isinstance(variables.get(name), list) and variables[name], "missing required render collection %s" % name)


def _render_jinja(template_text, variables):
    try:
        from jinja2 import Environment, StrictUndefined
    except ImportError as exc:
        raise RenderError("Jinja2 is required for EX4400 rendering: %s" % exc)
    environment = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)
    rendered = environment.from_string(template_text).render(**variables)
    lines = [line.rstrip() for line in rendered.splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


def validate_pre_stage_render(rendered, package):
    variables = package["variables"]
    provisioning_mode = package.get("provisioning_mode")
    lines = [line.strip() for line in rendered.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    line_set = set(lines)

    _require("{{" not in rendered and "{%" not in rendered, "render contains unresolved template syntax")
    _require(all(line.startswith(("set ", "deactivate ")) for line in lines), "render contains a non-Junos-set directive")

    forbidden_tokens = ("root-authentication", "encrypted-password", "plain-text-password")
    for token in forbidden_tokens:
        _require(not any(token in line for line in lines), "pre-stage render contains forbidden credential material: %s" % token)
    _require(not any(re.search(r"(^|\s)fxp0(?:\s|\.|$)", line) for line in lines), "migration template must not configure fxp0")
    _require(not any(re.match(r"^set interfaces ge-\d+/\d+/\d+ description ", line) for line in lines), "pre-stage render contains endpoint descriptions")

    nonstop_statement = "set protocols layer2-control nonstop-bridging"
    nonstop_deactivation = "deactivate protocols layer2-control"
    _require(
        nonstop_statement in line_set,
        "pre-stage render must declare layer2-control nonstop-bridging intent",
    )
    if provisioning_mode == "in-place-lab":
        _require(
            nonstop_deactivation in line_set,
            "in-place-lab render must deactivate layer2-control for the vJunos platform constraint",
        )
    else:
        _require(
            nonstop_deactivation not in line_set,
            "non-lab-in-place render must not deactivate layer2-control nonstop-bridging",
        )

    recovery_interface = variables["recovery_interface"]
    _require(bool(re.fullmatch(r"ge-[0-9]/0/47", recovery_interface)), "recovery interface is outside the standard edge-port range")
    expected_recovery_assignment = (
        "set interfaces %s unit 0 family ethernet-switching vlan members %s"
        % (recovery_interface, variables["temporary_recovery_vlan_name"])
    )
    physical_vlan_assignments = [
        line for line in lines
        if re.match(r"^set interfaces ge-\d+/\d+/\d+ unit \d+ family ethernet-switching vlan members ", line)
    ]
    _require(
        physical_vlan_assignments == [expected_recovery_assignment],
        "pre-stage render may contain only the bound TEMP-RECOVERY physical-port VLAN assignment",
    )

    required = {
        "set system host-name %s" % variables["new_hostname"],
        "set system syslog source-address %s" % variables["management_ip"],
        "set system ntp source-address %s" % variables["management_ip"],
        "set system services netconf ssh",
        "set interfaces interface-range edge_ports member \"ge-[0-9]/0/[2-47]\"",
        expected_recovery_assignment,
        "set interfaces irb unit %s family inet address %s" % (variables["management_vlan_id"], variables["management_prefix"]),
        "set interfaces ge-0/0/0 gigether-options 802.3ad ae0",
        "set interfaces ge-0/0/1 gigether-options 802.3ad ae0",
        "set interfaces ae0 aggregated-ether-options lacp active",
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members all",
        "set snmp name %s" % variables["new_hostname"],
        "set snmp location %s" % variables["snmp_location"],
        "set snmp engine-id local %s" % variables["snmp_engine_id"],
        "set snmp trap-options source-address %s" % variables["management_ip"],
        "set routing-options static route 0.0.0.0/0 next-hop %s" % variables["management_gateway"],
        "set switch-options voip interface edge_ports vlan %s" % variables["voice_vlan"],
        "set vlans %s l3-interface irb.%s" % (variables["management_vlan_name"], variables["management_vlan_id"]),
        "set vlans %s vlan-id %s" % (variables["temporary_recovery_vlan_name"], variables["temporary_recovery_vlan_id"]),
    }
    missing = sorted(required - line_set)
    _require(not missing, "pre-stage render is missing required statements: %s" % "; ".join(missing))

    configured = variables["configured_vlans"]
    expected_vlan_lines = {
        "set vlans %s vlan-id %s" % (item["name"], item["vlan_id"])
        for item in configured
    }
    _require(expected_vlan_lines <= line_set, "pre-stage render does not contain every approved configured VLAN")
    actual_vlan_lines = {
        line for line in lines
        if re.match(r"^set vlans \S+ vlan-id \d+$", line)
    }
    allowed_vlan_lines = set(expected_vlan_lines)
    allowed_vlan_lines.add("set vlans %s vlan-id %s" % (variables["temporary_recovery_vlan_name"], variables["temporary_recovery_vlan_id"]))
    _require(actual_vlan_lines == allowed_vlan_lines, "pre-stage render contains an unapproved or missing VLAN definition")

    for item in configured:
        if item.get("classification") == "data":
            _require(
                "set vlans %s forwarding-options dhcp-security group DHCP_TRUST interface ae0.0" % item["name"] in line_set,
                "data VLAN %s is missing DHCP trust on ae0.0" % item["name"],
            )
    _require(
        "set vlans %s forwarding-options dhcp-security group DHCP_TRUST interface ae0.0" % variables["voice_vlan"] in line_set,
        "voice VLAN is missing DHCP trust on ae0.0",
    )
    return {
        "result": "PASS",
        "checks": [
            "PACKAGE_RENDER_AUTHORIZED",
            "TEMPLATE_CONTRACT_VALID",
            "NO_UNRESOLVED_TEMPLATE_SYNTAX",
            "NO_CREDENTIAL_MATERIAL",
            "NO_FXP0_CONFIGURATION",
            "NO_ENDPOINT_DESCRIPTIONS",
            "NONSTOP_BRIDGING_MODE_VALID",
            "ONLY_TEMP_RECOVERY_PHYSICAL_VLAN_ASSIGNMENT",
            "TEMP_RECOVERY_PORT_PRESENT",
            "ALL_APPROVED_VLANS_PRESENT",
            "MANAGEMENT_IDENTITY_PRESENT",
            "AE0_TRUNK_PRESENT",
            "DHCP_TRUST_PRESENT",
        ],
    }


def render_pre_stage(template_text, contract, package, renderer_version):
    validate_renderable_package(package, renderer_version)
    _validate_contract(contract)
    variables = dict(package.get("variables", {}))
    variables["provisioning_mode"] = package.get("provisioning_mode")
    _validate_variables(contract, variables)
    rendered = _render_jinja(template_text, variables)
    validation = validate_pre_stage_render(rendered, package)
    return rendered, validation


def build_render_manifest(package, package_digest, config_digest, validation, renderer_version):
    key = {
        "package_id": package["package_id"],
        "package_digest": package_digest,
        "config_digest": config_digest,
        "renderer_version": renderer_version,
        "phase": "pre_stage",
    }
    render_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "render_id": render_id,
        "migration_id": package["migration_id"],
        "package_id": package["package_id"],
        "created_at": package["created_at"],
        "phase": "pre_stage",
        "inputs": {
            "package_digest": package_digest,
            "template_digest": package["inputs"]["template_digest"],
            "template_contract_digest": package["inputs"]["template_contract_digest"],
            "renderer_version": renderer_version,
        },
        "artifacts": [{"path": "ex4400-pre-stage.set", "sha256": config_digest}],
        "validation": validation,
        "safety": {
            "device_connections_allowed": False,
            "device_writes_allowed": False,
        },
    }
