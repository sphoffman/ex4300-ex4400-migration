from __future__ import annotations

import re
from copy import deepcopy

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes, utc_now
from ex_migration_discovery.parsers import parse_lldp_neighbors_text


class ProvisioningError(RuntimeError):
    pass


_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _ae_number(name):
    match = re.fullmatch(r"ae(\d+)", str(name))
    if not match:
        raise ProvisioningError("invalid AE interface %r" % name)
    return int(match.group(1))


def _validate_vlan(value, label):
    _require(isinstance(value, dict), "%s must be an object" % label)
    _require(isinstance(value.get("name"), str) and value["name"], "%s name is required" % label)
    _require(isinstance(value.get("vlan_id"), int) and 1 <= value["vlan_id"] <= 4094, "%s VLAN ID is invalid" % label)
    return value


def validate_site_policy(policy):
    required = {
        "schema_version", "site_policy_id", "environment", "production_eligible",
        "qfx_pair", "stage_port_pools", "excluded_interfaces", "management_vlan",
        "voice_vlan", "temporary_recovery_vlan", "port_to_ae", "esi", "lacp_system_id", "validation",
    }
    _require(isinstance(policy, dict), "QFX site policy must be an object")
    _require(required <= set(policy), "QFX site policy is missing required fields")
    _require(policy["schema_version"] == "1.0", "unsupported QFX site-policy schema")
    _require(policy["environment"] in ("lab", "production"), "invalid QFX site-policy environment")
    if policy["environment"] == "lab":
        _require(policy["production_eligible"] is False, "lab QFX policy cannot be production eligible")

    pair = policy["qfx_pair"]
    _require(isinstance(pair, list) and len(pair) == 2, "QFX policy must define exactly two devices")
    roles = {item.get("role") for item in pair}
    _require(roles == {"qfx-a", "qfx-b"}, "QFX pair roles must be qfx-a and qfx-b")
    _require(len({item.get("management_address") for item in pair}) == 2, "QFX management addresses must be unique")
    _require(len({str(item.get("expected_hostname", "")).lower() for item in pair}) == 2, "QFX hostnames must be unique")
    for item in pair:
        _require(item.get("management_address"), "QFX management address is required")
        _require(item.get("expected_hostname"), "QFX expected hostname is required")
        _require(item.get("expected_model"), "QFX expected model is required")
        if policy["environment"] == "production":
            _require(str(item["expected_model"]).upper() == "QFX5700", "production QFX policy requires QFX5700")

    management_vlan = _validate_vlan(policy["management_vlan"], "management VLAN")
    voice_vlan = _validate_vlan(policy["voice_vlan"], "voice VLAN")
    recovery_vlan = _validate_vlan(policy["temporary_recovery_vlan"], "temporary recovery VLAN")
    _require(
        len({management_vlan["vlan_id"], voice_vlan["vlan_id"], recovery_vlan["vlan_id"]}) == 3,
        "management, voice, and temporary recovery VLAN IDs must be distinct",
    )

    pools = policy["stage_port_pools"]
    _require(isinstance(pools, dict) and pools, "at least one QFX stage port pool is required")
    allowed_ports = set()
    for ports in pools.values():
        _require(isinstance(ports, list) and ports, "QFX stage port pools cannot be empty")
        allowed_ports.update(ports)
    excluded = set(policy["excluded_interfaces"])
    _require(not (allowed_ports & excluded), "QFX allowed and excluded interfaces overlap")

    mapping = policy["port_to_ae"]
    _require(mapping.get("method") == "explicit-migration-id-map", "unsupported QFX port-to-AE mapping method")
    assignments = mapping.get("assignments") or []
    _require(assignments, "QFX policy contains no migration assignments")
    _require(len({a.get("migration_id") for a in assignments}) == len(assignments), "duplicate migration IDs in QFX assignments")
    _require(len({a.get("physical_interface") for a in assignments}) == len(assignments), "duplicate physical interfaces in QFX assignments")
    _require(len({a.get("ae_interface") for a in assignments}) == len(assignments), "duplicate AE interfaces in QFX assignments")
    ae_min, ae_max = int(mapping["ae_min"]), int(mapping["ae_max"])
    _require(ae_min <= ae_max, "QFX AE range is invalid")
    for assignment in assignments:
        physical = assignment.get("physical_interface")
        ae = assignment.get("ae_interface")
        _require(physical in allowed_ports, "assigned QFX interface %s is not in an allowed stage pool" % physical)
        _require(physical not in excluded, "assigned QFX interface %s is excluded" % physical)
        number = _ae_number(ae)
        _require(ae_min <= number <= ae_max, "assigned AE %s is outside the permitted range" % ae)

    esi = policy["esi"]
    _require(esi.get("method") == "auto-derive-type-1-lacp", "unsupported ESI method")
    _require(esi.get("all_active") is True, "QFX ESI must be all-active")

    lacp = policy["lacp_system_id"]
    _require(lacp.get("method") == "explicit-per-ae", "unsupported LACP system-ID method")
    values = lacp.get("values") or {}
    assigned_aes = {a["ae_interface"] for a in assignments}
    _require(assigned_aes <= set(values), "every assigned AE requires an explicit LACP system ID")
    for ae, value in values.items():
        _ae_number(ae)
        _require(bool(re.fullmatch(_MAC, str(value))), "invalid LACP system ID for %s" % ae)

    validation = policy["validation"]
    for flag in (
        "require_interface_symmetry", "require_lldp", "require_lacp_partner",
        "require_matching_lacp_system_id",
    ):
        _require(validation.get(flag) is True, "QFX validation flag %s must be true" % flag)
    _require(validation.get("operator_supplied_ports_allowed") is False, "operator-supplied QFX ports must remain disabled")
    return policy


def assignment_for(policy, migration_id):
    validate_site_policy(policy)
    matches = [item for item in policy["port_to_ae"]["assignments"] if item["migration_id"] == migration_id]
    if len(matches) != 1:
        raise ProvisioningError("QFX policy has no unique assignment for migration %s" % migration_id)
    return deepcopy(matches[0])


def _configured_ae(text, physical):
    pattern = r"(?m)^set interfaces %s ether-options 802\.3ad (ae\d+)\s*$" % re.escape(physical)
    match = re.search(pattern, text or "")
    return match.group(1) if match else None


def _configured_lacp_system_id(text, ae):
    pattern = r"(?im)^set interfaces %s aggregated-ether-options lacp system-id (%s)\s*$" % (re.escape(ae), _MAC)
    match = re.search(pattern, text or "")
    return match.group(1).lower() if match else None


def _interface_up(text, physical):
    pattern = r"(?m)^%s(?:\.\d+)?\s+up\s+up(?:\s|$)" % re.escape(physical)
    return bool(re.search(pattern, text or ""))


def _lacp_operational(text, physical):
    value = text or ""
    return (
        physical in value
        and re.search(r"(?i)\bcollecting\b", value) is not None
        and re.search(r"(?i)\bdistributing\b", value) is not None
    )


def _lldp_system_name(text, physical):
    neighbors = parse_lldp_neighbors_text(text or "", "", "")
    matches = [
        item.get("remote_system_name")
        for item in neighbors
        if item.get("local_interface") == physical and item.get("remote_system_name")
    ]
    return matches[0] if len(matches) == 1 else None


def observe_qfx(dev, device_policy, assignment, policy):
    physical = assignment["physical_interface"]
    ae = assignment["ae_interface"]
    facts = getattr(dev, "facts", {}) or {}
    expected_system_id = policy["lacp_system_id"]["values"][ae].lower()

    physical_config = dev.cli("show configuration interfaces %s | display set" % physical, warning=False)
    ae_config = dev.cli("show configuration interfaces %s | display set" % ae, warning=False)
    terse = dev.cli("show interfaces %s terse" % physical, warning=False)
    lacp = dev.cli("show lacp interfaces %s extensive" % ae, warning=False)
    lldp = dev.cli("show lldp neighbors detail", warning=False)

    observed_hostname = str(facts.get("hostname") or "")
    observed_model = str(facts.get("model") or "")
    mapped_ae = _configured_ae(physical_config, physical)
    configured_system_id = _configured_lacp_system_id(ae_config, ae)
    esi_auto = bool(re.search(
        r"(?m)^set interfaces %s esi auto-derive type-1-lacp\s*$" % re.escape(ae), ae_config or ""
    ))
    esi_all_active = bool(re.search(
        r"(?m)^set interfaces %s esi all-active\s*$" % re.escape(ae), ae_config or ""
    ))
    neighbor = _lldp_system_name(lldp, physical)

    checks = {
        "hostname_matches": observed_hostname.lower() == str(device_policy["expected_hostname"]).lower(),
        "model_matches": observed_model.lower() == str(device_policy["expected_model"]).lower(),
        "physical_interface_up": _interface_up(terse, physical),
        "physical_maps_to_expected_ae": mapped_ae == ae,
        "configured_lacp_system_id_matches": configured_system_id == expected_system_id,
        "esi_auto_derive_type_1_lacp": esi_auto,
        "esi_all_active": esi_all_active,
        "lacp_collecting_distributing": _lacp_operational(lacp, physical),
        "lldp_neighbor_present": bool(neighbor),
    }
    return {
        "role": device_policy["role"],
        "management_address": device_policy["management_address"],
        "expected_hostname": device_policy["expected_hostname"],
        "expected_model": device_policy["expected_model"],
        "observed_hostname": observed_hostname,
        "observed_model": observed_model,
        "physical_interface": physical,
        "ae_interface": ae,
        "configured_ae": mapped_ae,
        "expected_lacp_system_id": expected_system_id,
        "configured_lacp_system_id": configured_system_id,
        "lldp_neighbor_system_name": neighbor,
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def run_qfx_preflight(policy, migration_id, devices, observed_at=None):
    validate_site_policy(policy)
    assignment = assignment_for(policy, migration_id)
    observations = []
    for device_policy in policy["qfx_pair"]:
        role = device_policy["role"]
        if role not in devices:
            raise ProvisioningError("missing connected QFX device for role %s" % role)
        observations.append(observe_qfx(devices[role], device_policy, assignment, policy))

    by_role = {item["role"]: item for item in observations}
    a, b = by_role["qfx-a"], by_role["qfx-b"]
    neighbor_a = (a.get("lldp_neighbor_system_name") or "").strip().lower()
    neighbor_b = (b.get("lldp_neighbor_system_name") or "").strip().lower()
    pair_checks = {
        "interface_symmetry": a["physical_interface"] == b["physical_interface"] == assignment["physical_interface"],
        "ae_symmetry": a["ae_interface"] == b["ae_interface"] == assignment["ae_interface"],
        "lacp_system_id_symmetry": (
            a["configured_lacp_system_id"] == b["configured_lacp_system_id"]
            == policy["lacp_system_id"]["values"][assignment["ae_interface"]].lower()
        ),
        "lldp_neighbor_symmetry": bool(neighbor_a) and neighbor_a == neighbor_b,
    }
    passed = all(item["result"] == "PASS" for item in observations) and all(pair_checks.values())
    return {
        "schema_version": "1.0",
        "migration_id": migration_id,
        "site_policy_id": policy["site_policy_id"],
        "observed_at": observed_at or utc_now(),
        "assignment": assignment,
        "devices": observations,
        "pair_checks": pair_checks,
        "result": "PASS" if passed else "FAIL",
    }


def _render_variables(plan, site_policy):
    variables = deepcopy(plan.get("template_variables", {}))
    management_vlan = site_policy["management_vlan"]
    voice_vlan = site_policy["voice_vlan"]
    recovery_vlan = site_policy["temporary_recovery_vlan"]

    _require(variables.get("management_vlan_id") == management_vlan["vlan_id"], "approved plan management VLAN does not match site policy")
    _require(isinstance(variables.get("management_vlan_name"), str) and variables["management_vlan_name"], "approved plan has no management VLAN name")
    configured = variables.get("configured_vlans")
    _require(isinstance(configured, list) and configured, "approved plan has no configured VLAN inventory")

    names = set()
    ids = set()
    normalized = []
    for vlan in configured:
        name = vlan.get("name")
        vlan_id = vlan.get("vlan_id")
        _require(isinstance(name, str) and name, "configured VLAN has no name")
        _require(isinstance(vlan_id, int) and 1 <= vlan_id <= 4094, "configured VLAN %s has no valid VLAN ID" % name)
        _require(name not in names, "duplicate configured VLAN name %s" % name)
        _require(vlan_id not in ids, "duplicate configured VLAN ID %s" % vlan_id)
        _require(vlan_id != recovery_vlan["vlan_id"] and name != recovery_vlan["name"], "temporary recovery VLAN collides with approved configured VLAN inventory")
        names.add(name); ids.add(vlan_id)
        item = deepcopy(vlan)
        if vlan_id == management_vlan["vlan_id"]:
            item["classification"] = "management"
        elif vlan_id == voice_vlan["vlan_id"]:
            item["classification"] = "voice"
        else:
            item["classification"] = "data"
        normalized.append(item)

    management_matches = [item for item in normalized if item["vlan_id"] == management_vlan["vlan_id"]]
    _require(len(management_matches) == 1, "approved VLAN inventory does not contain exactly one management VLAN")
    _require(management_matches[0]["name"] == variables["management_vlan_name"], "approved management VLAN name is inconsistent")
    voice_matches = [item for item in normalized if item["vlan_id"] == voice_vlan["vlan_id"]]
    _require(len(voice_matches) == 1 and voice_matches[0]["name"] == voice_vlan["name"], "approved VLAN inventory does not match the site-policy voice VLAN")

    variables["configured_vlans"] = normalized
    variables["voice_vlan"] = voice_vlan["name"]
    variables["voice_vlan_id"] = voice_vlan["vlan_id"]
    variables["temporary_recovery_vlan"] = deepcopy(recovery_vlan)
    variables["temporary_recovery_vlan_name"] = recovery_vlan["name"]
    variables["temporary_recovery_vlan_id"] = recovery_vlan["vlan_id"]
    variables["plan_id"] = plan["plan_id"]
    return variables


def build_package(
    plan, plan_digest, plan_approval, plan_approval_digest,
    settings_digest, template_digest, template_contract_digest,
    site_policy, site_policy_digest, bootstrap_profile, bootstrap_profile_digest,
    preflight, preflight_artifact_digest, renderer_version,
):
    validate_site_policy(site_policy)
    if preflight.get("result") != "PASS":
        raise ProvisioningError("QFX preflight did not pass")
    if plan_approval.get("plan_digest") != plan_digest:
        raise ProvisioningError("plan approval is not bound to the selected plan")
    if plan_approval.get("plan_id") != plan.get("plan_id"):
        raise ProvisioningError("plan approval ID does not match the selected plan")
    if preflight.get("migration_id") != plan.get("migration_id"):
        raise ProvisioningError("QFX preflight migration ID does not match the plan")
    if preflight.get("site_policy_id") != site_policy.get("site_policy_id"):
        raise ProvisioningError("QFX preflight site policy does not match")
    if bootstrap_profile.get("environment") != site_policy.get("environment"):
        raise ProvisioningError("bootstrap profile and QFX site policy environments differ")

    migration_id = plan["migration_id"]
    assignment = assignment_for(site_policy, migration_id)
    management_vlan = site_policy["management_vlan"]
    recovery_vlan = site_policy["temporary_recovery_vlan"]

    plan_eligible = bool(plan.get("eligibility", {}).get("production_eligible"))
    approval_eligible = bool(plan_approval.get("production_eligible"))
    bootstrap_eligible = bool(bootstrap_profile.get("production_eligible"))
    policy_eligible = bool(site_policy.get("production_eligible"))
    production_eligible = all((plan_eligible, approval_eligible, bootstrap_eligible, policy_eligible))
    reasons = []
    if not plan_eligible:
        reasons.append("approved migration plan is not production eligible")
    if not approval_eligible:
        reasons.append("plan approval is not production eligible")
    if not bootstrap_eligible:
        reasons.append("bootstrap profile is not production eligible")
    if not policy_eligible:
        reasons.append("QFX site policy is not production eligible")

    inputs = {
        "plan_digest": plan_digest,
        "plan_approval_digest": plan_approval_digest,
        "template_digest": template_digest,
        "template_contract_digest": template_contract_digest,
        "site_policy_digest": site_policy_digest,
        "bootstrap_profile_digest": bootstrap_profile_digest,
        "qfx_preflight_digest": sha256_bytes(canonical_bytes(preflight)),
        "settings_digest": settings_digest,
        "renderer_version": renderer_version,
    }
    variables = _render_variables(plan, site_policy)
    variables["qfx"] = {
        "site_policy_id": site_policy["site_policy_id"],
        "physical_interface": assignment["physical_interface"],
        "ae_interface": assignment["ae_interface"],
        "lacp_system_id": site_policy["lacp_system_id"]["values"][assignment["ae_interface"]],
    }

    phases = {
        "pre_stage": {
            "status": "PREFLIGHT_VALIDATED",
            "qfx_initial_vlan_ids": [management_vlan["vlan_id"], recovery_vlan["vlan_id"]],
            "qfx_physical_interface": assignment["physical_interface"],
            "qfx_ae_interface": assignment["ae_interface"],
            "device_writes_authorized": False,
        },
        "cutover": {"status": "NOT_AUTHORIZED", "device_writes_authorized": False},
        "post_move": {"status": "NOT_AUTHORIZED", "device_writes_authorized": False},
    }
    validation = {
        "result": "PASS",
        "checks": [
            "PLAN_INTEGRITY_VALID", "PLAN_APPROVAL_BOUND", "SITE_POLICY_VALID",
            "QFX_PREFLIGHT_PASS", "RENDER_VARIABLES_NORMALIZED", "INPUT_DIGESTS_BOUND",
        ],
    }
    key = {
        "migration_id": migration_id,
        "inputs": inputs,
        "provisioning_mode": bootstrap_profile["provisioning_mode"],
        "variables": variables,
        "phases": phases,
        "validation": validation,
    }
    package_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "package_id": package_id,
        "migration_id": migration_id,
        "created_at": preflight["observed_at"],
        "inputs": inputs,
        "eligibility": {
            "status": "PRODUCTION_ELIGIBLE" if production_eligible else "LAB_ONLY",
            "production_eligible": production_eligible,
            "reasons": reasons,
        },
        "provisioning_mode": bootstrap_profile["provisioning_mode"],
        "variables": variables,
        "phases": phases,
        "artifacts": [{"path": "qfx-preflight.json", "sha256": preflight_artifact_digest}],
        "validation": validation,
        "safety": {
            "rendering_allowed": True,
            "device_connections_allowed": False,
            "device_writes_allowed": False,
            "stale_if_any_input_digest_changes": True,
        },
    }
