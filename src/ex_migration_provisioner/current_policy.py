from __future__ import annotations

from copy import deepcopy

from .core import ProvisioningError


SITE_POLICY_SCHEMA_VERSION = "1.2"


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _validate_vlan(value, label):
    _require(isinstance(value, dict), "%s must be an object" % label)
    _require(isinstance(value.get("name"), str) and value["name"], "%s name is required" % label)
    _require(
        isinstance(value.get("vlan_id"), int) and 1 <= value["vlan_id"] <= 4094,
        "%s VLAN ID is invalid" % label,
    )
    return value


def validate_site_policy(policy):
    """Validate the generated current site policy.

    QFX identity and staged attachment ports are discovered site evidence. Voice
    VLAN is intentionally absent here; it is per-migration EX4300 evidence.
    Temp-Management remains part of the pre-cutover QFX baseline because the old
    EX4300 uses that VLAN to provide temporary upstream reachability to the
    replacement EX4400 fxp0.
    """
    required = {
        "schema_version",
        "site_policy_id",
        "site_id",
        "environment",
        "production_eligible",
        "qfx_pair",
        "stage_port_pools",
        "excluded_interfaces",
        "ae_pool",
        "management_vlan",
        "temporary_recovery_vlan",
        "prestage_access_vlan",
        "precutover_qfx_baseline",
        "esi",
        "validation",
        "source_site_inventory",
    }
    _require(isinstance(policy, dict), "QFX site policy must be an object")
    _require(required <= set(policy), "QFX site policy is missing required fields")
    _require(policy.get("schema_version") == SITE_POLICY_SCHEMA_VERSION, "unsupported QFX site-policy schema")
    _require(policy.get("environment") in ("lab", "production"), "invalid QFX site-policy environment")
    if policy["environment"] == "lab":
        _require(policy.get("production_eligible") is False, "lab QFX policy cannot be production eligible")

    pair = policy["qfx_pair"]
    _require(isinstance(pair, list) and len(pair) == 2, "QFX policy must define exactly two devices")
    _require({item.get("role") for item in pair} == {"qfx-a", "qfx-b"}, "QFX pair roles must be qfx-a and qfx-b")
    _require(len({item.get("management_address") for item in pair}) == 2, "QFX management addresses must be unique")
    _require(len({str(item.get("expected_hostname", "")).lower() for item in pair}) == 2, "QFX hostnames must be unique")
    for item in pair:
        _require(item.get("management_address"), "QFX management address is required")
        _require(item.get("expected_hostname"), "QFX discovered hostname is required")
        _require(item.get("expected_model"), "QFX discovered model is required")

    management_vlan = _validate_vlan(policy["management_vlan"], "management VLAN")
    temp_management_vlan = _validate_vlan(policy["temporary_recovery_vlan"], "temporary management VLAN")
    prestage_vlan = _validate_vlan(policy["prestage_access_vlan"], "pre-stage access VLAN")
    _require(
        len({management_vlan["vlan_id"], temp_management_vlan["vlan_id"], prestage_vlan["vlan_id"]}) == 3,
        "management, temporary management, and pre-stage access VLAN IDs must be distinct",
    )
    _require(
        len({management_vlan["name"], temp_management_vlan["name"], prestage_vlan["name"]}) == 3,
        "management, temporary management, and pre-stage access VLAN names must be distinct",
    )

    pools = policy["stage_port_pools"]
    _require(isinstance(pools, dict) and pools, "generated QFX staged-port inventory is missing")
    allowed_ports = set()
    for ports in pools.values():
        _require(isinstance(ports, list) and ports, "generated QFX staged-port pool cannot be empty")
        allowed_ports.update(ports)
    excluded = set(policy["excluded_interfaces"])
    _require(not (allowed_ports & excluded), "QFX staged and excluded interfaces overlap")

    ae_pool = policy["ae_pool"]
    _require(ae_pool.get("method") == "discover-from-existing-qfx-config", "unsupported QFX AE discovery method")
    ae_min = ae_pool.get("ae_min")
    ae_max = ae_pool.get("ae_max")
    _require(isinstance(ae_min, int) and isinstance(ae_max, int) and 0 <= ae_min <= ae_max, "QFX AE range is invalid")
    _require(ae_pool.get("migration_assignment_prebound") is False, "QFX migration attachment must not be pre-bound before cutover")

    baseline = policy["precutover_qfx_baseline"]
    _require(baseline.get("lacp_mode") == "active", "QFX migration AEs must use normal active LACP")
    _require(baseline.get("force_up") is False, "LACP force-up is prohibited for migration AEs")
    required_vlans = baseline.get("required_vlan_ids")
    _require(isinstance(required_vlans, list), "QFX baseline required VLAN list is invalid")
    _require(
        set(required_vlans) == {management_vlan["vlan_id"], temp_management_vlan["vlan_id"]},
        "QFX baseline must contain exactly management and temporary management VLANs",
    )
    _require(
        prestage_vlan["vlan_id"] not in set(required_vlans),
        "pre-stage access VLAN must remain EX-only and cannot be part of the QFX pre-cutover baseline",
    )

    esi = policy["esi"]
    _require(esi.get("method") == "auto-derive-type-1-lacp", "unsupported ESI method")
    _require(esi.get("all_active") is True, "QFX ESI must be all-active")

    validation = policy["validation"]
    for flag in (
        "attachment_discovered_post_cutover",
        "require_interface_symmetry",
        "require_lldp",
        "require_lacp_partner",
        "require_matching_ae",
        "require_matching_lacp_system_id",
    ):
        _require(validation.get(flag) is True, "QFX validation flag %s must be true" % flag)
    _require(validation.get("operator_supplied_ports_allowed") is False, "operator-supplied QFX ports must remain disabled")
    return policy


def migration_voice_vlan(plan):
    variables = plan.get("template_variables", {})
    name = variables.get("voice_vlan_name")
    vlan_id = variables.get("voice_vlan_id")
    _require(isinstance(name, str) and name, "approved migration plan has no discovered voice VLAN name")
    _require(isinstance(vlan_id, int) and 1 <= vlan_id <= 4094, "approved migration plan has no discovered voice VLAN ID")
    return {"name": name, "vlan_id": vlan_id}


def render_variables(plan, site_policy, bootstrap_profile):
    validate_site_policy(site_policy)
    variables = deepcopy(plan.get("template_variables", {}))
    management_vlan = site_policy["management_vlan"]
    voice_vlan = migration_voice_vlan(plan)
    temp_management_vlan = site_policy["temporary_recovery_vlan"]

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
        _require(
            vlan_id != temp_management_vlan["vlan_id"] and name != temp_management_vlan["name"],
            "temporary management VLAN collides with approved configured VLAN inventory",
        )
        names.add(name)
        ids.add(vlan_id)
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
    _require(len(voice_matches) == 1 and voice_matches[0]["name"] == voice_vlan["name"], "approved VLAN inventory does not match the EX4300-discovered voice VLAN")

    variables["configured_vlans"] = normalized
    variables["voice_vlan"] = voice_vlan["name"]
    variables["voice_vlan_id"] = voice_vlan["vlan_id"]
    variables.pop("temporary_recovery_vlan", None)
    variables.pop("temporary_recovery_vlan_name", None)
    variables.pop("temporary_recovery_vlan_id", None)
    variables.pop("recovery_interface", None)
    variables["plan_id"] = plan["plan_id"]
    return variables


def derive_required_qfx_vlans(plan, policy):
    """Derive only this migration's post-cutover data VLANs and EX-discovered voice VLAN."""
    validate_site_policy(policy)
    management_id = int(policy["management_vlan"]["vlan_id"])
    voice = migration_voice_vlan(plan)
    voice_id = int(voice["vlan_id"])
    configured_ids = {
        int(item["vlan_id"])
        for item in plan.get("vlan_intents", [])
        if item.get("vlan_id") is not None
    }

    endpoint_ids = set()
    for port in plan.get("port_intents", []):
        if port.get("planned_action") != "CORRELATE_AFTER_CABLE_MOVE":
            continue
        value = port.get("configured_data_vlan_id")
        if value is None:
            continue
        value = int(value)
        if value != management_id:
            endpoint_ids.add(value)

    required = set(endpoint_ids)
    _require(voice_id in configured_ids, "EX4300-discovered voice VLAN is not present in the approved configured VLAN inventory")
    required.add(voice_id)

    excluded_configured = sorted(
        value
        for value in configured_ids
        if value not in required
        and value != management_id
        and value != int(policy["temporary_recovery_vlan"]["vlan_id"])
    )
    return {
        "required_vlan_ids": sorted(required),
        "endpoint_data_vlan_ids": sorted(endpoint_ids),
        "voice_vlan_id": voice_id,
        "voice_vlan_name": voice["name"],
        "configured_but_not_required_vlan_ids": excluded_configured,
    }
