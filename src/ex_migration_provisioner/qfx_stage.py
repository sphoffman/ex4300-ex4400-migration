from __future__ import annotations

import re

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from .attachment import observe_qfx_attachment
from .core import ProvisioningError


_SCHEMA_VERSION = "1.0"
_VLAN_DEF = re.compile(
    r"(?m)^set (?:(?:routing-instances (?P<ri>\S+) )?)vlans "
    r"(?P<name>\S+) vlan-id (?P<id>\d+)\s*$"
)
_RI_INTERFACE = re.compile(
    r"(?m)^set routing-instances (?P<ri>\S+) interface (?P<if>\S+)\s*$"
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def attachment_candidates(migration_root):
    result = []
    root = migration_root / "qfx-attachments"
    for path in sorted(root.glob("*/attachment.json")):
        directory = path.parent
        try:
            integrity = read_json(directory / "integrity.json")
            _require(
                integrity.get("attachment.json") == sha256_file(path),
                "attachment integrity validation failed",
            )
            value = read_json(path)
            if value.get("migration_id") != migration_root.name:
                continue
            if value.get("result") != "PASS":
                continue
            result.append({
                "attachment": value,
                "attachment_path": path,
                "directory": directory,
            })
        except (OSError, ProvisioningError, ValueError):
            continue
    return sorted(
        result,
        key=lambda item: (
            item["attachment"].get("approved_at", ""),
            item["attachment"].get("attachment_id", ""),
        ),
        reverse=True,
    )


def choose_attachment(migration_root, attachment_id=None):
    values = attachment_candidates(migration_root)
    if attachment_id:
        values = [
            item for item in values
            if item["attachment"].get("attachment_id") == attachment_id
        ]
    if not values:
        suffix = " %s" % attachment_id if attachment_id else ""
        raise ProvisioningError(
            "no integrity-valid approved QFX attachment%s was found" % suffix
        )
    return values[0]


def derive_required_qfx_vlans(plan, policy):
    management_id = int(policy["management_vlan"]["vlan_id"])
    voice_id = int(policy["voice_vlan"]["vlan_id"])
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
    if voice_id in configured_ids:
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
        "voice_vlan_id": voice_id if voice_id in configured_ids else None,
        "configured_but_not_required_vlan_ids": excluded_configured,
    }


def _vlan_definitions(text):
    result = []
    for match in _VLAN_DEF.finditer(text or ""):
        result.append({
            "routing_instance": match.group("ri"),
            "name": match.group("name"),
            "vlan_id": int(match.group("id")),
        })
    return result


def _owning_routing_instance(text, ae):
    target = "%s.0" % ae
    matches = sorted({
        match.group("ri")
        for match in _RI_INTERFACE.finditer(text or "")
        if match.group("if") == target
    })
    return matches[0] if len(matches) == 1 else None


def _resolve_required(definitions, routing_instance, required_vlan_ids):
    resolved = []
    failures = []
    for vlan_id in required_vlan_ids:
        matches = [
            item for item in definitions
            if item["vlan_id"] == vlan_id
            and item["routing_instance"] == routing_instance
        ]
        if len(matches) != 1:
            failures.append({
                "vlan_id": vlan_id,
                "reason": (
                    "missing" if not matches else "ambiguous"
                ),
                "matches": matches,
            })
            continue
        resolved.append(matches[0])
    return resolved, failures


def observe_qfx_vlan_plan_device(
    dev,
    device_policy,
    policy,
    attachment_device,
    expected_ex_hostname,
    host_key,
    required_vlan_ids,
):
    observation = observe_qfx_attachment(
        dev,
        device_policy,
        policy,
        expected_ex_hostname,
        host_key,
    )

    bound_matches = (
        observation.get("result") == "PASS"
        and observation.get("physical_interface")
        == attachment_device.get("physical_interface")
        and observation.get("ae_interface")
        == attachment_device.get("ae_interface")
        and observation.get("lacp_system_id")
        == attachment_device.get("lacp_system_id")
        and host_key == attachment_device.get("ssh_host_key_sha256")
    )

    ae = observation.get("ae_interface")
    ri_text = dev.cli(
        "show configuration routing-instances | display set",
        warning=False,
    ) or ""
    top_vlan_text = dev.cli(
        "show configuration vlans | display set",
        warning=False,
    ) or ""
    routing_instance = _owning_routing_instance(ri_text, ae) if ae else None
    definitions = _vlan_definitions(top_vlan_text + "\n" + ri_text)
    resolved, failures = _resolve_required(
        definitions,
        routing_instance,
        required_vlan_ids,
    ) if routing_instance else ([], [{
        "vlan_id": vlan_id,
        "reason": "owning-routing-instance-unresolved",
        "matches": [],
    } for vlan_id in required_vlan_ids])

    statements = [
        "set interfaces %s unit 0 family ethernet-switching vlan members %s"
        % (ae, item["name"])
        for item in resolved
    ] if ae else []

    recovery_required = policy.get("_old_switch_recovery_required", True) is not False
    recovery_vlan = policy["temporary_recovery_vlan"]
    current_baseline = observation.get("baseline_vlan_ids") or []
    if (
        ae
        and not recovery_required
        and int(recovery_vlan["vlan_id"]) in current_baseline
    ):
        statements.append(
            "delete interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (ae, recovery_vlan["name"])
        )

    checks = {
        "attachment_still_valid": observation.get("result") == "PASS",
        "attachment_matches_bound_artifact": bound_matches,
        "owning_routing_instance_unique": bool(routing_instance),
        "all_required_vlans_defined_in_owning_mac_vrf": not failures,
    }

    return {
        "role": device_policy["role"],
        "management_address": device_policy["management_address"],
        "ssh_host_key_sha256": host_key,
        "physical_interface": observation.get("physical_interface"),
        "ae_interface": ae,
        "routing_instance": routing_instance,
        "current_baseline_vlan_ids": observation.get("baseline_vlan_ids"),
        "required_vlans": resolved,
        "resolution_failures": failures,
        "statements": statements,
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def build_qfx_vlan_plan(
    migration_id,
    approved_plan,
    plan_digest,
    attachment,
    attachment_digest,
    policy,
    policy_digest,
    devices,
    host_keys,
    created_at=None,
):
    _require(attachment.get("migration_id") == migration_id, "QFX attachment migration ID mismatch")
    _require(attachment.get("result") == "PASS", "QFX attachment is not approved/PASS")
    _require(
        attachment.get("plan", {}).get("plan_digest") == plan_digest,
        "QFX attachment is bound to a different approved migration plan",
    )
    _require(
        attachment.get("site_policy", {}).get("site_policy_digest") == policy_digest,
        "QFX attachment is stale: QFX site-policy digest changed",
    )

    derivation = derive_required_qfx_vlans(approved_plan, policy)
    required_vlan_ids = derivation["required_vlan_ids"]
    _require(required_vlan_ids, "approved migration intent requires no post-cutover QFX VLAN additions")

    attachment_by_role = {
        item["role"]: item for item in attachment.get("devices", [])
    }
    observations = []
    for device_policy in policy["qfx_pair"]:
        role = device_policy["role"]
        _require(role in devices, "missing connected QFX device for role %s" % role)
        _require(role in host_keys, "missing QFX host-key observation for role %s" % role)
        _require(role in attachment_by_role, "QFX attachment is missing role %s" % role)
        observations.append(
            observe_qfx_vlan_plan_device(
                devices[role],
                device_policy,
                policy,
                attachment_by_role[role],
                attachment["expected_ex_hostname"],
                host_keys[role],
                required_vlan_ids,
            )
        )

    by_role = {item["role"]: item for item in observations}
    a = by_role["qfx-a"]
    b = by_role["qfx-b"]
    pair_checks = {
        "same_bound_physical_interface": bool(a["physical_interface"])
        and a["physical_interface"] == b["physical_interface"],
        "same_bound_ae": bool(a["ae_interface"])
        and a["ae_interface"] == b["ae_interface"],
        "same_owning_routing_instance": bool(a["routing_instance"])
        and a["routing_instance"] == b["routing_instance"],
        "same_vlan_names_for_required_ids": [
            (item["vlan_id"], item["name"])
            for item in a["required_vlans"]
        ] == [
            (item["vlan_id"], item["name"])
            for item in b["required_vlans"]
        ],
        "same_candidate_statements": a["statements"] == b["statements"],
    }
    passed = all(item["result"] == "PASS" for item in observations) and all(pair_checks.values())

    inputs = {
        "migration_plan_digest": plan_digest,
        "attachment_id": attachment["attachment_id"],
        "attachment_digest": attachment_digest,
        "site_policy_id": policy["site_policy_id"],
        "site_policy_digest": policy_digest,
    }
    key = {
        "migration_id": migration_id,
        "inputs": inputs,
        "derivation": derivation,
        "devices": [
            {
                "role": item["role"],
                "physical_interface": item["physical_interface"],
                "ae_interface": item["ae_interface"],
                "routing_instance": item["routing_instance"],
                "required_vlans": item["required_vlans"],
                "statements": item["statements"],
            }
            for item in observations
        ],
    }
    qfx_plan_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": _SCHEMA_VERSION,
        "qfx_plan_id": qfx_plan_id,
        "migration_id": migration_id,
        "created_at": created_at or utc_now(),
        "inputs": inputs,
        "derivation": derivation,
        "devices": observations,
        "pair_checks": pair_checks,
        "result": "PASS" if passed else "FAIL",
        "safety": {
            "read_only_observation": True,
            "qfx_writes_authorized": False,
            "ex4400_writes_authorized": False,
            "operator_supplied_ports_used": False,
            "creates_vlan_definitions": False,
            "changes_ae_vlan_membership_only": True,
        },
    }


def write_qfx_vlan_plan(migration_root, value):
    _require(value.get("result") == "PASS", "QFX VLAN plan did not pass validation")
    destination = migration_root / "qfx-vlan-plans" / value["qfx_plan_id"]
    path = destination / "plan.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("plan.json") == sha256_file(path), "QFX VLAN plan integrity validation failed")
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(value)
        comparable_existing.pop("created_at", None)
        comparable_new.pop("created_at", None)
        _require(comparable_existing == comparable_new, "existing QFX VLAN plan ID has different content")
        return destination, existing, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {
        "plan.json": sha256_file(path),
    })
    return destination, value, "CREATED"
