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

from . import cli_base as base
from .core import _render_variables


PACKAGE_SCHEMA_VERSION = "1.1"
SITE_POLICY_SCHEMA_VERSION = "1.1"
_PHYSICAL_INTERFACE = re.compile(r"^(?:ge|xe|et)-[0-9]+/[0-9]+/[0-9]+$")


def _require(condition, message):
    if not condition:
        raise base.ProvisioningError(message)


def _validate_vlan(value, label):
    _require(isinstance(value, dict), "%s must be an object" % label)
    _require(isinstance(value.get("name"), str) and value["name"], "%s name is required" % label)
    _require(
        isinstance(value.get("vlan_id"), int) and 1 <= value["vlan_id"] <= 4094,
        "%s VLAN ID is invalid" % label,
    )
    return value


def _uplink_interfaces(bootstrap_profile):
    values = bootstrap_profile.get("uplink_interfaces")
    _require(isinstance(values, list) and values, "bootstrap profile must define EX4400 uplink_interfaces")
    normalized = [str(value).strip() for value in values]
    _require(all(normalized), "bootstrap uplink interface names cannot be empty")
    _require(len(normalized) == len(set(normalized)), "bootstrap uplink interface inventory contains duplicates")
    _require(
        all(_PHYSICAL_INTERFACE.fullmatch(value) for value in normalized),
        "bootstrap uplink interface inventory contains an unsupported physical interface",
    )
    return normalized


def validate_pre_cutover_site_policy(policy):
    required = {
        "schema_version",
        "site_policy_id",
        "environment",
        "production_eligible",
        "qfx_pair",
        "stage_port_pools",
        "excluded_interfaces",
        "ae_pool",
        "management_vlan",
        "voice_vlan",
        "temporary_recovery_vlan",
        "prestage_access_vlan",
        "precutover_qfx_baseline",
        "esi",
        "validation",
    }
    _require(isinstance(policy, dict), "QFX site policy must be an object")
    _require(required <= set(policy), "QFX site policy is missing required fields")
    _require(
        policy.get("schema_version") == SITE_POLICY_SCHEMA_VERSION,
        "unsupported QFX site-policy schema",
    )
    _require(
        policy.get("environment") in ("lab", "production"),
        "invalid QFX site-policy environment",
    )
    if policy["environment"] == "lab":
        _require(
            policy.get("production_eligible") is False,
            "lab QFX policy cannot be production eligible",
        )

    pair = policy["qfx_pair"]
    _require(isinstance(pair, list) and len(pair) == 2, "QFX policy must define exactly two devices")
    _require({item.get("role") for item in pair} == {"qfx-a", "qfx-b"}, "QFX pair roles must be qfx-a and qfx-b")
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
    prestage_vlan = _validate_vlan(policy["prestage_access_vlan"], "pre-stage access VLAN")
    _require(
        len({
            management_vlan["vlan_id"],
            voice_vlan["vlan_id"],
            recovery_vlan["vlan_id"],
            prestage_vlan["vlan_id"],
        }) == 4,
        "management, voice, temporary recovery, and pre-stage access VLAN IDs must be distinct",
    )
    _require(
        len({
            management_vlan["name"],
            voice_vlan["name"],
            recovery_vlan["name"],
            prestage_vlan["name"],
        }) == 4,
        "management, voice, temporary recovery, and pre-stage access VLAN names must be distinct",
    )

    pools = policy["stage_port_pools"]
    _require(isinstance(pools, dict) and pools, "at least one QFX stage port pool is required")
    allowed_ports = set()
    for ports in pools.values():
        _require(isinstance(ports, list) and ports, "QFX stage port pools cannot be empty")
        allowed_ports.update(ports)
    excluded = set(policy["excluded_interfaces"])
    _require(not (allowed_ports & excluded), "QFX allowed and excluded interfaces overlap")

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
        set(required_vlans) == {management_vlan["vlan_id"], recovery_vlan["vlan_id"]},
        "QFX baseline must contain exactly management and temporary recovery VLANs",
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
    _require(
        validation.get("operator_supplied_ports_allowed") is False,
        "operator-supplied QFX ports must remain disabled",
    )
    return policy


def build_pre_stage_package(
    plan,
    plan_digest,
    plan_approval,
    plan_approval_digest,
    settings_digest,
    template_digest,
    template_contract_digest,
    site_policy,
    site_policy_digest,
    bootstrap_profile,
    bootstrap_profile_digest,
    renderer_version,
    created_at=None,
):
    validate_pre_cutover_site_policy(site_policy)
    if plan_approval.get("plan_digest") != plan_digest:
        raise base.ProvisioningError("plan approval is not bound to the selected plan")
    if plan_approval.get("plan_id") != plan.get("plan_id"):
        raise base.ProvisioningError("plan approval ID does not match the selected plan")
    if bootstrap_profile.get("environment") != site_policy.get("environment"):
        raise base.ProvisioningError("bootstrap profile and QFX site policy environments differ")

    variables = _render_variables(plan, site_policy, bootstrap_profile)
    prestage_vlan = site_policy["prestage_access_vlan"]
    configured = variables.get("configured_vlans", [])
    _require(
        all(
            item.get("vlan_id") != prestage_vlan["vlan_id"]
            and item.get("name") not in (prestage_vlan["name"], "default")
            for item in configured
        ),
        "pre-stage default VLAN collides with the approved configured VLAN inventory",
    )
    variables["prestage_access_vlan"] = dict(prestage_vlan)
    variables["prestage_access_vlan_name"] = prestage_vlan["name"]
    variables["prestage_access_vlan_id"] = prestage_vlan["vlan_id"]
    variables["uplink_interfaces"] = _uplink_interfaces(bootstrap_profile)
    _require(
        variables["recovery_interface"] not in variables["uplink_interfaces"],
        "recovery interface cannot also be an EX4400 AE uplink member",
    )
    variables["qfx"] = {
        "site_policy_id": site_policy["site_policy_id"],
        "attachment_state": "UNKNOWN_UNTIL_POST_CUTOVER_DISCOVERY",
        "physical_interface": None,
        "ae_interface": None,
        "force_up": False,
    }

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
        "settings_digest": settings_digest,
        "renderer_version": renderer_version,
    }
    phases = {
        "pre_stage": {
            "status": "INPUTS_VALIDATED",
            "ex4400_recovery_interface": variables["recovery_interface"],
            "qfx_attachment_known": False,
            "qfx_connections_performed": False,
            "device_writes_authorized": False,
        },
        "cutover": {
            "status": "NOT_AUTHORIZED",
            "qfx_attachment_discovery_required": True,
            "device_writes_authorized": False,
        },
        "post_move": {
            "status": "NOT_AUTHORIZED",
            "qfx_attachment_discovery_required": True,
            "device_writes_authorized": False,
        },
    }
    validation = {
        "result": "PASS",
        "checks": [
            "PLAN_INTEGRITY_VALID",
            "PLAN_APPROVAL_BOUND",
            "SITE_POLICY_VALID",
            "NO_QFX_ATTACHMENT_PREBOUND",
            "QFX_BASELINE_POLICY_BOUND",
            "LACP_FORCE_UP_PROHIBITED",
            "RENDER_VARIABLES_NORMALIZED",
            "RECOVERY_INTERFACE_BOUND",
            "EX4400_UPLINK_INTERFACES_BOUND",
            "PRESTAGE_DEFAULT_VLAN_BOUND",
            "INPUT_DIGESTS_BOUND",
        ],
    }
    key = {
        "migration_id": plan["migration_id"],
        "inputs": inputs,
        "provisioning_mode": bootstrap_profile["provisioning_mode"],
        "variables": variables,
        "phases": phases,
        "validation": validation,
    }
    package_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "package_id": package_id,
        "migration_id": plan["migration_id"],
        "created_at": created_at or utc_now(),
        "inputs": inputs,
        "eligibility": {
            "status": "PRODUCTION_ELIGIBLE" if production_eligible else "LAB_ONLY",
            "production_eligible": production_eligible,
            "reasons": reasons,
        },
        "provisioning_mode": bootstrap_profile["provisioning_mode"],
        "variables": variables,
        "phases": phases,
        "artifacts": [],
        "validation": validation,
        "safety": {
            "rendering_allowed": True,
            "device_connections_allowed": False,
            "device_writes_allowed": False,
            "qfx_connections_allowed": False,
            "qfx_attachment_prebound": False,
            "stale_if_any_input_digest_changes": True,
        },
    }


def write_pre_stage_package(migration_root, package):
    destination = migration_root / "packages" / package["package_id"]
    package_path = destination / "package.json"
    if package_path.is_file():
        base._verify_integrity(destination, ("package.json",))
        if read_json(package_path) != package:
            raise base.ProvisioningError("existing package ID has different content")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(package_path, package)
    atomic_json(destination / "integrity.json", {
        "package.json": sha256_file(package_path),
    })
    return destination, "CREATED"


def package_candidates_compat(migration_root):
    """Return only current-schema provisioning packages.

    Historical package layouts are intentionally unsupported while this project is
    under development; regenerate migration artifacts after schema changes.
    """
    candidates = []
    for package_path in sorted((migration_root / "packages").glob("*/package.json")):
        directory = package_path.parent
        try:
            base._verify_integrity(directory, ("package.json",))
            package = read_json(package_path)
            if package.get("schema_version") != PACKAGE_SCHEMA_VERSION:
                continue
            if package.get("migration_id") != migration_root.name:
                continue
            candidates.append({
                "package": package,
                "package_path": package_path,
                "directory": directory,
            })
        except (base.AnalysisError, base.ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (
            item["package"].get("created_at", ""),
            item["package"].get("package_id", ""),
        ),
        reverse=True,
    )


def choose_package_compat(migration_root, package_id=None):
    candidates = package_candidates_compat(migration_root)
    if package_id:
        candidates = [item for item in candidates if item["package"].get("package_id") == package_id]
    if not candidates:
        suffix = " %s" % package_id if package_id else ""
        raise base.ProvisioningError("no current-schema integrity-valid provisioning package%s was found" % suffix)
    return candidates[0]


def verify_package_inputs_compat(selected, settings, migration_root, paths):
    package = selected["package"]
    if package.get("schema_version") != PACKAGE_SCHEMA_VERSION:
        raise base.ProvisioningError(
            "unsupported provisioning package schema %r; regenerate migration artifacts"
            % package.get("schema_version")
        )

    inputs = package.get("inputs", {})
    current = {
        "settings_digest": sha256_bytes(canonical_bytes(settings)),
        "template_digest": sha256_file(paths["template"]),
        "template_contract_digest": sha256_file(paths["contract"]),
        "site_policy_digest": sha256_file(paths["site_policy"]),
        "bootstrap_profile_digest": sha256_file(paths["bootstrap"]),
    }
    for name, value in current.items():
        if inputs.get(name) != value:
            raise base.ProvisioningError("provisioning package is stale: %s changed" % name)
    if inputs.get("renderer_version") != base.RENDERER_VERSION:
        raise base.ProvisioningError("provisioning package is stale: renderer version changed")

    plan_matches = [
        item for item in base.approved_plan_candidates(migration_root)
        if item["plan_digest"] == inputs.get("plan_digest")
        and item["approval_digest"] == inputs.get("plan_approval_digest")
    ]
    if len(plan_matches) != 1:
        raise base.ProvisioningError(
            "provisioning package no longer resolves to one approved integrity-valid plan"
        )
    return sha256_file(selected["package_path"])
