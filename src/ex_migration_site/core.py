from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from pathlib import Path

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from ex_migration_provisioner import cli_base as provisioner_base


class SiteError(RuntimeError):
    pass


_AE_PARENT = re.compile(
    r"(?m)^set interfaces (?P<physical>\S+) (?:ether-options|gigether-options) "
    r"802\.3ad (?P<ae>ae\d+)\s*$"
)
_INTERFACE_LINE = re.compile(r"(?m)^set interfaces (?P<interface>\S+) (?P<body>.+)$")
_TERSE_ET = re.compile(r"(?m)^(?P<interface>et-\d+/\d+/\d+)(?:\.\d+)?\s+")
_VLAN_DEF = re.compile(
    r"(?m)^set (?:(?:routing-instances (?P<ri>\S+) )?)vlans "
    r"(?P<name>\S+) vlan-id (?P<id>\d+)\s*$"
)
_VLAN_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<ae>ae\d+) unit 0 family ethernet-switching "
    r"vlan members (?P<value>\S+)\s*$"
)
_SYSTEM_ID = re.compile(
    r"(?im)^set interfaces (?P<ae>ae\d+) aggregated-ether-options lacp "
    r"system-id (?P<value>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*$"
)


def _require(condition, message):
    if not condition:
        raise SiteError(message)


def load_settings(path):
    return provisioner_base.load_settings(Path(path))


def profile_path(settings):
    return Path(settings.get("site_profile", "config/site-profile.json"))


def active_policy_path(settings):
    return Path(settings.get("qfx_site_policy", "config/qfx-site-policy.active.json"))


def load_profile(settings):
    path = profile_path(settings)
    if not path.is_file():
        raise SiteError("site profile is missing; run ./migrate site-init first")
    value = read_json(path)
    validate_profile(value)
    return value, path


def validate_profile(profile):
    required = {
        "schema_version",
        "site_id",
        "environment",
        "production_eligible",
        "qfx_pair",
        "management_vlan",
        "temporary_recovery_vlan",
        "prestage_access_vlan",
        "excluded_interfaces",
        "attachment_interfaces",
        "ae_pool",
        "esi",
        "validation",
    }
    _require(isinstance(profile, dict), "site profile must be an object")
    _require(required <= set(profile), "site profile is missing required fields")
    _require(profile.get("schema_version") == "1.0", "unsupported site-profile schema")
    _require(profile.get("environment") in ("lab", "production"), "site environment must be lab or production")
    if profile["environment"] == "lab":
        _require(profile.get("production_eligible") is False, "lab site profile cannot be production eligible")
    pair = profile["qfx_pair"]
    _require(isinstance(pair, list) and len(pair) == 2, "site profile must contain exactly two QFX management endpoints")
    _require({item.get("role") for item in pair} == {"qfx-a", "qfx-b"}, "QFX roles must be qfx-a and qfx-b")
    addresses = []
    for item in pair:
        address = str(item.get("management_address") or "").strip()
        _require(address, "QFX management address is required")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise SiteError("invalid QFX management address %r" % address)
        addresses.append(address)
    _require(len(set(addresses)) == 2, "QFX management addresses must be unique")

    vlan_ids = []
    vlan_names = []
    for key, label in (
        ("management_vlan", "management VLAN"),
        ("temporary_recovery_vlan", "temporary recovery VLAN"),
        ("prestage_access_vlan", "pre-stage access VLAN"),
    ):
        value = profile[key]
        _require(isinstance(value, dict), "%s must be an object" % label)
        _require(isinstance(value.get("name"), str) and value["name"], "%s name is required" % label)
        _require(isinstance(value.get("vlan_id"), int) and 1 <= value["vlan_id"] <= 4094, "%s ID is invalid" % label)
        vlan_ids.append(value["vlan_id"])
        vlan_names.append(value["name"])
    _require(len(set(vlan_ids)) == 3, "site VLAN IDs must be distinct")
    _require(len(set(vlan_names)) == 3, "site VLAN names must be distinct")

    selector = profile["attachment_interfaces"]
    _require(selector.get("media_prefix") == "et-", "current site staging supports ET attachment interfaces only")
    _require(selector.get("require_symmetry") is True, "QFX attachment interface symmetry must be required")

    ae_pool = profile["ae_pool"]
    ae_min = ae_pool.get("ae_min")
    ae_max = ae_pool.get("ae_max")
    _require(isinstance(ae_min, int) and isinstance(ae_max, int) and 0 <= ae_min <= ae_max <= 127, "QFX AE range must be between ae0 and ae127")

    esi = profile["esi"]
    _require(esi.get("method") == "auto-derive-type-1-lacp", "unsupported ESI method")
    _require(esi.get("all_active") is True, "QFX ESI must be all-active")
    validation = profile["validation"]
    for flag in (
        "require_interface_symmetry",
        "require_matching_ae",
        "require_matching_lacp_system_id",
    ):
        _require(validation.get(flag) is True, "site validation flag %s must be true" % flag)
    return profile


def build_profile(site_id, environment, qfx_a, qfx_b, management_vlan, recovery_vlan, prestage_vlan, excluded_interfaces, ae_min, ae_max):
    value = {
        "schema_version": "1.0",
        "site_id": site_id,
        "environment": environment,
        "production_eligible": environment == "production",
        "qfx_pair": [
            {"role": "qfx-a", "management_address": qfx_a},
            {"role": "qfx-b", "management_address": qfx_b},
        ],
        "management_vlan": dict(management_vlan),
        "temporary_recovery_vlan": dict(recovery_vlan),
        "prestage_access_vlan": dict(prestage_vlan),
        "excluded_interfaces": sorted(set(excluded_interfaces)),
        "attachment_interfaces": {
            "media_prefix": "et-",
            "require_symmetry": True,
            "stage_all_compatible": True,
        },
        "ae_pool": {
            "ae_min": int(ae_min),
            "ae_max": int(ae_max),
            "assignment": "preserve-symmetric-existing-else-lowest-free",
        },
        "esi": {"method": "auto-derive-type-1-lacp", "all_active": True},
        "validation": {
            "require_interface_symmetry": True,
            "require_matching_ae": True,
            "require_matching_lacp_system_id": True,
            "operator_supplied_ports_allowed": False,
        },
    }
    return validate_profile(value)


def write_profile(settings, value):
    path = profile_path(settings)
    atomic_json(path, value)
    return path


def site_root(settings, profile):
    return Path(settings["snapshot_root"]) / "site" / profile["site_id"]


def _interface_config_map(config_text):
    result = {}
    for match in _INTERFACE_LINE.finditer(config_text or ""):
        name = match.group("interface")
        result.setdefault(name, []).append(match.group(0))
    return result


def _ae_map(config_text):
    result = {}
    for match in _AE_PARENT.finditer(config_text or ""):
        result[match.group("physical")] = match.group("ae")
    return result


def _et_interfaces(terse_text):
    return sorted(set(match.group("interface") for match in _TERSE_ET.finditer(terse_text or "")))


def _vlan_definitions(config_text):
    by_id = {}
    for match in _VLAN_DEF.finditer(config_text or ""):
        vlan_id = int(match.group("id"))
        by_id.setdefault(vlan_id, set()).add(match.group("name"))
    return by_id


def _vlan_ids(config_text, ae, definitions):
    names_by_name = {}
    for vlan_id, names in definitions.items():
        for name in names:
            names_by_name.setdefault(name, set()).add(vlan_id)
    tokens = [
        match.group("value")
        for match in _VLAN_MEMBER.finditer(config_text or "")
        if match.group("ae") == ae
    ]
    if "all" in tokens:
        return None
    result = set()
    for token in tokens:
        if token.isdigit():
            result.add(int(token))
            continue
        ids = names_by_name.get(token, set())
        if len(ids) != 1:
            return None
        result.add(next(iter(ids)))
    return sorted(result)


def _lacp_system_id(config_text, ae):
    values = [
        match.group("value").lower()
        for match in _SYSTEM_ID.finditer(config_text or "")
        if match.group("ae") == ae
    ]
    return values[0] if len(values) == 1 else None


def _site_lacp_system_id(site_id, ae):
    number = int(str(ae)[2:])
    digest = hashlib.sha256(site_id.encode("utf-8")).digest()
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        digest[0],
        digest[1],
        digest[2],
        (number >> 8) & 0xff,
        number & 0xff,
    )


def observe_qfx(dev, role, address, host_key):
    facts = getattr(dev, "facts", {}) or {}
    config = dev.cli("show configuration interfaces | display set", warning=False) or ""
    vlan_top = dev.cli("show configuration vlans | display set", warning=False) or ""
    vlan_ri = dev.cli("show configuration routing-instances | display set", warning=False) or ""
    terse = dev.cli("show interfaces terse", warning=False) or ""
    return {
        "role": role,
        "management_address": address,
        "ssh_host_key_sha256": host_key,
        "hostname": str(facts.get("hostname") or ""),
        "model": str(facts.get("model") or ""),
        "serial_number": str(facts.get("serialnumber") or ""),
        "interfaces": _et_interfaces(terse),
        "ae_map": _ae_map(config),
        "interface_config": _interface_config_map(config),
        "interface_config_text": config,
        "vlan_config_text": vlan_top + "\n" + vlan_ri,
    }


def build_site_discovery(profile, observations, observed_at=None):
    validate_profile(profile)
    by_role = {item["role"]: item for item in observations}
    _require(set(by_role) == {"qfx-a", "qfx-b"}, "site discovery requires both QFX observations")
    a = by_role["qfx-a"]
    b = by_role["qfx-b"]
    _require(a["hostname"] and b["hostname"], "QFX hostnames could not be observed")
    _require(a["hostname"].lower() != b["hostname"].lower(), "QFX hostnames must be distinct")
    _require(a["model"] and b["model"], "QFX models could not be observed")

    excluded = set(profile["excluded_interfaces"])
    common = sorted((set(a["interfaces"]) & set(b["interfaces"])) - excluded)
    only_a = sorted(set(a["interfaces"]) - set(b["interfaces"]))
    only_b = sorted(set(b["interfaces"]) - set(a["interfaces"]))
    ae_min = profile["ae_pool"]["ae_min"]
    ae_max = profile["ae_pool"]["ae_max"]
    used = set(a["ae_map"].values()) | set(b["ae_map"].values())
    free = ["ae%d" % number for number in range(ae_min, ae_max + 1) if "ae%d" % number not in used]

    management_id = profile["management_vlan"]["vlan_id"]
    recovery_id = profile["temporary_recovery_vlan"]["vlan_id"]
    required_baseline = sorted([management_id, recovery_id])
    definitions_a = _vlan_definitions(a["vlan_config_text"])
    definitions_b = _vlan_definitions(b["vlan_config_text"])
    for vlan_id, label in ((management_id, "management"), (recovery_id, "temporary recovery")):
        _require(len(definitions_a.get(vlan_id, set())) == 1, "qfx-a does not define exactly one %s VLAN ID %s" % (label, vlan_id))
        _require(len(definitions_b.get(vlan_id, set())) == 1, "qfx-b does not define exactly one %s VLAN ID %s" % (label, vlan_id))

    attachments = []
    blocked = []
    for physical in common:
        ae_a = a["ae_map"].get(physical)
        ae_b = b["ae_map"].get(physical)
        config_a = a["interface_config"].get(physical, [])
        config_b = b["interface_config"].get(physical, [])
        if ae_a or ae_b:
            if not ae_a or ae_a != ae_b:
                blocked.append({"physical_interface": physical, "reason": "ASYMMETRIC_EXISTING_AE", "qfx_a_ae": ae_a, "qfx_b_ae": ae_b})
                continue
            number = int(ae_a[2:])
            if not ae_min <= number <= ae_max:
                blocked.append({"physical_interface": physical, "reason": "EXISTING_AE_OUTSIDE_POOL", "ae_interface": ae_a})
                continue
            vlan_a = _vlan_ids(a["interface_config_text"], ae_a, definitions_a)
            vlan_b = _vlan_ids(b["interface_config_text"], ae_b, definitions_b)
            if vlan_a not in ([], required_baseline) or vlan_b not in ([], required_baseline):
                blocked.append({"physical_interface": physical, "reason": "EXISTING_AE_HAS_NON_BASELINE_VLANS", "ae_interface": ae_a, "qfx_a_vlans": vlan_a, "qfx_b_vlans": vlan_b})
                continue
            attachments.append({"physical_interface": physical, "ae_interface": ae_a, "mapping_source": "EXISTING_SYMMETRIC", "current_vlan_ids": {"qfx-a": vlan_a, "qfx-b": vlan_b}})
            continue

        if config_a or config_b:
            blocked.append({"physical_interface": physical, "reason": "UNMAPPED_INTERFACE_HAS_CONFIGURATION"})
            continue
        if not free:
            blocked.append({"physical_interface": physical, "reason": "NO_FREE_AE"})
            continue
        ae = free.pop(0)
        attachments.append({"physical_interface": physical, "ae_interface": ae, "mapping_source": "PROPOSED_NEW", "current_vlan_ids": {"qfx-a": [], "qfx-b": []}})

    key = {
        "site_id": profile["site_id"],
        "profile": profile,
        "qfx": [
            {k: item.get(k) for k in ("role", "management_address", "ssh_host_key_sha256", "hostname", "model", "serial_number")}
            for item in sorted(observations, key=lambda value: value["role"])
        ],
        "attachments": attachments,
        "blocked": blocked,
    }
    discovery_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "discovery_id": discovery_id,
        "site_id": profile["site_id"],
        "observed_at": observed_at or utc_now(),
        "environment": profile["environment"],
        "qfx_pair": key["qfx"],
        "attachment_inventory": attachments,
        "blocked_interfaces": blocked,
        "asymmetric_interfaces": {"qfx-a-only": only_a, "qfx-b-only": only_b},
        "baseline_vlan_ids": required_baseline,
        "approval": {"approved": False},
    }


def write_site_discovery(settings, profile, discovery):
    root = site_root(settings, profile) / "discoveries" / discovery["discovery_id"]
    path = root / "discovery.json"
    if path.is_file():
        integrity = read_json(root / "integrity.json")
        _require(integrity.get("discovery.json") == sha256_file(path), "existing site discovery integrity failed")
        return root, read_json(path), "UNCHANGED"
    root.mkdir(parents=True, exist_ok=False)
    atomic_json(path, discovery)
    atomic_json(root / "integrity.json", {"discovery.json": sha256_file(path)})
    return root, discovery, "CREATED"


def approve_site_discovery(directory, discovery):
    value = dict(discovery)
    value["approval"] = {"approved": True, "approved_at": utc_now(), "scope": "qfx-identity-and-staging-plan"}
    path = directory / "discovery.json"
    atomic_json(path, value)
    atomic_json(directory / "integrity.json", {"discovery.json": sha256_file(path)})
    return value


def site_discovery_candidates(settings, profile):
    result = []
    root = site_root(settings, profile) / "discoveries"
    for path in root.glob("*/discovery.json"):
        try:
            integrity = read_json(path.parent / "integrity.json")
            if integrity.get("discovery.json") != sha256_file(path):
                continue
            value = read_json(path)
            if value.get("site_id") != profile["site_id"] or not value.get("approval", {}).get("approved"):
                continue
            result.append(value)
        except Exception:
            continue
    return sorted(result, key=lambda item: (item.get("approval", {}).get("approved_at", ""), item.get("discovery_id", "")), reverse=True)


def stage_statements(profile, discovery):
    statements = []
    mgmt = profile["management_vlan"]["name"]
    recovery = profile["temporary_recovery_vlan"]["name"]
    for item in discovery["attachment_inventory"]:
        physical = item["physical_interface"]
        ae = item["ae_interface"]
        system_id = _site_lacp_system_id(profile["site_id"], ae)
        statements.extend([
            "set interfaces %s ether-options 802.3ad %s" % (physical, ae),
            "set interfaces %s aggregated-ether-options lacp active" % ae,
            "set interfaces %s aggregated-ether-options lacp system-id %s" % (ae, system_id),
            "set interfaces %s esi auto-derive type-1-lacp" % ae,
            "set interfaces %s esi all-active" % ae,
            "set interfaces %s unit 0 family ethernet-switching interface-mode trunk" % ae,
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (ae, mgmt),
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (ae, recovery),
        ])
    return statements


def validate_staged_device(dev, profile, discovery):
    config = dev.cli("show configuration interfaces | display set", warning=False) or ""
    vlan_top = dev.cli("show configuration vlans | display set", warning=False) or ""
    vlan_ri = dev.cli("show configuration routing-instances | display set", warning=False) or ""
    definitions = _vlan_definitions(vlan_top + "\n" + vlan_ri)
    required = sorted([
        profile["management_vlan"]["vlan_id"],
        profile["temporary_recovery_vlan"]["vlan_id"],
    ])
    mapping = _ae_map(config)
    checks = []
    for item in discovery["attachment_inventory"]:
        physical = item["physical_interface"]
        ae = item["ae_interface"]
        observed_vlans = _vlan_ids(config, ae, definitions)
        observed_system = _lacp_system_id(config, ae)
        expected_system = _site_lacp_system_id(profile["site_id"], ae)
        checks.append({
            "physical_interface": physical,
            "ae_interface": ae,
            "mapping_matches": mapping.get(physical) == ae,
            "baseline_vlan_ids": observed_vlans,
            "baseline_exact": observed_vlans == required,
            "lacp_system_id": observed_system,
            "lacp_system_id_matches": observed_system == expected_system,
            "esi_auto": bool(re.search(r"(?m)^set interfaces %s esi auto-derive type-1-lacp\s*$" % re.escape(ae), config)),
            "esi_all_active": bool(re.search(r"(?m)^set interfaces %s esi all-active\s*$" % re.escape(ae), config)),
        })
    passed = all(
        item["mapping_matches"]
        and item["baseline_exact"]
        and item["lacp_system_id_matches"]
        and item["esi_auto"]
        and item["esi_all_active"]
        for item in checks
    )
    return checks, passed


def build_site_inventory(profile, discovery, qfx_observations, validation_by_role, created_at=None):
    _require(all(item["passed"] for item in validation_by_role.values()), "QFX baseline staging validation failed")
    attachments = []
    for item in discovery["attachment_inventory"]:
        ae = item["ae_interface"]
        attachments.append({
            "physical_interface": item["physical_interface"],
            "ae_interface": ae,
            "lacp_system_id": _site_lacp_system_id(profile["site_id"], ae),
            "baseline_vlan_ids": sorted([
                profile["management_vlan"]["vlan_id"],
                profile["temporary_recovery_vlan"]["vlan_id"],
            ]),
        })
    stable_qfx = [
        {k: item.get(k) for k in ("role", "management_address", "ssh_host_key_sha256", "hostname", "model", "serial_number")}
        for item in sorted(qfx_observations, key=lambda value: value["role"])
    ]
    key = {
        "site_id": profile["site_id"],
        "profile": profile,
        "source_discovery_id": discovery["discovery_id"],
        "qfx_pair": stable_qfx,
        "attachments": attachments,
    }
    inventory_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "inventory_id": inventory_id,
        "site_id": profile["site_id"],
        "created_at": created_at or utc_now(),
        "environment": profile["environment"],
        "source_discovery_id": discovery["discovery_id"],
        "qfx_pair": stable_qfx,
        "attachments": attachments,
        "baseline_vlan_ids": sorted([
            profile["management_vlan"]["vlan_id"],
            profile["temporary_recovery_vlan"]["vlan_id"],
        ]),
        "validation": {role: value for role, value in sorted(validation_by_role.items())},
        "result": "PASS",
    }


def write_site_inventory(settings, profile, inventory):
    directory = site_root(settings, profile) / "inventories" / inventory["inventory_id"]
    path = directory / "inventory.json"
    if path.is_file():
        integrity = read_json(directory / "integrity.json")
        _require(integrity.get("inventory.json") == sha256_file(path), "existing site inventory integrity failed")
        return directory, read_json(path), "UNCHANGED"
    directory.mkdir(parents=True, exist_ok=False)
    atomic_json(path, inventory)
    atomic_json(directory / "integrity.json", {"inventory.json": sha256_file(path)})
    return directory, inventory, "CREATED"


def build_active_policy(profile, inventory, inventory_path):
    pair = []
    for item in inventory["qfx_pair"]:
        pair.append({
            "role": item["role"],
            "management_address": item["management_address"],
            "expected_hostname": item["hostname"],
            "expected_model": item["model"],
        })
    ports = [item["physical_interface"] for item in inventory["attachments"]]
    ae_numbers = [int(item["ae_interface"][2:]) for item in inventory["attachments"]]
    return {
        "schema_version": "1.2",
        "site_policy_id": "%s-%s" % (profile["site_id"], inventory["inventory_id"]),
        "site_id": profile["site_id"],
        "environment": profile["environment"],
        "production_eligible": profile["production_eligible"],
        "qfx_pair": pair,
        "stage_port_pools": {"site-staged": ports},
        "excluded_interfaces": list(profile["excluded_interfaces"]),
        "ae_pool": {
            "method": "discover-from-existing-qfx-config",
            "ae_min": min(ae_numbers) if ae_numbers else profile["ae_pool"]["ae_min"],
            "ae_max": max(ae_numbers) if ae_numbers else profile["ae_pool"]["ae_max"],
            "migration_assignment_prebound": False,
        },
        "management_vlan": dict(profile["management_vlan"]),
        "temporary_recovery_vlan": dict(profile["temporary_recovery_vlan"]),
        "prestage_access_vlan": dict(profile["prestage_access_vlan"]),
        "precutover_qfx_baseline": {
            "required_vlan_ids": list(inventory["baseline_vlan_ids"]),
            "lacp_mode": "active",
            "force_up": False,
        },
        "esi": dict(profile["esi"]),
        "validation": {
            "attachment_discovered_post_cutover": True,
            "require_interface_symmetry": True,
            "require_lldp": True,
            "require_lacp_partner": True,
            "require_matching_ae": True,
            "require_matching_lacp_system_id": True,
            "operator_supplied_ports_allowed": False,
        },
        "source_site_inventory": {
            "inventory_id": inventory["inventory_id"],
            "inventory_digest": sha256_file(inventory_path),
            "path": str(inventory_path),
        },
    }


def write_active_policy(settings, policy):
    path = active_policy_path(settings)
    atomic_json(path, policy)
    return path


def site_inventory_candidates(settings, profile):
    result = []
    root = site_root(settings, profile) / "inventories"
    for path in root.glob("*/inventory.json"):
        try:
            integrity = read_json(path.parent / "integrity.json")
            if integrity.get("inventory.json") != sha256_file(path):
                continue
            value = read_json(path)
            if value.get("site_id") == profile["site_id"] and value.get("result") == "PASS":
                result.append((value, path))
        except Exception:
            continue
    return sorted(result, key=lambda item: (item[0].get("created_at", ""), item[0].get("inventory_id", "")), reverse=True)
