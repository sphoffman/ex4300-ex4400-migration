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
from ex_migration_discovery.parsers import parse_lldp_neighbors_text

from .core import ProvisioningError
from .prestage import validate_pre_cutover_site_policy


_AE_PARENT = re.compile(
    r"(?m)^set interfaces (?P<physical>\S+) (?:ether-options|gigether-options) "
    r"802\.3ad (?P<ae>ae\d+)\s*$"
)
_SYSTEM_ID = re.compile(
    r"(?im)^set interfaces (?P<ae>ae\d+) aggregated-ether-options lacp "
    r"system-id (?P<value>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*$"
)
_VLAN_DEF = re.compile(r"(?m)^set vlans (?P<name>\S+) vlan-id (?P<id>\d+)\s*$")
_VLAN_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<ae>ae\d+) unit 0 family ethernet-switching "
    r"vlan members (?P<value>\S+)\s*$"
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _ae_number(name):
    match = re.fullmatch(r"ae(\d+)", str(name or ""))
    if not match:
        return None
    return int(match.group(1))


def _allowed_ports(policy):
    result = set()
    for ports in policy.get("stage_port_pools", {}).values():
        result.update(ports)
    return result


def _configured_ae(config_text, physical):
    matches = [
        match.group("ae")
        for match in _AE_PARENT.finditer(config_text or "")
        if match.group("physical") == physical
    ]
    return matches[0] if len(matches) == 1 else None


def _system_id(config_text, ae):
    matches = [
        match.group("value").lower()
        for match in _SYSTEM_ID.finditer(config_text or "")
        if match.group("ae") == ae
    ]
    return matches[0] if len(matches) == 1 else None


def _vlan_ids(vlan_config, ae_config, ae):
    names = {
        match.group("name"): int(match.group("id"))
        for match in _VLAN_DEF.finditer(vlan_config or "")
    }
    tokens = [
        match.group("value")
        for match in _VLAN_MEMBER.finditer(ae_config or "")
        if match.group("ae") == ae
    ]
    if "all" in tokens:
        return None, ["all"]
    ids = []
    unresolved = []
    for token in tokens:
        if token.isdigit():
            ids.append(int(token))
        elif token in names:
            ids.append(names[token])
        else:
            unresolved.append(token)
    return sorted(set(ids)), sorted(set(unresolved))


def _lacp_operational(text, physical):
    value = text or ""
    return (
        physical in value
        and re.search(r"(?i)\bcollecting\b", value) is not None
        and re.search(r"(?i)\bdistributing\b", value) is not None
    )


def _target_neighbors(lldp_text, expected_hostname):
    expected = str(expected_hostname).strip().lower()
    return [
        item
        for item in parse_lldp_neighbors_text(lldp_text or "", "", "")
        if str(item.get("remote_system_name") or "").strip().lower() == expected
    ]


def observe_qfx_attachment(dev, device_policy, policy, expected_ex_hostname, host_key):
    facts = getattr(dev, "facts", {}) or {}
    observed_hostname = str(facts.get("hostname") or "")
    observed_model = str(facts.get("model") or "")

    lldp_text = dev.cli("show lldp neighbors detail", warning=False) or ""
    neighbors = _target_neighbors(lldp_text, expected_ex_hostname)
    unique_neighbor = neighbors[0] if len(neighbors) == 1 else None
    physical = str(unique_neighbor.get("local_interface") or "") if unique_neighbor else ""

    allowed = _allowed_ports(policy)
    excluded = set(policy.get("excluded_interfaces", []))
    physical_config = ""
    ae = None
    ae_config = ""
    lacp_text = ""
    vlan_config = ""
    system_id = None
    vlan_ids = None
    unresolved_vlans = []

    if physical:
        physical_config = dev.cli(
            "show configuration interfaces %s | display set" % physical,
            warning=False,
        ) or ""
        ae = _configured_ae(physical_config, physical)
    if ae:
        ae_config = dev.cli(
            "show configuration interfaces %s | display set" % ae,
            warning=False,
        ) or ""
        lacp_text = dev.cli(
            "show lacp interfaces %s extensive" % ae,
            warning=False,
        ) or ""
        vlan_config = dev.cli("show configuration vlans | display set", warning=False) or ""
        system_id = _system_id(ae_config, ae)
        vlan_ids, unresolved_vlans = _vlan_ids(vlan_config, ae_config, ae)

    ae_number = _ae_number(ae)
    ae_pool = policy["ae_pool"]
    required_vlans = sorted(policy["precutover_qfx_baseline"]["required_vlan_ids"])
    force_up_present = bool(
        ae and re.search(
            r"(?m)^set interfaces %s aggregated-ether-options lacp force-up\s*$"
            % re.escape(ae),
            ae_config,
        )
    )
    lacp_active = bool(
        ae and re.search(
            r"(?m)^set interfaces %s aggregated-ether-options lacp active\s*$"
            % re.escape(ae),
            ae_config,
        )
    )
    esi_auto = bool(
        ae and re.search(
            r"(?m)^set interfaces %s esi auto-derive type-1-lacp\s*$"
            % re.escape(ae),
            ae_config,
        )
    )
    esi_all_active = bool(
        ae and re.search(
            r"(?m)^set interfaces %s esi all-active\s*$" % re.escape(ae),
            ae_config,
        )
    )

    checks = {
        "qfx_hostname_matches": observed_hostname.lower()
        == str(device_policy["expected_hostname"]).lower(),
        "qfx_model_matches": observed_model.lower()
        == str(device_policy["expected_model"]).lower(),
        "exactly_one_target_lldp_neighbor": len(neighbors) == 1,
        "physical_interface_allowed": bool(physical) and physical in allowed,
        "physical_interface_not_excluded": bool(physical) and physical not in excluded,
        "physical_maps_to_one_ae": bool(ae),
        "ae_in_allowed_range": ae_number is not None
        and ae_pool["ae_min"] <= ae_number <= ae_pool["ae_max"],
        "lacp_active": lacp_active,
        "lacp_force_up_absent": not force_up_present,
        "lacp_system_id_present": bool(system_id),
        "esi_auto_derive_type_1_lacp": esi_auto,
        "esi_all_active": esi_all_active,
        "baseline_vlans_exact": vlan_ids == required_vlans and not unresolved_vlans,
        "lacp_collecting_distributing": bool(ae)
        and _lacp_operational(lacp_text, physical),
    }

    return {
        "role": device_policy["role"],
        "management_address": device_policy["management_address"],
        "ssh_host_key_sha256": host_key,
        "expected_qfx_hostname": device_policy["expected_hostname"],
        "expected_qfx_model": device_policy["expected_model"],
        "observed_qfx_hostname": observed_hostname,
        "observed_qfx_model": observed_model,
        "expected_ex_hostname": expected_ex_hostname,
        "lldp_match_count": len(neighbors),
        "physical_interface": physical or None,
        "remote_port_id": unique_neighbor.get("remote_port_id") if unique_neighbor else None,
        "ae_interface": ae,
        "lacp_system_id": system_id,
        "baseline_vlan_ids": vlan_ids,
        "unresolved_vlan_members": unresolved_vlans,
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def discover_qfx_attachment(policy, expected_ex_hostname, devices, host_keys, observed_at=None):
    validate_pre_cutover_site_policy(policy)
    observations = []
    for device_policy in policy["qfx_pair"]:
        role = device_policy["role"]
        _require(role in devices, "missing connected QFX device for role %s" % role)
        _require(role in host_keys, "missing QFX host-key observation for role %s" % role)
        observations.append(
            observe_qfx_attachment(
                devices[role],
                device_policy,
                policy,
                expected_ex_hostname,
                host_keys[role],
            )
        )

    by_role = {item["role"]: item for item in observations}
    a = by_role["qfx-a"]
    b = by_role["qfx-b"]
    pair_checks = {
        "same_target_ex_hostname": (
            a["expected_ex_hostname"].lower() == b["expected_ex_hostname"].lower()
            == str(expected_ex_hostname).lower()
        ),
        "physical_interface_symmetry": bool(a["physical_interface"])
        and a["physical_interface"] == b["physical_interface"],
        "ae_symmetry": bool(a["ae_interface"])
        and a["ae_interface"] == b["ae_interface"],
        "lacp_system_id_symmetry": bool(a["lacp_system_id"])
        and a["lacp_system_id"] == b["lacp_system_id"],
    }
    passed = all(item["result"] == "PASS" for item in observations) and all(
        pair_checks.values()
    )
    return {
        "schema_version": "1.0",
        "observed_at": observed_at or utc_now(),
        "expected_ex_hostname": expected_ex_hostname,
        "devices": observations,
        "pair_checks": pair_checks,
        "result": "PASS" if passed else "FAIL",
    }


def build_attachment_artifact(
    migration_id,
    plan_id,
    plan_digest,
    site_policy_id,
    site_policy_digest,
    discovery,
    approved_at,
):
    _require(discovery.get("result") == "PASS", "QFX attachment discovery did not pass")
    stable_devices = []
    for item in sorted(discovery["devices"], key=lambda value: value["role"]):
        stable_devices.append({
            "role": item["role"],
            "management_address": item["management_address"],
            "ssh_host_key_sha256": item["ssh_host_key_sha256"],
            "observed_qfx_hostname": item["observed_qfx_hostname"],
            "observed_qfx_model": item["observed_qfx_model"],
            "physical_interface": item["physical_interface"],
            "remote_port_id": item["remote_port_id"],
            "ae_interface": item["ae_interface"],
            "lacp_system_id": item["lacp_system_id"],
            "baseline_vlan_ids": item["baseline_vlan_ids"],
        })
    key = {
        "migration_id": migration_id,
        "plan_digest": plan_digest,
        "site_policy_digest": site_policy_digest,
        "expected_ex_hostname": discovery["expected_ex_hostname"],
        "devices": stable_devices,
    }
    attachment_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "attachment_id": attachment_id,
        "migration_id": migration_id,
        "observed_at": discovery["observed_at"],
        "approved_at": approved_at,
        "plan": {"plan_id": plan_id, "plan_digest": plan_digest},
        "site_policy": {
            "site_policy_id": site_policy_id,
            "site_policy_digest": site_policy_digest,
        },
        "expected_ex_hostname": discovery["expected_ex_hostname"],
        "devices": discovery["devices"],
        "pair_checks": discovery["pair_checks"],
        "result": "PASS",
        "approval": {
            "approved": True,
            "method": "interactive-operator-binding",
            "scope": "observed-post-cutover-qfx-attachment",
        },
        "safety": {
            "qfx_writes_authorized": False,
            "ex4400_writes_authorized": False,
            "operator_supplied_ports_used": False,
            "force_up_allowed": False,
        },
    }


def write_attachment(migration_root, artifact):
    destination = migration_root / "qfx-attachments" / artifact["attachment_id"]
    path = destination / "attachment.json"
    if path.is_file():
        integrity = destination / "integrity.json"
        _require(integrity.is_file(), "missing attachment integrity record")
        expected = read_json(integrity).get("attachment.json")
        _require(expected == sha256_file(path), "attachment integrity validation failed")
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(artifact)
        comparable_existing.pop("approved_at", None)
        comparable_new.pop("approved_at", None)
        if comparable_existing != comparable_new:
            raise ProvisioningError("existing QFX attachment ID has different content")
        return destination, existing, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, artifact)
    atomic_json(destination / "integrity.json", {
        "attachment.json": sha256_file(path),
    })
    return destination, artifact, "CREATED"
